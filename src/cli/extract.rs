use anyhow::Result;
use clap::{Args, ValueEnum};
use indicatif::{ProgressBar, ProgressStyle};
use log::debug;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::analyzer::complexity::{ComplexityAnalyzer, ComplexityScore};
use crate::analyzer::Analyzer;
use crate::db::{BinaryInfo, Database};
use crate::extractor::{ExtractionFilter, Extractor, InstructionCategory};
use crate::simulator::Simulator;

/// Selection strategy for smart block extraction.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum SelectionStrategy {
    /// Original random selection (default)
    #[default]
    Random,
    /// Maximize instruction variety across selected blocks
    Diverse,
    /// Maximize complexity score (likely to expose FEX-Emu bugs)
    Complex,
}

#[derive(Args)]
pub struct ExtractCommand {
    #[arg(help = "Path to the binary file (ELF or PE format)")]
    binary: PathBuf,

    #[arg(short, long, help = "Enable verbose logging")]
    verbose: bool,

    #[arg(short, long, help = "Suppress all output")]
    quiet: bool,

    #[arg(
        short,
        long,
        default_value = "snippex.db",
        help = "SQLite database path"
    )]
    database: PathBuf,

    #[arg(
        long,
        value_names = ["START", "END"],
        num_args = 2,
        help = "Extract from specific address range (must be instruction-aligned)"
    )]
    range: Option<Vec<String>>,

    #[arg(long, help = "Minimum block size in bytes")]
    min_size: Option<usize>,

    #[arg(long, help = "Maximum block size in bytes")]
    max_size: Option<usize>,

    #[arg(long, help = "Only extract blocks with memory access instructions")]
    has_memory_access: bool,

    #[arg(long, help = "Only extract blocks without memory access instructions")]
    no_memory_access: bool,

    #[arg(
        long,
        help = "Only extract blocks with control flow instructions (jumps, calls, returns)"
    )]
    has_control_flow: bool,

    #[arg(long, help = "Only extract blocks without control flow instructions")]
    no_control_flow: bool,

    #[arg(
        long,
        value_delimiter = ',',
        help = "Filter by instruction categories (comma-separated: general,fpu,sse,avx,avx512,branch,syscall)"
    )]
    instruction_types: Option<Vec<String>>,

    #[arg(
        long,
        help = "Preview filter effectiveness without extracting (shows match rate)"
    )]
    dry_run: bool,

    #[arg(
        long,
        default_value = "100",
        help = "Number of samples for dry-run preview"
    )]
    dry_run_samples: usize,

    #[arg(
        long,
        help = "Enable smart block selection based on instruction complexity"
    )]
    smart_select: bool,

    #[arg(
        long,
        value_enum,
        default_value = "random",
        help = "Selection strategy: random (default), diverse (maximize variety), complex (maximize complexity)"
    )]
    select_strategy: SelectionStrategy,

    #[arg(
        long,
        default_value = "1",
        help = "Number of blocks to extract (used with --smart-select)"
    )]
    count: usize,

    #[arg(
        long,
        help = "Show detailed selection report explaining why blocks were chosen"
    )]
    selection_report: bool,

    #[arg(
        long,
        help = "Only keep blocks that execute natively (simulates each block)"
    )]
    valid_only: bool,

    #[arg(
        long,
        default_value = "5",
        help = "Number of native simulation runs for --valid-only validation"
    )]
    validation_runs: usize,

    #[arg(
        long,
        help = "Max extraction attempts for --valid-only before giving up (default: 10x count)"
    )]
    max_attempts: Option<usize>,
}

impl ExtractCommand {
    pub fn execute(self) -> Result<()> {
        // Validate conflicting options
        if self.has_memory_access && self.no_memory_access {
            return Err(anyhow::anyhow!(
                "Cannot use both --has-memory-access and --no-memory-access"
            ));
        }

        if self.has_control_flow && self.no_control_flow {
            return Err(anyhow::anyhow!(
                "Cannot use both --has-control-flow and --no-control-flow"
            ));
        }

        if self.count == 0 {
            return Err(anyhow::anyhow!("--count must be at least 1"));
        }

        if self.valid_only && self.dry_run {
            return Err(anyhow::anyhow!(
                "Cannot use both --valid-only and --dry-run"
            ));
        }

        if !self.quiet {
            println!("Extracting from binary: {}", self.binary.display());
        }

        if self.verbose {
            debug!("Verbose mode enabled");
        }

        let extractor = Extractor::new(self.binary.clone())?;
        let binary_info = extractor.get_binary_info()?;

        if !self.quiet {
            println!(
                "Binary info: {} {} (SHA256: {}...)",
                binary_info.format,
                binary_info.architecture,
                &binary_info.hash[..8]
            );
        }

        if self.verbose {
            debug!("Full binary info: {binary_info:?}");
        }

        // Build the extraction filter
        let filter = self.build_filter()?;

        // Handle dry-run mode
        if self.dry_run {
            return self.execute_dry_run(&extractor, &filter);
        }

        // Handle smart selection mode (but not --valid-only without --smart-select)
        if self.smart_select || (self.count > 1 && !self.valid_only) {
            return self.execute_smart_select(&extractor, &binary_info, &filter);
        }

        let mut db = Database::new(&self.database)?;
        db.init()?;

        if !self.quiet {
            println!("Database initialized: {}", self.database.display());
        }

        if self.valid_only {
            return self.execute_validated_single(&extractor, &binary_info, &filter, &mut db);
        }

        let (start_addr, end_addr, assembly_block) = if let Some(range) = &self.range {
            if range.len() != 2 {
                return Err(anyhow::anyhow!(
                    "Range option requires exactly two addresses"
                ));
            }

            let start_addr = Self::parse_address(&range[0])?;
            let end_addr = Self::parse_address(&range[1])?;

            if !self.quiet {
                println!("Extracting from specified range: 0x{start_addr:08x} - 0x{end_addr:08x}");
            }

            extractor.extract_range(start_addr, end_addr)?
        } else if !filter.is_empty() {
            if !self.quiet {
                println!("Extracting with filters...");
                self.print_filter_summary(&filter);
            }
            extractor.extract_filtered_block(&filter)?
        } else {
            extractor.extract_random_aligned_block()?
        };

        if !self.quiet {
            let instruction_count = if let Ok(cs) = extractor.create_capstone() {
                cs.disasm_all(&assembly_block, start_addr)
                    .map(|insns| insns.len())
                    .unwrap_or(0)
            } else {
                0
            };

            println!(
                "Extracted block: 0x{:08x} - 0x{:08x} ({} bytes, {} instructions)",
                start_addr,
                end_addr,
                assembly_block.len(),
                instruction_count
            );

            if self.verbose && !filter.is_empty() {
                if let Ok(filter_match) =
                    extractor.check_block_filter(&assembly_block, start_addr, &filter)
                {
                    let categories: Vec<_> = filter_match
                        .categories_found
                        .iter()
                        .map(|c| c.as_str())
                        .collect();
                    println!(
                        "  Memory access: {}, Categories: {}",
                        if filter_match.has_memory_access {
                            "yes"
                        } else {
                            "no"
                        },
                        categories.join(", ")
                    );
                }
            }
        }

        if self.verbose {
            debug!(
                "Assembly block first 16 bytes: {:02x?}",
                &assembly_block[..16.min(assembly_block.len())]
            );
        }

        let is_new = db.store_extraction(&binary_info, start_addr, end_addr, &assembly_block)?;

        if !self.quiet {
            if is_new {
                println!("✓ Extraction stored in database successfully");
            } else {
                println!("Duplicate block, not stored");
            }
        }

        Ok(())
    }

    fn build_filter(&self) -> Result<ExtractionFilter> {
        let mut filter = ExtractionFilter::new();

        if let Some(min) = self.min_size {
            filter = filter.with_min_size(min);
        }

        if let Some(max) = self.max_size {
            filter = filter.with_max_size(max);
        }

        if self.has_memory_access {
            filter = filter.with_memory_access(true);
        } else if self.no_memory_access {
            filter = filter.with_memory_access(false);
        }

        if self.has_control_flow {
            filter = filter.with_control_flow(true);
        } else if self.no_control_flow {
            filter = filter.with_control_flow(false);
        }

        if let Some(ref types) = self.instruction_types {
            let mut categories = HashSet::new();
            for type_str in types {
                match type_str.parse::<InstructionCategory>() {
                    Ok(cat) => {
                        categories.insert(cat);
                    }
                    Err(_) => {
                        return Err(anyhow::anyhow!(
                            "Unknown instruction category '{}'. Valid categories: \
                             general, fpu, sse, avx, avx512, branch, syscall",
                            type_str
                        ));
                    }
                }
            }
            if !categories.is_empty() {
                filter = filter.with_instruction_categories(categories);
            }
        }

        filter.validate()?;
        Ok(filter)
    }

    fn print_filter_summary(&self, filter: &ExtractionFilter) {
        let mut criteria = Vec::new();

        if let Some(min) = filter.min_size {
            criteria.push(format!("min-size: {} bytes", min));
        }
        if let Some(max) = filter.max_size {
            criteria.push(format!("max-size: {} bytes", max));
        }
        if let Some(mem) = filter.require_memory_access {
            criteria.push(format!(
                "memory access: {}",
                if mem { "required" } else { "excluded" }
            ));
        }
        if let Some(cf) = filter.require_control_flow {
            criteria.push(format!(
                "control flow: {}",
                if cf { "required" } else { "excluded" }
            ));
        }
        if let Some(ref cats) = filter.instruction_categories {
            let cat_names: Vec<_> = cats.iter().map(|c| c.as_str()).collect();
            criteria.push(format!("instruction types: {}", cat_names.join(", ")));
        }

        if !criteria.is_empty() {
            println!("  Filter criteria: {}", criteria.join(", "));
        }
    }

    fn execute_dry_run(&self, extractor: &Extractor, filter: &ExtractionFilter) -> Result<()> {
        println!(
            "Dry-run mode: sampling {} random blocks...",
            self.dry_run_samples
        );

        if !filter.is_empty() {
            self.print_filter_summary(filter);
        }

        let (matching, total) = extractor.count_matching_blocks(filter, self.dry_run_samples)?;

        if total == 0 {
            println!("\nNo blocks could be extracted from this binary.");
            return Ok(());
        }

        let match_rate = (matching as f64 / total as f64) * 100.0;

        println!("\nDry-run results:");
        println!("  Total sampled:  {}", total);
        println!("  Matching:       {} ({:.1}%)", matching, match_rate);
        println!(
            "  Not matching:   {} ({:.1}%)",
            total - matching,
            100.0 - match_rate
        );

        if matching == 0 {
            println!("\n⚠ Warning: No blocks matched the filter criteria.");
            println!("  Consider relaxing the filter constraints.");
        } else if match_rate < 10.0 {
            println!(
                "\n⚠ Low match rate ({:.1}%). Extraction may require many attempts.",
                match_rate
            );
        } else {
            println!("\n✓ Filter looks reasonable for extraction.");
        }

        Ok(())
    }

    fn parse_address(addr_str: &str) -> Result<u64> {
        if addr_str.starts_with("0x") || addr_str.starts_with("0X") {
            // Parse as hexadecimal
            u64::from_str_radix(&addr_str[2..], 16)
                .map_err(|e| anyhow::anyhow!("Invalid hexadecimal address '{}': {}", addr_str, e))
        } else {
            // Parse as decimal
            addr_str
                .parse::<u64>()
                .map_err(|e| anyhow::anyhow!("Invalid decimal address '{}': {}", addr_str, e))
        }
    }

    fn execute_smart_select(
        &self,
        extractor: &Extractor,
        binary_info: &crate::db::BinaryInfo,
        filter: &ExtractionFilter,
    ) -> Result<()> {
        let mut db = Database::new(&self.database)?;
        db.init()?;

        if !self.quiet {
            println!("Database initialized: {}", self.database.display());
            println!(
                "Smart selection mode: extracting {} block(s) with {:?} strategy",
                self.count, self.select_strategy
            );
            if !filter.is_empty() {
                self.print_filter_summary(filter);
            }
        }

        let complexity_analyzer = ComplexityAnalyzer::new();
        let cs = extractor.create_capstone()?;

        // Generate candidate blocks
        let candidate_count = self.count * 10; // Sample 10x the requested count
        let mut candidates: Vec<CandidateBlock> = Vec::new();

        // Create progress bar
        let progress = if !self.quiet {
            let pb = ProgressBar::new(candidate_count as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) {msg}")
                    .unwrap()
                    .progress_chars("█▓▒░"),
            );
            pb.set_message("sampling candidates...");
            Some(pb)
        } else {
            None
        };

        let mut simulator = if self.valid_only {
            Some(Simulator::new()?)
        } else {
            None
        };

        for _ in 0..candidate_count {
            let result = if !filter.is_empty() {
                extractor.extract_filtered_block(filter)
            } else {
                extractor.extract_random_aligned_block()
            };

            if let Ok((start_addr, end_addr, assembly_block)) = result {
                if self.valid_only {
                    if let Some(ref mut sim) = simulator {
                        if !self.validate_block_natively(
                            &self.binary,
                            binary_info,
                            start_addr,
                            end_addr,
                            &assembly_block,
                            sim,
                        )? {
                            if let Some(ref pb) = progress {
                                pb.inc(1);
                            }
                            continue;
                        }
                    }
                }

                if let Ok(insns) = cs.disasm_all(&assembly_block, start_addr) {
                    let score = complexity_analyzer.score_block(&insns);
                    let variety = complexity_analyzer.get_instruction_variety(&insns);
                    let has_problematic = complexity_analyzer.has_problematic_instructions(&insns);

                    candidates.push(CandidateBlock {
                        start_addr,
                        end_addr,
                        assembly_block,
                        complexity_score: score,
                        instruction_variety: variety,
                        has_problematic_instructions: has_problematic,
                        instruction_count: insns.len(),
                    });
                }
            }

            if let Some(ref pb) = progress {
                pb.inc(1);
                pb.set_message(format!("{} valid candidates", candidates.len()));
            }
        }

        if let Some(pb) = progress {
            pb.finish_with_message(format!("found {} valid candidates", candidates.len()));
        }

        if candidates.is_empty() {
            return Err(anyhow::anyhow!(
                "Could not extract any valid blocks from this binary"
            ));
        }

        // Select blocks based on strategy
        let selected = self.select_blocks(&mut candidates);

        if !self.quiet {
            println!(
                "\nSelected {} block(s) from {} candidates:",
                selected.len(),
                candidates.len() + selected.len()
            );
        }

        // Store selected blocks and print report
        let mut total_instructions = HashSet::new();
        for (i, block) in selected.iter().enumerate() {
            let is_new = db.store_extraction(
                binary_info,
                block.start_addr,
                block.end_addr,
                &block.assembly_block,
            )?;

            total_instructions.extend(block.instruction_variety.iter().cloned());

            if !is_new && !self.quiet {
                println!("\n  Block {}: duplicate, skipped", i + 1);
            } else if !self.quiet {
                println!(
                    "\n  Block {}: 0x{:08x} - 0x{:08x} ({} bytes, {} instructions)",
                    i + 1,
                    block.start_addr,
                    block.end_addr,
                    block.assembly_block.len(),
                    block.instruction_count
                );

                if self.selection_report || self.verbose {
                    self.print_block_report(block);
                }
            }
        }

        if !self.quiet {
            println!(
                "\n✓ {} block(s) stored in database successfully",
                selected.len()
            );

            if self.selection_report {
                self.print_selection_summary(&selected, &total_instructions);
            }
        }

        Ok(())
    }

    fn select_blocks(&self, candidates: &mut Vec<CandidateBlock>) -> Vec<CandidateBlock> {
        match self.select_strategy {
            SelectionStrategy::Random => {
                // Just take first N (already randomly extracted)
                candidates.truncate(self.count);
                std::mem::take(candidates)
            }
            SelectionStrategy::Complex => {
                // Sort by complexity score (descending) and take top N
                candidates.sort_by(|a, b| {
                    b.complexity_score
                        .total
                        .partial_cmp(&a.complexity_score.total)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
                candidates.truncate(self.count);
                std::mem::take(candidates)
            }
            SelectionStrategy::Diverse => {
                // Greedy selection to maximize instruction variety
                let mut selected = Vec::new();
                let mut covered_instructions: HashSet<String> = HashSet::new();

                while selected.len() < self.count && !candidates.is_empty() {
                    // Find candidate that adds most new instructions
                    let best_idx = candidates
                        .iter()
                        .enumerate()
                        .max_by_key(|(_, c)| {
                            c.instruction_variety
                                .difference(&covered_instructions)
                                .count()
                        })
                        .map(|(i, _)| i);

                    if let Some(idx) = best_idx {
                        let block = candidates.remove(idx);
                        covered_instructions.extend(block.instruction_variety.iter().cloned());
                        selected.push(block);
                    } else {
                        break;
                    }
                }

                selected
            }
        }
    }

    fn print_block_report(&self, block: &CandidateBlock) {
        println!("    Complexity Score: {:.2}", block.complexity_score.total);
        println!("      - Rarity:     {:.2}", block.complexity_score.rarity);
        println!(
            "      - Addressing: {:.2}",
            block.complexity_score.addressing
        );
        println!("      - Operands:   {:.2}", block.complexity_score.operands);
        println!(
            "    Instruction Variety: {} unique mnemonics",
            block.instruction_variety.len()
        );
        if block.has_problematic_instructions {
            println!("    ⚠ Contains problematic instructions (likely to expose FEX-Emu bugs)");
        }

        // Show top instructions
        let mut instr_list: Vec<_> = block.instruction_variety.iter().collect();
        instr_list.sort();
        let display_list: Vec<_> = instr_list.iter().take(10).map(|s| s.as_str()).collect();
        if !display_list.is_empty() {
            println!("    Instructions: {}", display_list.join(", "));
            if block.instruction_variety.len() > 10 {
                println!(
                    "                  ... and {} more",
                    block.instruction_variety.len() - 10
                );
            }
        }
    }

    fn print_selection_summary(
        &self,
        selected: &[CandidateBlock],
        total_instructions: &HashSet<String>,
    ) {
        println!("\n=== Selection Summary ===");
        println!("Strategy: {:?}", self.select_strategy);
        println!("Blocks selected: {}", selected.len());
        println!(
            "Total unique instructions covered: {}",
            total_instructions.len()
        );

        // Count blocks with problematic instructions
        let problematic_count = selected
            .iter()
            .filter(|b| b.has_problematic_instructions)
            .count();
        println!(
            "Blocks with problematic instructions: {}",
            problematic_count
        );

        // Average complexity
        let avg_complexity: f64 = selected
            .iter()
            .map(|b| b.complexity_score.total)
            .sum::<f64>()
            / selected.len() as f64;
        println!("Average complexity score: {:.2}", avg_complexity);

        // Show instruction coverage
        let mut instr_list: Vec<_> = total_instructions.iter().collect();
        instr_list.sort();
        println!("\nInstruction categories covered:");
        for chunk in instr_list.chunks(8) {
            let line: Vec<_> = chunk.iter().map(|s| s.as_str()).collect();
            println!("  {}", line.join(", "));
        }
    }

    fn execute_validated_single(
        &self,
        extractor: &Extractor,
        binary_info: &BinaryInfo,
        filter: &ExtractionFilter,
        db: &mut Database,
    ) -> Result<()> {
        let mut simulator = Simulator::new()?;
        let mut rejected = 0;

        // For --range, extract once and validate
        if let Some(range) = &self.range {
            if range.len() != 2 {
                return Err(anyhow::anyhow!(
                    "Range option requires exactly two addresses"
                ));
            }
            let start_addr = Self::parse_address(&range[0])?;
            let end_addr = Self::parse_address(&range[1])?;
            let (start_addr, end_addr, assembly_block) =
                extractor.extract_range(start_addr, end_addr)?;

            if !self.quiet {
                print!(
                    "  Block 0x{:08x}-0x{:08x} ({} bytes) - validating... ",
                    start_addr,
                    end_addr,
                    assembly_block.len()
                );
            }

            if self.validate_block_natively(
                &self.binary,
                binary_info,
                start_addr,
                end_addr,
                &assembly_block,
                &mut simulator,
            )? {
                if !self.quiet {
                    println!(
                        "PASS ({}/{} runs)",
                        self.validation_runs, self.validation_runs
                    );
                }
                let is_new = db.store_extraction(binary_info, start_addr, end_addr, &assembly_block)?;
                if !self.quiet {
                    if is_new {
                        println!("✓ Valid block stored in database");
                    } else {
                        println!("  Duplicate block, skipped");
                    }
                }
            } else {
                if !self.quiet {
                    println!("FAIL");
                }
                return Err(anyhow::anyhow!(
                    "Block at specified range failed native validation"
                ));
            }
            return Ok(());
        }

        let blocks_needed = if self.smart_select || self.count > 1 {
            self.count
        } else {
            1
        };
        let max_attempts = self.max_attempts.unwrap_or(blocks_needed * 10);
        let mut stored = 0;

        if !self.quiet {
            println!(
                "Extracting valid blocks (up to {} attempts, {} validation runs each)",
                max_attempts, self.validation_runs
            );
        }

        let mut attempt = 0;
        let mut consecutive_dupes = 0;
        let max_consecutive_dupes = 50;

        while stored < blocks_needed && attempt < max_attempts {
            attempt += 1;

            let result = if !filter.is_empty() {
                extractor.extract_filtered_block(filter)
            } else {
                extractor.extract_random_aligned_block()
            };

            let (start_addr, end_addr, assembly_block) = match result {
                Ok(v) => v,
                Err(_) => continue,
            };

            if !self.quiet {
                print!(
                    "  Attempt {}: block 0x{:08x}-0x{:08x} ({} bytes) - validating... ",
                    attempt,
                    start_addr,
                    end_addr,
                    assembly_block.len()
                );
            }

            if self.validate_block_natively(
                &self.binary,
                binary_info,
                start_addr,
                end_addr,
                &assembly_block,
                &mut simulator,
            )? {
                if !self.quiet {
                    println!(
                        "PASS ({}/{} runs)",
                        self.validation_runs, self.validation_runs
                    );
                }
                let is_new = db.store_extraction(binary_info, start_addr, end_addr, &assembly_block)?;
                if is_new {
                    stored += 1;
                    consecutive_dupes = 0;
                    if !self.quiet {
                        println!("  Stored as block #{}", stored);
                    }
                } else {
                    consecutive_dupes += 1;
                    if !self.quiet {
                        println!("  Duplicate block, skipped");
                    }
                    if consecutive_dupes >= max_consecutive_dupes {
                        if !self.quiet {
                            println!(
                                "\nStopping: {} consecutive duplicates suggests no more unique blocks match the filters",
                                max_consecutive_dupes
                            );
                        }
                        break;
                    }
                }
            } else {
                if !self.quiet {
                    println!("FAIL");
                }
                rejected += 1;
            }
        }

        if !self.quiet {
            println!();
            if stored > 0 {
                println!(
                    "Extraction complete: {} valid block(s) found ({} rejected)",
                    stored, rejected
                );
            } else {
                println!(
                    "Extraction failed: no valid blocks found after {} attempts ({} rejected)",
                    max_attempts, rejected
                );
            }
        }

        if stored == 0 {
            Err(anyhow::anyhow!(
                "No valid blocks found after {} attempts",
                max_attempts
            ))
        } else {
            Ok(())
        }
    }

    fn validate_block_natively(
        &self,
        binary_path: &Path,
        binary_info: &BinaryInfo,
        start_addr: u64,
        end_addr: u64,
        assembly_block: &[u8],
        simulator: &mut Simulator,
    ) -> Result<bool> {
        use crate::db::ExtractionInfo;

        let analyzer = Analyzer::new(&binary_info.architecture);
        let analysis = match analyzer.analyze_block(assembly_block, start_addr) {
            Ok(a) => a,
            Err(_) => return Ok(false),
        };

        let temp_extraction = ExtractionInfo {
            id: 0,
            binary_path: binary_path.to_string_lossy().to_string(),
            binary_hash: binary_info.hash.clone(),
            binary_format: binary_info.format.clone(),
            binary_architecture: binary_info.architecture.clone(),
            binary_base_address: binary_info.base_address,
            start_address: start_addr,
            end_address: end_addr,
            assembly_block: assembly_block.to_vec(),
            created_at: String::new(),
            analysis_status: "analyzed".to_string(),
            analysis_results: None,
        };

        for _ in 0..self.validation_runs {
            match simulator.simulate_block(&temp_extraction, &analysis, None, false) {
                Ok(result) => {
                    if result.exit_code != 0 {
                        return Ok(false);
                    }
                }
                Err(_) => return Ok(false),
            }
        }

        Ok(true)
    }
}

/// A candidate block for smart selection.
struct CandidateBlock {
    start_addr: u64,
    end_addr: u64,
    assembly_block: Vec<u8>,
    complexity_score: ComplexityScore,
    instruction_variety: HashSet<String>,
    has_problematic_instructions: bool,
    instruction_count: usize,
}
