use anyhow::Result;
use clap::Args;
use log::debug;
use std::collections::HashSet;
use std::path::PathBuf;

use crate::db::Database;
use crate::extractor::{ExtractionFilter, Extractor, InstructionCategory};

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
}

impl ExtractCommand {
    pub fn execute(self) -> Result<()> {
        // Validate conflicting options
        if self.has_memory_access && self.no_memory_access {
            return Err(anyhow::anyhow!(
                "Cannot use both --has-memory-access and --no-memory-access"
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

        let mut db = Database::new(&self.database)?;
        db.init()?;

        if !self.quiet {
            println!("Database initialized: {}", self.database.display());
        }

        let (start_addr, end_addr, assembly_block) = if let Some(range) = &self.range {
            if range.len() != 2 {
                return Err(anyhow::anyhow!(
                    "Range option requires exactly two addresses"
                ));
            }

            // Parse the addresses - support both hex (0x...) and decimal
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
            // Try to count instructions to show in output
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

            // Show filter match details in verbose mode
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

        db.store_extraction(&binary_info, start_addr, end_addr, &assembly_block)?;

        if !self.quiet {
            println!("✓ Extraction stored in database successfully");
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
}
