//! Batch validation command for validating multiple blocks.

use anyhow::{anyhow, Result};
use clap::Args;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::arch::{get_effective_architecture, EmulatorDispatcher, ExecutionTarget};
use crate::config::Config;
use crate::db::Database;
use crate::export::{CsvExportConfig, CsvExporter, ValidationResultRow};
use crate::remote::{ExecutionPackage, RemoteOrchestrator};
use crate::simulator::{
    EmulatorConfig, FinalState, RandomStateGenerator, SimulationResult, Simulator,
};

#[derive(Args)]
pub struct ValidateBatchCommand {
    #[arg(help = "Block range to validate (e.g., '1-100', '1,5,10', 'all')")]
    pub range: String,

    #[arg(
        short,
        long,
        default_value = "snippex.db",
        help = "SQLite database path"
    )]
    pub database: PathBuf,

    #[arg(short, long, help = "Seed for random value generation")]
    pub seed: Option<u64>,

    #[arg(short, long, help = "Show detailed execution output")]
    pub verbose: bool,

    #[arg(long, help = "Only run native x86 execution")]
    pub native_only: bool,

    #[arg(long, help = "Only run FEX-Emu execution")]
    pub fex_only: bool,

    #[arg(long, help = "Keep generated assembly and binary files")]
    pub keep_files: bool,

    #[arg(long, help = "Stop on first validation failure")]
    pub stop_on_failure: bool,

    #[arg(long, help = "Output results as JSON")]
    pub output_json: bool,

    #[arg(long, help = "Skip cache and force re-execution")]
    pub no_cache: bool,

    #[arg(long, default_value = "7", help = "Cache TTL in days")]
    pub cache_ttl: u32,

    #[arg(long, help = "Export results to CSV file (use '-' for stdout)")]
    pub export_csv: Option<String>,

    #[arg(long, help = "Append to existing CSV instead of overwriting")]
    pub csv_append: bool,

    #[arg(long, help = "Enable parallel execution of validations")]
    pub parallel: bool,

    #[arg(
        long,
        default_value = "0",
        help = "Number of worker threads (0 = CPU count)"
    )]
    pub threads: usize,

    #[arg(
        long,
        default_value = "true",
        help = "Use transfer cache to skip redundant binary uploads to remote (default: on for batch)"
    )]
    pub use_transfer_cache: bool,
}

/// Statistics for batch validation.
#[derive(Debug, Default, Serialize)]
pub struct BatchStatistics {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub native_errors: usize,
    pub fex_errors: usize,
    pub total_time: Duration,
}

/// Result of a single block validation.
#[derive(Debug, Serialize)]
pub struct BlockValidationResult {
    pub block_number: usize,
    pub status: ValidationStatus,
    pub native_exit_code: Option<i32>,
    pub fex_exit_code: Option<i32>,
    pub comparison_passed: Option<bool>,
    pub error_message: Option<String>,
    pub execution_time: Duration,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_address: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_address: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_flags: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fex_flags: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub register_diff_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_diff_count: Option<usize>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum ValidationStatus {
    Pass,
    Fail,
    NativeError,
    FexError,
    BothError,
    Skipped,
}

impl std::fmt::Display for ValidationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationStatus::Pass => write!(f, "PASS"),
            ValidationStatus::Fail => write!(f, "FAIL"),
            ValidationStatus::NativeError => write!(f, "NATIVE_ERROR"),
            ValidationStatus::FexError => write!(f, "FEX_ERROR"),
            ValidationStatus::BothError => write!(f, "BOTH_ERROR"),
            ValidationStatus::Skipped => write!(f, "SKIPPED"),
        }
    }
}

/// JSON output format for batch validation.
#[derive(Debug, Serialize)]
pub struct BatchOutput {
    pub statistics: BatchStatistics,
    pub results: Vec<BlockValidationResult>,
}

impl ValidateBatchCommand {
    pub fn execute(self) -> Result<()> {
        if !self.database.exists() {
            return Err(anyhow!("No database found"));
        }

        let config = Config::load().unwrap_or_default();
        let host_arch = get_effective_architecture()
            .map_err(|e| anyhow!("Architecture detection failed: {}", e))?;
        let dispatcher = EmulatorDispatcher::with_arch(host_arch, config.clone());

        if self.native_only && self.fex_only {
            return Err(anyhow!("Cannot specify both --native-only and --fex-only"));
        }

        let native_target = dispatcher.select_native_host();
        let fex_target = dispatcher.select_fex_host();

        let db = Database::new(&self.database)?;
        let extractions = db.list_extractions()?;

        if extractions.is_empty() {
            return Err(anyhow!("No blocks in database"));
        }

        let block_numbers = self.parse_range(&self.range, extractions.len())?;

        // Configure thread pool if parallel execution is enabled
        if self.parallel {
            let num_threads = if self.threads == 0 {
                num_cpus()
            } else {
                self.threads
            };
            rayon::ThreadPoolBuilder::new()
                .num_threads(num_threads)
                .build_global()
                .ok(); // Ignore if already initialized
        }

        if !self.output_json {
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("Batch Validation: {} blocks", block_numbers.len());
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!();
            println!("Host: {}", host_arch.display_name());
            println!("Native execution: {}", native_target.description());
            println!("FEX-Emu execution: {}", fex_target.description());
            if self.parallel {
                let num_threads = if self.threads == 0 {
                    num_cpus()
                } else {
                    self.threads
                };
                println!("Parallel execution: {} threads", num_threads);
            }
            println!();
        }

        let batch_start = Instant::now();

        // Execute validations (parallel or sequential)
        let (results, stats) = if self.parallel {
            self.execute_parallel(
                &block_numbers,
                &db,
                &extractions,
                &native_target,
                &fex_target,
                &config,
            )?
        } else {
            self.execute_sequential(
                &block_numbers,
                &db,
                &extractions,
                &native_target,
                &fex_target,
                &config,
            )?
        };

        let mut stats = stats;
        stats.total_time = batch_start.elapsed();

        // Export to CSV if requested (do this before consuming results for JSON)
        if let Some(csv_path) = &self.export_csv {
            self.export_results_to_csv(csv_path, &results)?;
        }

        if self.output_json {
            let output = BatchOutput {
                statistics: stats,
                results,
            };
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            self.display_summary(&stats);
        }

        Ok(())
    }

    fn execute_sequential(
        &self,
        block_numbers: &[usize],
        db: &Database,
        extractions: &[crate::db::ExtractionInfo],
        native_target: &ExecutionTarget,
        fex_target: &ExecutionTarget,
        config: &Config,
    ) -> Result<(Vec<BlockValidationResult>, BatchStatistics)> {
        let mut stats = BatchStatistics::default();
        let mut results = Vec::new();

        for (idx, block_num) in block_numbers.iter().enumerate() {
            let block_start = Instant::now();

            if !self.output_json {
                print!(
                    "[{}/{}] Block #{}: ",
                    idx + 1,
                    block_numbers.len(),
                    block_num
                );
            }

            let result = self.validate_single_block(
                *block_num,
                db,
                extractions,
                native_target,
                fex_target,
                config,
            );

            let execution_time = block_start.elapsed();

            let block_result = match result {
                Ok(validation) => {
                    let status = if let Some(passed) = validation.comparison_passed {
                        if passed {
                            stats.passed += 1;
                            ValidationStatus::Pass
                        } else {
                            stats.failed += 1;
                            ValidationStatus::Fail
                        }
                    } else if validation.native_exit_code.is_none()
                        && validation.fex_exit_code.is_none()
                    {
                        stats.native_errors += 1;
                        stats.fex_errors += 1;
                        ValidationStatus::BothError
                    } else if validation.native_exit_code.is_none() {
                        stats.native_errors += 1;
                        ValidationStatus::NativeError
                    } else {
                        stats.fex_errors += 1;
                        ValidationStatus::FexError
                    };

                    BlockValidationResult {
                        block_number: *block_num,
                        status,
                        native_exit_code: validation.native_exit_code,
                        fex_exit_code: validation.fex_exit_code,
                        comparison_passed: validation.comparison_passed,
                        error_message: None,
                        execution_time,
                        binary_path: Some(validation.binary_path),
                        start_address: Some(validation.start_address),
                        end_address: Some(validation.end_address),
                        native_flags: validation.native_flags,
                        fex_flags: validation.fex_flags,
                        register_diff_count: Some(validation.register_diff_count),
                        memory_diff_count: Some(validation.memory_diff_count),
                    }
                }
                Err(e) => {
                    let extraction = &extractions[*block_num - 1];
                    stats.skipped += 1;
                    BlockValidationResult {
                        block_number: *block_num,
                        status: ValidationStatus::Skipped,
                        native_exit_code: None,
                        fex_exit_code: None,
                        comparison_passed: None,
                        error_message: Some(e.to_string()),
                        execution_time,
                        binary_path: Some(extraction.binary_path.clone()),
                        start_address: Some(extraction.start_address),
                        end_address: Some(extraction.end_address),
                        native_flags: None,
                        fex_flags: None,
                        register_diff_count: None,
                        memory_diff_count: None,
                    }
                }
            };

            if !self.output_json {
                let status_symbol = match block_result.status {
                    ValidationStatus::Pass => "✓",
                    ValidationStatus::Fail => "✗",
                    ValidationStatus::NativeError => "N",
                    ValidationStatus::FexError => "F",
                    ValidationStatus::BothError => "!",
                    ValidationStatus::Skipped => "-",
                };
                println!("{} ({:?})", status_symbol, block_result.execution_time);
            }

            let should_stop = self.stop_on_failure && block_result.status == ValidationStatus::Fail;

            results.push(block_result);
            stats.total += 1;

            if should_stop {
                if !self.output_json {
                    println!();
                    println!("Stopping due to --stop-on-failure");
                }
                break;
            }
        }

        Ok((results, stats))
    }

    fn execute_parallel(
        &self,
        block_numbers: &[usize],
        db: &Database,
        extractions: &[crate::db::ExtractionInfo],
        native_target: &ExecutionTarget,
        fex_target: &ExecutionTarget,
        config: &Config,
    ) -> Result<(Vec<BlockValidationResult>, BatchStatistics)> {
        use std::collections::HashMap;

        // Pre-load all block analyses from database (database is not thread-safe)
        let mut analyses: HashMap<usize, crate::analyzer::BlockAnalysis> = HashMap::new();
        for block_num in block_numbers {
            let extraction = &extractions[*block_num - 1];
            if extraction.analysis_status == "analyzed" {
                if let Ok(Some(analysis)) = db.load_block_analysis(extraction.id) {
                    analyses.insert(*block_num, analysis);
                }
            }
        }

        // Thread-safe counters for progress tracking
        let passed = AtomicUsize::new(0);
        let failed = AtomicUsize::new(0);
        let skipped = AtomicUsize::new(0);
        let native_errors = AtomicUsize::new(0);
        let fex_errors = AtomicUsize::new(0);
        let processed = AtomicUsize::new(0);

        // Results are collected in a thread-safe vector
        let results: Arc<Mutex<Vec<BlockValidationResult>>> = Arc::new(Mutex::new(Vec::new()));

        // Setup progress bar
        let progress_bar = if !self.output_json {
            let pb = ProgressBar::new(block_numbers.len() as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
                    .unwrap()
                    .progress_chars("#>-"),
            );
            Some(pb)
        } else {
            None
        };

        let progress_bar = Arc::new(progress_bar);

        // Process blocks in parallel
        block_numbers.par_iter().for_each(|block_num| {
            let block_start = Instant::now();

            let result = self.validate_single_block_with_analysis(
                *block_num,
                extractions,
                analyses.get(block_num),
                native_target,
                fex_target,
                config,
            );

            let execution_time = block_start.elapsed();

            let block_result = match result {
                Ok(validation) => {
                    let status = if let Some(comparison_passed) = validation.comparison_passed {
                        if comparison_passed {
                            passed.fetch_add(1, Ordering::Relaxed);
                            ValidationStatus::Pass
                        } else {
                            failed.fetch_add(1, Ordering::Relaxed);
                            ValidationStatus::Fail
                        }
                    } else if validation.native_exit_code.is_none()
                        && validation.fex_exit_code.is_none()
                    {
                        native_errors.fetch_add(1, Ordering::Relaxed);
                        fex_errors.fetch_add(1, Ordering::Relaxed);
                        ValidationStatus::BothError
                    } else if validation.native_exit_code.is_none() {
                        native_errors.fetch_add(1, Ordering::Relaxed);
                        ValidationStatus::NativeError
                    } else {
                        fex_errors.fetch_add(1, Ordering::Relaxed);
                        ValidationStatus::FexError
                    };

                    BlockValidationResult {
                        block_number: *block_num,
                        status,
                        native_exit_code: validation.native_exit_code,
                        fex_exit_code: validation.fex_exit_code,
                        comparison_passed: validation.comparison_passed,
                        error_message: None,
                        execution_time,
                        binary_path: Some(validation.binary_path),
                        start_address: Some(validation.start_address),
                        end_address: Some(validation.end_address),
                        native_flags: validation.native_flags,
                        fex_flags: validation.fex_flags,
                        register_diff_count: Some(validation.register_diff_count),
                        memory_diff_count: Some(validation.memory_diff_count),
                    }
                }
                Err(e) => {
                    let extraction = &extractions[*block_num - 1];
                    skipped.fetch_add(1, Ordering::Relaxed);
                    BlockValidationResult {
                        block_number: *block_num,
                        status: ValidationStatus::Skipped,
                        native_exit_code: None,
                        fex_exit_code: None,
                        comparison_passed: None,
                        error_message: Some(e.to_string()),
                        execution_time,
                        binary_path: Some(extraction.binary_path.clone()),
                        start_address: Some(extraction.start_address),
                        end_address: Some(extraction.end_address),
                        native_flags: None,
                        fex_flags: None,
                        register_diff_count: None,
                        memory_diff_count: None,
                    }
                }
            };

            // Update progress
            let current = processed.fetch_add(1, Ordering::Relaxed) + 1;
            let current_passed = passed.load(Ordering::Relaxed);
            let current_failed = failed.load(Ordering::Relaxed);

            if let Some(ref pb) = *progress_bar {
                pb.set_position(current as u64);
                pb.set_message(format!("✓{} ✗{}", current_passed, current_failed));
            }

            // Store result
            results.lock().unwrap().push(block_result);
        });

        // Finish progress bar
        if let Some(ref pb) = *progress_bar {
            pb.finish_with_message("done");
        }

        // Collect final results
        let mut final_results = Arc::try_unwrap(results)
            .map_err(|_| anyhow!("Failed to unwrap results"))?
            .into_inner()
            .map_err(|_| anyhow!("Failed to lock results"))?;

        // Sort results by block number for consistent output
        final_results.sort_by_key(|r| r.block_number);

        let stats = BatchStatistics {
            total: final_results.len(),
            passed: passed.load(Ordering::Relaxed),
            failed: failed.load(Ordering::Relaxed),
            skipped: skipped.load(Ordering::Relaxed),
            native_errors: native_errors.load(Ordering::Relaxed),
            fex_errors: fex_errors.load(Ordering::Relaxed),
            total_time: Duration::default(), // Set by caller
        };

        Ok((final_results, stats))
    }

    fn validate_single_block_with_analysis(
        &self,
        block_num: usize,
        extractions: &[crate::db::ExtractionInfo],
        analysis: Option<&crate::analyzer::BlockAnalysis>,
        native_target: &ExecutionTarget,
        fex_target: &ExecutionTarget,
        config: &Config,
    ) -> Result<SingleBlockResult> {
        let extraction = &extractions[block_num - 1];

        if extraction.analysis_status != "analyzed" {
            return Err(anyhow!("Block #{} is not analyzed", block_num));
        }

        let analysis = analysis.ok_or_else(|| anyhow!("Block analysis not found"))?;

        let mut random_gen = RandomStateGenerator::new();
        if let Some(seed) = self.seed {
            random_gen = RandomStateGenerator::with_seed(seed + block_num as u64);
        }
        let initial_state = random_gen.generate_initial_state(analysis);

        let mut native_result: Option<SimulationResult> = None;
        let mut fex_result: Option<SimulationResult> = None;

        // Run native simulation
        if !self.fex_only && !native_target.is_unavailable() {
            match self.run_simulation(
                extraction,
                analysis,
                &initial_state,
                native_target,
                None,
                config,
            ) {
                Ok(result) => native_result = Some(result),
                Err(_e) => {}
            }
        }

        // Run FEX-Emu simulation
        if !self.native_only && !fex_target.is_unavailable() {
            // Use configured FEX path if available in remote config
            let fex_path = fex_target
                .remote_config()
                .and_then(|rc| rc.fex_path.as_deref());
            let emulator = EmulatorConfig::fex_emu_with_optional_path(fex_path);
            match self.run_simulation(
                extraction,
                analysis,
                &initial_state,
                fex_target,
                Some(emulator),
                config,
            ) {
                Ok(result) => fex_result = Some(result),
                Err(_e) => {}
            }
        }

        // Compare results and collect diff counts
        let (comparison_passed, register_diff_count, memory_diff_count) =
            if let (Some(ref native), Some(ref fex)) = (&native_result, &fex_result) {
                let passed = compare_results(
                    &native.final_state,
                    &fex.final_state,
                    native.exit_code,
                    fex.exit_code,
                );
                let reg_diff = count_register_diffs(&native.final_state, &fex.final_state);
                let mem_diff = count_memory_diffs(&native.final_state, &fex.final_state);
                (Some(passed), reg_diff, mem_diff)
            } else {
                (None, 0, 0)
            };

        Ok(SingleBlockResult {
            native_exit_code: native_result.as_ref().map(|r| r.exit_code),
            fex_exit_code: fex_result.as_ref().map(|r| r.exit_code),
            comparison_passed,
            binary_path: extraction.binary_path.clone(),
            start_address: extraction.start_address,
            end_address: extraction.end_address,
            native_flags: native_result.as_ref().map(|r| r.final_state.flags),
            fex_flags: fex_result.as_ref().map(|r| r.final_state.flags),
            register_diff_count,
            memory_diff_count,
        })
    }

    fn export_results_to_csv(
        &self,
        csv_path: &str,
        results: &[BlockValidationResult],
    ) -> Result<()> {
        let timestamp = chrono::Utc::now().to_rfc3339();

        let csv_rows: Vec<ValidationResultRow> = results
            .iter()
            .map(|r| ValidationResultRow {
                timestamp: timestamp.clone(),
                block_id: r.block_number,
                binary_path: r.binary_path.clone().unwrap_or_default(),
                start_address: r
                    .start_address
                    .map(|a| format!("0x{:x}", a))
                    .unwrap_or_default(),
                end_address: r
                    .end_address
                    .map(|a| format!("0x{:x}", a))
                    .unwrap_or_default(),
                block_size: r
                    .end_address
                    .unwrap_or(0)
                    .saturating_sub(r.start_address.unwrap_or(0))
                    as usize,
                native_exit_code: r
                    .native_exit_code
                    .map(|c| c.to_string())
                    .unwrap_or_default(),
                fex_exit_code: r.fex_exit_code.map(|c| c.to_string()).unwrap_or_default(),
                status: r.status.to_string(),
                passed: r
                    .comparison_passed
                    .map(|p| if p { "true" } else { "false" })
                    .unwrap_or("")
                    .to_string(),
                execution_time_ms: r.execution_time.as_secs_f64() * 1000.0,
                error_message: r.error_message.clone().unwrap_or_default(),
                native_flags: r
                    .native_flags
                    .map(|f| format!("0x{:x}", f))
                    .unwrap_or_default(),
                fex_flags: r
                    .fex_flags
                    .map(|f| format!("0x{:x}", f))
                    .unwrap_or_default(),
                flags_match: if r.native_flags.is_some() && r.fex_flags.is_some() {
                    if r.native_flags == r.fex_flags {
                        "true"
                    } else {
                        "false"
                    }
                    .to_string()
                } else {
                    String::new()
                },
                register_diff_count: r.register_diff_count.unwrap_or(0),
                memory_diff_count: r.memory_diff_count.unwrap_or(0),
            })
            .collect();

        let config = CsvExportConfig {
            append: self.csv_append,
            ..Default::default()
        };
        let exporter = CsvExporter::new(config);

        if csv_path == "-" {
            // Write to stdout
            exporter.export_validation_results_to_writer(std::io::stdout(), &csv_rows)?;
        } else {
            exporter.export_validation_results(csv_path, &csv_rows)?;
            if !self.output_json {
                println!();
                println!("CSV exported to: {}", csv_path);
            }
        }

        Ok(())
    }

    fn parse_range(&self, range: &str, max_blocks: usize) -> Result<Vec<usize>> {
        let range = range.trim().to_lowercase();

        if range == "all" {
            return Ok((1..=max_blocks).collect());
        }

        let mut block_numbers = Vec::new();

        for part in range.split(',') {
            let part = part.trim();

            if part.contains('-') {
                let bounds: Vec<&str> = part.split('-').collect();
                if bounds.len() != 2 {
                    return Err(anyhow!("Invalid range format: '{}'", part));
                }

                let start: usize = bounds[0]
                    .trim()
                    .parse()
                    .map_err(|_| anyhow!("Invalid number: '{}'", bounds[0]))?;
                let end: usize = bounds[1]
                    .trim()
                    .parse()
                    .map_err(|_| anyhow!("Invalid number: '{}'", bounds[1]))?;

                if start == 0 || end == 0 {
                    return Err(anyhow!("Block numbers start at 1"));
                }
                if start > end {
                    return Err(anyhow!("Invalid range: start ({}) > end ({})", start, end));
                }
                if end > max_blocks {
                    return Err(anyhow!("Block {} exceeds maximum ({})", end, max_blocks));
                }

                block_numbers.extend(start..=end);
            } else {
                let num: usize = part
                    .parse()
                    .map_err(|_| anyhow!("Invalid number: '{}'", part))?;

                if num == 0 {
                    return Err(anyhow!("Block numbers start at 1"));
                }
                if num > max_blocks {
                    return Err(anyhow!("Block {} exceeds maximum ({})", num, max_blocks));
                }

                block_numbers.push(num);
            }
        }

        // Remove duplicates and sort
        block_numbers.sort();
        block_numbers.dedup();

        if block_numbers.is_empty() {
            return Err(anyhow!("No valid block numbers in range"));
        }

        Ok(block_numbers)
    }

    fn validate_single_block(
        &self,
        block_num: usize,
        db: &Database,
        extractions: &[crate::db::ExtractionInfo],
        native_target: &ExecutionTarget,
        fex_target: &ExecutionTarget,
        config: &Config,
    ) -> Result<SingleBlockResult> {
        let extraction = &extractions[block_num - 1];

        if extraction.analysis_status != "analyzed" {
            return Err(anyhow!("Block #{} is not analyzed", block_num));
        }

        let analysis = db
            .load_block_analysis(extraction.id)?
            .ok_or_else(|| anyhow!("Block analysis not found"))?;

        let mut random_gen = RandomStateGenerator::new();
        if let Some(seed) = self.seed {
            random_gen = RandomStateGenerator::with_seed(seed);
        }
        let initial_state = random_gen.generate_initial_state(&analysis);

        let mut native_result: Option<SimulationResult> = None;
        let mut fex_result: Option<SimulationResult> = None;

        // Run native simulation
        if !self.fex_only && !native_target.is_unavailable() {
            match self.run_simulation(
                extraction,
                &analysis,
                &initial_state,
                native_target,
                None,
                config,
            ) {
                Ok(result) => native_result = Some(result),
                Err(e) => {
                    if self.verbose {
                        eprintln!("Native error: {}", e);
                    }
                }
            }
        }

        // Run FEX-Emu simulation
        if !self.native_only && !fex_target.is_unavailable() {
            // Use configured FEX path if available in remote config
            let fex_path = fex_target
                .remote_config()
                .and_then(|rc| rc.fex_path.as_deref());
            let emulator = EmulatorConfig::fex_emu_with_optional_path(fex_path);
            match self.run_simulation(
                extraction,
                &analysis,
                &initial_state,
                fex_target,
                Some(emulator),
                config,
            ) {
                Ok(result) => fex_result = Some(result),
                Err(e) => {
                    if self.verbose {
                        eprintln!("FEX error: {}", e);
                    }
                }
            }
        }

        // Compare results and collect diff counts
        let (comparison_passed, register_diff_count, memory_diff_count) =
            if let (Some(ref native), Some(ref fex)) = (&native_result, &fex_result) {
                let passed = compare_results(
                    &native.final_state,
                    &fex.final_state,
                    native.exit_code,
                    fex.exit_code,
                );
                let reg_diff = count_register_diffs(&native.final_state, &fex.final_state);
                let mem_diff = count_memory_diffs(&native.final_state, &fex.final_state);
                (Some(passed), reg_diff, mem_diff)
            } else {
                (None, 0, 0)
            };

        Ok(SingleBlockResult {
            native_exit_code: native_result.as_ref().map(|r| r.exit_code),
            fex_exit_code: fex_result.as_ref().map(|r| r.exit_code),
            comparison_passed,
            binary_path: extraction.binary_path.clone(),
            start_address: extraction.start_address,
            end_address: extraction.end_address,
            native_flags: native_result.as_ref().map(|r| r.final_state.flags),
            fex_flags: fex_result.as_ref().map(|r| r.final_state.flags),
            register_diff_count,
            memory_diff_count,
        })
    }

    fn run_simulation(
        &self,
        extraction: &crate::db::ExtractionInfo,
        analysis: &crate::analyzer::BlockAnalysis,
        initial_state: &crate::simulator::InitialState,
        target: &ExecutionTarget,
        emulator_config: Option<EmulatorConfig>,
        _config: &Config,
    ) -> Result<SimulationResult> {
        match target {
            ExecutionTarget::Local => {
                let mut simulator = Simulator::new()?;
                Ok(simulator.simulate_block_with_state(
                    extraction,
                    analysis,
                    initial_state,
                    emulator_config,
                    self.keep_files,
                )?)
            }
            ExecutionTarget::Remote(remote_config) => {
                let package = ExecutionPackage::new(
                    extraction,
                    analysis,
                    initial_state,
                    emulator_config.as_ref(),
                );

                let orchestrator = RemoteOrchestrator::new(remote_config.clone());
                orchestrator
                    .execute_remote_simulation(&package)
                    .map_err(|e| anyhow!("Remote execution failed: {}", e))
            }
            ExecutionTarget::Unavailable(reason) => Err(anyhow!("Target unavailable: {}", reason)),
        }
    }

    fn display_summary(&self, stats: &BatchStatistics) {
        println!();
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Batch Summary");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!();
        println!("Total blocks:    {}", stats.total);
        println!("  Passed:        {} ✓", stats.passed);
        println!("  Failed:        {} ✗", stats.failed);
        println!("  Native errors: {}", stats.native_errors);
        println!("  FEX errors:    {}", stats.fex_errors);
        println!("  Skipped:       {}", stats.skipped);
        println!();

        let success_rate = if stats.passed + stats.failed > 0 {
            (stats.passed as f64 / (stats.passed + stats.failed) as f64) * 100.0
        } else {
            0.0
        };

        println!("Success rate:    {:.1}%", success_rate);
        println!("Total time:      {:?}", stats.total_time);
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    }
}

struct SingleBlockResult {
    native_exit_code: Option<i32>,
    fex_exit_code: Option<i32>,
    comparison_passed: Option<bool>,
    binary_path: String,
    start_address: u64,
    end_address: u64,
    native_flags: Option<u64>,
    fex_flags: Option<u64>,
    register_diff_count: usize,
    memory_diff_count: usize,
}

fn compare_results(native: &FinalState, fex: &FinalState, native_exit: i32, fex_exit: i32) -> bool {
    if native_exit != fex_exit {
        return false;
    }
    if native.flags != fex.flags {
        return false;
    }
    for (name, native_value) in &native.registers {
        if let Some(fex_value) = fex.registers.get(name) {
            if native_value != fex_value {
                return false;
            }
        }
    }
    for (addr, native_bytes) in &native.memory_locations {
        if let Some(fex_bytes) = fex.memory_locations.get(addr) {
            if native_bytes != fex_bytes {
                return false;
            }
        }
    }
    true
}

fn count_register_diffs(native: &FinalState, fex: &FinalState) -> usize {
    let mut count = 0;
    for (name, native_value) in &native.registers {
        if let Some(fex_value) = fex.registers.get(name) {
            if native_value != fex_value {
                count += 1;
            }
        } else {
            count += 1;
        }
    }
    for name in fex.registers.keys() {
        if !native.registers.contains_key(name) {
            count += 1;
        }
    }
    count
}

fn count_memory_diffs(native: &FinalState, fex: &FinalState) -> usize {
    let mut count = 0;
    for (addr, native_bytes) in &native.memory_locations {
        if let Some(fex_bytes) = fex.memory_locations.get(addr) {
            if native_bytes != fex_bytes {
                count += 1;
            }
        } else {
            count += 1;
        }
    }
    for addr in fex.memory_locations.keys() {
        if !native.memory_locations.contains_key(addr) {
            count += 1;
        }
    }
    count
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4)
}
