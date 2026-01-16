//! Batch validation command for validating multiple blocks.

use anyhow::{anyhow, Result};
use clap::Args;
use serde::Serialize;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::arch::{get_effective_architecture, EmulatorDispatcher, ExecutionTarget};
use crate::config::Config;
use crate::db::Database;
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

        if !self.output_json {
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("Batch Validation: {} blocks", block_numbers.len());
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!();
            println!("Host: {}", host_arch.display_name());
            println!("Native execution: {}", native_target.description());
            println!("FEX-Emu execution: {}", fex_target.description());
            println!();
        }

        let batch_start = Instant::now();
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
                &db,
                &extractions,
                &native_target,
                &fex_target,
                &config,
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
                    }
                }
                Err(e) => {
                    stats.skipped += 1;
                    BlockValidationResult {
                        block_number: *block_num,
                        status: ValidationStatus::Skipped,
                        native_exit_code: None,
                        fex_exit_code: None,
                        comparison_passed: None,
                        error_message: Some(e.to_string()),
                        execution_time,
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

        stats.total_time = batch_start.elapsed();

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
            let emulator = EmulatorConfig::fex_emu();
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

        // Compare results
        let comparison_passed =
            if let (Some(ref native), Some(ref fex)) = (&native_result, &fex_result) {
                Some(compare_results(
                    &native.final_state,
                    &fex.final_state,
                    native.exit_code,
                    fex.exit_code,
                ))
            } else {
                None
            };

        Ok(SingleBlockResult {
            native_exit_code: native_result.as_ref().map(|r| r.exit_code),
            fex_exit_code: fex_result.as_ref().map(|r| r.exit_code),
            comparison_passed,
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
