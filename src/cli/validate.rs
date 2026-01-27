//! Validation command for comparing native x86 and FEX-Emu execution results.

use anyhow::{anyhow, Result};
use clap::Args;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::arch::{
    get_effective_architecture, EmulatorDispatcher, ExecutionTarget, FlagComparison,
};
use crate::cli::block_range::BlockRange;
use crate::config::Config;
use crate::db::{CachedValidationResult, Database};
use crate::remote::{ExecutionPackage, RemoteOrchestrator};
use crate::simulator::{
    EmulatorConfig, FinalState, InitialState, RandomStateGenerator, SimulationResult, Simulator,
};

#[derive(Args)]
pub struct ValidateCommand {
    #[arg(help = "Block(s) to validate: 5, 1-10, 5-, 3,7,12, or all")]
    pub blocks: BlockRange,

    #[arg(
        short,
        long,
        default_value = "snippex.db",
        help = "SQLite database path"
    )]
    pub database: PathBuf,

    #[arg(
        short,
        long,
        default_value = "1",
        help = "Number of validation runs per block"
    )]
    pub runs: usize,

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

    #[arg(long, help = "Skip cache and force re-execution")]
    pub no_cache: bool,

    #[arg(long, default_value = "7", help = "Cache TTL in days")]
    pub cache_ttl: u32,

    #[arg(long, help = "Show flag-by-flag breakdown")]
    pub flag_detail: bool,

    #[arg(long, help = "Stop on first validation failure")]
    pub stop_on_failure: bool,

    #[arg(
        long,
        help = "Use transfer cache to skip redundant binary uploads to remote (default: off for single validation)"
    )]
    pub use_transfer_cache: bool,
}

/// Represents the result of validating a block against both native and FEX-Emu.
#[allow(dead_code)]
#[derive(Debug)]
pub struct ValidationResult {
    pub block_number: usize,
    pub native_result: Option<SimulationResult>,
    pub fex_result: Option<SimulationResult>,
    pub native_target: String,
    pub fex_target: String,
    pub comparison: Option<ComparisonResult>,
}

/// Represents the detailed comparison between two simulation results.
#[derive(Debug)]
pub struct ComparisonResult {
    pub exit_codes_match: bool,
    pub flags_match: bool,
    pub registers_match: bool,
    pub memory_match: bool,
    pub register_differences: Vec<RegisterDiff>,
    pub memory_differences: Vec<MemoryDiff>,
    pub native_flags: u64,
    pub fex_flags: u64,
}

#[derive(Debug)]
pub struct RegisterDiff {
    pub name: String,
    pub native_value: u64,
    pub fex_value: u64,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct MemoryDiff {
    pub address: u64,
    pub native_value: Vec<u8>,
    pub fex_value: Vec<u8>,
}

/// Statistics for multiple validation runs.
#[derive(Debug, Default)]
pub struct RunStatistics {
    pub total_runs: usize,
    pub passed: usize,
    pub failed: usize,
    pub native_errors: usize,
    pub fex_errors: usize,
    pub total_time: Duration,
    pub failed_seeds: Vec<u64>,
}

impl RunStatistics {
    fn record_pass(&mut self) {
        self.total_runs += 1;
        self.passed += 1;
    }

    fn record_fail(&mut self, seed: u64) {
        self.total_runs += 1;
        self.failed += 1;
        self.failed_seeds.push(seed);
    }

    fn record_native_error(&mut self) {
        self.total_runs += 1;
        self.native_errors += 1;
    }

    fn record_fex_error(&mut self) {
        self.total_runs += 1;
        self.fex_errors += 1;
    }

    fn success_rate(&self) -> f64 {
        let comparable = self.passed + self.failed;
        if comparable > 0 {
            (self.passed as f64 / comparable as f64) * 100.0
        } else {
            0.0
        }
    }
}

impl ComparisonResult {
    pub fn is_pass(&self) -> bool {
        self.exit_codes_match && self.flags_match && self.registers_match && self.memory_match
    }

    fn compare(native: &FinalState, fex: &FinalState, native_exit: i32, fex_exit: i32) -> Self {
        let exit_codes_match = native_exit == fex_exit;
        let flags_match = native.flags == fex.flags;

        let mut register_differences = Vec::new();
        let mut registers_match = true;

        // Registers to exclude from comparison - these will always differ between
        // native and emulated execution due to different process contexts
        const EXCLUDED_REGISTERS: &[&str] = &["rsp", "esp", "sp"];

        // Compare all registers (except excluded ones)
        for (name, native_value) in &native.registers {
            // Skip excluded registers
            if EXCLUDED_REGISTERS.contains(&name.as_str()) {
                continue;
            }
            if let Some(fex_value) = fex.registers.get(name) {
                if native_value != fex_value {
                    registers_match = false;
                    register_differences.push(RegisterDiff {
                        name: name.clone(),
                        native_value: *native_value,
                        fex_value: *fex_value,
                    });
                }
            }
        }

        let mut memory_differences = Vec::new();
        let mut memory_match = true;

        // Compare memory locations
        for (addr, native_bytes) in &native.memory_locations {
            if let Some(fex_bytes) = fex.memory_locations.get(addr) {
                if native_bytes != fex_bytes {
                    memory_match = false;
                    memory_differences.push(MemoryDiff {
                        address: *addr,
                        native_value: native_bytes.clone(),
                        fex_value: fex_bytes.clone(),
                    });
                }
            }
        }

        Self {
            exit_codes_match,
            flags_match,
            registers_match,
            memory_match,
            register_differences,
            memory_differences,
            native_flags: native.flags,
            fex_flags: fex.flags,
        }
    }
}

impl ValidateCommand {
    pub fn execute(self) -> Result<()> {
        // Check if database exists
        if !self.database.exists() {
            return Err(anyhow!(
                "Database not found at '{}'\n\n\
                 Suggestions:\n\
                 • Extract blocks first: snippex extract <binary>\n\
                 • Specify a different database: snippex validate <blocks> -d <path>",
                self.database.display(),
            ));
        }

        // Validate command-line flags
        if self.native_only && self.fex_only {
            return Err(anyhow!("Cannot specify both --native-only and --fex-only"));
        }

        // Load configuration
        let config = Config::load().unwrap_or_default();

        // Detect host architecture
        let host_arch = get_effective_architecture()
            .map_err(|e| anyhow!("Architecture detection failed: {}", e))?;

        // Create dispatcher
        let dispatcher = EmulatorDispatcher::with_arch(host_arch, config.clone());

        let native_target = dispatcher.select_native_host();
        let fex_target = dispatcher.select_fex_host();

        // Check for unavailable targets
        if !self.fex_only && native_target.is_unavailable() {
            println!(
                "Warning: Native execution unavailable - {}",
                native_target.description()
            );
            if self.native_only {
                return Err(anyhow!("Native execution requested but not available"));
            }
        }

        if !self.native_only && fex_target.is_unavailable() {
            println!(
                "Warning: FEX-Emu execution unavailable - {}",
                fex_target.description()
            );
            if self.fex_only {
                return Err(anyhow!("FEX-Emu execution requested but not available"));
            }
        }

        // Load extractions from database
        let mut db = Database::new(&self.database)?;
        let extractions = db.list_extractions()?;

        // Resolve block range
        let block_numbers = self.blocks.resolve(extractions.len())?;
        let multiple_blocks = block_numbers.len() > 1;

        // Track overall results across all blocks
        let mut total_blocks_passed = 0usize;
        let mut total_blocks_failed = 0usize;
        let mut total_blocks_errored = 0usize;
        let mut any_failure = false;

        for (block_idx, &block_number) in block_numbers.iter().enumerate() {
            let extraction = &extractions[block_number - 1];

            // Show block header
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            if multiple_blocks {
                println!(
                    "Block #{} Validation ({}/{})",
                    block_number,
                    block_idx + 1,
                    block_numbers.len()
                );
            } else {
                println!("Block #{} Validation", block_number);
            }
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!();

            if !multiple_blocks {
                println!("Host: {}", host_arch.display_name());
                println!("Native execution: {}", native_target.description());
                println!("FEX-Emu execution: {}", fex_target.description());
                if self.runs > 1 {
                    println!("Runs: {}", self.runs);
                }
                println!();
            }

            // Check if block is analyzed
            if extraction.analysis_status != "analyzed" {
                println!(
                    "Block #{} is not analyzed - skipping (run: snippex analyze {})",
                    block_number, block_number
                );
                total_blocks_errored += 1;
                println!();
                continue;
            }

            // Load analysis
            let analysis = match db.load_block_analysis(extraction.id)? {
                Some(a) => a,
                None => {
                    println!(
                        "Block #{} analysis data missing - skipping (run: snippex analyze {})",
                        block_number, block_number
                    );
                    total_blocks_errored += 1;
                    println!();
                    continue;
                }
            };

            println!("Block: {}", extraction.binary_path);
            println!(
                "Address range: 0x{:08x} - 0x{:08x}",
                extraction.start_address, extraction.end_address
            );
            println!();

            // For multiple runs, track statistics
            let mut stats = RunStatistics::default();
            let total_start = Instant::now();

            // Base seed for generating run-specific seeds
            let base_seed = self.seed.unwrap_or_else(|| {
                use std::time::SystemTime;
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(42)
            });

            // Track the last failed comparison for display
            let mut last_failed_comparison: Option<(
                SimulationResult,
                SimulationResult,
                ComparisonResult,
                u64,
            )> = None;

            let single_run = self.runs == 1;

            for run_idx in 0..self.runs {
                let run_seed = base_seed.wrapping_add(run_idx as u64);

                if !single_run {
                    print!("[{}/{}] Seed {}: ", run_idx + 1, self.runs, run_seed);
                    let _ = std::io::stdout().flush();
                } else if self.seed.is_some() {
                    println!("Seed: {}", run_seed);
                }

                // Generate initial state for this run
                let mut random_gen = RandomStateGenerator::with_seed(run_seed);
                let initial_state = random_gen.generate_initial_state(&analysis);

                // Run validations
                let mut native_result: Option<SimulationResult> = None;
                let mut fex_result: Option<SimulationResult> = None;

                // Check caches first to see if we need to compile
                let native_cached = if !self.fex_only
                    && !native_target.is_unavailable()
                    && !self.no_cache
                    && single_run
                {
                    db.get_validation_cache(extraction.id, "native", Some(run_seed), self.cache_ttl)
                        .ok()
                        .flatten()
                } else {
                    None
                };

                let fex_cached = if !self.native_only
                    && !fex_target.is_unavailable()
                    && !self.no_cache
                    && single_run
                {
                    db.get_validation_cache(
                        extraction.id,
                        "fex-emu",
                        Some(run_seed),
                        self.cache_ttl,
                    )
                    .ok()
                    .flatten()
                } else {
                    None
                };

                // Compile binary once if we need to run either simulation (not cached)
                let needs_native_run =
                    !self.fex_only && !native_target.is_unavailable() && native_cached.is_none();
                let needs_fex_run =
                    !self.native_only && !fex_target.is_unavailable() && fex_cached.is_none();

                let compiled_binary = if needs_native_run || needs_fex_run {
                    if single_run {
                        println!("Compiling simulation binary...");
                    }
                    let simulator = Simulator::new()?;
                    match simulator.compile_simulation_binary(extraction, &analysis, &initial_state)
                    {
                        Ok(path) => {
                            if single_run {
                                println!("  Binary: {}", path.display());
                            }
                            Some(path)
                        }
                        Err(e) => {
                            if single_run {
                                println!("  Compilation failed: {}", e);
                            } else {
                                println!("compile error: {}", e);
                            }
                            stats.record_native_error();
                            continue;
                        }
                    }
                } else {
                    None
                };

                // Run native simulation
                if !self.fex_only && !native_target.is_unavailable() {
                    if let Some(cached) = native_cached {
                        if self.verbose {
                            println!("Using cached native result (from {})", cached.cached_at);
                        }
                        native_result = Some(cached_to_simulation_result(
                            cached,
                            &initial_state,
                            "native",
                        ));
                        if single_run {
                            println!("Native x86 simulation: cached");
                        }
                    } else if let Some(ref binary_path) = compiled_binary {
                        if single_run {
                            println!("Running native x86 simulation...");
                        }
                        match self.run_simulation_with_binary(
                            extraction,
                            &analysis,
                            &initial_state,
                            &native_target,
                            None,
                            &config,
                            Some(binary_path),
                        ) {
                            Ok(result) => {
                                if self.verbose && single_run {
                                    println!("  Exit code: {}", result.exit_code);
                                    println!("  Execution time: {:?}", result.execution_time);
                                }
                                if single_run {
                                    if let Err(e) = db.store_validation_cache(
                                        extraction.id,
                                        "native",
                                        &host_arch.to_string(),
                                        &result,
                                        Some(run_seed),
                                    ) {
                                        log::warn!("Failed to cache native result: {}", e);
                                    }
                                }
                                native_result = Some(result);
                                if single_run {
                                    println!("  Done.");
                                }
                            }
                            Err(e) => {
                                if single_run {
                                    println!("  Failed: {}", e);
                                } else {
                                    println!("native error: {}", e);
                                }
                                stats.record_native_error();
                                if !self.keep_files {
                                    if let Some(ref path) = compiled_binary {
                                        let _ = std::fs::remove_file(path);
                                    }
                                }
                                continue;
                            }
                        }
                    }
                }

                // Run FEX-Emu simulation
                if !self.native_only && !fex_target.is_unavailable() {
                    if let Some(cached) = fex_cached {
                        if self.verbose {
                            println!("Using cached FEX-Emu result (from {})", cached.cached_at);
                        }
                        fex_result = Some(cached_to_simulation_result(
                            cached,
                            &initial_state,
                            "fex-emu",
                        ));
                        if single_run {
                            println!("FEX-Emu simulation: cached");
                        }
                    } else if let Some(ref binary_path) = compiled_binary {
                        if single_run {
                            println!("Running FEX-Emu simulation...");
                        }
                        let fex_path = fex_target
                            .remote_config()
                            .and_then(|rc| rc.fex_path.as_deref());
                        let emulator = EmulatorConfig::fex_emu_with_optional_path(fex_path);
                        match self.run_simulation_with_binary(
                            extraction,
                            &analysis,
                            &initial_state,
                            &fex_target,
                            Some(emulator),
                            &config,
                            Some(binary_path),
                        ) {
                            Ok(result) => {
                                if self.verbose && single_run {
                                    println!("  Exit code: {}", result.exit_code);
                                    println!("  Execution time: {:?}", result.execution_time);
                                }
                                if single_run {
                                    if let Err(e) = db.store_validation_cache(
                                        extraction.id,
                                        "fex-emu",
                                        &host_arch.to_string(),
                                        &result,
                                        Some(run_seed),
                                    ) {
                                        log::warn!("Failed to cache FEX-Emu result: {}", e);
                                    }
                                }
                                fex_result = Some(result);
                                if single_run {
                                    println!("  Done.");
                                }
                            }
                            Err(e) => {
                                if single_run {
                                    println!("  Failed: {}", e);
                                } else {
                                    println!("FEX error: {}", e);
                                }
                                stats.record_fex_error();
                                if !self.keep_files {
                                    if let Some(ref path) = compiled_binary {
                                        let _ = std::fs::remove_file(path);
                                    }
                                }
                                continue;
                            }
                        }
                    }
                }

                // Compare results
                let mut this_run_failed = false;
                if let (Some(ref native), Some(ref fex)) = (&native_result, &fex_result) {
                    let comparison = ComparisonResult::compare(
                        &native.final_state,
                        &fex.final_state,
                        native.exit_code,
                        fex.exit_code,
                    );

                    if comparison.is_pass() {
                        stats.record_pass();
                        if !single_run {
                            println!("✓");
                        }
                    } else {
                        this_run_failed = true;
                        stats.record_fail(run_seed);
                        if !single_run {
                            println!("✗ FAIL");
                        }
                        last_failed_comparison = Some((
                            native_result.clone().unwrap(),
                            fex_result.clone().unwrap(),
                            comparison,
                            run_seed,
                        ));

                        if self.stop_on_failure {
                            if !single_run {
                                println!();
                                println!("Stopping due to --stop-on-failure");
                            }
                            break;
                        }
                    }
                } else if single_run {
                    println!();
                }

                // Clean up compiled binary if not keeping files and not a failure
                if !self.keep_files && !this_run_failed {
                    if let Some(ref path) = compiled_binary {
                        let _ = std::fs::remove_file(path);
                    }
                }
            }

            stats.total_time = total_start.elapsed();

            // Display per-block results
            if single_run {
                println!();

                if let Some((native, fex, comparison, _seed)) = last_failed_comparison.take() {
                    self.display_results(
                        &Some(native),
                        &Some(fex),
                        &native_target,
                        &fex_target,
                        &Some(comparison),
                    );
                    total_blocks_failed += 1;
                    any_failure = true;
                    if !multiple_blocks {
                        return Err(anyhow!("Validation failed: results differ"));
                    }
                } else if stats.passed == 1 {
                    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                    println!("Results");
                    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                    println!();
                    println!("VERDICT: PASS ✓");
                    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                    total_blocks_passed += 1;
                } else if stats.native_errors > 0 || stats.fex_errors > 0 {
                    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                    println!("Results");
                    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                    println!();
                    println!("Comparison: Not available (execution error)");
                    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                    total_blocks_errored += 1;
                }
            } else {
                // Multiple runs: show summary
                println!();
                self.display_run_summary(&stats, &native_target, &fex_target);

                if let Some((native, fex, comparison, seed)) = last_failed_comparison.take() {
                    println!();
                    println!("First failure (seed {}):", seed);
                    self.display_results(
                        &Some(native),
                        &Some(fex),
                        &native_target,
                        &fex_target,
                        &Some(comparison),
                    );
                }

                if stats.failed > 0 {
                    total_blocks_failed += 1;
                    any_failure = true;
                    if !multiple_blocks {
                        return Err(anyhow!(
                            "Validation failed: {}/{} runs differ",
                            stats.failed,
                            stats.total_runs
                        ));
                    }
                } else {
                    total_blocks_passed += 1;
                }
            }

            if multiple_blocks {
                println!();
            }
        }

        // Show overall summary for multiple blocks
        if multiple_blocks {
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("Overall Summary");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!();
            println!("Blocks validated: {}", block_numbers.len());
            println!("  Passed:  {} ✓", total_blocks_passed);
            println!("  Failed:  {} ✗", total_blocks_failed);
            if total_blocks_errored > 0 {
                println!("  Errors:  {}", total_blocks_errored);
            }
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

            if any_failure {
                return Err(anyhow!(
                    "Validation failed: {}/{} blocks had failures",
                    total_blocks_failed,
                    block_numbers.len()
                ));
            }
        }

        Ok(())
    }

    fn display_run_summary(
        &self,
        stats: &RunStatistics,
        _native_target: &ExecutionTarget,
        _fex_target: &ExecutionTarget,
    ) {
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Run Summary");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!();
        println!("Total runs:      {}", stats.total_runs);
        println!("  Passed:        {} ✓", stats.passed);
        println!("  Failed:        {} ✗", stats.failed);
        if stats.native_errors > 0 {
            println!("  Native errors: {}", stats.native_errors);
        }
        if stats.fex_errors > 0 {
            println!("  FEX errors:    {}", stats.fex_errors);
        }
        println!();
        println!("Success rate:    {:.1}%", stats.success_rate());
        println!("Total time:      {:?}", stats.total_time);

        if !stats.failed_seeds.is_empty() && stats.failed_seeds.len() <= 10 {
            println!();
            println!("Failed seeds:    {:?}", stats.failed_seeds);
        } else if stats.failed_seeds.len() > 10 {
            println!();
            println!(
                "Failed seeds:    {:?} ... ({} more)",
                &stats.failed_seeds[..10],
                stats.failed_seeds.len() - 10
            );
        }

        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    }

    #[allow(clippy::too_many_arguments)]
    fn run_simulation_with_binary(
        &self,
        extraction: &crate::db::ExtractionInfo,
        analysis: &crate::analyzer::BlockAnalysis,
        initial_state: &crate::simulator::InitialState,
        target: &ExecutionTarget,
        emulator_config: Option<EmulatorConfig>,
        _config: &Config,
        precompiled_binary: Option<&std::path::Path>,
    ) -> Result<SimulationResult> {
        match target {
            ExecutionTarget::Local => {
                // Run locally
                let simulator = Simulator::new()?;
                if let Some(binary_path) = precompiled_binary {
                    // Use pre-compiled binary
                    Ok(simulator.run_precompiled_binary(
                        binary_path,
                        initial_state,
                        emulator_config,
                    )?)
                } else {
                    // Compile and run
                    let mut simulator = simulator;
                    Ok(simulator.simulate_block_with_state(
                        extraction,
                        analysis,
                        initial_state,
                        emulator_config,
                        self.keep_files,
                    )?)
                }
            }
            ExecutionTarget::Remote(remote_config) => {
                // Run remotely
                let package = ExecutionPackage::new(
                    extraction,
                    analysis,
                    initial_state,
                    emulator_config.as_ref(),
                );

                let orchestrator = RemoteOrchestrator::new(remote_config.clone());
                orchestrator
                    .execute_remote_simulation_with_binary(&package, precompiled_binary)
                    .map_err(|e| anyhow!("Remote execution failed: {}", e))
            }
            ExecutionTarget::Unavailable(reason) => Err(anyhow!("Target unavailable: {}", reason)),
        }
    }

    fn display_results(
        &self,
        native_result: &Option<SimulationResult>,
        fex_result: &Option<SimulationResult>,
        native_target: &ExecutionTarget,
        fex_target: &ExecutionTarget,
        comparison: &Option<ComparisonResult>,
    ) {
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Results");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!();

        // Show initial state when there's a failure (useful for reproduction)
        let has_failure = comparison.as_ref().is_some_and(|c| !c.is_pass());
        if has_failure {
            if let Some(ref result) = native_result {
                println!("Initial State (inputs):");
                println!("  Registers:");
                let mut regs: Vec<_> = result.initial_state.registers.iter().collect();
                regs.sort_by_key(|(name, _)| *name);
                for (reg, val) in regs {
                    println!("    {:>5}: 0x{:016x}", reg, val);
                }
                if !result.initial_state.memory_locations.is_empty() {
                    println!("  Memory:");
                    for (addr, data) in &result.initial_state.memory_locations {
                        println!(
                            "    0x{:016x}: {} ({} bytes)",
                            addr,
                            data.iter()
                                .take(16)
                                .map(|b| format!("{:02x}", b))
                                .collect::<Vec<_>>()
                                .join(" "),
                            data.len()
                        );
                    }
                }
                println!();
            }
        }

        // Native results
        if let Some(ref result) = native_result {
            println!("Native (x86_64@{}):", native_target.description());
            println!("  Exit code: {}", result.exit_code);
            println!("  Execution time: {:?}", result.execution_time);
            if self.verbose {
                println!("  Flags: 0x{:016x}", result.final_state.flags);
                for (reg, val) in &result.final_state.registers {
                    println!("  {}: 0x{:016x}", reg, val);
                }
            }
            println!();
        } else if !self.fex_only {
            println!("Native: Not executed");
            println!();
        }

        // FEX-Emu results
        if let Some(ref result) = fex_result {
            println!("FEX-Emu (aarch64@{}):", fex_target.description());
            println!("  Exit code: {}", result.exit_code);
            println!("  Execution time: {:?}", result.execution_time);
            if self.verbose {
                println!("  Flags: 0x{:016x}", result.final_state.flags);
                for (reg, val) in &result.final_state.registers {
                    println!("  {}: 0x{:016x}", reg, val);
                }
            }
            println!();
        } else if !self.native_only {
            println!("FEX-Emu: Not executed");
            println!();
        }

        // Comparison
        if let Some(ref comp) = comparison {
            println!("Comparison:");

            let check_mark = |passed: bool| if passed { "✓" } else { "✗" };

            println!(
                "  {} Exit codes {}",
                check_mark(comp.exit_codes_match),
                if comp.exit_codes_match {
                    "match"
                } else {
                    "differ"
                }
            );

            println!(
                "  {} Flags {} (0x{:016x} vs 0x{:016x})",
                check_mark(comp.flags_match),
                if comp.flags_match { "match" } else { "differ" },
                comp.native_flags,
                comp.fex_flags
            );

            // Show flag-by-flag breakdown if requested or if flags differ
            if self.flag_detail || !comp.flags_match {
                let flag_comp = FlagComparison::compare(comp.native_flags, comp.fex_flags);
                if !flag_comp.all_match() {
                    println!();
                    println!("    Flag Breakdown:");
                    for line in flag_comp.format_table().lines() {
                        println!("      {}", line);
                    }
                } else if self.flag_detail {
                    println!("    All individual flags match");
                }
            }

            let reg_count = native_result
                .as_ref()
                .map(|r| r.final_state.registers.len())
                .unwrap_or(0);
            let matching_regs = reg_count - comp.register_differences.len();
            println!(
                "  {} Registers {} ({}/{})",
                check_mark(comp.registers_match),
                if comp.registers_match {
                    "match"
                } else {
                    "differ"
                },
                matching_regs,
                reg_count
            );

            // Always show register differences when they exist
            if !comp.registers_match {
                println!();
                println!("    Register Differences (native vs FEX):");
                for diff in &comp.register_differences {
                    println!(
                        "      {:>5}: 0x{:016x} vs 0x{:016x}",
                        diff.name, diff.native_value, diff.fex_value
                    );
                }
            }

            let mem_count = native_result
                .as_ref()
                .map(|r| r.final_state.memory_locations.len())
                .unwrap_or(0);
            let matching_mem = mem_count - comp.memory_differences.len();
            println!(
                "  {} Memory {} ({}/{} locations)",
                check_mark(comp.memory_match),
                if comp.memory_match {
                    "match"
                } else {
                    "differs"
                },
                matching_mem,
                mem_count
            );

            // Always show memory differences when they exist
            if !comp.memory_match {
                println!();
                println!("    Memory Differences:");
                for diff in &comp.memory_differences {
                    println!("      0x{:016x}:", diff.address);
                    println!(
                        "        native: {}",
                        diff.native_value
                            .iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<_>>()
                            .join(" ")
                    );
                    println!(
                        "        FEX:    {}",
                        diff.fex_value
                            .iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<_>>()
                            .join(" ")
                    );
                }
            }

            println!();
            if comp.is_pass() {
                println!("VERDICT: PASS ✓");
            } else {
                println!("VERDICT: FAIL ✗");
            }
        } else if native_result.is_some() || fex_result.is_some() {
            println!("Comparison: Not available (only one execution completed)");
        }

        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    }
}

fn cached_to_simulation_result(
    cached: CachedValidationResult,
    initial_state: &InitialState,
    emulator_type: &str,
) -> SimulationResult {
    SimulationResult {
        simulation_id: format!("cached-{}", emulator_type),
        initial_state: initial_state.clone(),
        final_state: cached.final_state,
        execution_time: cached.execution_time,
        exit_code: cached.exit_code,
        emulator_used: if emulator_type == "native" {
            None
        } else {
            Some("FEXInterpreter".to_string())
        },
        assembly_file_path: None,
        binary_file_path: None,
    }
}
