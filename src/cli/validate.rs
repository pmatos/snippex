//! Validation command for comparing native x86 and FEX-Emu execution results.

use anyhow::{anyhow, Result};
use clap::Args;
use std::path::PathBuf;

use crate::arch::{
    get_effective_architecture, EmulatorDispatcher, ExecutionTarget, FlagComparison,
};
use crate::config::Config;
use crate::db::{CachedValidationResult, Database};
use crate::remote::{ExecutionPackage, RemoteOrchestrator};
use crate::simulator::{
    EmulatorConfig, FinalState, InitialState, RandomStateGenerator, SimulationResult, Simulator,
};

#[derive(Args)]
pub struct ValidateCommand {
    #[arg(help = "Block number to validate (as shown by list command)")]
    pub block_number: usize,

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

    #[arg(long, help = "Skip cache and force re-execution")]
    pub no_cache: bool,

    #[arg(long, default_value = "7", help = "Cache TTL in days")]
    pub cache_ttl: u32,

    #[arg(long, help = "Show flag-by-flag breakdown")]
    pub flag_detail: bool,

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

impl ComparisonResult {
    pub fn is_pass(&self) -> bool {
        self.exit_codes_match && self.flags_match && self.registers_match && self.memory_match
    }

    fn compare(native: &FinalState, fex: &FinalState, native_exit: i32, fex_exit: i32) -> Self {
        let exit_codes_match = native_exit == fex_exit;
        let flags_match = native.flags == fex.flags;

        let mut register_differences = Vec::new();
        let mut registers_match = true;

        // Compare all registers
        for (name, native_value) in &native.registers {
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
                 • Specify a different database: snippex validate {} -d <path>",
                self.database.display(),
                self.block_number
            ));
        }

        // Load configuration
        let config = Config::load().unwrap_or_default();

        // Detect host architecture
        let host_arch = get_effective_architecture()
            .map_err(|e| anyhow!("Architecture detection failed: {}", e))?;

        // Create dispatcher
        let dispatcher = EmulatorDispatcher::with_arch(host_arch, config.clone());

        // Show configuration
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Block #{} Validation", self.block_number);
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!();
        println!("Host: {}", host_arch.display_name());

        let native_target = dispatcher.select_native_host();
        let fex_target = dispatcher.select_fex_host();

        println!("Native execution: {}", native_target.description());
        println!("FEX-Emu execution: {}", fex_target.description());
        println!();

        // Validate command-line flags
        if self.native_only && self.fex_only {
            return Err(anyhow!("Cannot specify both --native-only and --fex-only"));
        }

        // Check for unavailable targets
        if !self.fex_only && native_target.is_unavailable() {
            println!(
                "Warning: Native execution unavailable - {}",
                native_target.description()
            );
            if !self.native_only {
                println!("  Use --fex-only to run FEX-Emu execution only");
            } else {
                return Err(anyhow!("Native execution requested but not available"));
            }
        }

        if !self.native_only && fex_target.is_unavailable() {
            println!(
                "Warning: FEX-Emu execution unavailable - {}",
                fex_target.description()
            );
            if !self.fex_only {
                println!("  Use --native-only to run native execution only");
            } else {
                return Err(anyhow!("FEX-Emu execution requested but not available"));
            }
        }

        // Load extraction from database
        let mut db = Database::new(&self.database)?;
        let extractions = db.list_extractions()?;

        if self.block_number == 0 || self.block_number > extractions.len() {
            return Err(anyhow!(
                "Invalid block number: {}\n\n\
                 Valid block range: 1-{}\n\n\
                 Suggestions:\n\
                 • List available blocks: snippex list",
                self.block_number,
                extractions.len()
            ));
        }

        let extraction = &extractions[self.block_number - 1];

        // Check if block is analyzed
        if extraction.analysis_status != "analyzed" {
            return Err(anyhow!(
                "Block #{} is not analyzed\n\n\
                 Suggestions:\n\
                 • Analyze this block: snippex analyze {}",
                self.block_number,
                self.block_number
            ));
        }

        // Load analysis
        let analysis = db.load_block_analysis(extraction.id)?.ok_or_else(|| {
            anyhow!(
                "Block analysis not found in database\n\n\
                 This is unexpected - the block shows as analyzed but no analysis data exists.\n\n\
                 Suggestions:\n\
                 • Re-analyze this block: snippex analyze {}\n\
                 • Check database integrity",
                self.block_number
            )
        })?;

        println!("Block: {}", extraction.binary_path);
        println!(
            "Address range: 0x{:08x} - 0x{:08x}",
            extraction.start_address, extraction.end_address
        );
        println!();

        // Generate initial state (same for both)
        let mut random_gen = RandomStateGenerator::new();
        if let Some(seed) = self.seed {
            println!("Seed: {}", seed);
            random_gen = RandomStateGenerator::with_seed(seed);
        }
        let initial_state = random_gen.generate_initial_state(&analysis);

        // Run validations
        let mut native_result: Option<SimulationResult> = None;
        let mut fex_result: Option<SimulationResult> = None;
        let mut native_from_cache = false;
        let mut fex_from_cache = false;

        // Run native simulation
        if !self.fex_only && !native_target.is_unavailable() {
            // Check cache first
            if !self.no_cache {
                if let Ok(Some(cached)) =
                    db.get_validation_cache(extraction.id, "native", self.seed, self.cache_ttl)
                {
                    if self.verbose {
                        println!("Using cached native result (from {})", cached.cached_at);
                    }
                    native_result = Some(cached_to_simulation_result(
                        cached,
                        &initial_state,
                        "native",
                    ));
                    native_from_cache = true;
                }
            }

            if native_result.is_none() {
                println!("Running native x86 simulation...");
                match self.run_simulation(
                    extraction,
                    &analysis,
                    &initial_state,
                    &native_target,
                    None,
                    &config,
                ) {
                    Ok(result) => {
                        if self.verbose {
                            println!("  Exit code: {}", result.exit_code);
                            println!("  Execution time: {:?}", result.execution_time);
                        }
                        // Store in cache
                        if let Err(e) = db.store_validation_cache(
                            extraction.id,
                            "native",
                            &host_arch.to_string(),
                            &result,
                            self.seed,
                        ) {
                            log::warn!("Failed to cache native result: {}", e);
                        }
                        native_result = Some(result);
                        println!("  Done.");
                    }
                    Err(e) => {
                        println!("  Failed: {}", e);
                    }
                }
            } else {
                println!("Native x86 simulation: cached");
            }
        }

        // Run FEX-Emu simulation
        if !self.native_only && !fex_target.is_unavailable() {
            // Check cache first
            if !self.no_cache {
                if let Ok(Some(cached)) =
                    db.get_validation_cache(extraction.id, "fex-emu", self.seed, self.cache_ttl)
                {
                    if self.verbose {
                        println!("Using cached FEX-Emu result (from {})", cached.cached_at);
                    }
                    fex_result = Some(cached_to_simulation_result(
                        cached,
                        &initial_state,
                        "fex-emu",
                    ));
                    fex_from_cache = true;
                }
            }

            if fex_result.is_none() {
                println!("Running FEX-Emu simulation...");
                let emulator = EmulatorConfig::fex_emu();
                match self.run_simulation(
                    extraction,
                    &analysis,
                    &initial_state,
                    &fex_target,
                    Some(emulator),
                    &config,
                ) {
                    Ok(result) => {
                        if self.verbose {
                            println!("  Exit code: {}", result.exit_code);
                            println!("  Execution time: {:?}", result.execution_time);
                        }
                        // Store in cache
                        if let Err(e) = db.store_validation_cache(
                            extraction.id,
                            "fex-emu",
                            &host_arch.to_string(),
                            &result,
                            self.seed,
                        ) {
                            log::warn!("Failed to cache FEX-Emu result: {}", e);
                        }
                        fex_result = Some(result);
                        println!("  Done.");
                    }
                    Err(e) => {
                        println!("  Failed: {}", e);
                    }
                }
            } else {
                println!("FEX-Emu simulation: cached");
            }
        }

        // Suppress warnings about unused variables
        let _ = native_from_cache;
        let _ = fex_from_cache;

        println!();

        // Compare results
        let comparison = if let (Some(ref native), Some(ref fex)) = (&native_result, &fex_result) {
            Some(ComparisonResult::compare(
                &native.final_state,
                &fex.final_state,
                native.exit_code,
                fex.exit_code,
            ))
        } else {
            None
        };

        // Display results
        self.display_results(
            &native_result,
            &fex_result,
            &native_target,
            &fex_target,
            &comparison,
        );

        // Return error if validation failed
        if let Some(ref comp) = comparison {
            if !comp.is_pass() {
                return Err(anyhow!("Validation failed: results differ"));
            }
        }

        Ok(())
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
                // Run locally
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
                // Run remotely
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
            if self.flag_detail || (!comp.flags_match && self.verbose) {
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

            if !comp.registers_match && self.verbose {
                for diff in &comp.register_differences {
                    println!(
                        "      {}: 0x{:016x} (native) vs 0x{:016x} (FEX)",
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
