//! Emulate command - replay stored native simulations through FEX-Emu and compare results.
//!
//! This command is the core of FEX-Emu bug detection:
//! 1. Load stored native simulation results (ground truth from x86 machine)
//! 2. Replay each simulation's initial state through FEX-Emu
//! 3. Compare FEX output against stored native output
//! 4. Report any discrepancies (potential FEX bugs)

use anyhow::{anyhow, Result};
use clap::Args;
use console::style;
use std::path::PathBuf;

use crate::cli::block_range::BlockRange;
use crate::db::Database;
use crate::simulator::{EmulatorConfig, FinalState, SimulationResult, Simulator};

#[derive(Args)]
pub struct EmulateCommand {
    #[arg(help = "Block(s) to emulate: 5, 1-10, 5-, 3,7,12, or all")]
    pub blocks: BlockRange,

    #[arg(
        short,
        long,
        default_value = "snippex.db",
        help = "SQLite database path"
    )]
    pub database: PathBuf,

    #[arg(long, help = "Override host architecture for testing (x86_64 or aarch64)")]
    pub arch: Option<String>,

    #[arg(long, help = "Only emulate specific simulation by ID")]
    pub simulation_id: Option<String>,

    #[arg(long, help = "Stop on first mismatch")]
    pub stop_on_failure: bool,

    #[arg(short, long, help = "Keep generated assembly and binary files")]
    pub keep_files: bool,

    #[arg(short, long, help = "Show detailed execution output")]
    pub verbose: bool,

    #[arg(long, help = "Show flag-by-flag breakdown on mismatch")]
    pub flag_detail: bool,

    #[arg(long, help = "Show all register values, not just differences")]
    pub show_all_registers: bool,
}

/// Result of comparing FEX output against native oracle
#[derive(Debug)]
pub struct EmulationComparison {
    pub simulation_id: String,
    pub registers_match: bool,
    pub flags_match: bool,
    pub memory_match: bool,
    pub exit_code_match: bool,
    pub register_diffs: Vec<(String, u64, u64)>, // (name, native, fex)
    pub native_flags: u64,
    pub fex_flags: u64,
}

impl EmulationComparison {
    pub fn is_pass(&self) -> bool {
        self.registers_match && self.flags_match && self.memory_match && self.exit_code_match
    }

    fn compare(
        simulation_id: &str,
        native: &FinalState,
        fex: &FinalState,
        native_exit: i32,
        fex_exit: i32,
    ) -> Self {
        let exit_code_match = native_exit == fex_exit;
        let flags_match = native.flags == fex.flags;

        let mut register_diffs = Vec::new();
        let mut registers_match = true;

        for (name, native_value) in &native.registers {
            if let Some(fex_value) = fex.registers.get(name) {
                if native_value != fex_value {
                    registers_match = false;
                    register_diffs.push((name.clone(), *native_value, *fex_value));
                }
            }
        }

        let mut memory_match = true;
        for (addr, native_bytes) in &native.memory_locations {
            if let Some(fex_bytes) = fex.memory_locations.get(addr) {
                if native_bytes != fex_bytes {
                    memory_match = false;
                }
            }
        }

        Self {
            simulation_id: simulation_id.to_string(),
            registers_match,
            flags_match,
            memory_match,
            exit_code_match,
            register_diffs,
            native_flags: native.flags,
            fex_flags: fex.flags,
        }
    }
}

impl EmulateCommand {
    pub fn execute(self) -> Result<()> {
        if !self.database.exists() {
            return Err(anyhow!(
                "Database not found at '{}'\n\n\
                 Suggestions:\n\
                 • Import native results first: snippex import-results <file.json>\n\
                 • Specify a different database: snippex emulate {} -d <path>",
                self.database.display(),
                self.blocks
            ));
        }

        // Check FEX-Emu availability
        let fex_config = EmulatorConfig::fex_emu();
        if !fex_config.is_available() {
            return Err(anyhow!(
                "FEX-Emu is not available on this system\n\n\
                 The emulate command requires FEX-Emu to compare against native results.\n\n\
                 Suggestions:\n\
                 • Install FEX-Emu: https://github.com/FEX-Emu/FEX\n\
                 • Ensure FEXInterpreter is in your PATH"
            ));
        }

        let db = Database::new(&self.database)?;
        let extractions = db.list_extractions()?;

        let block_numbers = self.blocks.resolve(extractions.len())?;
        let multiple_blocks = block_numbers.len() > 1;

        // Initialize simulator once
        let mut simulator = Simulator::new()?;

        let mut total_pass = 0;
        let mut total_fail = 0;
        let mut blocks_with_no_simulations = 0;

        for (block_idx, block_number) in block_numbers.iter().enumerate() {
            if multiple_blocks && block_idx > 0 {
                println!();
                println!("{}", style("═".repeat(60)).dim());
                println!();
            }

            let extraction = &extractions[block_number - 1];

            // Check if block is analyzed
            if extraction.analysis_status != "analyzed" {
                eprintln!(
                    "{} Block #{} is not analyzed. Run 'snippex analyze {}' first.",
                    style("✗").red(),
                    block_number,
                    block_number
                );
                total_fail += 1;
                if self.stop_on_failure {
                    break;
                }
                continue;
            }

            // Load analysis
            let analysis = match db.load_block_analysis(extraction.id) {
                Ok(Some(a)) => a,
                Ok(None) => {
                    eprintln!(
                        "{} Block #{} analysis not found in database",
                        style("✗").red(),
                        block_number
                    );
                    total_fail += 1;
                    if self.stop_on_failure {
                        break;
                    }
                    continue;
                }
                Err(e) => {
                    eprintln!(
                        "{} Failed to load analysis for block #{}: {}",
                        style("✗").red(),
                        block_number,
                        e
                    );
                    total_fail += 1;
                    if self.stop_on_failure {
                        break;
                    }
                    continue;
                }
            };

            // Load stored native simulations
            let simulations = match db.get_simulations_for_extraction(extraction.id) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!(
                        "{} Failed to load simulations for block #{}: {}",
                        style("✗").red(),
                        block_number,
                        e
                    );
                    total_fail += 1;
                    if self.stop_on_failure {
                        break;
                    }
                    continue;
                }
            };

            // Filter to native simulations only (no emulator used)
            let native_simulations: Vec<_> = simulations
                .iter()
                .filter(|s| s.emulator_used.is_none())
                .collect();

            if native_simulations.is_empty() {
                if !multiple_blocks {
                    return Err(anyhow!(
                        "No native simulations found for block #{}\n\n\
                         The emulate command requires native simulation results as ground truth.\n\n\
                         Workflow:\n\
                         1. On x86 machine: snippex simulate {} --runs N\n\
                         2. On x86 machine: snippex export -o results.json\n\
                         3. On ARM64 machine: snippex import-results results.json\n\
                         4. On ARM64 machine: snippex emulate {}",
                        block_number, block_number, block_number
                    ));
                }
                blocks_with_no_simulations += 1;
                if self.verbose {
                    println!(
                        "  {} Block #{}: No native simulations found, skipping",
                        style("⚠").yellow(),
                        block_number
                    );
                }
                continue;
            }

            // Filter by simulation ID if specified
            let simulations_to_run: Vec<_> = if let Some(ref target_id) = self.simulation_id {
                native_simulations
                    .into_iter()
                    .filter(|s| s.simulation_id == *target_id)
                    .collect()
            } else {
                native_simulations
            };

            if simulations_to_run.is_empty() {
                if let Some(ref target_id) = self.simulation_id {
                    eprintln!(
                        "  {} Simulation '{}' not found for block #{}",
                        style("⚠").yellow(),
                        target_id,
                        block_number
                    );
                }
                continue;
            }

            if multiple_blocks {
                println!(
                    "{} Block #{} ({}/{})",
                    style("▶").cyan(),
                    block_number,
                    block_idx + 1,
                    block_numbers.len()
                );
            } else {
                println!(
                    "{}",
                    style(format!("Emulating block #{}", block_number))
                        .bold()
                        .cyan()
                );
            }
            println!("  Binary: {}", style(&extraction.binary_path).dim());
            println!(
                "  Range:  {} - {}",
                style(format!("0x{:08x}", extraction.start_address)).yellow(),
                style(format!("0x{:08x}", extraction.end_address)).yellow()
            );
            println!(
                "  Native simulations to replay: {}",
                simulations_to_run.len()
            );
            println!();

            let mut block_pass = 0;
            let mut block_fail = 0;

            for (i, native_sim) in simulations_to_run.iter().enumerate() {
                let sim_num = i + 1;
                let total = simulations_to_run.len();

                if self.verbose {
                    println!(
                        "  [{}/{}] Replaying simulation {}...",
                        sim_num,
                        total,
                        &native_sim.simulation_id[..8.min(native_sim.simulation_id.len())]
                    );
                }

                // Run through FEX-Emu with the same initial state
                let fex_result = simulator.simulate_block_with_state(
                    extraction,
                    &analysis,
                    &native_sim.initial_state,
                    Some(fex_config.clone()),
                    self.keep_files,
                );

                match fex_result {
                    Ok(fex_sim) => {
                        // Compare FEX result against native oracle
                        let comparison = EmulationComparison::compare(
                            &native_sim.simulation_id,
                            &native_sim.final_state,
                            &fex_sim.final_state,
                            native_sim.exit_code,
                            fex_sim.exit_code,
                        );

                        if comparison.is_pass() {
                            block_pass += 1;
                            if self.verbose {
                                println!("    {} PASS", style("✓").green());
                            }
                        } else {
                            block_fail += 1;
                            self.print_failure(&comparison, native_sim, &fex_sim);

                            if self.stop_on_failure {
                                println!();
                                println!(
                                    "{}",
                                    style("Stopping on first failure (--stop-on-failure)").red()
                                );
                                total_pass += block_pass;
                                total_fail += block_fail;
                                return Err(anyhow!("Emulation mismatch detected"));
                            }
                        }
                    }
                    Err(e) => {
                        block_fail += 1;
                        println!(
                            "  [{}/{}] {} FEX execution failed: {}",
                            sim_num,
                            total,
                            style("✗").red(),
                            e
                        );

                        if self.stop_on_failure {
                            total_pass += block_pass;
                            total_fail += block_fail;
                            return Err(anyhow!("FEX execution failed: {}", e));
                        }
                    }
                }
            }

            total_pass += block_pass;
            total_fail += block_fail;

            if multiple_blocks {
                println!(
                    "  Block #{}: {} passed, {} failed",
                    block_number,
                    style(block_pass).green(),
                    if block_fail > 0 {
                        style(block_fail).red()
                    } else {
                        style(block_fail).green()
                    }
                );
            }
        }

        // Summary
        println!();
        println!("{}", style("═".repeat(60)).dim());
        println!(
            "Total: {} passed, {} failed",
            style(total_pass).green().bold(),
            if total_fail > 0 {
                style(total_fail).red().bold()
            } else {
                style(total_fail).green().bold()
            }
        );

        if blocks_with_no_simulations > 0 {
            println!(
                "  ({} blocks had no native simulations)",
                blocks_with_no_simulations
            );
        }

        if total_fail > 0 {
            println!();
            println!(
                "{}",
                style("⚠ FEX-Emu produced different results than native x86!")
                    .yellow()
                    .bold()
            );
            println!("  This may indicate a bug in FEX-Emu.");
            Err(anyhow!(
                "{} of {} simulations produced different results",
                total_fail,
                total_pass + total_fail
            ))
        } else {
            println!();
            println!(
                "{}",
                style("✓ All simulations match native results").green()
            );
            Ok(())
        }
    }

    fn print_failure(
        &self,
        comparison: &EmulationComparison,
        native: &SimulationResult,
        fex: &SimulationResult,
    ) {
        let sim_id_display = if comparison.simulation_id.len() > 8 {
            &comparison.simulation_id[..8]
        } else {
            &comparison.simulation_id
        };

        println!(
            "  {} FAIL - Simulation {}",
            style("✗").red().bold(),
            sim_id_display
        );

        if !comparison.exit_code_match {
            println!(
                "    Exit code: native={}, fex={}",
                native.exit_code, fex.exit_code
            );
        }

        if !comparison.flags_match {
            println!(
                "    Flags mismatch: native=0x{:016x}, fex=0x{:016x}",
                comparison.native_flags, comparison.fex_flags
            );

            if self.flag_detail {
                self.print_flag_diff(comparison.native_flags, comparison.fex_flags);
            }
        }

        if !comparison.registers_match {
            println!("    Register differences:");
            for (name, native_val, fex_val) in &comparison.register_diffs {
                println!(
                    "      {}: native=0x{:016x}, fex=0x{:016x}",
                    style(name).yellow(),
                    native_val,
                    fex_val
                );
            }
        }

        if self.show_all_registers {
            println!("    All final registers (native):");
            let mut regs: Vec<_> = native.final_state.registers.iter().collect();
            regs.sort_by_key(|(k, _)| *k);
            for (name, value) in regs {
                println!("      {}: 0x{:016x}", name, value);
            }
        }

        if !comparison.memory_match {
            println!("    Memory differences detected");
        }
    }

    fn print_flag_diff(&self, native: u64, fex: u64) {
        let flags = [
            ("CF", 0),
            ("PF", 2),
            ("AF", 4),
            ("ZF", 6),
            ("SF", 7),
            ("OF", 11),
        ];

        for (name, bit) in flags {
            let native_bit = (native >> bit) & 1;
            let fex_bit = (fex >> bit) & 1;
            if native_bit != fex_bit {
                println!(
                    "      {}: native={}, fex={}",
                    style(name).yellow(),
                    native_bit,
                    fex_bit
                );
            }
        }
    }
}
