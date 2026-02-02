use anyhow::{anyhow, Result};
use clap::Args;
use std::path::PathBuf;
use std::str::FromStr;

use crate::cli::block_range::BlockRange;
use crate::config::Config;
use crate::db::Database;
use crate::remote::{ExecutionPackage, RemoteOrchestrator};
use crate::simulator::{EmulatorConfig, Simulator};

#[derive(Args)]
pub struct SimulateCommand {
    #[arg(help = "Block(s) to simulate: 5, 1-10, 5-, 3,7,12, or all")]
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
        help = "Number of simulation runs per block"
    )]
    pub runs: usize,

    #[arg(short, long, help = "Seed for random value generation")]
    pub seed: Option<u64>,

    #[arg(short, long, help = "Keep generated assembly and binary files")]
    pub keep_files: bool,

    #[arg(
        short,
        long,
        help = "Use emulator (native, qemu-x86_64, qemu-i386, fex-emu)"
    )]
    pub emulator: Option<String>,

    #[arg(short, long, help = "Show detailed execution output")]
    pub verbose: bool,

    #[arg(long, help = "Execute on remote machine (name from config)")]
    pub remote: Option<String>,

    #[arg(long, help = "Stop on first simulation failure")]
    pub stop_on_failure: bool,
}

impl SimulateCommand {
    pub fn execute(self) -> Result<()> {
        if !self.database.exists() {
            return Err(anyhow!(
                "Database not found at '{}'\n\n\
                 Suggestions:\n\
                 • Extract blocks first: snippex extract <binary>\n\
                 • Specify a different database: snippex simulate {} -d <path>",
                self.database.display(),
                self.blocks
            ));
        }

        // If remote execution requested, delegate to remote execution
        if let Some(ref remote_name) = self.remote {
            return self.execute_remote(remote_name);
        }

        let mut db = Database::new(&self.database)?;

        let extractions = match db.list_extractions() {
            Ok(extractions) => extractions,
            Err(_) => {
                return Err(anyhow!(
                    "No blocks found in database\n\n\
                     Suggestions:\n\
                     • Extract blocks first: snippex extract <binary>\n\
                     • Import NASM file: snippex import <file.asm>"
                ));
            }
        };

        let block_numbers = self.blocks.resolve(extractions.len())?;
        let multiple_blocks = block_numbers.len() > 1;

        // Parse emulator configuration once
        let emulator_config = if let Some(emulator_str) = &self.emulator {
            let config = EmulatorConfig::from_str(emulator_str)
                .map_err(|e| anyhow!("Invalid emulator configuration: {}", e))?;

            if !config.is_available() {
                return Err(anyhow!(
                    "Emulator '{}' is not available on this system\n\n\
                     Available emulators:\n\
                     • native - Native execution (always available)\n\
                     • fex-emu - FEX-Emu x86 emulator (requires FEXInterpreter)\n\
                     • qemu-x86_64 - QEMU user-mode emulation\n\n\
                     Suggestions:\n\
                     • Use native: snippex simulate {} --emulator native",
                    emulator_str,
                    self.blocks
                ));
            }

            Some(config)
        } else {
            None
        };

        // Initialize simulator once (arch will be updated per-block if needed)
        let mut simulator = Simulator::new()?;
        if let Some(seed) = self.seed {
            simulator.random_generator = crate::simulator::RandomStateGenerator::with_seed(seed);
        }
        // Track current arch to re-init simulator when arch changes
        let mut current_arch = String::from("x86_64");

        let mut total_success = 0;
        let mut total_failure = 0;

        for (block_idx, block_number) in block_numbers.iter().enumerate() {
            if multiple_blocks && block_idx > 0 {
                println!();
                println!("{}", "─".repeat(60));
                println!();
            }

            let extraction = &extractions[block_number - 1];

            // Re-initialize simulator if architecture changed
            if extraction.binary_architecture != current_arch {
                current_arch = extraction.binary_architecture.clone();
                simulator = Simulator::for_target(&current_arch)?;
                if let Some(seed) = self.seed {
                    simulator.random_generator =
                        crate::simulator::RandomStateGenerator::with_seed(seed);
                }
            }

            // Check if block is analyzed
            if extraction.analysis_status != "analyzed" {
                eprintln!(
                    "✗ Block #{} is not analyzed. Run 'snippex analyze {}' first.",
                    block_number, block_number
                );
                total_failure += 1;
                if self.stop_on_failure {
                    break;
                }
                continue;
            }

            let extraction_id = extraction.id;

            // Load analysis from database
            let analysis = match db.load_block_analysis(extraction_id) {
                Ok(Some(a)) => a,
                Ok(None) => {
                    eprintln!("✗ Block #{} analysis not found in database", block_number);
                    total_failure += 1;
                    if self.stop_on_failure {
                        break;
                    }
                    continue;
                }
                Err(e) => {
                    eprintln!(
                        "✗ Failed to load analysis for block #{}: {}",
                        block_number, e
                    );
                    total_failure += 1;
                    if self.stop_on_failure {
                        break;
                    }
                    continue;
                }
            };

            if multiple_blocks {
                println!(
                    "Block #{} ({}/{})",
                    block_number,
                    block_idx + 1,
                    block_numbers.len()
                );
            } else {
                println!("Simulating block #{}...", block_number);
            }
            println!("  Binary: {}", extraction.binary_path);
            println!(
                "  Address range: 0x{:08x} - 0x{:08x}",
                extraction.start_address, extraction.end_address
            );
            println!("  Runs: {}", self.runs);
            if let Some(seed) = self.seed {
                println!("  Seed: {seed}");
            }
            if let Some(ref emulator) = self.emulator {
                println!("  Emulator: {emulator}");
            }
            println!();

            let mut block_success = 0;
            let mut block_failure = 0;

            for run in 1..=self.runs {
                if self.runs > 1 {
                    println!("  Run {}/{}:", run, self.runs);
                }

                match simulator.simulate_block(
                    extraction,
                    &analysis,
                    emulator_config.clone(),
                    self.keep_files,
                ) {
                    Ok(result) => {
                        println!("    ✓ Simulation completed");
                        println!("      Execution time: {:?}", result.execution_time);
                        println!("      Exit code: {}", result.exit_code);

                        if self.verbose {
                            println!("      Simulation ID: {}", result.simulation_id);
                            println!(
                                "      Initial registers: {}",
                                result.initial_state.registers.len()
                            );
                            println!(
                                "      Final registers: {}",
                                result.final_state.registers.len()
                            );

                            if let Some(ref asm_path) = result.assembly_file_path {
                                println!("      Assembly file: {asm_path}");
                            }
                            if let Some(ref bin_path) = result.binary_file_path {
                                println!("      Binary file: {bin_path}");
                            }
                        }

                        if let Err(e) = db.store_simulation_result(extraction_id, &result) {
                            eprintln!("    Warning: Failed to store simulation result: {e}");
                        }

                        block_success += 1;
                    }
                    Err(e) => {
                        println!("    ✗ Simulation failed: {e}");
                        block_failure += 1;
                        if self.stop_on_failure {
                            break;
                        }
                    }
                }
            }

            total_success += block_success;
            total_failure += block_failure;

            if self.runs > 1 {
                println!();
                println!(
                    "  Block #{}: {} succeeded, {} failed",
                    block_number, block_success, block_failure
                );
            }

            if self.stop_on_failure && block_failure > 0 {
                break;
            }
        }

        println!();
        if multiple_blocks || self.runs > 1 {
            println!("{}", "═".repeat(60));
            println!(
                "Total: {} simulations succeeded, {} failed",
                total_success, total_failure
            );
        } else {
            println!("✓ Simulation completed");
        }

        if total_failure > 0 && total_success == 0 {
            Err(anyhow!("All simulations failed"))
        } else {
            Ok(())
        }
    }

    fn execute_remote(&self, remote_name: &str) -> Result<()> {
        let config = Config::load().map_err(|e| anyhow!("Failed to load config: {}", e))?;

        let remote_config = config
            .get_remote(remote_name)
            .ok_or_else(|| anyhow!("Remote '{}' not found in configuration", remote_name))?
            .clone();

        println!(
            "Remote execution on: {}@{}",
            remote_config.user, remote_config.host
        );

        let mut db = Database::new(&self.database)?;
        let extractions = db.list_extractions()?;

        let block_numbers = self.blocks.resolve(extractions.len())?;

        // Parse emulator configuration
        let emulator_config = if let Some(emulator_str) = &self.emulator {
            Some(
                EmulatorConfig::from_str(emulator_str)
                    .map_err(|e| anyhow!("Invalid emulator configuration: {}", e))?,
            )
        } else {
            None
        };

        let orchestrator = RemoteOrchestrator::new(remote_config);

        let mut total_success = 0;
        let mut total_failure = 0;

        for block_number in &block_numbers {
            let extraction = &extractions[block_number - 1];

            if extraction.analysis_status != "analyzed" {
                eprintln!(
                    "✗ Block #{} is not analyzed. Run 'analyze {}' first.",
                    block_number, block_number
                );
                total_failure += 1;
                if self.stop_on_failure {
                    break;
                }
                continue;
            }

            let analysis = db
                .load_block_analysis(extraction.id)?
                .ok_or_else(|| anyhow!("Block analysis not found in database"))?;

            println!("Preparing remote simulation for block #{}...", block_number);
            println!("  Binary: {}", extraction.binary_path);
            println!(
                "  Address range: 0x{:08x} - 0x{:08x}",
                extraction.start_address, extraction.end_address
            );

            for run in 1..=self.runs {
                if self.runs > 1 {
                    println!("  Run {}/{}:", run, self.runs);
                }

                let mut random_gen = crate::simulator::RandomStateGenerator::new();
                if let Some(seed) = self.seed {
                    random_gen =
                        crate::simulator::RandomStateGenerator::with_seed(seed + run as u64);
                }
                let initial_state = random_gen.generate_initial_state(&analysis);

                let package = ExecutionPackage::new(
                    extraction,
                    &analysis,
                    &initial_state,
                    emulator_config.as_ref(),
                );

                println!("    Executing simulation remotely...");
                match orchestrator.execute_remote_simulation(&package) {
                    Ok(result) => {
                        println!("    ✓ Remote simulation completed");
                        println!("      Execution time: {:?}", result.execution_time);
                        println!("      Exit code: {}", result.exit_code);

                        if self.verbose {
                            println!("      Simulation ID: {}", result.simulation_id);
                            println!(
                                "      Initial registers: {}",
                                result.initial_state.registers.len()
                            );
                            println!(
                                "      Final registers: {}",
                                result.final_state.registers.len()
                            );
                        }

                        if let Err(e) = db.store_simulation_result(extraction.id, &result) {
                            eprintln!("    Warning: Failed to store simulation result: {e}");
                        }

                        total_success += 1;
                    }
                    Err(e) => {
                        eprintln!("    ✗ Remote execution failed: {}", e);
                        total_failure += 1;
                        if self.stop_on_failure {
                            break;
                        }
                    }
                }
            }

            if self.stop_on_failure && total_failure > 0 {
                break;
            }
        }

        println!();
        println!("{}", "═".repeat(60));
        println!(
            "Total: {} remote simulations succeeded, {} failed",
            total_success, total_failure
        );

        if total_failure > 0 && total_success == 0 {
            Err(anyhow!("All remote simulations failed"))
        } else {
            Ok(())
        }
    }
}
