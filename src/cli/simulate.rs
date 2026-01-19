use anyhow::{anyhow, Result};
use clap::Args;
use std::path::PathBuf;
use std::str::FromStr;

use crate::config::Config;
use crate::db::Database;
use crate::remote::{ExecutionPackage, RemoteOrchestrator};
use crate::simulator::{EmulatorConfig, Simulator};

#[derive(Args)]
pub struct SimulateCommand {
    #[arg(help = "Block number to simulate (as shown by list command)")]
    pub block_number: usize,

    #[arg(
        short,
        long,
        default_value = "snippex.db",
        help = "SQLite database path"
    )]
    pub database: PathBuf,

    #[arg(short, long, default_value = "1", help = "Number of simulation runs")]
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
}

impl SimulateCommand {
    pub fn execute(self) -> Result<()> {
        // Check if database exists
        if !self.database.exists() {
            return Err(anyhow!(
                "Database not found at '{}'\n\n\
                 Suggestions:\n\
                 • Extract blocks first: snippex extract <binary>\n\
                 • Specify a different database: snippex simulate {} -d <path>",
                self.database.display(),
                self.block_number
            ));
        }

        // If remote execution requested, delegate to remote execution
        if let Some(ref remote_name) = self.remote {
            return self.execute_remote(remote_name);
        }

        let mut db = Database::new(&self.database)?;

        // Get the extraction to simulate
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

        // Load the full analysis from the database
        println!("Loading block analysis...");

        // Get extraction ID from database
        let extraction_id = self.get_extraction_id(&db, extraction)?;

        // Load actual analysis from database
        let analysis = db
            .load_block_analysis(extraction_id)?
            .ok_or_else(|| anyhow!("Block analysis not found in database"))?;

        // Parse emulator configuration
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
                     • Use native: snippex simulate {} --emulator native\n\
                     • Install the required emulator",
                    emulator_str,
                    self.block_number
                ));
            }

            Some(config)
        } else {
            None
        };

        println!("Simulating block #{}...", self.block_number);
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

        // Initialize simulator
        let mut simulator = Simulator::new()?;

        // Set seed if provided
        if let Some(seed) = self.seed {
            simulator.random_generator = crate::simulator::RandomStateGenerator::with_seed(seed);
        }

        // Use the actual analysis loaded from database

        // Run simulations
        for run in 1..=self.runs {
            if self.runs > 1 {
                println!("Run {}/{}:", run, self.runs);
            }

            match simulator.simulate_block(
                extraction,
                &analysis,
                emulator_config.clone(),
                self.keep_files,
            ) {
                Ok(result) => {
                    println!("  ✓ Simulation completed successfully");
                    println!("    Execution time: {:?}", result.execution_time);
                    println!("    Exit code: {}", result.exit_code);

                    if self.verbose {
                        println!("    Simulation ID: {}", result.simulation_id);
                        println!(
                            "    Initial registers: {}",
                            result.initial_state.registers.len()
                        );
                        println!(
                            "    Final registers: {}",
                            result.final_state.registers.len()
                        );

                        if let Some(ref asm_path) = result.assembly_file_path {
                            println!("    Assembly file: {asm_path}");
                        }
                        if let Some(ref bin_path) = result.binary_file_path {
                            println!("    Binary file: {bin_path}");
                        }
                    }

                    // Store simulation result in database
                    if let Err(e) = db.store_simulation_result(extraction_id, &result) {
                        eprintln!("Warning: Failed to store simulation result: {e}");
                    }
                }
                Err(e) => {
                    println!("  ✗ Simulation failed: {e}");
                    if self.runs > 1 {
                        continue;
                    } else {
                        return Err(e.into());
                    }
                }
            }

            if self.runs > 1 {
                println!();
            }
        }

        println!("✓ All simulations completed");
        Ok(())
    }

    fn get_extraction_id(
        &self,
        _db: &Database,
        extraction: &crate::db::ExtractionInfo,
    ) -> Result<i64> {
        Ok(extraction.id)
    }

    fn execute_remote(&self, remote_name: &str) -> Result<()> {
        // Load configuration
        let config = Config::load().map_err(|e| anyhow!("Failed to load config: {}", e))?;

        // Get remote configuration
        let remote_config = config
            .get_remote(remote_name)
            .ok_or_else(|| anyhow!("Remote '{}' not found in configuration", remote_name))?
            .clone();

        println!(
            "Remote execution on: {}@{}",
            remote_config.user, remote_config.host
        );

        // Load extraction from database
        let mut db = Database::new(&self.database)?;
        let extractions = db.list_extractions()?;

        if self.block_number == 0 || self.block_number > extractions.len() {
            return Err(anyhow!(
                "Invalid block number. Valid range: 1-{}",
                extractions.len()
            ));
        }

        let extraction = &extractions[self.block_number - 1];

        // Check if block is analyzed
        if extraction.analysis_status != "analyzed" {
            return Err(anyhow!(
                "Block #{} is not analyzed. Run 'analyze {}' first.",
                self.block_number,
                self.block_number
            ));
        }

        // Load analysis
        let analysis = db
            .load_block_analysis(extraction.id)?
            .ok_or_else(|| anyhow!("Block analysis not found in database"))?;

        // Parse emulator configuration
        let emulator_config = if let Some(emulator_str) = &self.emulator {
            Some(
                EmulatorConfig::from_str(emulator_str)
                    .map_err(|e| anyhow!("Invalid emulator configuration: {}", e))?,
            )
        } else {
            None
        };

        println!(
            "Preparing remote simulation for block #{}...",
            self.block_number
        );
        println!("  Binary: {}", extraction.binary_path);
        println!(
            "  Address range: 0x{:08x} - 0x{:08x}",
            extraction.start_address, extraction.end_address
        );

        // Generate initial state
        let mut random_gen = crate::simulator::RandomStateGenerator::new();
        if let Some(seed) = self.seed {
            random_gen = crate::simulator::RandomStateGenerator::with_seed(seed);
        }
        let initial_state = random_gen.generate_initial_state(&analysis);

        // Create execution package
        let package = ExecutionPackage::new(
            extraction,
            &analysis,
            &initial_state,
            emulator_config.as_ref(),
        );

        // Create orchestrator and execute remotely
        let orchestrator = RemoteOrchestrator::new(remote_config);

        println!("Executing simulation remotely...");
        let result = orchestrator
            .execute_remote_simulation(&package)
            .map_err(|e| anyhow!("Remote execution failed: {}", e))?;

        // Display results
        println!();
        println!("  ✓ Remote simulation completed successfully");
        println!("    Execution time: {:?}", result.execution_time);
        println!("    Exit code: {}", result.exit_code);

        if self.verbose {
            println!("    Simulation ID: {}", result.simulation_id);
            println!(
                "    Initial registers: {}",
                result.initial_state.registers.len()
            );
            println!(
                "    Final registers: {}",
                result.final_state.registers.len()
            );
        }

        // Store result in database
        if let Err(e) = db.store_simulation_result(extraction.id, &result) {
            eprintln!("Warning: Failed to store simulation result: {e}");
        }

        println!("✓ Remote simulation completed");
        Ok(())
    }
}
