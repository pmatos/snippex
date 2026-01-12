use anyhow::{anyhow, Result};
use clap::Args;
use std::path::PathBuf;
use std::str::FromStr;

use crate::db::Database;
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
}

impl SimulateCommand {
    pub fn execute(self) -> Result<()> {
        // Check if database exists
        if !self.database.exists() {
            return Err(anyhow!("No database found"));
        }

        let mut db = Database::new(&self.database)?;

        // Get the extraction to simulate
        let extractions = match db.list_extractions() {
            Ok(extractions) => extractions,
            Err(_) => {
                return Err(anyhow!("No blocks found in database"));
            }
        };

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
                return Err(anyhow!("Emulator '{}' is not available", emulator_str));
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
        db: &Database,
        extraction: &crate::db::ExtractionInfo,
    ) -> Result<i64> {
        // Find the extraction ID by matching the extraction info
        // This is a simplified approach - in a real implementation,
        // we might want to store the ID in ExtractionInfo
        let extractions = db.list_extractions()?;

        for (idx, ext) in extractions.iter().enumerate() {
            if ext.binary_path == extraction.binary_path
                && ext.start_address == extraction.start_address
                && ext.end_address == extraction.end_address
                && ext.binary_hash == extraction.binary_hash
            {
                // Return 1-based index as ID (this is a simplification)
                return Ok((idx + 1) as i64);
            }
        }

        Err(anyhow!("Extraction not found in database"))
    }
}
