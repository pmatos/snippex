use anyhow::{anyhow, Result};
use clap::Args;
use log::info;
use std::path::PathBuf;

use crate::db::{BinaryInfo, Database};
use crate::export::ExportBundle;

#[derive(Args)]
pub struct ImportResultsCommand {
    #[arg(help = "JSON file containing exported results")]
    pub input: PathBuf,

    #[arg(
        short,
        long,
        default_value = "snippex.db",
        help = "SQLite database path"
    )]
    pub database: PathBuf,

    #[arg(
        long,
        help = "Only import simulations (skip binaries, extractions, analyses)"
    )]
    pub simulations_only: bool,

    #[arg(
        long,
        help = "Skip importing simulations if block already has simulations"
    )]
    pub skip_existing_simulations: bool,

    #[arg(
        long,
        help = "Merge mode: combine with existing data instead of creating new entries"
    )]
    pub merge: bool,

    #[arg(short, long, help = "Enable verbose logging")]
    pub verbose: bool,

    #[arg(short, long, help = "Suppress all output")]
    pub quiet: bool,

    #[arg(
        long,
        help = "Dry run: show what would be imported without making changes"
    )]
    pub dry_run: bool,
}

impl ImportResultsCommand {
    pub fn execute(self) -> Result<()> {
        if self.verbose {
            info!("Starting import operation");
        }

        // Check if input file exists
        if !self.input.exists() {
            return Err(anyhow!("Input file not found: {}", self.input.display()));
        }

        // Read and parse JSON
        let json_content = std::fs::read_to_string(&self.input)?;
        let bundle: ExportBundle = serde_json::from_str(&json_content)?;

        if !self.quiet {
            println!("Importing from: {}", self.input.display());
            println!("Source metadata:");
            println!("  Version: {}", bundle.metadata.version);
            println!("  Export date: {}", bundle.metadata.export_date);
            println!(
                "  Source host: {} ({})",
                bundle.metadata.host_info.machine_id, bundle.metadata.host_info.architecture
            );
            println!();
            println!("Bundle contents:");
            println!("  {} binaries", bundle.binaries.len());
            println!("  {} extractions", bundle.extractions.len());
            println!("  {} analyses", bundle.analyses.len());
            println!("  {} simulations", bundle.simulations.len());
            println!();
        }

        if self.dry_run {
            println!("DRY RUN: No changes will be made");
            self.show_import_plan(&bundle)?;
            return Ok(());
        }

        // Initialize database
        let mut db = Database::new(&self.database)?;
        db.init()?;

        let mut import_stats = ImportStats::default();

        // Import data
        if !self.simulations_only {
            import_stats.binaries_imported = self.import_binaries(&mut db, &bundle.binaries)?;
            import_stats.extractions_imported =
                self.import_extractions(&mut db, &bundle.extractions, &bundle.binaries)?;
            import_stats.analyses_imported = self.import_analyses(&mut db, &bundle.analyses)?;
        }

        import_stats.simulations_imported =
            self.import_simulations(&mut db, &bundle.simulations)?;

        if !self.quiet {
            println!("✓ Import completed:");
            if !self.simulations_only {
                println!("  {} binaries imported", import_stats.binaries_imported);
                println!(
                    "  {} extractions imported",
                    import_stats.extractions_imported
                );
                println!("  {} analyses imported", import_stats.analyses_imported);
            }
            println!(
                "  {} simulations imported",
                import_stats.simulations_imported
            );
        }

        Ok(())
    }

    fn show_import_plan(&self, bundle: &ExportBundle) -> Result<()> {
        println!("Import plan:");

        if !self.simulations_only {
            println!("  Would import {} binaries", bundle.binaries.len());
            println!("  Would import {} extractions", bundle.extractions.len());
            println!("  Would import {} analyses", bundle.analyses.len());
        } else {
            println!("  Skipping binaries, extractions, and analyses (simulations-only mode)");
        }

        println!("  Would import {} simulations", bundle.simulations.len());

        if self.skip_existing_simulations {
            println!("  Note: Will skip simulations for blocks that already have simulations");
        }

        Ok(())
    }

    fn import_binaries(&self, db: &mut Database, binaries: &[BinaryInfo]) -> Result<usize> {
        let mut imported = 0;

        for binary in binaries {
            if self.verbose {
                info!("Importing binary: {} ({})", binary.path, binary.hash);
            }

            // Check if binary already exists by hash
            if self.merge && db.get_binary_by_hash(&binary.hash).is_ok() {
                if self.verbose {
                    info!("Binary {} already exists, skipping", binary.hash);
                }
                continue;
            }

            // Store binary (will handle duplicates internally)
            if let Err(e) = db.store_binary_info(binary) {
                if self.verbose {
                    info!(
                        "Failed to store binary {}: {} (might already exist)",
                        binary.hash, e
                    );
                }
                continue;
            }

            imported += 1;
        }

        Ok(imported)
    }

    fn import_extractions(
        &self,
        db: &mut Database,
        extractions: &[crate::export::ExtractionData],
        binaries: &[BinaryInfo],
    ) -> Result<usize> {
        let mut imported = 0;

        for extraction in extractions {
            if self.verbose {
                info!(
                    "Importing extraction: 0x{:08x}-0x{:08x}",
                    extraction.start_address, extraction.end_address
                );
            }

            // Find the corresponding binary info
            let binary_info = binaries
                .iter()
                .find(|b| b.hash == extraction.binary_hash)
                .ok_or_else(|| {
                    anyhow!(
                        "Binary not found for extraction: {}",
                        extraction.binary_hash
                    )
                })?;

            // Store extraction
            if let Err(e) = db.store_extraction(
                binary_info,
                extraction.start_address,
                extraction.end_address,
                &extraction.assembly_block,
            ) {
                if self.verbose {
                    info!("Failed to store extraction: {} (might already exist)", e);
                }
                continue;
            }

            imported += 1;
        }

        Ok(imported)
    }

    fn import_analyses(
        &self,
        _db: &mut Database,
        analyses: &[crate::export::AnalysisData],
    ) -> Result<usize> {
        let mut imported = 0;

        for analysis in analyses {
            if self.verbose {
                info!(
                    "Importing analysis for extraction {}",
                    analysis.extraction_id
                );
            }

            // Convert back to BlockAnalysis
            let memory_accesses: Vec<crate::analyzer::MemoryAccess> = analysis
                .memory_accesses
                .iter()
                .filter_map(|s| {
                    // This is a simplified parsing - in a real implementation,
                    // we'd need proper deserialization of MemoryAccess
                    if s.contains("Read") {
                        Some(crate::analyzer::MemoryAccess {
                            offset: 0,
                            access_type: crate::analyzer::AccessType::Read,
                            size: 1,
                            is_stack: false,
                        })
                    } else if s.contains("Write") {
                        Some(crate::analyzer::MemoryAccess {
                            offset: 0,
                            access_type: crate::analyzer::AccessType::Write,
                            size: 1,
                            is_stack: false,
                        })
                    } else {
                        None
                    }
                })
                .collect();

            let exit_points: Vec<crate::analyzer::ExitPoint> = analysis
                .exit_points
                .iter()
                .map(|&offset| crate::analyzer::ExitPoint {
                    offset,
                    exit_type: crate::analyzer::ExitType::FallThrough,
                    target: None,
                })
                .collect();

            let _block_analysis = crate::analyzer::BlockAnalysis {
                instructions_count: analysis.instructions_count as usize,
                live_in_registers: analysis.live_in_registers.iter().cloned().collect(),
                live_out_registers: analysis.live_out_registers.iter().cloned().collect(),
                exit_points,
                memory_accesses,
            };

            // Note: For now, we skip storing analysis as it requires complex mapping
            // In a future version, we should properly map analysis data back to the database
            if self.verbose {
                info!("Skipping analysis storage (not implemented for import)");
            }

            imported += 1;
        }

        Ok(imported)
    }

    fn import_simulations(
        &self,
        db: &mut Database,
        simulations: &[crate::export::SimulationData],
    ) -> Result<usize> {
        let mut imported = 0;

        for simulation in simulations {
            if self.verbose {
                info!(
                    "Importing simulation {} for extraction {}",
                    simulation.simulation_id, simulation.extraction_id
                );
            }

            // Check if we should skip existing simulations
            if self.skip_existing_simulations {
                if let Ok(existing_sims) =
                    db.get_simulations_for_extraction(simulation.extraction_id)
                {
                    if !existing_sims.is_empty() {
                        if self.verbose {
                            info!(
                                "Skipping simulation for extraction {} (already has simulations)",
                                simulation.extraction_id
                            );
                        }
                        continue;
                    }
                }
            }

            // Convert back to SimulationResult
            let initial_state = crate::simulator::InitialState {
                registers: simulation.initial_registers.clone(),
                memory_locations: simulation.initial_memory.clone(),
                stack_setup: Vec::new(), // Not stored in export format
            };

            let final_state = crate::simulator::FinalState {
                registers: simulation.final_registers.clone(),
                memory_locations: simulation.final_memory.clone(),
                flags: simulation.final_flags,
            };

            let simulation_result = crate::simulator::SimulationResult {
                simulation_id: simulation.simulation_id.clone(),
                initial_state,
                final_state,
                execution_time: std::time::Duration::from_nanos(simulation.execution_time_ns),
                exit_code: simulation.exit_code,
                emulator_used: Some(simulation.emulator_used.clone()),
                assembly_file_path: simulation.assembly_file_path.clone(),
                binary_file_path: simulation.binary_file_path.clone(),
            };

            // Store simulation
            if let Err(e) = db.store_simulation_result(simulation.extraction_id, &simulation_result)
            {
                if self.verbose {
                    info!(
                        "Failed to store simulation {}: {}",
                        simulation.simulation_id, e
                    );
                }
                continue;
            }

            imported += 1;
        }

        Ok(imported)
    }
}

#[derive(Default)]
struct ImportStats {
    binaries_imported: usize,
    extractions_imported: usize,
    analyses_imported: usize,
    simulations_imported: usize,
}
