use anyhow::{anyhow, Result};
use clap::Args;
use log::info;
use std::path::PathBuf;

use crate::db::Database;
use crate::export::{
    AnalysisData, ExportBundle, ExportMetadata, ExportType, ExtractionData, SimulationData,
};

#[derive(Args)]
pub struct ExportCommand {
    #[arg(
        short,
        long,
        help = "Block number to export (as shown by list command). If not specified, exports all blocks"
    )]
    pub block: Option<usize>,

    #[arg(
        short,
        long,
        default_value = "snippex.db",
        help = "SQLite database path"
    )]
    pub database: PathBuf,

    #[arg(short, long, help = "Output file path (JSON format)")]
    pub output: PathBuf,

    #[arg(long, help = "Include only blocks with simulations")]
    pub simulated_only: bool,

    #[arg(long, help = "Include only blocks with analyses")]
    pub analyzed_only: bool,

    #[arg(short, long, help = "Enable verbose logging")]
    pub verbose: bool,

    #[arg(short, long, help = "Suppress all output")]
    pub quiet: bool,
}

impl ExportCommand {
    pub fn execute(self) -> Result<()> {
        if self.verbose {
            info!("Starting export operation");
        }

        // Check if database exists
        if !self.database.exists() {
            return Err(anyhow!(
                "Database file not found: {}",
                self.database.display()
            ));
        }

        let mut db = Database::new(&self.database)?;

        // Determine export type
        let export_type = if let Some(block_num) = self.block {
            ExportType::SingleBlock {
                extraction_id: block_num as i64,
            }
        } else {
            ExportType::FullDatabase
        };

        let metadata = ExportMetadata::new(export_type.clone());

        if !self.quiet {
            match &export_type {
                ExportType::SingleBlock { extraction_id } => {
                    println!("Exporting block #{}", extraction_id);
                }
                ExportType::FullDatabase => {
                    println!("Exporting entire database");
                }
                _ => {}
            }
        }

        // Get extractions to export
        let extractions = self.get_extractions_to_export(&mut db)?;

        if extractions.is_empty() {
            return Err(anyhow!("No extractions found matching the criteria"));
        }

        if !self.quiet {
            println!("Found {} extraction(s) to export", extractions.len());
        }

        // Build export bundle
        let mut bundle = ExportBundle {
            metadata,
            binaries: Vec::new(),
            extractions: Vec::new(),
            analyses: Vec::new(),
            simulations: Vec::new(),
        };

        // Collect unique binaries
        let mut binary_hashes = std::collections::HashSet::new();

        for extraction in &extractions {
            if binary_hashes.insert(extraction.binary_hash.clone()) {
                if let Ok(binary_info) = db.get_binary_by_hash(&extraction.binary_hash) {
                    bundle.binaries.push(binary_info);
                }
            }

            // Add extraction data
            let mut extraction_data = ExtractionData::from(extraction);
            extraction_data.id = self.get_extraction_id(&db, extraction)?;
            bundle.extractions.push(extraction_data);

            // Add analysis data if available
            let extraction_id = self.get_extraction_id(&db, extraction)?;
            if let Ok(Some(analysis)) = db.load_block_analysis(extraction_id) {
                let mut analysis_data = AnalysisData::from(&analysis);
                analysis_data.extraction_id = extraction_id;
                bundle.analyses.push(analysis_data);
            }

            // Add simulation data if available
            if let Ok(simulations) = db.get_simulations_for_extraction(extraction_id) {
                for simulation in simulations {
                    let mut sim_data = SimulationData::from(&simulation);
                    sim_data.extraction_id = extraction_id;
                    bundle.simulations.push(sim_data);
                }
            }
        }

        if self.verbose {
            info!("Export bundle contains:");
            info!("  {} binaries", bundle.binaries.len());
            info!("  {} extractions", bundle.extractions.len());
            info!("  {} analyses", bundle.analyses.len());
            info!("  {} simulations", bundle.simulations.len());
        }

        // Write to file
        let json_output = serde_json::to_string_pretty(&bundle)?;
        std::fs::write(&self.output, json_output)?;

        if !self.quiet {
            println!("✓ Export completed: {}", self.output.display());
            println!("  {} binaries", bundle.binaries.len());
            println!("  {} extractions", bundle.extractions.len());
            println!("  {} analyses", bundle.analyses.len());
            println!("  {} simulations", bundle.simulations.len());
        }

        Ok(())
    }

    fn get_extractions_to_export(
        &self,
        db: &mut Database,
    ) -> Result<Vec<crate::db::ExtractionInfo>> {
        let all_extractions = db.list_extractions()?;

        let mut filtered_extractions = Vec::new();

        for (idx, extraction) in all_extractions.iter().enumerate() {
            let extraction_id = (idx + 1) as i64;

            // Filter by block number if specified
            if let Some(target_block) = self.block {
                if (idx + 1) != target_block {
                    continue;
                }
            }

            // Filter by analysis status if specified
            if self.analyzed_only && extraction.analysis_status != "analyzed" {
                continue;
            }

            // Filter by simulation status if specified
            if self.simulated_only {
                if let Ok(simulations) = db.get_simulations_for_extraction(extraction_id) {
                    if simulations.is_empty() {
                        continue;
                    }
                } else {
                    continue;
                }
            }

            filtered_extractions.push(extraction.clone());
        }

        Ok(filtered_extractions)
    }

    fn get_extraction_id(
        &self,
        db: &Database,
        extraction: &crate::db::ExtractionInfo,
    ) -> Result<i64> {
        // Find the extraction ID by matching the extraction info
        let extractions = db.list_extractions()?;

        for (idx, ext) in extractions.iter().enumerate() {
            if ext.binary_path == extraction.binary_path
                && ext.start_address == extraction.start_address
                && ext.end_address == extraction.end_address
                && ext.binary_hash == extraction.binary_hash
            {
                return Ok((idx + 1) as i64);
            }
        }

        Err(anyhow!("Extraction not found in database"))
    }
}
