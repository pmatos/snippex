use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

use crate::db::Database;

#[derive(Args)]
pub struct ListCommand {
    #[arg(
        short,
        long,
        default_value = "snippex.db",
        help = "SQLite database path"
    )]
    database: PathBuf,

    #[arg(short, long, help = "Show detailed information")]
    verbose: bool,
}

impl ListCommand {
    pub fn execute(self) -> Result<()> {
        // Check if database file exists, if not, there are no blocks
        if !self.database.exists() {
            return Ok(());
        }

        let db = Database::new(&self.database)?;
        let blocks = match db.list_extractions() {
            Ok(blocks) => blocks,
            Err(_) => {
                // Database exists but tables don't - treat as empty
                return Ok(());
            }
        };

        if blocks.is_empty() {
            return Ok(());
        }

        println!("Listing stored blocks from: {}", self.database.display());
        println!();
        println!("Found {} blocks:", blocks.len());
        println!("{:-<80}", "");

        for (idx, block) in blocks.iter().enumerate() {
            println!("Block #{}", idx + 1);
            println!("  Binary: {} ({})", block.binary_path, block.binary_hash);
            println!(
                "  Format: {} {}",
                block.binary_format, block.binary_architecture
            );
            println!(
                "  Address range: 0x{:08x} - 0x{:08x}",
                block.start_address, block.end_address
            );
            println!("  Size: {} bytes", block.assembly_block.len());
            println!("  Extracted at: {}", block.created_at);
            println!("  Status: {}", block.analysis_status);

            if block.analysis_status == "analyzed" {
                if let Some(results) = &block.analysis_results {
                    if let Ok(summary) = serde_json::from_str::<serde_json::Value>(results) {
                        if let Some(instructions) = summary.get("instructions") {
                            println!("  Instructions: {instructions}");
                        }
                        if let Some(live_in) = summary.get("live_in").and_then(|v| v.as_str()) {
                            if !live_in.is_empty() {
                                println!("  Live-in: {live_in}");
                            }
                        }
                        if let Some(live_out) = summary.get("live_out").and_then(|v| v.as_str()) {
                            if !live_out.is_empty() {
                                println!("  Live-out: {live_out}");
                            }
                        }
                    }
                }
            }

            if self.verbose && !block.assembly_block.is_empty() {
                let preview_len = 32.min(block.assembly_block.len());
                println!("  Preview (first {preview_len} bytes):");
                print!("    ");
                for (i, byte) in block.assembly_block[..preview_len].iter().enumerate() {
                    if i > 0 && i % 16 == 0 {
                        println!();
                        print!("    ");
                    }
                    print!("{byte:02x} ");
                }
                println!();
            }

            if idx < blocks.len() - 1 {
                println!("{:-<80}", "");
            }
        }

        Ok(())
    }
}
