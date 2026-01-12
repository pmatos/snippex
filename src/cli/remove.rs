use anyhow::{anyhow, Result};
use clap::Args;
use std::path::PathBuf;

use crate::db::Database;

#[derive(Args)]
pub struct RemoveCommand {
    #[arg(
        short,
        long,
        default_value = "snippex.db",
        help = "SQLite database path"
    )]
    database: PathBuf,

    #[arg(short, long, help = "Remove all blocks from database")]
    all: bool,

    #[arg(
        value_name = "BLOCK_NUMBER",
        help = "Block number to remove (as shown by list command)"
    )]
    block_number: Option<usize>,
}

impl RemoveCommand {
    pub fn execute(self) -> Result<()> {
        if !self.all && self.block_number.is_none() {
            return Err(anyhow!(
                "Must specify either --all or a block number to remove"
            ));
        }

        if self.all && self.block_number.is_some() {
            return Err(anyhow!("Cannot specify both --all and a block number"));
        }

        // Check if database exists
        if !self.database.exists() {
            if self.all {
                println!("✓ No database found, nothing to remove");
            } else {
                return Err(anyhow!("No database found"));
            }
            return Ok(());
        }

        let mut db = Database::new(&self.database)?;

        if self.all {
            println!("Removing all blocks from database...");
            let count = match db.remove_all_extractions() {
                Ok(count) => count,
                Err(e) => {
                    // Database exists but tables don't - treat as empty
                    if e.to_string().contains("no such table") {
                        println!("✓ No blocks found, nothing to remove");
                        return Ok(());
                    } else {
                        return Err(e);
                    }
                }
            };
            println!("✓ Removed {count} blocks from database");
        } else if let Some(block_num) = self.block_number {
            // Get list of extractions to find the one to delete
            let extractions = match db.list_extractions() {
                Ok(extractions) => extractions,
                Err(_) => {
                    return Err(anyhow!("No blocks found in database"));
                }
            };

            if block_num == 0 || block_num > extractions.len() {
                return Err(anyhow!(
                    "Invalid block number. Valid range: 1-{}",
                    extractions.len()
                ));
            }

            // Block numbers are 1-indexed in the UI, but 0-indexed in the vector
            let extraction = &extractions[block_num - 1];

            println!("Removing block #{block_num} from database...");
            println!("  Binary: {}", extraction.binary_path);
            println!(
                "  Address range: 0x{:08x} - 0x{:08x}",
                extraction.start_address, extraction.end_address
            );

            db.remove_extraction(
                extraction.start_address,
                extraction.end_address,
                &extraction.binary_hash,
            )?;
            println!("✓ Block removed successfully");
        }

        Ok(())
    }
}
