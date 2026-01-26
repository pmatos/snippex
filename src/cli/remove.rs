use anyhow::{anyhow, Result};
use clap::Args;
use std::path::PathBuf;

use crate::cli::block_range::BlockRange;
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

    #[arg(
        value_name = "BLOCKS",
        help = "Blocks to remove: 5, 1-10, 5-, 3,7,12, or all"
    )]
    blocks: Option<BlockRange>,
}

impl RemoveCommand {
    pub fn execute(self) -> Result<()> {
        let blocks = match self.blocks {
            Some(b) => b,
            None => {
                return Err(anyhow!(
                    "Must specify blocks to remove.\n\n\
                     Examples:\n  \
                     snippex remove 5        - remove block 5\n  \
                     snippex remove 1-10     - remove blocks 1 through 10\n  \
                     snippex remove 3,7,12   - remove specific blocks\n  \
                     snippex remove all      - remove all blocks"
                ));
            }
        };

        // Check if database exists
        if !self.database.exists() {
            if matches!(blocks, BlockRange::All) {
                println!("✓ No database found, nothing to remove");
                return Ok(());
            } else {
                return Err(anyhow!("No database found"));
            }
        }

        let mut db = Database::new(&self.database)?;

        // Handle "all" specially for efficiency
        if matches!(blocks, BlockRange::All) {
            println!("Removing all blocks from database...");
            let count = match db.remove_all_extractions() {
                Ok(count) => count,
                Err(e) => {
                    if e.to_string().contains("no such table") {
                        println!("✓ No blocks found, nothing to remove");
                        return Ok(());
                    } else {
                        return Err(e);
                    }
                }
            };
            println!("✓ Removed {count} block(s) from database");
            return Ok(());
        }

        // Get list of extractions
        let extractions = match db.list_extractions() {
            Ok(extractions) => extractions,
            Err(_) => {
                return Err(anyhow!("No blocks found in database"));
            }
        };

        if extractions.is_empty() {
            return Err(anyhow!("No blocks found in database"));
        }

        // Resolve block range to specific numbers
        let block_nums = blocks.resolve(extractions.len())?;

        if block_nums.len() == 1 {
            let block_num = block_nums[0];
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
        } else {
            println!("Removing {} blocks from database...", block_nums.len());

            // Remove in reverse order to avoid index shifting issues
            let mut sorted_nums = block_nums.clone();
            sorted_nums.sort();
            sorted_nums.reverse();

            let mut removed = 0;
            for block_num in sorted_nums {
                let extraction = &extractions[block_num - 1];
                db.remove_extraction(
                    extraction.start_address,
                    extraction.end_address,
                    &extraction.binary_hash,
                )?;
                removed += 1;
            }

            println!("✓ Removed {removed} block(s) successfully");
        }

        Ok(())
    }
}
