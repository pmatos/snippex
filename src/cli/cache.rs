//! Cache management commands.

use anyhow::{anyhow, Result};
use clap::{Args, Subcommand};
use std::path::PathBuf;

use crate::db::Database;

#[derive(Args)]
pub struct CacheCommand {
    #[command(subcommand)]
    pub command: CacheSubcommand,
}

#[derive(Subcommand)]
pub enum CacheSubcommand {
    /// Show cache statistics
    Stats(CacheStatsCommand),
    /// Clear all cached validation results
    Clear(CacheClearCommand),
    /// Clear expired cache entries
    Expire(CacheExpireCommand),
    /// Prune cache to maximum size using LRU eviction
    Prune(CachePruneCommand),
}

#[derive(Args)]
pub struct CacheStatsCommand {
    #[arg(
        short,
        long,
        default_value = "snippex.db",
        help = "SQLite database path"
    )]
    pub database: PathBuf,

    #[arg(long, help = "Show detailed statistics including age distribution")]
    pub detailed: bool,
}

#[derive(Args)]
pub struct CacheClearCommand {
    #[arg(
        short,
        long,
        default_value = "snippex.db",
        help = "SQLite database path"
    )]
    pub database: PathBuf,

    #[arg(short, long, help = "Skip confirmation prompt")]
    pub force: bool,
}

#[derive(Args)]
pub struct CacheExpireCommand {
    #[arg(
        short,
        long,
        default_value = "snippex.db",
        help = "SQLite database path"
    )]
    pub database: PathBuf,

    #[arg(
        long,
        default_value = "7",
        help = "TTL in days (clear entries older than this)"
    )]
    pub ttl: u32,
}

#[derive(Args)]
pub struct CachePruneCommand {
    #[arg(
        short,
        long,
        default_value = "snippex.db",
        help = "SQLite database path"
    )]
    pub database: PathBuf,

    #[arg(
        long,
        default_value = "10000",
        help = "Maximum number of cache entries to keep"
    )]
    pub max_entries: usize,
}

impl CacheCommand {
    pub fn execute(self) -> Result<()> {
        match self.command {
            CacheSubcommand::Stats(cmd) => cmd.execute(),
            CacheSubcommand::Clear(cmd) => cmd.execute(),
            CacheSubcommand::Expire(cmd) => cmd.execute(),
            CacheSubcommand::Prune(cmd) => cmd.execute(),
        }
    }
}

impl CacheStatsCommand {
    pub fn execute(self) -> Result<()> {
        if !self.database.exists() {
            return Err(anyhow!("No database found at {:?}", self.database));
        }

        let db = Database::new(&self.database)?;
        let stats = if self.detailed {
            db.get_validation_cache_stats_detailed()?
        } else {
            db.get_validation_cache_stats()?
        };

        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Validation Cache Statistics");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!();
        println!("Total entries:  {}", stats.total_entries);
        println!("  Native:       {}", stats.native_entries);
        println!("  FEX-Emu:      {}", stats.fex_entries);
        println!();

        if let Some(oldest) = &stats.oldest_entry {
            println!("Oldest entry:   {}", oldest);
        }
        if let Some(newest) = &stats.newest_entry {
            println!("Newest entry:   {}", newest);
        }

        if let Some(size) = stats.estimated_size_bytes {
            println!();
            println!("Estimated size: {}", format_bytes(size));
        }

        if let Some(age_dist) = &stats.age_distribution {
            println!();
            println!("Age Distribution:");
            println!("  < 1 day:      {} entries", age_dist.under_1_day);
            println!("  1-7 days:     {} entries", age_dist.from_1_to_7_days);
            println!("  7-30 days:    {} entries", age_dist.from_7_to_30_days);
            println!("  > 30 days:    {} entries", age_dist.over_30_days);

            if stats.total_entries > 0 {
                println!();
                println!("Age Distribution Chart:");
                let max_bar = 40;
                let total = stats.total_entries as f64;

                let bars = [
                    ("< 1d ", age_dist.under_1_day),
                    ("1-7d ", age_dist.from_1_to_7_days),
                    ("7-30d", age_dist.from_7_to_30_days),
                    ("> 30d", age_dist.over_30_days),
                ];

                for (label, count) in bars {
                    let pct = count as f64 / total;
                    let bar_len = (pct * max_bar as f64).round() as usize;
                    let bar = "█".repeat(bar_len);
                    println!("  {} |{:<40}| {:>5.1}%", label, bar, pct * 100.0);
                }
            }
        }

        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

        Ok(())
    }
}

impl CacheClearCommand {
    pub fn execute(self) -> Result<()> {
        if !self.database.exists() {
            return Err(anyhow!("No database found at {:?}", self.database));
        }

        let mut db = Database::new(&self.database)?;

        if !self.force {
            let stats = db.get_validation_cache_stats()?;
            if stats.total_entries == 0 {
                println!("Cache is already empty.");
                return Ok(());
            }

            println!(
                "This will delete {} cached validation results.",
                stats.total_entries
            );
            print!("Are you sure? [y/N] ");

            use std::io::{self, Write};
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;

            if !input.trim().eq_ignore_ascii_case("y") {
                println!("Cancelled.");
                return Ok(());
            }
        }

        let cleared = db.clear_validation_cache()?;
        println!("Cleared {} cached validation results.", cleared);

        Ok(())
    }
}

impl CacheExpireCommand {
    pub fn execute(self) -> Result<()> {
        if !self.database.exists() {
            return Err(anyhow!("No database found at {:?}", self.database));
        }

        let mut db = Database::new(&self.database)?;
        let cleared = db.clear_expired_validation_cache(self.ttl)?;

        if cleared > 0 {
            println!(
                "Cleared {} expired cache entries (older than {} days).",
                cleared, self.ttl
            );
        } else {
            println!("No expired cache entries found.");
        }

        Ok(())
    }
}

impl CachePruneCommand {
    pub fn execute(self) -> Result<()> {
        if !self.database.exists() {
            return Err(anyhow!("No database found at {:?}", self.database));
        }

        let mut db = Database::new(&self.database)?;
        let stats = db.get_validation_cache_stats()?;

        if stats.total_entries <= self.max_entries {
            println!(
                "Cache has {} entries, which is within the limit of {}. No pruning needed.",
                stats.total_entries, self.max_entries
            );
            return Ok(());
        }

        let evicted = db.evict_lru_cache(self.max_entries)?;

        if evicted > 0 {
            println!(
                "Pruned {} least recently used cache entries (keeping {} entries).",
                evicted, self.max_entries
            );
        } else {
            println!("No cache entries needed to be pruned.");
        }

        Ok(())
    }
}

fn format_bytes(bytes: usize) -> String {
    const KB: usize = 1024;
    const MB: usize = KB * 1024;
    const GB: usize = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} bytes", bytes)
    }
}
