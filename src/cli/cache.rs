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

impl CacheCommand {
    pub fn execute(self) -> Result<()> {
        match self.command {
            CacheSubcommand::Stats(cmd) => cmd.execute(),
            CacheSubcommand::Clear(cmd) => cmd.execute(),
            CacheSubcommand::Expire(cmd) => cmd.execute(),
        }
    }
}

impl CacheStatsCommand {
    pub fn execute(self) -> Result<()> {
        if !self.database.exists() {
            return Err(anyhow!("No database found at {:?}", self.database));
        }

        let db = Database::new(&self.database)?;
        let stats = db.get_validation_cache_stats()?;

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
