//! Statistics command for viewing batch validation metrics.

use anyhow::Result;
use clap::{Args, Subcommand, ValueEnum};
use std::path::PathBuf;

use crate::db::{
    BatchRunInfo, BatchSummaryStats, DailyStats, Database, FailingBlockInfo, FailureModeInfo,
    FlakyBlockInfo,
};

#[derive(Args)]
#[command(about = "View and analyze batch validation statistics")]
pub struct StatsCommand {
    /// SQLite database path
    #[arg(short, long, default_value = "snippex.db")]
    database: PathBuf,

    #[command(subcommand)]
    subcommand: StatsSubcommand,
}

#[derive(Subcommand)]
enum StatsSubcommand {
    /// Show overall summary statistics
    Summary,

    /// Show pass rate trends over time
    Trends {
        /// Number of days to include
        #[arg(short, long, default_value = "7")]
        days: usize,

        /// Output format
        #[arg(short, long, value_enum, default_value = "table")]
        format: OutputFormat,
    },

    /// List recent batch runs
    Runs {
        /// Number of runs to show
        #[arg(short, long, default_value = "10")]
        limit: usize,
    },

    /// List consistently failing blocks
    Failing {
        /// Minimum number of failures to include
        #[arg(short, long, default_value = "2")]
        min_failures: usize,
    },

    /// List intermittently failing (flaky) blocks
    Flaky {
        /// Minimum number of runs to consider
        #[arg(short, long, default_value = "3")]
        min_runs: usize,
    },

    /// Show failure mode distribution
    Modes,

    /// Clear all statistics
    Clear {
        /// Skip confirmation prompt
        #[arg(short, long)]
        yes: bool,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Table,
    Chart,
    Json,
}

impl StatsCommand {
    pub fn execute(&self) -> Result<()> {
        let mut db = Database::new(&self.database)?;
        db.init()?;

        match &self.subcommand {
            StatsSubcommand::Summary => self.show_summary(&db),
            StatsSubcommand::Trends { days, format } => self.show_trends(&db, *days, *format),
            StatsSubcommand::Runs { limit } => self.show_runs(&db, *limit),
            StatsSubcommand::Failing { min_failures } => self.show_failing(&db, *min_failures),
            StatsSubcommand::Flaky { min_runs } => self.show_flaky(&db, *min_runs),
            StatsSubcommand::Modes => self.show_modes(&db),
            StatsSubcommand::Clear { yes } => self.clear_stats(*yes),
        }
    }

    fn show_summary(&self, db: &Database) -> Result<()> {
        let stats = db.get_batch_summary_stats()?;

        println!("╔══════════════════════════════════════════════════════════════╗");
        println!("║             Snippex Validation Statistics Summary            ║");
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║                                                              ║");

        if stats.total_runs == 0 {
            println!("║  No batch runs recorded yet.                                 ║");
            println!("║  Run `snippex validate-batch` to generate statistics.       ║");
            println!("║                                                              ║");
        } else {
            self.print_summary_stats(&stats);
        }

        println!("╚══════════════════════════════════════════════════════════════╝");

        Ok(())
    }

    fn print_summary_stats(&self, stats: &BatchSummaryStats) {
        println!(
            "║  Total Batch Runs:     {:>6}                                ║",
            stats.total_runs
        );
        println!(
            "║  Total Blocks Tested:  {:>6}                                ║",
            stats.total_blocks
        );
        println!("║                                                              ║");
        println!(
            "║  Passed:               {:>6}  ({:>5.1}%)                       ║",
            stats.total_pass, stats.pass_rate
        );
        println!(
            "║  Failed:               {:>6}  ({:>5.1}%)                       ║",
            stats.total_fail,
            if stats.total_blocks > 0 {
                (stats.total_fail as f64 / stats.total_blocks as f64) * 100.0
            } else {
                0.0
            }
        );
        println!(
            "║  Skipped:              {:>6}  ({:>5.1}%)                       ║",
            stats.total_skip,
            if stats.total_blocks > 0 {
                (stats.total_skip as f64 / stats.total_blocks as f64) * 100.0
            } else {
                0.0
            }
        );
        println!("║                                                              ║");
        println!(
            "║  Avg Duration:         {:>6.0} ms                             ║",
            stats.avg_duration_ms
        );
        println!("║                                                              ║");

        // ASCII progress bar for pass rate
        let bar_width = 40;
        let filled = (stats.pass_rate / 100.0 * bar_width as f64) as usize;
        let bar: String = "█".repeat(filled) + &"░".repeat(bar_width - filled);
        println!("║  Pass Rate: [{}] ║", bar);
        println!("║                                                              ║");
    }

    fn show_trends(&self, db: &Database, days: usize, format: OutputFormat) -> Result<()> {
        let trends = db.get_pass_rate_trends(days)?;

        if trends.is_empty() {
            println!("No data available for the last {} days.", days);
            return Ok(());
        }

        match format {
            OutputFormat::Table => self.print_trends_table(&trends),
            OutputFormat::Chart => self.print_trends_chart(&trends),
            OutputFormat::Json => self.print_trends_json(&trends)?,
        }

        Ok(())
    }

    fn print_trends_table(&self, trends: &[DailyStats]) {
        println!("\nPass Rate Trends (Last {} Days)", trends.len());
        println!("═══════════════════════════════════════════════════════════════");
        println!(
            "{:<12} {:>8} {:>8} {:>8} {:>10}",
            "Date", "Blocks", "Pass", "Fail", "Pass Rate"
        );
        println!("───────────────────────────────────────────────────────────────");

        for day in trends {
            println!(
                "{:<12} {:>8} {:>8} {:>8} {:>9.1}%",
                day.date, day.total_blocks, day.pass_count, day.fail_count, day.pass_rate
            );
        }
        println!("═══════════════════════════════════════════════════════════════");
    }

    fn print_trends_chart(&self, trends: &[DailyStats]) {
        println!("\nPass Rate Over Time");
        println!("═══════════════════════════════════════════════════════════════");
        println!();

        let max_bar_width = 40;

        for day in trends {
            let bar_width = (day.pass_rate / 100.0 * max_bar_width as f64) as usize;
            let bar = "█".repeat(bar_width);

            // Color the bar based on pass rate
            let color_start = if day.pass_rate >= 90.0 {
                "\x1b[32m" // Green
            } else if day.pass_rate >= 70.0 {
                "\x1b[33m" // Yellow
            } else {
                "\x1b[31m" // Red
            };
            let color_end = "\x1b[0m";

            println!(
                "  {} {}{:<40}{} {:>5.1}%",
                &day.date[5..], // Show only MM-DD
                color_start,
                bar,
                color_end,
                day.pass_rate
            );
        }
        println!();
    }

    fn print_trends_json(&self, trends: &[DailyStats]) -> Result<()> {
        let json = serde_json::to_string_pretty(
            &trends
                .iter()
                .map(|d| {
                    serde_json::json!({
                        "date": d.date,
                        "total_blocks": d.total_blocks,
                        "pass_count": d.pass_count,
                        "fail_count": d.fail_count,
                        "pass_rate": d.pass_rate
                    })
                })
                .collect::<Vec<_>>(),
        )?;
        println!("{}", json);
        Ok(())
    }

    fn show_runs(&self, db: &Database, limit: usize) -> Result<()> {
        let runs = db.get_recent_batch_runs(limit)?;

        if runs.is_empty() {
            println!("No batch runs found.");
            return Ok(());
        }

        println!("\nRecent Batch Runs");
        println!("══════════════════════════════════════════════════════════════════════════════");
        println!(
            "{:<4} {:<20} {:>6} {:>6} {:>6} {:>6} {:>10} {:<12}",
            "ID", "Started", "Blocks", "Pass", "Fail", "Skip", "Duration", "Emulator"
        );
        println!("──────────────────────────────────────────────────────────────────────────────");

        for run in runs {
            self.print_run_row(&run);
        }

        println!("══════════════════════════════════════════════════════════════════════════════");

        Ok(())
    }

    fn print_run_row(&self, run: &BatchRunInfo) {
        let duration_str = run
            .duration_ms
            .map(|d| format!("{:.1}s", d as f64 / 1000.0))
            .unwrap_or_else(|| "running".to_string());

        let emulator = run.emulator.as_deref().unwrap_or("-");

        // Truncate started_at to fit
        let started = if run.started_at.len() > 19 {
            &run.started_at[..19]
        } else {
            &run.started_at
        };

        // Status indicator
        let status = if run.completed_at.is_some() {
            if run.fail_count == 0 {
                "✓"
            } else {
                "✗"
            }
        } else {
            "⏳"
        };

        println!(
            "{:<4} {:<20} {:>6} {:>6} {:>6} {:>6} {:>10} {:<12} {}",
            run.id,
            started,
            run.block_count,
            run.pass_count,
            run.fail_count,
            run.skip_count,
            duration_str,
            emulator,
            status
        );
    }

    fn show_failing(&self, db: &Database, min_failures: usize) -> Result<()> {
        let blocks = db.get_consistently_failing_blocks(min_failures)?;

        if blocks.is_empty() {
            println!("No blocks with {} or more failures found.", min_failures);
            return Ok(());
        }

        println!(
            "\nConsistently Failing Blocks (min {} failures)",
            min_failures
        );
        println!("══════════════════════════════════════════════════════════════════════════════");
        println!(
            "{:<6} {:>8} {:>18} {:>18} {:<30}",
            "ID", "Failures", "Start Addr", "End Addr", "Binary"
        );
        println!("──────────────────────────────────────────────────────────────────────────────");

        for block in blocks {
            self.print_failing_block(&block);
        }

        println!("══════════════════════════════════════════════════════════════════════════════");

        Ok(())
    }

    fn print_failing_block(&self, block: &FailingBlockInfo) {
        let binary = if block.binary_path.len() > 30 {
            format!("...{}", &block.binary_path[block.binary_path.len() - 27..])
        } else {
            block.binary_path.clone()
        };

        println!(
            "{:<6} {:>8} 0x{:016x} 0x{:016x} {:<30}",
            block.extraction_id,
            block.failure_count,
            block.start_address,
            block.end_address,
            binary
        );
    }

    fn show_flaky(&self, db: &Database, min_runs: usize) -> Result<()> {
        let blocks = db.get_flaky_blocks(min_runs)?;

        if blocks.is_empty() {
            println!("No flaky blocks found (min {} runs required).", min_runs);
            return Ok(());
        }

        println!("\nFlaky Blocks (pass sometimes, fail sometimes)");
        println!("══════════════════════════════════════════════════════════════════════════════════════");
        println!(
            "{:<6} {:>6} {:>6} {:>6} {:>10} {:>18} {:>18}",
            "ID", "Pass", "Fail", "Runs", "Flakiness", "Start Addr", "End Addr"
        );
        println!("──────────────────────────────────────────────────────────────────────────────────────");

        for block in blocks {
            self.print_flaky_block(&block);
        }

        println!("══════════════════════════════════════════════════════════════════════════════════════");

        Ok(())
    }

    fn print_flaky_block(&self, block: &FlakyBlockInfo) {
        println!(
            "{:<6} {:>6} {:>6} {:>6} {:>9.1}% 0x{:016x} 0x{:016x}",
            block.extraction_id,
            block.pass_count,
            block.fail_count,
            block.total_runs,
            block.flakiness_percent,
            block.start_address,
            block.end_address
        );
    }

    fn show_modes(&self, db: &Database) -> Result<()> {
        let modes = db.get_failure_modes()?;

        if modes.is_empty() {
            println!("No failures recorded.");
            return Ok(());
        }

        let total: usize = modes.iter().map(|m| m.count).sum();

        println!("\nFailure Mode Distribution");
        println!("══════════════════════════════════════════════════════════════════");

        let max_bar_width = 40;
        let max_count = modes.iter().map(|m| m.count).max().unwrap_or(1);

        for mode in &modes {
            self.print_mode_row(mode, total, max_count, max_bar_width);
        }

        println!("══════════════════════════════════════════════════════════════════");
        println!("Total failures: {}", total);

        Ok(())
    }

    fn print_mode_row(
        &self,
        mode: &FailureModeInfo,
        total: usize,
        max_count: usize,
        max_bar_width: usize,
    ) {
        let percentage = (mode.count as f64 / total as f64) * 100.0;
        let bar_width = (mode.count as f64 / max_count as f64 * max_bar_width as f64) as usize;
        let bar = "█".repeat(bar_width);

        println!(
            "  {:<20} {:>6} ({:>5.1}%) {}",
            mode.mode, mode.count, percentage, bar
        );
    }

    fn clear_stats(&self, skip_confirm: bool) -> Result<()> {
        if !skip_confirm {
            println!("This will delete all batch run statistics from the database.");
            println!("This action cannot be undone.");
            print!("Are you sure? [y/N] ");

            use std::io::{self, Write};
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;

            if !input.trim().eq_ignore_ascii_case("y") {
                println!("Aborted.");
                return Ok(());
            }
        }

        let mut db = Database::new(&self.database)?;
        let count = db.clear_batch_stats()?;

        println!("Cleared {} batch run(s).", count);

        Ok(())
    }
}
