//! Metrics tracking and dashboard commands.

use anyhow::{anyhow, Result};
use clap::{Args, Subcommand};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use crate::db::Database;

#[derive(Args)]
pub struct MetricsCommand {
    #[command(subcommand)]
    pub command: MetricsSubcommand,
}

#[derive(Subcommand)]
pub enum MetricsSubcommand {
    /// Record current validation state as a metrics snapshot
    Record(MetricsRecordCommand),
    /// Display metrics summary and history
    Show(MetricsShowCommand),
    /// Export metrics to JSON or CSV
    Export(MetricsExportCommand),
    /// Export metrics in Prometheus format for monitoring integration
    Prometheus(MetricsPrometheusCommand),
    /// Clear all metrics history
    Clear(MetricsClearCommand),
}

#[derive(Args)]
pub struct MetricsRecordCommand {
    #[arg(
        short,
        long,
        default_value = "snippex.db",
        help = "SQLite database path"
    )]
    pub database: PathBuf,

    #[arg(long, help = "Optional notes to attach to the snapshot")]
    pub notes: Option<String>,

    #[arg(short, long, help = "Suppress output")]
    pub quiet: bool,
}

#[derive(Args)]
pub struct MetricsShowCommand {
    #[arg(
        short,
        long,
        default_value = "snippex.db",
        help = "SQLite database path"
    )]
    pub database: PathBuf,

    #[arg(
        long,
        default_value = "10",
        help = "Number of recent snapshots to show"
    )]
    pub limit: usize,

    #[arg(long, help = "Show detailed information including per-snapshot data")]
    pub detailed: bool,

    #[arg(
        long,
        help = "Show trend analysis with improvement/regression detection"
    )]
    pub trends: bool,

    #[arg(
        long,
        default_value = "5.0",
        help = "Threshold (percentage points) for alerting on pass rate changes"
    )]
    pub alert_threshold: f64,
}

#[derive(Args)]
pub struct MetricsExportCommand {
    #[arg(
        short,
        long,
        default_value = "snippex.db",
        help = "SQLite database path"
    )]
    pub database: PathBuf,

    #[arg(
        short,
        long,
        help = "Output file path (extension determines format: .json or .csv)"
    )]
    pub output: PathBuf,

    #[arg(long, help = "Number of recent snapshots to export (default: all)")]
    pub limit: Option<usize>,
}

#[derive(Args)]
pub struct MetricsClearCommand {
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
pub struct MetricsPrometheusCommand {
    #[arg(
        short,
        long,
        default_value = "snippex.db",
        help = "SQLite database path"
    )]
    pub database: PathBuf,

    #[arg(short, long, help = "Output file path (default: stdout)")]
    pub output: Option<PathBuf>,

    #[arg(long, default_value = "snippex", help = "Metric name prefix")]
    pub prefix: String,

    #[arg(long, help = "Include help text for each metric")]
    pub with_help: bool,
}

impl MetricsCommand {
    pub fn execute(self) -> Result<()> {
        match self.command {
            MetricsSubcommand::Record(cmd) => cmd.execute(),
            MetricsSubcommand::Show(cmd) => cmd.execute(),
            MetricsSubcommand::Export(cmd) => cmd.execute(),
            MetricsSubcommand::Prometheus(cmd) => cmd.execute(),
            MetricsSubcommand::Clear(cmd) => cmd.execute(),
        }
    }
}

impl MetricsRecordCommand {
    pub fn execute(self) -> Result<()> {
        if !self.database.exists() {
            return Err(anyhow!(
                "Database not found at '{}'.\n\n\
                 Suggestions:\n\
                 • Extract blocks first: snippex extract <binary>\n\
                 • Specify a different database: snippex metrics record -d <path>",
                self.database.display()
            ));
        }

        let mut db = Database::new(&self.database)?;
        let snapshot_id = db.record_metrics_snapshot(self.notes.as_deref())?;

        if !self.quiet {
            let snapshot = db.get_latest_metrics_snapshot()?;
            if let Some(s) = snapshot {
                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                println!("Metrics Snapshot Recorded (ID: {})", snapshot_id);
                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                println!();
                println!("Timestamp:        {}", s.recorded_at);
                println!("Total Blocks:     {}", s.total_blocks);
                println!("Analyzed:         {}", s.analyzed_blocks);
                println!("Validated:        {}", s.validated_blocks);
                println!();
                println!("Pass Count:       {}", s.pass_count);
                println!("Fail Count:       {}", s.fail_count);
                println!("Skip Count:       {}", s.skip_count);
                println!("Pass Rate:        {:.1}%", s.pass_rate());
                if let Some(notes) = &s.notes {
                    println!();
                    println!("Notes:            {}", notes);
                }
                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            }
        }

        Ok(())
    }
}

impl MetricsShowCommand {
    pub fn execute(self) -> Result<()> {
        if !self.database.exists() {
            return Err(anyhow!(
                "Database not found at '{}'.\n\n\
                 Suggestions:\n\
                 • Extract blocks first: snippex extract <binary>\n\
                 • Specify a different database: snippex metrics show -d <path>",
                self.database.display()
            ));
        }

        let db = Database::new(&self.database)?;
        let snapshots = db.get_metrics_snapshots(self.limit)?;

        if snapshots.is_empty() {
            println!("No metrics snapshots recorded yet.");
            println!();
            println!("Record a snapshot with: snippex metrics record");
            return Ok(());
        }

        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Validation Metrics Dashboard");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!();

        // Show latest snapshot summary
        let latest = &snapshots[0];
        println!("Latest Snapshot: {}", latest.recorded_at);
        println!("  Total Blocks:     {}", latest.total_blocks);
        println!(
            "  Analyzed:         {} ({:.1}%)",
            latest.analyzed_blocks,
            if latest.total_blocks > 0 {
                (latest.analyzed_blocks as f64 / latest.total_blocks as f64) * 100.0
            } else {
                0.0
            }
        );
        println!(
            "  Validated:        {} ({:.1}%)",
            latest.validated_blocks,
            if latest.total_blocks > 0 {
                (latest.validated_blocks as f64 / latest.total_blocks as f64) * 100.0
            } else {
                0.0
            }
        );
        println!();
        println!(
            "  Pass: {} | Fail: {} | Skip: {}",
            latest.pass_count, latest.fail_count, latest.skip_count
        );
        println!("  Pass Rate: {:.1}%", latest.pass_rate());
        println!();

        // Show pass rate trend if we have multiple snapshots
        if snapshots.len() > 1 {
            println!("Pass Rate History (recent {} snapshots):", snapshots.len());
            println!();

            let max_bar_width = 40;
            for snapshot in snapshots.iter().rev() {
                let rate = snapshot.pass_rate();
                let bar_len = ((rate / 100.0) * max_bar_width as f64).round() as usize;
                let bar = "█".repeat(bar_len);
                let empty = "░".repeat(max_bar_width - bar_len);

                // Parse date to show shorter version
                let date_short = snapshot
                    .recorded_at
                    .split(' ')
                    .next()
                    .unwrap_or(&snapshot.recorded_at);
                println!("  {} |{}{}| {:5.1}%", date_short, bar, empty, rate);
            }
            println!();
        }

        // Show trend analysis if requested or by default when we have enough data
        if self.trends || snapshots.len() >= 2 {
            self.show_trend_analysis(&snapshots);
        }

        if self.detailed {
            println!(
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            );
            println!("Detailed Snapshot History");
            println!(
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            );
            println!();
            println!(
                "{:4} {:20} {:>7} {:>7} {:>7} {:>5} {:>5} {:>5} {:>7}",
                "ID", "Timestamp", "Total", "Analyz", "Valid", "Pass", "Fail", "Skip", "Rate"
            );
            println!("{}", "─".repeat(78));

            for s in &snapshots {
                println!(
                    "{:4} {:20} {:>7} {:>7} {:>7} {:>5} {:>5} {:>5} {:>6.1}%",
                    s.id,
                    &s.recorded_at[..20.min(s.recorded_at.len())],
                    s.total_blocks,
                    s.analyzed_blocks,
                    s.validated_blocks,
                    s.pass_count,
                    s.fail_count,
                    s.skip_count,
                    s.pass_rate()
                );
            }
            println!();
        }

        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

        Ok(())
    }

    fn show_trend_analysis(&self, snapshots: &[crate::db::MetricsSnapshot]) {
        if snapshots.len() < 2 {
            return;
        }

        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Trend Analysis");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!();

        let latest = &snapshots[0];
        let oldest = &snapshots[snapshots.len() - 1];

        // Calculate overall change
        let pass_rate_change = latest.pass_rate() - oldest.pass_rate();
        let total_blocks_change = latest.total_blocks as i64 - oldest.total_blocks as i64;

        // Determine trend direction
        let trend_icon = if pass_rate_change > self.alert_threshold {
            "📈 IMPROVING"
        } else if pass_rate_change < -self.alert_threshold {
            "📉 REGRESSING"
        } else {
            "➡️  STABLE"
        };

        println!("Overall Trend: {}", trend_icon);
        println!();
        println!(
            "  Pass Rate Change:   {:+.1} percentage points",
            pass_rate_change
        );
        println!(
            "    from {:.1}% to {:.1}%",
            oldest.pass_rate(),
            latest.pass_rate()
        );
        println!();
        println!("  Block Count Change: {:+}", total_blocks_change);
        println!(
            "    from {} to {}",
            oldest.total_blocks, latest.total_blocks
        );
        println!();

        // Calculate average improvement per snapshot
        if snapshots.len() > 2 {
            let avg_change: f64 = snapshots
                .windows(2)
                .map(|w| w[0].pass_rate() - w[1].pass_rate())
                .sum::<f64>()
                / (snapshots.len() - 1) as f64;
            println!("  Average Change:     {:+.2}% per snapshot", avg_change);
            println!();
        }

        // Detect significant regressions
        let mut regressions = Vec::new();
        for window in snapshots.windows(2) {
            let current = &window[0];
            let previous = &window[1];
            let change = current.pass_rate() - previous.pass_rate();
            if change < -self.alert_threshold {
                regressions.push((current.recorded_at.clone(), change));
            }
        }

        if !regressions.is_empty() {
            println!("⚠️  Significant Regressions Detected:");
            for (date, change) in regressions.iter().take(5) {
                println!(
                    "    {} ({:.1}% drop)",
                    date.split(' ').next().unwrap_or(date),
                    change.abs()
                );
            }
            if regressions.len() > 5 {
                println!("    ... and {} more", regressions.len() - 5);
            }
            println!();
        }

        // Detect significant improvements
        let mut improvements = Vec::new();
        for window in snapshots.windows(2) {
            let current = &window[0];
            let previous = &window[1];
            let change = current.pass_rate() - previous.pass_rate();
            if change > self.alert_threshold {
                improvements.push((current.recorded_at.clone(), change));
            }
        }

        if !improvements.is_empty() {
            println!("✅ Significant Improvements:");
            for (date, change) in improvements.iter().take(5) {
                println!(
                    "    {} (+{:.1}% gain)",
                    date.split(' ').next().unwrap_or(date),
                    change
                );
            }
            if improvements.len() > 5 {
                println!("    ... and {} more", improvements.len() - 5);
            }
            println!();
        }

        // Alert for recent regression
        if snapshots.len() >= 2 {
            let recent_change = latest.pass_rate() - snapshots[1].pass_rate();
            if recent_change < -self.alert_threshold {
                println!(
                    "🚨 ALERT: Pass rate dropped by {:.1}% in the most recent snapshot!",
                    recent_change.abs()
                );
                println!(
                    "   Previous: {:.1}% | Current: {:.1}%",
                    snapshots[1].pass_rate(),
                    latest.pass_rate()
                );
                println!();
            }
        }
    }
}

impl MetricsExportCommand {
    pub fn execute(self) -> Result<()> {
        if !self.database.exists() {
            return Err(anyhow!(
                "Database not found at '{}'.\n\n\
                 Suggestions:\n\
                 • Extract blocks first: snippex extract <binary>\n\
                 • Specify a different database: snippex metrics export -d <path>",
                self.database.display()
            ));
        }

        let db = Database::new(&self.database)?;
        let limit = self.limit.unwrap_or(1000);
        let snapshots = db.get_metrics_snapshots(limit)?;

        if snapshots.is_empty() {
            return Err(anyhow!(
                "No metrics snapshots to export.\n\n\
                 Record a snapshot first: snippex metrics record"
            ));
        }

        let extension = self
            .output
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase());

        match extension.as_deref() {
            Some("json") => self.export_json(&snapshots)?,
            Some("csv") => self.export_csv(&snapshots)?,
            _ => {
                return Err(anyhow!(
                    "Unknown output format. Use .json or .csv file extension.\n\n\
                     Examples:\n\
                     • snippex metrics export -o metrics.json\n\
                     • snippex metrics export -o metrics.csv"
                ));
            }
        }

        println!(
            "Exported {} snapshots to {}",
            snapshots.len(),
            self.output.display()
        );
        Ok(())
    }

    fn export_json(&self, snapshots: &[crate::db::MetricsSnapshot]) -> Result<()> {
        use serde::Serialize;

        #[derive(Serialize)]
        struct ExportSnapshot {
            id: i64,
            recorded_at: String,
            total_blocks: usize,
            analyzed_blocks: usize,
            validated_blocks: usize,
            pass_count: usize,
            fail_count: usize,
            skip_count: usize,
            pass_rate: f64,
            avg_duration_ns: Option<u64>,
            notes: Option<String>,
        }

        let export_data: Vec<ExportSnapshot> = snapshots
            .iter()
            .map(|s| ExportSnapshot {
                id: s.id,
                recorded_at: s.recorded_at.clone(),
                total_blocks: s.total_blocks,
                analyzed_blocks: s.analyzed_blocks,
                validated_blocks: s.validated_blocks,
                pass_count: s.pass_count,
                fail_count: s.fail_count,
                skip_count: s.skip_count,
                pass_rate: s.pass_rate(),
                avg_duration_ns: s.avg_duration_ns,
                notes: s.notes.clone(),
            })
            .collect();

        let json = serde_json::to_string_pretty(&export_data)?;
        let mut file = File::create(&self.output)?;
        file.write_all(json.as_bytes())?;
        Ok(())
    }

    fn export_csv(&self, snapshots: &[crate::db::MetricsSnapshot]) -> Result<()> {
        let mut file = File::create(&self.output)?;

        // Write header
        writeln!(file, "id,recorded_at,total_blocks,analyzed_blocks,validated_blocks,pass_count,fail_count,skip_count,pass_rate,avg_duration_ns,notes")?;

        // Write data rows
        for s in snapshots {
            writeln!(
                file,
                "{},{},{},{},{},{},{},{},{:.2},{},\"{}\"",
                s.id,
                s.recorded_at,
                s.total_blocks,
                s.analyzed_blocks,
                s.validated_blocks,
                s.pass_count,
                s.fail_count,
                s.skip_count,
                s.pass_rate(),
                s.avg_duration_ns.map(|d| d.to_string()).unwrap_or_default(),
                s.notes.as_deref().unwrap_or("").replace('"', "\"\"")
            )?;
        }

        Ok(())
    }
}

impl MetricsClearCommand {
    pub fn execute(self) -> Result<()> {
        if !self.database.exists() {
            return Err(anyhow!(
                "Database not found at '{}'.\n\n\
                 Suggestions:\n\
                 • Specify a different database: snippex metrics clear -d <path>",
                self.database.display()
            ));
        }

        let mut db = Database::new(&self.database)?;
        let snapshots = db.get_metrics_snapshots(1)?;

        if snapshots.is_empty() {
            println!("No metrics snapshots to clear.");
            return Ok(());
        }

        let count = db.get_metrics_snapshots(10000)?.len();

        if !self.force {
            println!("This will delete {} metrics snapshot(s).", count);
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

        let cleared = db.clear_metrics_snapshots()?;
        println!("Cleared {} metrics snapshot(s).", cleared);

        Ok(())
    }
}

impl MetricsPrometheusCommand {
    pub fn execute(self) -> Result<()> {
        if !self.database.exists() {
            return Err(anyhow!(
                "Database not found at '{}'.\n\n\
                 Suggestions:\n\
                 • Extract blocks first: snippex extract <binary>\n\
                 • Specify a different database: snippex metrics prometheus -d <path>",
                self.database.display()
            ));
        }

        let db = Database::new(&self.database)?;
        let latest = db.get_latest_metrics_snapshot()?;

        let output = self.generate_prometheus_output(latest.as_ref());

        if let Some(output_path) = &self.output {
            let mut file = File::create(output_path)?;
            file.write_all(output.as_bytes())?;
            eprintln!("Prometheus metrics written to {}", output_path.display());
        } else {
            print!("{}", output);
        }

        Ok(())
    }

    fn generate_prometheus_output(&self, snapshot: Option<&crate::db::MetricsSnapshot>) -> String {
        let mut output = String::new();
        let prefix = &self.prefix;

        // Add help text if requested
        if self.with_help {
            output.push_str(&format!(
                "# HELP {}_total_blocks Total number of extracted assembly blocks\n",
                prefix
            ));
            output.push_str(&format!("# TYPE {}_total_blocks gauge\n", prefix));
        }
        if let Some(s) = snapshot {
            output.push_str(&format!("{}_total_blocks {}\n", prefix, s.total_blocks));
        } else {
            output.push_str(&format!("{}_total_blocks 0\n", prefix));
        }

        if self.with_help {
            output.push_str(&format!(
                "# HELP {}_analyzed_blocks Number of blocks that have been analyzed\n",
                prefix
            ));
            output.push_str(&format!("# TYPE {}_analyzed_blocks gauge\n", prefix));
        }
        if let Some(s) = snapshot {
            output.push_str(&format!(
                "{}_analyzed_blocks {}\n",
                prefix, s.analyzed_blocks
            ));
        } else {
            output.push_str(&format!("{}_analyzed_blocks 0\n", prefix));
        }

        if self.with_help {
            output.push_str(&format!(
                "# HELP {}_validated_blocks Number of blocks that have been validated\n",
                prefix
            ));
            output.push_str(&format!("# TYPE {}_validated_blocks gauge\n", prefix));
        }
        if let Some(s) = snapshot {
            output.push_str(&format!(
                "{}_validated_blocks {}\n",
                prefix, s.validated_blocks
            ));
        } else {
            output.push_str(&format!("{}_validated_blocks 0\n", prefix));
        }

        if self.with_help {
            output.push_str(&format!(
                "# HELP {}_validation_pass_total Total number of passed validations\n",
                prefix
            ));
            output.push_str(&format!(
                "# TYPE {}_validation_pass_total counter\n",
                prefix
            ));
        }
        if let Some(s) = snapshot {
            output.push_str(&format!(
                "{}_validation_pass_total {}\n",
                prefix, s.pass_count
            ));
        } else {
            output.push_str(&format!("{}_validation_pass_total 0\n", prefix));
        }

        if self.with_help {
            output.push_str(&format!(
                "# HELP {}_validation_fail_total Total number of failed validations\n",
                prefix
            ));
            output.push_str(&format!(
                "# TYPE {}_validation_fail_total counter\n",
                prefix
            ));
        }
        if let Some(s) = snapshot {
            output.push_str(&format!(
                "{}_validation_fail_total {}\n",
                prefix, s.fail_count
            ));
        } else {
            output.push_str(&format!("{}_validation_fail_total 0\n", prefix));
        }

        if self.with_help {
            output.push_str(&format!(
                "# HELP {}_validation_skip_total Total number of skipped validations\n",
                prefix
            ));
            output.push_str(&format!(
                "# TYPE {}_validation_skip_total counter\n",
                prefix
            ));
        }
        if let Some(s) = snapshot {
            output.push_str(&format!(
                "{}_validation_skip_total {}\n",
                prefix, s.skip_count
            ));
        } else {
            output.push_str(&format!("{}_validation_skip_total 0\n", prefix));
        }

        if self.with_help {
            output.push_str(&format!(
                "# HELP {}_validation_pass_rate Percentage of validations that passed\n",
                prefix
            ));
            output.push_str(&format!("# TYPE {}_validation_pass_rate gauge\n", prefix));
        }
        if let Some(s) = snapshot {
            output.push_str(&format!(
                "{}_validation_pass_rate {:.2}\n",
                prefix,
                s.pass_rate()
            ));
        } else {
            output.push_str(&format!("{}_validation_pass_rate 0\n", prefix));
        }

        if self.with_help {
            output.push_str(&format!("# HELP {}_avg_validation_duration_seconds Average validation duration in seconds\n", prefix));
            output.push_str(&format!(
                "# TYPE {}_avg_validation_duration_seconds gauge\n",
                prefix
            ));
        }
        if let Some(s) = snapshot {
            if let Some(duration_ns) = s.avg_duration_ns {
                let duration_secs = duration_ns as f64 / 1_000_000_000.0;
                output.push_str(&format!(
                    "{}_avg_validation_duration_seconds {:.6}\n",
                    prefix, duration_secs
                ));
            } else {
                output.push_str(&format!("{}_avg_validation_duration_seconds 0\n", prefix));
            }
        } else {
            output.push_str(&format!("{}_avg_validation_duration_seconds 0\n", prefix));
        }

        if self.with_help {
            output.push_str(&format!(
                "# HELP {}_last_snapshot_timestamp Unix timestamp of the last metrics snapshot\n",
                prefix
            ));
            output.push_str(&format!(
                "# TYPE {}_last_snapshot_timestamp gauge\n",
                prefix
            ));
        }
        if let Some(s) = snapshot {
            // Parse timestamp and convert to Unix time
            if let Ok(dt) =
                chrono::NaiveDateTime::parse_from_str(&s.recorded_at, "%Y-%m-%d %H:%M:%S")
            {
                output.push_str(&format!(
                    "{}_last_snapshot_timestamp {}\n",
                    prefix,
                    dt.and_utc().timestamp()
                ));
            } else {
                output.push_str(&format!("{}_last_snapshot_timestamp 0\n", prefix));
            }
        } else {
            output.push_str(&format!("{}_last_snapshot_timestamp 0\n", prefix));
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn create_test_db() -> (Database, NamedTempFile) {
        let temp_file = NamedTempFile::new().unwrap();
        let mut db = Database::new(temp_file.path()).unwrap();
        db.init().unwrap();
        (db, temp_file)
    }

    #[test]
    fn test_record_and_show_metrics() {
        let (mut db, _temp) = create_test_db();

        // Record a snapshot
        let id = db.record_metrics_snapshot(Some("Test snapshot")).unwrap();
        assert!(id > 0);

        // Get the snapshot
        let latest = db.get_latest_metrics_snapshot().unwrap();
        assert!(latest.is_some());
        let snapshot = latest.unwrap();
        assert_eq!(snapshot.notes, Some("Test snapshot".to_string()));
    }

    #[test]
    fn test_multiple_snapshots() {
        let (mut db, _temp) = create_test_db();

        // Record multiple snapshots
        db.record_metrics_snapshot(Some("First")).unwrap();
        db.record_metrics_snapshot(Some("Second")).unwrap();
        db.record_metrics_snapshot(Some("Third")).unwrap();

        let snapshots = db.get_metrics_snapshots(10).unwrap();
        assert_eq!(snapshots.len(), 3);

        // Most recent should be first
        assert_eq!(snapshots[0].notes, Some("Third".to_string()));
    }

    #[test]
    fn test_clear_metrics() {
        let (mut db, _temp) = create_test_db();

        db.record_metrics_snapshot(None).unwrap();
        db.record_metrics_snapshot(None).unwrap();

        let cleared = db.clear_metrics_snapshots().unwrap();
        assert_eq!(cleared, 2);

        let snapshots = db.get_metrics_snapshots(10).unwrap();
        assert!(snapshots.is_empty());
    }
}
