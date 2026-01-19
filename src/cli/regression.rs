use anyhow::Result;
use clap::{Args, Subcommand};
use std::path::PathBuf;

use crate::db::{BatchRunInfo, Database};

#[derive(Args)]
pub struct RegressionCommand {
    #[command(subcommand)]
    pub subcommand: RegressionSubcommand,
}

#[derive(Subcommand)]
pub enum RegressionSubcommand {
    /// Record current validation results as baseline
    Record(RegressionRecordCommand),
    /// Run regression test against baseline
    Test(RegressionTestCommand),
    /// Update baseline with current results
    Update(RegressionUpdateCommand),
    /// Show regression history
    History(RegressionHistoryCommand),
    /// Export baseline to JSON
    Export(RegressionExportCommand),
    /// Import baseline from JSON
    Import(RegressionImportCommand),
}

#[derive(Args)]
pub struct RegressionRecordCommand {
    #[arg(short, long, default_value = "snippex.db")]
    pub database: PathBuf,

    /// Emulator type for the baseline (e.g., "fex", "native")
    #[arg(long)]
    pub emulator: Option<String>,

    /// Baseline version identifier
    #[arg(long)]
    pub version: Option<String>,

    /// Notes for this baseline
    #[arg(long)]
    pub notes: Option<String>,
}

#[derive(Args)]
pub struct RegressionTestCommand {
    #[arg(short, long, default_value = "snippex.db")]
    pub database: PathBuf,

    /// Emulator to use for testing
    #[arg(long)]
    pub emulator: Option<String>,

    /// Fail if any regressions are detected
    #[arg(long)]
    pub fail_on_regression: bool,

    /// Show detailed output
    #[arg(long)]
    pub verbose: bool,
}

#[derive(Args)]
pub struct RegressionUpdateCommand {
    #[arg(short, long, default_value = "snippex.db")]
    pub database: PathBuf,

    /// Update only specific blocks (comma-separated IDs)
    #[arg(long)]
    pub blocks: Option<String>,

    /// Update baseline version
    #[arg(long)]
    pub version: Option<String>,
}

#[derive(Args)]
pub struct RegressionHistoryCommand {
    #[arg(short, long, default_value = "snippex.db")]
    pub database: PathBuf,

    /// Number of runs to show
    #[arg(long, default_value = "10")]
    pub limit: usize,

    /// Show details for specific run
    #[arg(long)]
    pub run_id: Option<String>,
}

#[derive(Args)]
pub struct RegressionExportCommand {
    #[arg(short, long, default_value = "snippex.db")]
    pub database: PathBuf,

    /// Output file (use - for stdout)
    #[arg(short, long, default_value = "baseline.json")]
    pub output: PathBuf,
}

#[derive(Args)]
pub struct RegressionImportCommand {
    #[arg(short, long, default_value = "snippex.db")]
    pub database: PathBuf,

    /// Input file
    pub input: PathBuf,

    /// Replace existing baseline
    #[arg(long)]
    pub replace: bool,
}

impl RegressionCommand {
    pub fn execute(&self) -> Result<()> {
        match &self.subcommand {
            RegressionSubcommand::Record(cmd) => cmd.execute(),
            RegressionSubcommand::Test(cmd) => cmd.execute(),
            RegressionSubcommand::Update(cmd) => cmd.execute(),
            RegressionSubcommand::History(cmd) => cmd.execute(),
            RegressionSubcommand::Export(cmd) => cmd.execute(),
            RegressionSubcommand::Import(cmd) => cmd.execute(),
        }
    }
}

impl RegressionRecordCommand {
    pub fn execute(&self) -> Result<()> {
        let mut db = Database::new(&self.database)?;
        db.init()?;

        println!("Recording baseline from current validation results...\n");

        // Get all blocks with their latest validation status
        let extractions = db.list_extractions()?;
        let batch_runs = db.get_recent_batch_runs(10)?;

        if extractions.is_empty() {
            println!("No extractions found in database.");
            return Ok(());
        }

        let mut recorded = 0;
        let mut skipped = 0;

        for extraction in &extractions {
            // Determine status from recent batch results
            let status = determine_block_status(&db, extraction.id, &batch_runs);

            if let Some(status) = status {
                let block_hash = format!("{:x}", extraction.id);

                db.record_expected_result(
                    extraction.id,
                    &block_hash,
                    &status,
                    None,
                    None,
                    self.emulator.as_deref(),
                    self.notes.as_deref(),
                )?;
                recorded += 1;
            } else {
                skipped += 1;
            }
        }

        println!("Baseline recorded:");
        println!("  Blocks recorded: {}", recorded);
        println!("  Blocks skipped:  {} (no validation data)", skipped);

        if let Some(version) = &self.version {
            println!("  Version:         {}", version);
        }

        Ok(())
    }
}

impl RegressionTestCommand {
    pub fn execute(&self) -> Result<()> {
        let mut db = Database::new(&self.database)?;
        db.init()?;

        println!("Running regression test...\n");

        let baseline = db.get_all_expected_results()?;

        if baseline.is_empty() {
            println!("No baseline found. Run 'snippex regression record' first.");
            return Ok(());
        }

        let run_id = uuid::Uuid::new_v4().to_string();
        db.start_regression_run(&run_id, self.emulator.as_deref(), None)?;

        let mut total = 0;
        let mut pass = 0;
        let mut fail = 0;
        let mut regressions = 0;
        let mut improvements = 0;

        let batch_runs = db.get_recent_batch_runs(10)?;

        for expected in &baseline {
            total += 1;

            // Get current status
            let current_status = determine_block_status(&db, expected.extraction_id, &batch_runs)
                .unwrap_or("unknown".to_string());

            let is_regression = expected.expected_status == "pass" && current_status == "fail";
            let is_improvement = expected.expected_status == "fail" && current_status == "pass";

            if is_regression {
                regressions += 1;
                fail += 1;
            } else if is_improvement {
                improvements += 1;
                pass += 1;
            } else if current_status == "pass" {
                pass += 1;
            } else {
                fail += 1;
            }

            db.record_regression_detail(
                &run_id,
                expected.extraction_id,
                &expected.expected_status,
                &current_status,
                is_regression,
                is_improvement,
                None,
            )?;

            if self.verbose && (is_regression || is_improvement) {
                let marker = if is_regression {
                    "⚠️  REGRESSION"
                } else {
                    "🎉 IMPROVEMENT"
                };
                println!(
                    "  Block #{}: {} -> {} {}",
                    expected.extraction_id, expected.expected_status, current_status, marker
                );
            }
        }

        db.complete_regression_run(&run_id, total, pass, fail, improvements, regressions, None)?;

        // Print summary
        println!();
        println!("Regression Test Results");
        println!("═══════════════════════════════════════════════");
        println!();

        if regressions > 0 {
            println!("Previously Passing, Now Failing: {} blocks ⚠️", regressions);

            let regression_details = db.get_regressions(&run_id)?;
            for detail in regression_details.iter().take(10) {
                println!(
                    "  Block #{}: Expected {}, got {}",
                    detail.extraction_id, detail.expected_status, detail.actual_status
                );
            }
            if regression_details.len() > 10 {
                println!("  ... and {} more", regression_details.len() - 10);
            }
            println!();
        }

        if improvements > 0 {
            println!(
                "Previously Failing, Now Passing: {} blocks 🎉",
                improvements
            );

            let improvement_details = db.get_improvements(&run_id)?;
            for detail in improvement_details.iter().take(10) {
                println!(
                    "  Block #{}: Expected {}, got {}",
                    detail.extraction_id, detail.expected_status, detail.actual_status
                );
            }
            if improvement_details.len() > 10 {
                println!("  ... and {} more", improvement_details.len() - 10);
            }
            println!();
        }

        let stable = total - regressions - improvements;
        println!("Stable: {} blocks (unchanged)", stable);
        println!();
        println!("Run ID: {}", run_id);

        if self.fail_on_regression && regressions > 0 {
            anyhow::bail!("{} regressions detected", regressions);
        }

        Ok(())
    }
}

impl RegressionUpdateCommand {
    pub fn execute(&self) -> Result<()> {
        let mut db = Database::new(&self.database)?;
        db.init()?;

        println!("Updating baseline...\n");

        let batch_runs = db.get_recent_batch_runs(10)?;

        if let Some(blocks_str) = &self.blocks {
            // Update specific blocks
            let block_ids: Vec<i64> = blocks_str
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();

            for block_id in &block_ids {
                if let Some(status) = determine_block_status(&db, *block_id, &batch_runs) {
                    let block_hash = format!("{:x}", block_id);
                    db.record_expected_result(
                        *block_id,
                        &block_hash,
                        &status,
                        None,
                        None,
                        None,
                        self.version.as_deref(),
                    )?;
                    println!("  Updated block #{}: {}", block_id, status);
                }
            }
        } else {
            // Update all blocks
            let extractions = db.list_extractions()?;
            let mut updated = 0;

            for extraction in &extractions {
                if let Some(status) = determine_block_status(&db, extraction.id, &batch_runs) {
                    let block_hash = format!("{:x}", extraction.id);
                    db.record_expected_result(
                        extraction.id,
                        &block_hash,
                        &status,
                        None,
                        None,
                        None,
                        self.version.as_deref(),
                    )?;
                    updated += 1;
                }
            }

            println!("Updated {} blocks in baseline", updated);
        }

        Ok(())
    }
}

impl RegressionHistoryCommand {
    pub fn execute(&self) -> Result<()> {
        let db = Database::new(&self.database)?;

        if let Some(run_id) = &self.run_id {
            // Show details for specific run
            let details = db.get_regression_run_details(run_id)?;

            if details.is_empty() {
                println!("No details found for run: {}", run_id);
                return Ok(());
            }

            println!("Regression Run: {}", run_id);
            println!("═══════════════════════════════════════════════════════════════");
            println!();

            for detail in details {
                let marker = if detail.is_regression {
                    "⚠️  REGRESSION"
                } else if detail.is_improvement {
                    "🎉 IMPROVEMENT"
                } else {
                    "   stable"
                };

                println!(
                    "Block #{}: {} -> {} {}",
                    detail.extraction_id, detail.expected_status, detail.actual_status, marker
                );
            }
        } else {
            // Show run history
            let runs = db.get_regression_runs(self.limit)?;

            if runs.is_empty() {
                println!("No regression runs found.");
                return Ok(());
            }

            println!("Regression Test History");
            println!("═══════════════════════════════════════════════════════════════");
            println!();
            println!(
                "{:<20} {:>8} {:>8} {:>8} {:>10} {:>10}",
                "Date", "Total", "Pass", "Fail", "Regressions", "Improvements"
            );
            println!(
                "{:-<20} {:->8} {:->8} {:->8} {:->10} {:->10}",
                "", "", "", "", "", ""
            );

            for run in runs {
                let date = run.started_at.split('T').next().unwrap_or(&run.started_at);
                println!(
                    "{:<20} {:>8} {:>8} {:>8} {:>10} {:>10}",
                    date,
                    run.total_blocks,
                    run.pass_count,
                    run.fail_count,
                    run.new_fail_count,
                    run.new_pass_count
                );
            }
        }

        Ok(())
    }
}

impl RegressionExportCommand {
    pub fn execute(&self) -> Result<()> {
        let db = Database::new(&self.database)?;

        let baseline = db.get_all_expected_results()?;

        if baseline.is_empty() {
            println!("No baseline to export.");
            return Ok(());
        }

        let json = serde_json::to_string_pretty(&baseline)?;

        if self.output.to_string_lossy() == "-" {
            println!("{}", json);
        } else {
            std::fs::write(&self.output, json)?;
            println!(
                "Exported {} baseline entries to {}",
                baseline.len(),
                self.output.display()
            );
        }

        Ok(())
    }
}

impl RegressionImportCommand {
    pub fn execute(&self) -> Result<()> {
        let mut db = Database::new(&self.database)?;
        db.init()?;

        let json = std::fs::read_to_string(&self.input)?;
        let baseline: Vec<crate::db::ExpectedResult> = serde_json::from_str(&json)?;

        if self.replace {
            let cleared = db.clear_expected_results()?;
            println!("Cleared {} existing baseline entries", cleared);
        }

        let mut imported = 0;
        for entry in baseline {
            db.record_expected_result(
                entry.extraction_id,
                &entry.block_hash,
                &entry.expected_status,
                entry.expected_registers.as_deref(),
                entry.expected_flags,
                entry.emulator_type.as_deref(),
                entry.notes.as_deref(),
            )?;
            imported += 1;
        }

        println!(
            "Imported {} baseline entries from {}",
            imported,
            self.input.display()
        );

        Ok(())
    }
}

/// Determine block status from batch run results.
fn determine_block_status(
    db: &Database,
    extraction_id: i64,
    batch_runs: &[BatchRunInfo],
) -> Option<String> {
    // Look through recent batch runs for this block's status
    for run in batch_runs {
        if let Ok(details) = db.get_batch_run_details(run.id) {
            for detail in details {
                if detail.extraction_id == extraction_id {
                    return Some(detail.status.to_lowercase());
                }
            }
        }
    }

    None
}
