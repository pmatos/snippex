//! Report command for creating GitHub issues from validation failures.

use anyhow::{anyhow, Result};
use clap::{Args, Subcommand};
use std::path::PathBuf;

use crate::config::Config;
use crate::db::Database;
use crate::export::github::{GitHubClient, GitHubConfig, IssueData, IssueTemplate, create_issue_template};
use crate::export::{AnalysisData, HostInfo};
use crate::simulator::{InitialState, SimulationResult};

#[derive(Args)]
pub struct ReportCommand {
    #[command(subcommand)]
    pub subcommand: ReportSubcommand,
}

#[derive(Subcommand)]
pub enum ReportSubcommand {
    /// Create GitHub issue for a validation failure
    Github(GithubReportCommand),
}

#[derive(Args)]
pub struct GithubReportCommand {
    /// Block number to report
    #[arg(long, conflicts_with = "batch")]
    pub block: Option<usize>,

    /// Range of blocks to report (e.g., "1-100")
    #[arg(long, conflicts_with = "block")]
    pub batch: Option<String>,

    /// Only report blocks that failed validation
    #[arg(long)]
    pub failing: bool,

    /// SQLite database path
    #[arg(short, long, default_value = "snippex.db")]
    pub database: PathBuf,

    /// Target repository (default: FEX-Emu/FEX)
    #[arg(long)]
    pub repo: Option<String>,

    /// Dry run - show what would be created without creating issues
    #[arg(long)]
    pub dry_run: bool,

    /// Show verbose output
    #[arg(short, long)]
    pub verbose: bool,

    /// Maximum number of issues to create in batch mode
    #[arg(long, default_value = "10")]
    pub max_issues: usize,
}

impl ReportCommand {
    pub fn execute(self) -> Result<()> {
        match self.subcommand {
            ReportSubcommand::Github(cmd) => cmd.execute(),
        }
    }
}

impl GithubReportCommand {
    pub fn execute(self) -> Result<()> {
        if !self.database.exists() {
            return Err(anyhow!(
                "Database not found at '{}'\n\n\
                 Suggestions:\n\
                 • Extract blocks first: snippex extract <binary>\n\
                 • Specify a different database: snippex report github --block N -d <path>",
                self.database.display()
            ));
        }

        let _config = Config::load().unwrap_or_default();

        let mut github_config = GitHubConfig::default();
        if let Some(ref repo) = self.repo {
            github_config.repository = repo.clone();
        }

        if self.block.is_none() && self.batch.is_none() {
            return Err(anyhow!(
                "Either --block or --batch must be specified\n\n\
                 Examples:\n\
                 • Report single block: snippex report github --block 42\n\
                 • Report batch: snippex report github --batch 1-100 --failing"
            ));
        }

        if let Some(block) = self.block {
            self.report_single_block(block, &github_config)
        } else if let Some(ref batch) = self.batch {
            self.report_batch(batch, &github_config)
        } else {
            unreachable!()
        }
    }

    fn report_single_block(&self, block_number: usize, github_config: &GitHubConfig) -> Result<()> {
        let mut db = Database::new(&self.database)?;
        let extractions = db.list_extractions()?;

        if block_number == 0 || block_number > extractions.len() {
            return Err(anyhow!(
                "Invalid block number: {}\n\n\
                 Valid block range: 1-{}\n\n\
                 Suggestions:\n\
                 • List available blocks: snippex list",
                block_number,
                extractions.len()
            ));
        }

        let extraction = &extractions[block_number - 1];

        let issue_data = self.get_validation_data(&mut db, block_number, extraction)?;

        if self.failing && !self.has_failures(&issue_data) {
            println!("Block #{} passed validation, skipping", block_number);
            return Ok(());
        }

        let template = create_issue_template(&issue_data);

        if self.dry_run {
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("DRY RUN - Would create issue:");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!();
            self.display_template(&template, github_config);
            return Ok(());
        }

        println!("Creating GitHub issue for block #{}...", block_number);

        let client = GitHubClient::new(github_config.clone());

        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| anyhow!("Failed to create async runtime: {}", e))?;

        let (created_issue, is_new) = rt.block_on(async {
            client.create_or_update(&issue_data).await
        }).map_err(|e| anyhow!("{}", e))?;

        if is_new {
            println!("✓ Created issue #{}: {}", created_issue.number, created_issue.url);
        } else {
            println!("✓ Added comment to existing issue #{}: {}", created_issue.number, created_issue.url);
        }

        Ok(())
    }

    fn report_batch(&self, batch: &str, github_config: &GitHubConfig) -> Result<()> {
        let (start, end) = self.parse_batch_range(batch)?;

        let mut db = Database::new(&self.database)?;
        let extractions = db.list_extractions()?;

        if end > extractions.len() {
            return Err(anyhow!(
                "Batch range {}-{} exceeds available blocks (1-{})",
                start, end, extractions.len()
            ));
        }

        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Batch Report: Blocks {}-{}", start, end);
        if self.failing {
            println!("Mode: Failing blocks only");
        }
        if self.dry_run {
            println!("Mode: DRY RUN");
        }
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!();

        let mut issues_created = 0;
        let mut issues_updated = 0;
        let mut skipped = 0;
        let mut errors = 0;

        let client = if !self.dry_run {
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| anyhow!("Failed to create async runtime: {}", e))?;
            Some((GitHubClient::new(github_config.clone()), rt))
        } else {
            None
        };

        for block_number in start..=end {
            if issues_created >= self.max_issues {
                println!("\nReached maximum issue limit ({}), stopping.", self.max_issues);
                break;
            }

            let extraction = &extractions[block_number - 1];

            match self.get_validation_data(&mut db, block_number, extraction) {
                Ok(issue_data) => {
                    if self.failing && !self.has_failures(&issue_data) {
                        if self.verbose {
                            println!("[{}] Passed validation, skipping", block_number);
                        }
                        skipped += 1;
                        continue;
                    }

                    if self.dry_run {
                        let template = create_issue_template(&issue_data);
                        println!("[{}] Would create: {}", block_number, template.title);
                        issues_created += 1;
                    } else if let Some((ref client_inner, ref rt)) = client {
                        match rt.block_on(async { client_inner.create_or_update(&issue_data).await }) {
                            Ok((created_issue, is_new)) => {
                                if is_new {
                                    println!("[{}] ✓ Created #{}: {}", block_number, created_issue.number, created_issue.url);
                                    issues_created += 1;
                                } else {
                                    println!("[{}] ✓ Updated #{}", block_number, created_issue.number);
                                    issues_updated += 1;
                                }
                            }
                            Err(e) => {
                                println!("[{}] ✗ Error: {}", block_number, e);
                                errors += 1;
                            }
                        }
                    }
                }
                Err(e) => {
                    if self.verbose {
                        println!("[{}] Skipped: {}", block_number, e);
                    }
                    skipped += 1;
                }
            }
        }

        println!();
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Summary:");
        if self.dry_run {
            println!("  Would create: {}", issues_created);
        } else {
            println!("  Created: {}", issues_created);
            println!("  Updated: {}", issues_updated);
        }
        println!("  Skipped: {}", skipped);
        println!("  Errors: {}", errors);
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

        Ok(())
    }

    fn parse_batch_range(&self, batch: &str) -> Result<(usize, usize)> {
        let parts: Vec<&str> = batch.split('-').collect();
        if parts.len() != 2 {
            return Err(anyhow!(
                "Invalid batch format '{}'. Expected 'start-end' (e.g., '1-100')",
                batch
            ));
        }

        let start: usize = parts[0].parse().map_err(|_| {
            anyhow!("Invalid start number '{}' in batch range", parts[0])
        })?;
        let end: usize = parts[1].parse().map_err(|_| {
            anyhow!("Invalid end number '{}' in batch range", parts[1])
        })?;

        if start == 0 {
            return Err(anyhow!("Batch start must be at least 1"));
        }
        if start > end {
            return Err(anyhow!(
                "Batch start ({}) must be less than or equal to end ({})",
                start, end
            ));
        }

        Ok((start, end))
    }

    fn get_validation_data(
        &self,
        db: &mut Database,
        block_number: usize,
        extraction: &crate::db::ExtractionInfo,
    ) -> Result<IssueData> {
        let native_cached = db
            .get_validation_cache(extraction.id, "native", None, 365)?
            .ok_or_else(|| anyhow!("No native validation result cached for block #{}", block_number))?;

        let fex_cached = db
            .get_validation_cache(extraction.id, "fex-emu", None, 365)?
            .ok_or_else(|| anyhow!("No FEX-Emu validation result cached for block #{}", block_number))?;

        let analysis = db.load_block_analysis(extraction.id)?;
        let analysis_data = analysis.map(|a| AnalysisData::from(&a));

        let native_result = SimulationResult {
            simulation_id: "native-cached".to_string(),
            initial_state: InitialState {
                registers: std::collections::HashMap::new(),
                memory_locations: std::collections::HashMap::new(),
                stack_setup: Vec::new(),
            },
            final_state: native_cached.final_state,
            execution_time: native_cached.execution_time,
            exit_code: native_cached.exit_code,
            emulator_used: None,
            assembly_file_path: None,
            binary_file_path: None,
        };

        let fex_result = SimulationResult {
            simulation_id: "fex-cached".to_string(),
            initial_state: InitialState {
                registers: std::collections::HashMap::new(),
                memory_locations: std::collections::HashMap::new(),
                stack_setup: Vec::new(),
            },
            final_state: fex_cached.final_state,
            execution_time: fex_cached.execution_time,
            exit_code: fex_cached.exit_code,
            emulator_used: Some("FEXInterpreter".to_string()),
            assembly_file_path: None,
            binary_file_path: None,
        };

        Ok(IssueData {
            extraction: extraction.clone(),
            analysis: analysis_data,
            native_result,
            fex_result,
            host_info: HostInfo::current(),
            notes: None,
        })
    }

    fn has_failures(&self, data: &IssueData) -> bool {
        let native = &data.native_result;
        let fex = &data.fex_result;

        if native.exit_code != fex.exit_code {
            return true;
        }
        if native.final_state.flags != fex.final_state.flags {
            return true;
        }
        for (reg, native_val) in &native.final_state.registers {
            if let Some(fex_val) = fex.final_state.registers.get(reg) {
                if native_val != fex_val {
                    return true;
                }
            }
        }
        for (addr, native_bytes) in &native.final_state.memory_locations {
            if let Some(fex_bytes) = fex.final_state.memory_locations.get(addr) {
                if native_bytes != fex_bytes {
                    return true;
                }
            }
        }
        false
    }

    fn display_template(&self, template: &IssueTemplate, config: &GitHubConfig) {
        println!("Repository: {}", config.repository);
        println!("Labels: {}", template.labels.join(", "));
        println!();
        println!("Title: {}", template.title);
        println!();
        println!("Body:");
        println!("────────────────────────────────────────────────");
        if self.verbose {
            println!("{}", template.body);
        } else {
            let lines: Vec<&str> = template.body.lines().take(30).collect();
            for line in lines {
                println!("{}", line);
            }
            if template.body.lines().count() > 30 {
                println!("... ({} more lines)", template.body.lines().count() - 30);
            }
        }
        println!("────────────────────────────────────────────────");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_batch_range_valid() {
        let cmd = GithubReportCommand {
            block: None,
            batch: None,
            failing: false,
            database: PathBuf::from("test.db"),
            repo: None,
            dry_run: false,
            verbose: false,
            max_issues: 10,
        };

        assert_eq!(cmd.parse_batch_range("1-100").unwrap(), (1, 100));
        assert_eq!(cmd.parse_batch_range("5-5").unwrap(), (5, 5));
        assert_eq!(cmd.parse_batch_range("10-20").unwrap(), (10, 20));
    }

    #[test]
    fn test_parse_batch_range_invalid() {
        let cmd = GithubReportCommand {
            block: None,
            batch: None,
            failing: false,
            database: PathBuf::from("test.db"),
            repo: None,
            dry_run: false,
            verbose: false,
            max_issues: 10,
        };

        assert!(cmd.parse_batch_range("invalid").is_err());
        assert!(cmd.parse_batch_range("1-2-3").is_err());
        assert!(cmd.parse_batch_range("10-5").is_err());
        assert!(cmd.parse_batch_range("0-10").is_err());
        assert!(cmd.parse_batch_range("abc-def").is_err());
    }
}
