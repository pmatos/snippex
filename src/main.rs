use anyhow::Result;
use clap::{Parser, Subcommand};
use std::sync::Arc;

mod analyzer;
mod arch;
mod cli;
mod config;
mod db;
mod error;
mod export;
mod extractor;
mod formatting;
mod remote;
mod simulator;

use cli::analyze::AnalyzeCommand;
use cli::cache::CacheCommand;
use cli::compare::CompareCommand;
use cli::completions::CompletionsCommand;
use cli::config::ConfigCommand;
use cli::disasm::DisasmCommand;
use cli::emulate::EmulateCommand;
use cli::export::ExportCommand;
use cli::extract::ExtractCommand;
use cli::import::ImportCommand;
use cli::import_results::ImportResultsCommand;
use cli::list::ListCommand;
use cli::metrics::MetricsCommand;
use cli::regression::RegressionCommand;
use cli::remote_setup::RemoteSetupCommand;
use cli::remove::RemoveCommand;
use cli::report::ReportCommand;
use cli::simulate::SimulateCommand;
use cli::simulate_remote::SimulateRemoteCommand;
use cli::stats::StatsCommand;
use cli::validate::ValidateCommand;
use cli::validate_batch::ValidateBatchCommand;

/// Build the version string with host architecture info.
fn version_string() -> String {
    let version = env!("CARGO_PKG_VERSION");
    let host_info = arch::host_info();
    let arch_status = match arch::get_effective_architecture() {
        Ok(arch) => {
            let native = if arch.can_run_x86_native() {
                "native x86"
            } else {
                "FEX-Emu"
            };
            let override_note = if arch::has_arch_override() {
                " [OVERRIDE]"
            } else {
                ""
            };
            format!("{} ({}){}", arch.display_name(), native, override_note)
        }
        Err(_) => "unsupported".to_string(),
    };
    format!("{} ({}, {})", version, host_info, arch_status)
}

#[derive(Parser)]
#[command(name = "snippex")]
#[command(version = None)] // Disable default version, we'll handle it manually
#[command(about = "A framework for extracting and analyzing assembly code blocks from ELF and PE binaries", long_about = None)]
struct Cli {
    /// Print version information including host architecture
    #[arg(short = 'V', long = "version")]
    version: bool,

    /// Override host architecture for testing (x86_64 or aarch64)
    #[arg(long = "arch", global = true, value_parser = parse_arch)]
    arch_override: Option<arch::HostArch>,

    #[command(subcommand)]
    command: Option<Commands>,
}

/// Parse architecture string for CLI argument
fn parse_arch(s: &str) -> Result<arch::HostArch, String> {
    s.parse()
}

#[derive(Subcommand)]
enum Commands {
    Extract(ExtractCommand),
    Import(ImportCommand),
    List(ListCommand),
    Remove(RemoveCommand),
    Analyze(AnalyzeCommand),
    /// Show disassembly of a block with color-coded analysis
    Disasm(DisasmCommand),
    Simulate(SimulateCommand),
    SimulateRemote(SimulateRemoteCommand),
    /// Replay stored native simulations through FEX-Emu and compare results
    Emulate(EmulateCommand),
    Validate(ValidateCommand),
    ValidateBatch(ValidateBatchCommand),
    Export(ExportCommand),
    ImportResults(ImportResultsCommand),
    Compare(CompareCommand),
    Config(ConfigCommand),
    Cache(CacheCommand),
    Stats(StatsCommand),
    /// Create GitHub issues from validation failures
    Report(ReportCommand),
    /// Track and display validation metrics over time
    Metrics(MetricsCommand),
    /// Generate shell completion scripts
    Completions(CompletionsCommand),
    /// Regression testing - track and detect behavior changes
    Regression(RegressionCommand),
    /// Cross-compile and deploy snippex to a remote machine
    RemoteSetup(RemoteSetupCommand),
}

fn main() -> Result<()> {
    // Initialize logging with INFO level by default
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Create global cleanup registry for remote operations
    let cleanup_registry = Arc::new(remote::CleanupRegistry::new());
    let cleanup_for_handler = cleanup_registry.clone();

    // Register Ctrl+C handler for cleanup on interruption
    ctrlc::set_handler(move || {
        log::warn!("Received interrupt signal (Ctrl+C), cleaning up...");
        cleanup_for_handler.cleanup_all();
        std::process::exit(130); // Exit code 130 for SIGINT
    })
    .expect("Error setting Ctrl+C handler");

    let cli = Cli::parse();

    // Set architecture override if provided
    if let Some(arch_override) = cli.arch_override {
        if arch::set_arch_override(arch_override).is_err() {
            log::warn!("Architecture override was already set, ignoring --arch flag");
        } else {
            log::info!("Architecture override set to: {}", arch_override);
        }
    }

    // Handle version flag
    if cli.version {
        println!("snippex {}", version_string());
        return Ok(());
    }

    // Require a subcommand if not requesting version
    let command = cli
        .command
        .ok_or_else(|| anyhow::anyhow!("No command provided. Use --help for usage information."))?;

    match command {
        Commands::Extract(cmd) => cmd.execute(),
        Commands::Import(cmd) => cmd.execute(),
        Commands::List(cmd) => cmd.execute(),
        Commands::Remove(cmd) => cmd.execute(),
        Commands::Analyze(cmd) => cmd.execute(),
        Commands::Disasm(cmd) => cmd.execute(),
        Commands::Simulate(cmd) => cmd.execute(),
        Commands::SimulateRemote(cmd) => cmd.execute(),
        Commands::Emulate(cmd) => cmd.execute(),
        Commands::Validate(cmd) => cmd.execute(),
        Commands::ValidateBatch(cmd) => cmd.execute(),
        Commands::Export(cmd) => cmd.execute(),
        Commands::ImportResults(cmd) => cmd.execute(),
        Commands::Compare(cmd) => cmd.execute(),
        Commands::Config(cmd) => cmd.execute(),
        Commands::Cache(cmd) => cmd.execute(),
        Commands::Stats(cmd) => cmd.execute(),
        Commands::Report(cmd) => cmd.execute(),
        Commands::Metrics(cmd) => cmd.execute(),
        Commands::Completions(cmd) => cmd.execute(),
        Commands::Regression(cmd) => cmd.execute(),
        Commands::RemoteSetup(cmd) => cmd.execute(),
    }
}
