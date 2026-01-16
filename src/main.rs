use anyhow::Result;
use clap::{Parser, Subcommand};
use std::sync::Arc;

mod analyzer;
mod cli;
mod config;
mod db;
mod error;
mod export;
mod extractor;
mod remote;
mod simulator;

use cli::analyze::AnalyzeCommand;
use cli::compare::CompareCommand;
use cli::config::ConfigCommand;
use cli::export::ExportCommand;
use cli::extract::ExtractCommand;
use cli::import::ImportCommand;
use cli::import_results::ImportResultsCommand;
use cli::list::ListCommand;
use cli::remove::RemoveCommand;
use cli::simulate::SimulateCommand;
use cli::simulate_remote::SimulateRemoteCommand;

#[derive(Parser)]
#[command(name = "snippex")]
#[command(about = "A framework for extracting and analyzing assembly code blocks from ELF and PE binaries", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Extract(ExtractCommand),
    Import(ImportCommand),
    List(ListCommand),
    Remove(RemoveCommand),
    Analyze(AnalyzeCommand),
    Simulate(SimulateCommand),
    SimulateRemote(SimulateRemoteCommand),
    Export(ExportCommand),
    ImportResults(ImportResultsCommand),
    Compare(CompareCommand),
    Config(ConfigCommand),
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

    match cli.command {
        Commands::Extract(cmd) => cmd.execute(),
        Commands::Import(cmd) => cmd.execute(),
        Commands::List(cmd) => cmd.execute(),
        Commands::Remove(cmd) => cmd.execute(),
        Commands::Analyze(cmd) => cmd.execute(),
        Commands::Simulate(cmd) => cmd.execute(),
        Commands::SimulateRemote(cmd) => cmd.execute(),
        Commands::Export(cmd) => cmd.execute(),
        Commands::ImportResults(cmd) => cmd.execute(),
        Commands::Compare(cmd) => cmd.execute(),
        Commands::Config(cmd) => cmd.execute(),
    }
}
