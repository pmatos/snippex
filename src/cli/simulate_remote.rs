//! Remote simulation subcommand for executing packages on remote machines.
//!
//! This command is designed to be invoked on a remote machine after an
//! ExecutionPackage has been transferred via SCP.
//!
//! If the package includes a pre-compiled simulation binary, it will be used
//! directly without re-compiling (faster and avoids NASM version issues).

use anyhow::{anyhow, Result};
use clap::Args;
use std::path::PathBuf;
use std::str::FromStr;

use crate::remote::ExecutionPackage;
use crate::simulator::{EmulatorConfig, SimulationResult, Simulator};

#[derive(Args)]
pub struct SimulateRemoteCommand {
    #[arg(
        short,
        long,
        required = true,
        help = "Path to the execution package (directory or .tar.gz)"
    )]
    pub package: PathBuf,

    #[arg(short, long, help = "Keep generated assembly and binary files")]
    pub keep_files: bool,

    #[arg(
        short,
        long,
        help = "Override emulator (native, qemu-x86_64, qemu-i386, fex-emu)"
    )]
    pub emulator: Option<String>,

    #[arg(
        short,
        long,
        help = "Output JSON file path (defaults to results.json in package dir)"
    )]
    pub output: Option<PathBuf>,

    #[arg(short, long, help = "Show detailed execution output")]
    pub verbose: bool,
}

impl SimulateRemoteCommand {
    pub fn execute(self) -> Result<()> {
        // Determine if we have a tarball or directory
        let (package_dir, temp_dir) = if self.package.extension().is_some_and(|ext| ext == "gz")
            || self.package.to_string_lossy().ends_with(".tar.gz")
        {
            // Extract tarball to temp directory
            if self.verbose {
                println!("Extracting tarball: {}", self.package.display());
            }

            let temp = tempfile::TempDir::new()?;
            let extracted_dir = ExecutionPackage::extract_tarball(&self.package, temp.path())
                .map_err(|e| {
                    anyhow!(
                        "Failed to extract tarball {}: {}",
                        self.package.display(),
                        e
                    )
                })?;

            if self.verbose {
                println!("Extracted to: {}", extracted_dir.display());
            }

            (extracted_dir, Some(temp))
        } else if self.package.is_dir() {
            (self.package.clone(), None)
        } else {
            return Err(anyhow!(
                "Package path must be a directory or .tar.gz file: {}",
                self.package.display()
            ));
        };

        // Load the execution package
        if self.verbose {
            println!("Loading package from: {}", package_dir.display());
        }

        let package = ExecutionPackage::load_from_directory(&package_dir).map_err(|e| {
            anyhow!(
                "Failed to load package from {}: {}",
                package_dir.display(),
                e
            )
        })?;

        println!("Executing remote simulation...");
        println!("  Package ID: {}", package.metadata.package_id);
        println!("  Created by: {}", package.metadata.created_by);
        println!("  Created at: {}", package.metadata.created_at);
        println!(
            "  Block: 0x{:08x} - 0x{:08x}",
            package.extraction.start_address, package.extraction.end_address
        );

        // Determine binary path
        let binary_path = package.get_binary_path(&package_dir);
        if binary_path.is_none() && self.verbose {
            println!(
                "  Warning: Binary not found in package or at original path: {}",
                package.extraction.binary_path
            );
        }

        // Convert package data to simulation inputs
        let extraction_info = package.to_extraction_info(binary_path.as_deref());
        let analysis = package.to_block_analysis();
        let initial_state = &package.initial_state;

        // Determine emulator configuration
        let emulator_config = if let Some(emulator_str) = &self.emulator {
            // Use override from command line
            let config = EmulatorConfig::from_str(emulator_str)
                .map_err(|e| anyhow!("Invalid emulator configuration: {}", e))?;

            if !config.is_available() {
                return Err(anyhow!("Emulator '{}' is not available", emulator_str));
            }

            Some(config)
        } else {
            // Use emulator from package if present
            package.to_emulator_config()
        };

        if let Some(ref emu) = emulator_config {
            println!("  Emulator: {}", emu.name());
        } else {
            println!("  Emulator: native");
        }

        // Check for pre-compiled simulation binary
        let simulation_binary_path = package.get_simulation_binary_path(&package_dir);

        // Initialize simulator with the target architecture from the package
        let target_arch = &package.extraction.binary_architecture;
        let simulator = Simulator::for_target(target_arch)?;

        // Run simulation - use pre-compiled binary if available, otherwise compile from scratch
        let result = if let Some(ref sim_binary) = simulation_binary_path {
            println!("  Using pre-compiled binary: {}", sim_binary.display());
            simulator.run_precompiled_binary(sim_binary, initial_state, emulator_config)?
        } else {
            println!("  Compiling from assembly...");
            let mut simulator = simulator;
            simulator.simulate_block_with_state(
                &extraction_info,
                &analysis,
                initial_state,
                emulator_config,
                self.keep_files,
            )?
        };

        println!("  Status: Completed");
        println!("  Execution time: {:?}", result.execution_time);
        println!("  Exit code: {}", result.exit_code);

        // Determine output path
        let output_path = match self.output {
            Some(path) => path,
            None => {
                if temp_dir.is_some() {
                    // If we extracted a tarball, put results next to the original tarball
                    self.package.with_extension("results.json")
                } else {
                    // Put results in the package directory
                    package_dir.join("results.json")
                }
            }
        };

        // Write results to JSON
        Self::write_results(&output_path, &result)?;

        println!();
        println!("Results written to: {}", output_path.display());

        if self.verbose {
            println!();
            println!("Simulation details:");
            println!("  Simulation ID: {}", result.simulation_id);
            println!(
                "  Initial registers: {}",
                result.initial_state.registers.len()
            );
            println!("  Final registers: {}", result.final_state.registers.len());

            if let Some(ref asm_path) = result.assembly_file_path {
                println!("  Assembly file: {}", asm_path);
            }
            if let Some(ref bin_path) = result.binary_file_path {
                println!("  Binary file: {}", bin_path);
            }
        }

        Ok(())
    }

    fn write_results(output_path: &PathBuf, result: &SimulationResult) -> Result<()> {
        let json = serde_json::to_string_pretty(result)
            .map_err(|e| anyhow!("Failed to serialize results: {}", e))?;

        std::fs::write(output_path, json).map_err(|e| {
            anyhow!(
                "Failed to write results to {}: {}",
                output_path.display(),
                e
            )
        })?;

        Ok(())
    }
}
