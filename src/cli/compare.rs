use anyhow::{anyhow, Result};
use clap::Args;
use std::collections::HashMap;
use std::path::PathBuf;

use crate::db::Database;
use crate::simulator::SimulationResult;

#[derive(Args)]
pub struct CompareCommand {
    #[arg(help = "Block number to compare simulations for")]
    pub block_number: usize,

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
        help = "Filter by emulator types (comma-separated, e.g., 'native,fex-emu')"
    )]
    pub emulators: Option<String>,

    #[arg(long, help = "Show detailed register differences")]
    pub detailed_registers: bool,

    #[arg(long, help = "Show detailed memory differences")]
    pub detailed_memory: bool,

    #[arg(long, help = "Export comparison to JSON file")]
    pub export_json: Option<PathBuf>,

    #[arg(short, long, help = "Enable verbose logging")]
    pub verbose: bool,

    #[arg(short, long, help = "Suppress all output")]
    pub quiet: bool,
}

impl CompareCommand {
    pub fn execute(self) -> Result<()> {
        // Check if database exists
        if !self.database.exists() {
            return Err(anyhow!(
                "Database file not found: {}",
                self.database.display()
            ));
        }

        let db = Database::new(&self.database)?;

        // Get the extraction ID
        let extractions = db.list_extractions()?;
        if self.block_number == 0 || self.block_number > extractions.len() {
            return Err(anyhow!(
                "Invalid block number. Valid range: 1-{}",
                extractions.len()
            ));
        }

        let extraction_id = self.block_number as i64;
        let extraction = &extractions[self.block_number - 1];

        if !self.quiet {
            println!("Comparing simulations for block #{}", self.block_number);
            println!("  Binary: {}", extraction.binary_path);
            println!(
                "  Address range: 0x{:08x} - 0x{:08x}",
                extraction.start_address, extraction.end_address
            );
            println!();
        }

        // Get all simulations for this extraction
        let simulations = db.get_simulations_for_extraction(extraction_id)?;

        if simulations.is_empty() {
            return Err(anyhow!(
                "No simulations found for block #{}",
                self.block_number
            ));
        }

        // Filter by emulator if specified
        let filtered_simulations = if let Some(emulator_filter) = &self.emulators {
            let emulator_list: Vec<&str> = emulator_filter.split(',').map(|s| s.trim()).collect();
            simulations
                .into_iter()
                .filter(|sim| {
                    if let Some(emulator_used) = &sim.emulator_used {
                        emulator_list.iter().any(|filter| {
                            // Check if the emulator matches (handle both simple names and full host info)
                            emulator_used.contains(filter)
                                || emulator_used.split('@').next().unwrap_or("") == *filter
                        })
                    } else {
                        false
                    }
                })
                .collect()
        } else {
            simulations
        };

        if filtered_simulations.is_empty() {
            return Err(anyhow!(
                "No simulations found matching the specified emulator filter"
            ));
        }

        if !self.quiet {
            println!(
                "Found {} simulation(s) to compare:",
                filtered_simulations.len()
            );
            for sim in &filtered_simulations {
                println!(
                    "  - {} (exit: {}, time: {:?})",
                    sim.emulator_used.as_ref().unwrap_or(&"unknown".to_string()),
                    sim.exit_code,
                    sim.execution_time
                );
            }
            println!();
        }

        // Perform comparison
        let comparison = self.perform_comparison(&filtered_simulations)?;

        // Display results
        self.display_comparison(&comparison)?;

        // Export to JSON if requested
        if let Some(export_path) = &self.export_json {
            let json_output = serde_json::to_string_pretty(&comparison)?;
            std::fs::write(export_path, json_output)?;
            if !self.quiet {
                println!("Comparison exported to: {}", export_path.display());
            }
        }

        Ok(())
    }

    fn perform_comparison(&self, simulations: &[SimulationResult]) -> Result<ComparisonResult> {
        let mut comparison = ComparisonResult {
            block_number: self.block_number,
            simulations_compared: simulations.len(),
            emulator_summary: Vec::new(),
            register_differences: HashMap::new(),
            memory_differences: HashMap::new(),
            execution_differences: HashMap::new(),
            consensus: None,
        };

        // Build emulator summary
        for sim in simulations {
            let unknown = "unknown".to_string();
            let emulator_name = sim.emulator_used.as_ref().unwrap_or(&unknown);
            let summary = EmulatorSummary {
                emulator: emulator_name.clone(),
                exit_code: sim.exit_code,
                execution_time_ns: sim.execution_time.as_nanos() as u64,
                final_flags: sim.final_state.flags,
                register_count: sim.final_state.registers.len(),
                memory_locations_count: sim.final_state.memory_locations.len(),
            };
            comparison.emulator_summary.push(summary);
        }

        // Compare registers
        if simulations.len() >= 2 {
            let base_sim = &simulations[0];
            for (_i, other_sim) in simulations.iter().enumerate().skip(1) {
                let unknown_base = "unknown".to_string();
                let unknown_other = "unknown".to_string();
                let base_emulator = base_sim.emulator_used.as_ref().unwrap_or(&unknown_base);
                let other_emulator = other_sim.emulator_used.as_ref().unwrap_or(&unknown_other);

                let key = format!("{} vs {}", base_emulator, other_emulator);

                let reg_diff = self.compare_registers(
                    &base_sim.final_state.registers,
                    &other_sim.final_state.registers,
                );
                comparison
                    .register_differences
                    .insert(key.clone(), reg_diff);

                let mem_diff = self.compare_memory(
                    &base_sim.final_state.memory_locations,
                    &other_sim.final_state.memory_locations,
                );
                comparison.memory_differences.insert(key.clone(), mem_diff);

                let exec_diff = ExecutionDifference {
                    exit_code_match: base_sim.exit_code == other_sim.exit_code,
                    flags_match: base_sim.final_state.flags == other_sim.final_state.flags,
                    execution_time_ratio: other_sim.execution_time.as_nanos() as f64
                        / base_sim.execution_time.as_nanos() as f64,
                };
                comparison.execution_differences.insert(key, exec_diff);
            }
        }

        // Determine consensus
        comparison.consensus = self.determine_consensus(simulations);

        Ok(comparison)
    }

    fn compare_registers(
        &self,
        base: &HashMap<String, u64>,
        other: &HashMap<String, u64>,
    ) -> RegisterDifference {
        let mut differences = Vec::new();
        let mut all_registers: std::collections::HashSet<String> = base.keys().cloned().collect();
        all_registers.extend(other.keys().cloned());

        for register in all_registers {
            let base_value = base.get(&register).copied();
            let other_value = other.get(&register).copied();

            if base_value != other_value {
                differences.push(RegisterValueDiff {
                    register: register.clone(),
                    base_value,
                    other_value,
                });
            }
        }

        RegisterDifference {
            total_differences: differences.len(),
            differences: if self.detailed_registers {
                differences
            } else {
                Vec::new()
            },
        }
    }

    fn compare_memory(
        &self,
        base: &HashMap<u64, Vec<u8>>,
        other: &HashMap<u64, Vec<u8>>,
    ) -> MemoryDifference {
        let mut differences = Vec::new();
        let mut all_addresses: std::collections::HashSet<u64> = base.keys().copied().collect();
        all_addresses.extend(other.keys().copied());

        for address in all_addresses {
            let base_data = base.get(&address);
            let other_data = other.get(&address);

            if base_data != other_data {
                differences.push(MemoryValueDiff {
                    address,
                    base_data: base_data.cloned(),
                    other_data: other_data.cloned(),
                });
            }
        }

        MemoryDifference {
            total_differences: differences.len(),
            differences: if self.detailed_memory {
                differences
            } else {
                Vec::new()
            },
        }
    }

    fn determine_consensus(&self, simulations: &[SimulationResult]) -> Option<Consensus> {
        if simulations.len() < 2 {
            return None;
        }

        let exit_codes: Vec<i32> = simulations.iter().map(|s| s.exit_code).collect();
        let flags: Vec<u64> = simulations.iter().map(|s| s.final_state.flags).collect();

        let exit_code_consensus = exit_codes.iter().all(|&code| code == exit_codes[0]);
        let flags_consensus = flags.iter().all(|&flag| flag == flags[0]);

        // Check register consensus for common registers
        let mut register_consensus = true;
        if simulations.len() >= 2 {
            let base_registers = &simulations[0].final_state.registers;
            for sim in simulations.iter().skip(1) {
                for (reg, value) in base_registers {
                    if sim.final_state.registers.get(reg) != Some(value) {
                        register_consensus = false;
                        break;
                    }
                }
                if !register_consensus {
                    break;
                }
            }
        }

        Some(Consensus {
            exit_code_consensus,
            flags_consensus,
            register_consensus,
            overall_consensus: exit_code_consensus && flags_consensus && register_consensus,
        })
    }

    fn display_comparison(&self, comparison: &ComparisonResult) -> Result<()> {
        if self.quiet {
            return Ok(());
        }

        println!("=== Comparison Results ===");
        println!();

        // Emulator summary
        println!("Emulator Summary:");
        for summary in &comparison.emulator_summary {
            println!("  {}:", summary.emulator);
            println!("    Exit code: {}", summary.exit_code);
            println!("    Execution time: {} ns", summary.execution_time_ns);
            println!("    Final flags: 0x{:016x}", summary.final_flags);
            println!("    Registers set: {}", summary.register_count);
            println!("    Memory locations: {}", summary.memory_locations_count);
        }
        println!();

        // Consensus
        if let Some(consensus) = &comparison.consensus {
            println!("Consensus Analysis:");
            println!(
                "  Exit codes match: {}",
                if consensus.exit_code_consensus {
                    "✓"
                } else {
                    "✗"
                }
            );
            println!(
                "  Flags match: {}",
                if consensus.flags_consensus {
                    "✓"
                } else {
                    "✗"
                }
            );
            println!(
                "  Registers match: {}",
                if consensus.register_consensus {
                    "✓"
                } else {
                    "✗"
                }
            );
            println!(
                "  Overall consensus: {}",
                if consensus.overall_consensus {
                    "✓ PASS"
                } else {
                    "✗ FAIL"
                }
            );
            println!();
        }

        // Differences
        if !comparison.register_differences.is_empty() {
            println!("Register Differences:");
            for (comparison_name, diff) in &comparison.register_differences {
                println!(
                    "  {}: {} differences",
                    comparison_name, diff.total_differences
                );
                if self.detailed_registers && !diff.differences.is_empty() {
                    for reg_diff in &diff.differences {
                        println!(
                            "    {}: {:?} vs {:?}",
                            reg_diff.register, reg_diff.base_value, reg_diff.other_value
                        );
                    }
                }
            }
            println!();
        }

        if !comparison.memory_differences.is_empty() {
            println!("Memory Differences:");
            for (comparison_name, diff) in &comparison.memory_differences {
                println!(
                    "  {}: {} differences",
                    comparison_name, diff.total_differences
                );
                if self.detailed_memory && !diff.differences.is_empty() {
                    for mem_diff in &diff.differences {
                        println!(
                            "    0x{:016x}: {:?} vs {:?}",
                            mem_diff.address, mem_diff.base_data, mem_diff.other_data
                        );
                    }
                }
            }
            println!();
        }

        if !comparison.execution_differences.is_empty() {
            println!("Execution Differences:");
            for (comparison_name, diff) in &comparison.execution_differences {
                println!("  {}:", comparison_name);
                println!(
                    "    Exit codes match: {}",
                    if diff.exit_code_match { "✓" } else { "✗" }
                );
                println!(
                    "    Flags match: {}",
                    if diff.flags_match { "✓" } else { "✗" }
                );
                println!("    Time ratio: {:.2}x", diff.execution_time_ratio);
            }
            println!();
        }

        Ok(())
    }
}

#[derive(Debug, serde::Serialize)]
struct ComparisonResult {
    block_number: usize,
    simulations_compared: usize,
    emulator_summary: Vec<EmulatorSummary>,
    register_differences: HashMap<String, RegisterDifference>,
    memory_differences: HashMap<String, MemoryDifference>,
    execution_differences: HashMap<String, ExecutionDifference>,
    consensus: Option<Consensus>,
}

#[derive(Debug, serde::Serialize)]
struct EmulatorSummary {
    emulator: String,
    exit_code: i32,
    execution_time_ns: u64,
    final_flags: u64,
    register_count: usize,
    memory_locations_count: usize,
}

#[derive(Debug, serde::Serialize)]
struct RegisterDifference {
    total_differences: usize,
    differences: Vec<RegisterValueDiff>,
}

#[derive(Debug, serde::Serialize)]
struct RegisterValueDiff {
    register: String,
    base_value: Option<u64>,
    other_value: Option<u64>,
}

#[derive(Debug, serde::Serialize)]
struct MemoryDifference {
    total_differences: usize,
    differences: Vec<MemoryValueDiff>,
}

#[derive(Debug, serde::Serialize)]
struct MemoryValueDiff {
    address: u64,
    base_data: Option<Vec<u8>>,
    other_data: Option<Vec<u8>>,
}

#[derive(Debug, serde::Serialize)]
struct ExecutionDifference {
    exit_code_match: bool,
    flags_match: bool,
    execution_time_ratio: f64,
}

#[derive(Debug, serde::Serialize)]
struct Consensus {
    exit_code_consensus: bool,
    flags_consensus: bool,
    register_consensus: bool,
    overall_consensus: bool,
}
