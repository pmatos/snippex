pub mod assembly_generator;
pub mod compilation;
pub mod emulator;
pub mod execution;
pub mod random_generator;
pub mod sandbox;
pub mod state;

#[cfg(test)]
mod tests;

use serde::{Deserialize, Serialize};
use std::time::Duration;
use uuid::Uuid;

use crate::analyzer::BlockAnalysis;
use crate::db::ExtractionInfo;

pub use assembly_generator::AssemblyGenerator;
pub use compilation::CompilationPipeline;
pub use emulator::EmulatorConfig;
pub use execution::ExecutionHarness;
pub use random_generator::RandomStateGenerator;
pub use sandbox::{SandboxMemoryLayout, SectionMapping, SANDBOX_BASE, SANDBOX_SIZE};
pub use state::{FinalState, InitialState};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    pub simulation_id: String,
    pub initial_state: InitialState,
    pub final_state: FinalState,
    pub execution_time: Duration,
    pub exit_code: i32,
    pub emulator_used: Option<String>,
    pub assembly_file_path: Option<String>,
    pub binary_file_path: Option<String>,
}

impl SimulationResult {
    pub fn new(
        initial_state: InitialState,
        final_state: FinalState,
        execution_time: Duration,
        exit_code: i32,
        emulator_used: Option<String>,
        assembly_file_path: Option<String>,
        binary_file_path: Option<String>,
    ) -> Self {
        Self {
            simulation_id: Uuid::new_v4().to_string(),
            initial_state,
            final_state,
            execution_time,
            exit_code,
            emulator_used,
            assembly_file_path,
            binary_file_path,
        }
    }
}

pub struct Simulator {
    pub assembly_generator: AssemblyGenerator,
    pub compilation_pipeline: CompilationPipeline,
    pub execution_harness: ExecutionHarness,
    pub random_generator: RandomStateGenerator,
}

impl Simulator {
    pub fn new() -> crate::error::Result<Self> {
        Ok(Self {
            assembly_generator: AssemblyGenerator::new(),
            compilation_pipeline: CompilationPipeline::new()?,
            execution_harness: ExecutionHarness::new(),
            random_generator: RandomStateGenerator::new(),
        })
    }

    pub fn simulate_block(
        &mut self,
        extraction: &ExtractionInfo,
        analysis: &BlockAnalysis,
        emulator: Option<EmulatorConfig>,
        keep_files: bool,
    ) -> crate::error::Result<SimulationResult> {
        // Generate random initial state
        let initial_state = self.random_generator.generate_initial_state(analysis);

        // Generate assembly file
        // TODO: Create and pass SandboxMemoryLayout once binary section loading is integrated
        let assembly_source = self.assembly_generator.generate_simulation_file(
            extraction,
            analysis,
            &initial_state,
            None, // No sandbox for now - maintains backward compatibility
        )?;

        // Compile and link
        let (binary_path, assembly_path) = self
            .compilation_pipeline
            .compile_and_link(&assembly_source, &format!("simulation_{}", Uuid::new_v4()))?;

        // Execute
        let execution_result = self
            .execution_harness
            .execute_binary(&binary_path, emulator.as_ref())?;

        // Parse final state from execution output
        let final_state = FinalState::parse_from_output(&execution_result.output_data)?;

        // Clean up files if not keeping them
        let (assembly_file_path, binary_file_path) = if keep_files {
            (
                Some(assembly_path.to_string_lossy().to_string()),
                Some(binary_path.to_string_lossy().to_string()),
            )
        } else {
            let _ = std::fs::remove_file(&assembly_path);
            let _ = std::fs::remove_file(&binary_path);
            (None, None)
        };

        Ok(SimulationResult::new(
            initial_state,
            final_state,
            execution_result.execution_time,
            execution_result.exit_code,
            Some(emulator.map_or_else(
                || EmulatorConfig::Native.name_with_host_info(),
                |e| e.name_with_host_info(),
            )),
            assembly_file_path,
            binary_file_path,
        ))
    }
}
