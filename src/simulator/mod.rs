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
#[allow(unused_imports)]
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
        self.simulate_block_with_state(extraction, analysis, &initial_state, emulator, keep_files)
    }

    /// Simulate a block with a provided initial state.
    /// Used by remote execution to replay with the same state.
    pub fn simulate_block_with_state(
        &mut self,
        extraction: &ExtractionInfo,
        analysis: &BlockAnalysis,
        initial_state: &InitialState,
        emulator: Option<EmulatorConfig>,
        keep_files: bool,
    ) -> crate::error::Result<SimulationResult> {
        // Create sandbox with address translation if binary has valid base address
        let sandbox = if extraction.binary_base_address > 0 {
            use crate::extractor::section_loader::BinarySectionLoader;
            use sandbox::SandboxMemoryLayout;
            use std::path::Path;

            let binary_path = Path::new(&extraction.binary_path);
            if binary_path.exists() {
                let mut sandbox_layout = SandboxMemoryLayout::new(extraction.binary_base_address);

                if let Ok(loader) = BinarySectionLoader::new(binary_path) {
                    if let Ok((text_meta, text_data)) = loader.extract_text_section() {
                        let _ = sandbox_layout.add_section(text_meta, Some(text_data));
                    }
                    if let Ok((data_meta, data_data)) = loader.extract_data_section() {
                        let _ = sandbox_layout.add_section(data_meta, Some(data_data));
                    }
                    if let Ok((rodata_meta, rodata_data)) = loader.extract_rodata_section() {
                        let _ = sandbox_layout.add_section(rodata_meta, Some(rodata_data));
                    }
                    Some(sandbox_layout)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        // Generate assembly file with sandbox for address translation
        let assembly_source = self.assembly_generator.generate_simulation_file(
            extraction,
            analysis,
            initial_state,
            sandbox.as_ref(),
        )?;

        // DEBUG: Save assembly to /tmp for inspection
        let debug_asm_path = format!("/tmp/debug_simulation_{}.asm", Uuid::new_v4());
        if let Err(e) = std::fs::write(&debug_asm_path, &assembly_source) {
            eprintln!(
                "Warning: Could not save debug assembly to {}: {}",
                debug_asm_path, e
            );
        } else {
            eprintln!("DEBUG: Assembly saved to {}", debug_asm_path);
        }

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
            initial_state.clone(),
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
