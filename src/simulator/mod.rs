pub mod assembly_generator;
pub mod compilation;
pub mod diagnostics;
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
        Self::for_target("x86_64")
    }

    pub fn for_target(target_arch: &str) -> crate::error::Result<Self> {
        Ok(Self {
            assembly_generator: AssemblyGenerator::new(),
            compilation_pipeline: CompilationPipeline::for_target(target_arch)?,
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

    /// Compile a simulation binary without executing it.
    /// Returns the path to the compiled binary in a persistent location.
    /// Used when we need to compile once and run through multiple emulators.
    pub fn compile_simulation_binary(
        &self,
        extraction: &ExtractionInfo,
        analysis: &BlockAnalysis,
        initial_state: &InitialState,
    ) -> crate::error::Result<std::path::PathBuf> {
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

        // Compile and link (binary is in pipeline's temp dir)
        let (temp_binary_path, _assembly_path) = self
            .compilation_pipeline
            .compile_and_link(&assembly_source, &format!("simulation_{}", Uuid::new_v4()))?;

        // Copy binary to a persistent location (outside the pipeline's temp dir)
        // This prevents the binary from being deleted when the simulator is dropped
        let persistent_path =
            std::path::PathBuf::from(format!("/tmp/snippex_sim_{}", Uuid::new_v4()));
        std::fs::copy(&temp_binary_path, &persistent_path).map_err(|e| {
            crate::error::Error::Simulation(format!(
                "Failed to copy binary to persistent location: {}",
                e
            ))
        })?;

        // Make it executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&persistent_path)
                .map_err(|e| {
                    crate::error::Error::Simulation(format!(
                        "Failed to get binary permissions: {}",
                        e
                    ))
                })?
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&persistent_path, perms).map_err(|e| {
                crate::error::Error::Simulation(format!("Failed to set binary permissions: {}", e))
            })?;
        }

        Ok(persistent_path)
    }

    /// Run a pre-compiled binary directly, skipping assembly generation and compilation.
    /// Used for remote execution where we transfer the compiled binary instead of re-compiling.
    pub fn run_precompiled_binary(
        &self,
        binary_path: &std::path::Path,
        initial_state: &InitialState,
        emulator: Option<EmulatorConfig>,
    ) -> crate::error::Result<SimulationResult> {
        // Execute the pre-compiled binary
        let execution_result = self
            .execution_harness
            .execute_binary(binary_path, emulator.as_ref())?;

        // Parse final state from execution output
        let final_state = FinalState::parse_from_output(&execution_result.output_data)?;

        Ok(SimulationResult::new(
            initial_state.clone(),
            final_state,
            execution_result.execution_time,
            execution_result.exit_code,
            Some(emulator.map_or_else(
                || EmulatorConfig::Native.name_with_host_info(),
                |e| e.name_with_host_info(),
            )),
            None, // No assembly file - we used pre-compiled binary
            Some(binary_path.to_string_lossy().to_string()),
        ))
    }
}
