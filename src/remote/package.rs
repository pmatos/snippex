//! Execution package format for transferring simulation data between machines.
//!
//! An ExecutionPackage contains all the data needed to run a simulation
//! on a remote machine:
//! - The source binary (or reference to it)
//! - Extraction metadata (addresses, block data)
//! - Analysis results
//! - Initial state for simulation
//! - Emulator configuration

#![allow(dead_code)]

use crate::analyzer::BlockAnalysis;
use crate::db::ExtractionInfo;
use crate::error::{Error, Result};
use crate::simulator::{EmulatorConfig, InitialState};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Metadata about an execution package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageMetadata {
    /// Unique identifier for this package
    pub package_id: String,
    /// Version of the package format
    pub format_version: u32,
    /// Timestamp when the package was created
    pub created_at: String,
    /// Hostname of the machine that created the package
    pub created_by: String,
}

impl Default for PackageMetadata {
    fn default() -> Self {
        Self::new()
    }
}

impl PackageMetadata {
    pub fn new() -> Self {
        Self {
            package_id: Uuid::new_v4().to_string(),
            format_version: 1,
            created_at: chrono::Utc::now().to_rfc3339(),
            created_by: hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string()),
        }
    }
}

/// Extraction data serializable for package transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionData {
    /// Database ID of the extraction
    pub id: i64,
    /// Path to the binary on the original machine
    pub binary_path: String,
    /// SHA256 hash of the binary
    pub binary_hash: String,
    /// Binary format (ELF, PE)
    pub binary_format: String,
    /// Binary architecture (x86_64, i386)
    pub binary_architecture: String,
    /// Base address where the binary is loaded
    pub binary_base_address: u64,
    /// Start address of the extracted block
    pub start_address: u64,
    /// End address of the extracted block
    pub end_address: u64,
    /// The raw assembly bytes
    pub assembly_block: Vec<u8>,
}

impl From<&ExtractionInfo> for ExtractionData {
    fn from(info: &ExtractionInfo) -> Self {
        Self {
            id: info.id,
            binary_path: info.binary_path.clone(),
            binary_hash: info.binary_hash.clone(),
            binary_format: info.binary_format.clone(),
            binary_architecture: info.binary_architecture.clone(),
            binary_base_address: info.binary_base_address,
            start_address: info.start_address,
            end_address: info.end_address,
            assembly_block: info.assembly_block.clone(),
        }
    }
}

/// Analysis data serializable for package transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisData {
    pub instructions_count: usize,
    pub live_in_registers: Vec<String>,
    pub live_out_registers: Vec<String>,
    pub exit_points: Vec<crate::analyzer::ExitPoint>,
    pub memory_accesses: Vec<crate::analyzer::MemoryAccess>,
    pub pointer_registers: std::collections::HashMap<String, crate::analyzer::PointerRegisterUsage>,
}

impl From<&BlockAnalysis> for AnalysisData {
    fn from(analysis: &BlockAnalysis) -> Self {
        Self {
            instructions_count: analysis.instructions_count,
            live_in_registers: analysis.live_in_registers.iter().cloned().collect(),
            live_out_registers: analysis.live_out_registers.iter().cloned().collect(),
            exit_points: analysis.exit_points.clone(),
            memory_accesses: analysis.memory_accesses.clone(),
            pointer_registers: analysis.pointer_registers.clone(),
        }
    }
}

impl From<&AnalysisData> for BlockAnalysis {
    fn from(data: &AnalysisData) -> Self {
        Self {
            instructions_count: data.instructions_count,
            live_in_registers: data.live_in_registers.iter().cloned().collect(),
            live_out_registers: data.live_out_registers.iter().cloned().collect(),
            exit_points: data.exit_points.clone(),
            memory_accesses: data.memory_accesses.clone(),
            pointer_registers: data.pointer_registers.clone(),
        }
    }
}

/// Emulator configuration serializable for package transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EmulatorData {
    Native,
    Qemu { binary: String, args: Vec<String> },
    FexEmu { binary: String, args: Vec<String> },
}

impl From<&EmulatorConfig> for EmulatorData {
    fn from(config: &EmulatorConfig) -> Self {
        match config {
            EmulatorConfig::Native => EmulatorData::Native,
            EmulatorConfig::Qemu { binary, args } => EmulatorData::Qemu {
                binary: binary.clone(),
                args: args.clone(),
            },
            EmulatorConfig::FexEmu { binary, args } => EmulatorData::FexEmu {
                binary: binary.clone(),
                args: args.clone(),
            },
        }
    }
}

impl From<&EmulatorData> for EmulatorConfig {
    fn from(data: &EmulatorData) -> Self {
        match data {
            EmulatorData::Native => EmulatorConfig::Native,
            EmulatorData::Qemu { binary, args } => EmulatorConfig::Qemu {
                binary: binary.clone(),
                args: args.clone(),
            },
            EmulatorData::FexEmu { binary, args } => EmulatorConfig::FexEmu {
                binary: binary.clone(),
                args: args.clone(),
            },
        }
    }
}

/// Complete execution package for remote simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPackage {
    /// Package metadata
    pub metadata: PackageMetadata,
    /// Extraction data
    pub extraction: ExtractionData,
    /// Analysis results
    pub analysis: AnalysisData,
    /// Initial state for simulation
    pub initial_state: InitialState,
    /// Emulator configuration
    pub emulator: Option<EmulatorData>,
    /// Whether the binary file is included in the package
    pub binary_included: bool,
}

impl ExecutionPackage {
    /// Create a new execution package from simulation inputs.
    pub fn new(
        extraction: &ExtractionInfo,
        analysis: &BlockAnalysis,
        initial_state: &InitialState,
        emulator: Option<&EmulatorConfig>,
    ) -> Self {
        Self {
            metadata: PackageMetadata::new(),
            extraction: ExtractionData::from(extraction),
            analysis: AnalysisData::from(analysis),
            initial_state: initial_state.clone(),
            emulator: emulator.map(EmulatorData::from),
            binary_included: false,
        }
    }

    /// Save the package to a directory, optionally including the binary.
    pub fn save_to_directory(&self, dir: &Path, include_binary: bool) -> Result<PathBuf> {
        // Create the package directory
        fs::create_dir_all(dir).map_err(Error::Io)?;

        // Save metadata
        let metadata_path = dir.join("metadata.json");
        let metadata_json = serde_json::to_string_pretty(&self.metadata)
            .map_err(|e| Error::InvalidBinary(format!("Failed to serialize metadata: {}", e)))?;
        fs::write(&metadata_path, metadata_json).map_err(Error::Io)?;

        // Save extraction data
        let extraction_path = dir.join("extraction.json");
        let extraction_json = serde_json::to_string_pretty(&self.extraction)
            .map_err(|e| Error::InvalidBinary(format!("Failed to serialize extraction: {}", e)))?;
        fs::write(&extraction_path, extraction_json).map_err(Error::Io)?;

        // Save analysis data
        let analysis_path = dir.join("analysis.json");
        let analysis_json = serde_json::to_string_pretty(&self.analysis)
            .map_err(|e| Error::InvalidBinary(format!("Failed to serialize analysis: {}", e)))?;
        fs::write(&analysis_path, analysis_json).map_err(Error::Io)?;

        // Save initial state
        let state_path = dir.join("initial_state.json");
        let state_json = serde_json::to_string_pretty(&self.initial_state)
            .map_err(|e| Error::InvalidBinary(format!("Failed to serialize state: {}", e)))?;
        fs::write(&state_path, state_json).map_err(Error::Io)?;

        // Save emulator config if present
        if let Some(ref emulator) = self.emulator {
            let emulator_path = dir.join("emulator.json");
            let emulator_json = serde_json::to_string_pretty(emulator).map_err(|e| {
                Error::InvalidBinary(format!("Failed to serialize emulator config: {}", e))
            })?;
            fs::write(&emulator_path, emulator_json).map_err(Error::Io)?;
        }

        // Copy binary file if requested and source exists
        if include_binary {
            let binary_source = Path::new(&self.extraction.binary_path);
            if binary_source.exists() {
                let binary_dest = dir.join("binary");
                fs::copy(binary_source, &binary_dest).map_err(Error::Io)?;

                // Update manifest to indicate binary is included
                let manifest_path = dir.join("manifest.json");
                let manifest = serde_json::json!({
                    "binary_included": true,
                    "binary_filename": "binary",
                    "original_path": self.extraction.binary_path,
                });
                fs::write(
                    &manifest_path,
                    serde_json::to_string_pretty(&manifest).unwrap(),
                )
                .map_err(Error::Io)?;
            }
        }

        Ok(dir.to_path_buf())
    }

    /// Load a package from a directory.
    pub fn load_from_directory(dir: &Path) -> Result<Self> {
        // Load metadata
        let metadata_path = dir.join("metadata.json");
        let metadata_json = fs::read_to_string(&metadata_path).map_err(Error::Io)?;
        let metadata: PackageMetadata = serde_json::from_str(&metadata_json)
            .map_err(|e| Error::InvalidBinary(format!("Failed to parse metadata: {}", e)))?;

        // Load extraction data
        let extraction_path = dir.join("extraction.json");
        let extraction_json = fs::read_to_string(&extraction_path).map_err(Error::Io)?;
        let extraction: ExtractionData = serde_json::from_str(&extraction_json)
            .map_err(|e| Error::InvalidBinary(format!("Failed to parse extraction: {}", e)))?;

        // Load analysis data
        let analysis_path = dir.join("analysis.json");
        let analysis_json = fs::read_to_string(&analysis_path).map_err(Error::Io)?;
        let analysis: AnalysisData = serde_json::from_str(&analysis_json)
            .map_err(|e| Error::InvalidBinary(format!("Failed to parse analysis: {}", e)))?;

        // Load initial state
        let state_path = dir.join("initial_state.json");
        let state_json = fs::read_to_string(&state_path).map_err(Error::Io)?;
        let initial_state: InitialState = serde_json::from_str(&state_json)
            .map_err(|e| Error::InvalidBinary(format!("Failed to parse initial state: {}", e)))?;

        // Load emulator config if present
        let emulator_path = dir.join("emulator.json");
        let emulator = if emulator_path.exists() {
            let emulator_json = fs::read_to_string(&emulator_path).map_err(Error::Io)?;
            Some(serde_json::from_str(&emulator_json).map_err(|e| {
                Error::InvalidBinary(format!("Failed to parse emulator config: {}", e))
            })?)
        } else {
            None
        };

        // Check if binary is included
        let manifest_path = dir.join("manifest.json");
        let binary_included = manifest_path.exists();

        Ok(Self {
            metadata,
            extraction,
            analysis,
            initial_state,
            emulator,
            binary_included,
        })
    }

    /// Create a tarball from a package directory.
    pub fn create_tarball(package_dir: &Path, output_path: &Path) -> Result<PathBuf> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use tar::Builder;

        let tar_gz = File::create(output_path).map_err(Error::Io)?;
        let enc = GzEncoder::new(tar_gz, Compression::default());
        let mut tar = Builder::new(enc);

        // Add all files from the package directory
        tar.append_dir_all("package", package_dir)
            .map_err(|e| Error::Io(std::io::Error::other(e)))?;

        tar.finish()
            .map_err(|e| Error::Io(std::io::Error::other(e)))?;

        Ok(output_path.to_path_buf())
    }

    /// Extract a tarball to a directory.
    pub fn extract_tarball(tarball_path: &Path, output_dir: &Path) -> Result<PathBuf> {
        use flate2::read::GzDecoder;
        use tar::Archive;

        let tar_gz = File::open(tarball_path).map_err(Error::Io)?;
        let dec = GzDecoder::new(tar_gz);
        let mut archive = Archive::new(dec);

        archive
            .unpack(output_dir)
            .map_err(|e| Error::Io(std::io::Error::other(e)))?;

        // The tarball contains a "package" subdirectory
        Ok(output_dir.join("package"))
    }

    /// Get the path to the binary file within the package directory.
    pub fn get_binary_path(&self, package_dir: &Path) -> Option<PathBuf> {
        if self.binary_included {
            let binary_path = package_dir.join("binary");
            if binary_path.exists() {
                return Some(binary_path);
            }
        }
        // Fallback to original path if binary not in package
        let original_path = Path::new(&self.extraction.binary_path);
        if original_path.exists() {
            Some(original_path.to_path_buf())
        } else {
            None
        }
    }

    /// Convert extraction data back to ExtractionInfo for simulation.
    pub fn to_extraction_info(&self, binary_path_override: Option<&Path>) -> ExtractionInfo {
        ExtractionInfo {
            id: self.extraction.id,
            binary_path: binary_path_override
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| self.extraction.binary_path.clone()),
            binary_hash: self.extraction.binary_hash.clone(),
            binary_format: self.extraction.binary_format.clone(),
            binary_architecture: self.extraction.binary_architecture.clone(),
            binary_base_address: self.extraction.binary_base_address,
            start_address: self.extraction.start_address,
            end_address: self.extraction.end_address,
            assembly_block: self.extraction.assembly_block.clone(),
            created_at: String::new(),
            analysis_status: "analyzed".to_string(),
            analysis_results: None,
        }
    }

    /// Convert analysis data back to BlockAnalysis for simulation.
    pub fn to_block_analysis(&self) -> BlockAnalysis {
        BlockAnalysis::from(&self.analysis)
    }

    /// Get emulator config if present.
    pub fn to_emulator_config(&self) -> Option<EmulatorConfig> {
        self.emulator.as_ref().map(EmulatorConfig::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use tempfile::TempDir;

    fn create_test_extraction() -> ExtractionInfo {
        ExtractionInfo {
            id: 1,
            binary_path: "/bin/ls".to_string(),
            binary_hash: "abc123".to_string(),
            binary_format: "ELF".to_string(),
            binary_architecture: "x86_64".to_string(),
            binary_base_address: 0x400000,
            start_address: 0x401000,
            end_address: 0x401020,
            assembly_block: vec![0x55, 0x48, 0x89, 0xe5], // push rbp; mov rbp, rsp
            created_at: "2024-01-01".to_string(),
            analysis_status: "analyzed".to_string(),
            analysis_results: None,
        }
    }

    fn create_test_analysis() -> BlockAnalysis {
        BlockAnalysis {
            instructions_count: 2,
            live_in_registers: HashSet::from(["rbp".to_string(), "rsp".to_string()]),
            live_out_registers: HashSet::from(["rbp".to_string()]),
            exit_points: vec![],
            memory_accesses: vec![],
            pointer_registers: HashMap::new(),
        }
    }

    fn create_test_initial_state() -> InitialState {
        let mut state = InitialState::new();
        state.set_register("rax", 0x1234);
        state.set_register("rbx", 0x5678);
        state
    }

    #[test]
    fn test_package_creation() {
        let extraction = create_test_extraction();
        let analysis = create_test_analysis();
        let initial_state = create_test_initial_state();

        let package = ExecutionPackage::new(&extraction, &analysis, &initial_state, None);

        assert_eq!(package.extraction.id, 1);
        assert_eq!(package.extraction.binary_hash, "abc123");
        assert_eq!(package.analysis.instructions_count, 2);
        assert!(package.emulator.is_none());
    }

    #[test]
    fn test_package_with_emulator() {
        let extraction = create_test_extraction();
        let analysis = create_test_analysis();
        let initial_state = create_test_initial_state();
        let emulator = EmulatorConfig::fex_emu();

        let package =
            ExecutionPackage::new(&extraction, &analysis, &initial_state, Some(&emulator));

        assert!(package.emulator.is_some());
        match &package.emulator {
            Some(EmulatorData::FexEmu { binary, .. }) => {
                assert_eq!(binary, "FEXInterpreter");
            }
            _ => panic!("Expected FexEmu emulator"),
        }
    }

    #[test]
    fn test_package_save_and_load() {
        let extraction = create_test_extraction();
        let analysis = create_test_analysis();
        let initial_state = create_test_initial_state();

        let package = ExecutionPackage::new(&extraction, &analysis, &initial_state, None);

        let temp_dir = TempDir::new().unwrap();
        let package_dir = temp_dir.path().join("test_package");

        // Save package (without binary since /bin/ls test won't work everywhere)
        package.save_to_directory(&package_dir, false).unwrap();

        // Load package
        let loaded = ExecutionPackage::load_from_directory(&package_dir).unwrap();

        assert_eq!(loaded.extraction.id, package.extraction.id);
        assert_eq!(
            loaded.extraction.binary_hash,
            package.extraction.binary_hash
        );
        assert_eq!(
            loaded.analysis.instructions_count,
            package.analysis.instructions_count
        );
    }

    #[test]
    fn test_extraction_data_conversion() {
        let extraction = create_test_extraction();
        let data = ExtractionData::from(&extraction);

        assert_eq!(data.id, extraction.id);
        assert_eq!(data.binary_path, extraction.binary_path);
        assert_eq!(data.start_address, extraction.start_address);
    }

    #[test]
    fn test_analysis_data_roundtrip() {
        let analysis = create_test_analysis();
        let data = AnalysisData::from(&analysis);
        let restored = BlockAnalysis::from(&data);

        assert_eq!(restored.instructions_count, analysis.instructions_count);
        assert_eq!(restored.live_in_registers, analysis.live_in_registers);
    }
}
