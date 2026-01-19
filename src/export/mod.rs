pub mod csv;
pub mod html;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[allow(unused_imports)]
pub use csv::{
    BlockMetadataRow, CsvExportConfig, CsvExporter, SimulationResultRow, ValidationResultRow,
};
#[allow(unused_imports)]
pub use html::{BlockValidationResult, HtmlReportGenerator};

use crate::analyzer::BlockAnalysis;
use crate::db::{BinaryInfo, ExtractionInfo};
use crate::simulator::SimulationResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportMetadata {
    pub version: String,
    pub export_date: String,
    pub host_info: HostInfo,
    pub export_type: ExportType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub architecture: String,
    pub machine_id: String,
    pub kernel: String,
    pub os: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExportType {
    SingleBlock { extraction_id: i64 },
    MultipleBlocks { extraction_ids: Vec<i64> },
    FullDatabase,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportBundle {
    pub metadata: ExportMetadata,
    pub binaries: Vec<BinaryInfo>,
    pub extractions: Vec<ExtractionData>,
    pub analyses: Vec<AnalysisData>,
    pub simulations: Vec<SimulationData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionData {
    pub id: i64,
    pub binary_hash: String,
    pub start_address: u64,
    pub end_address: u64,
    pub assembly_block: Vec<u8>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisData {
    pub extraction_id: i64,
    pub instructions_count: u32,
    pub live_in_registers: Vec<String>,
    pub live_out_registers: Vec<String>,
    pub exit_points: Vec<u64>,
    pub memory_accesses: Vec<String>,
    pub analyzed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationData {
    pub extraction_id: i64,
    pub simulation_id: String,
    pub initial_registers: HashMap<String, u64>,
    pub initial_memory: HashMap<u64, Vec<u8>>,
    pub final_registers: HashMap<String, u64>,
    pub final_memory: HashMap<u64, Vec<u8>>,
    pub final_flags: u64,
    pub execution_time_ns: u64,
    pub exit_code: i32,
    pub emulator_used: String,
    pub assembly_file_path: Option<String>,
    pub binary_file_path: Option<String>,
    pub created_at: String,
}

impl ExportMetadata {
    pub fn new(export_type: ExportType) -> Self {
        Self {
            version: "1.0".to_string(),
            export_date: chrono::Utc::now().to_rfc3339(),
            host_info: HostInfo::current(),
            export_type,
        }
    }
}

impl HostInfo {
    pub fn current() -> Self {
        let machine_id = get_machine_id();
        let kernel = get_kernel_version();

        Self {
            architecture: std::env::consts::ARCH.to_string(),
            machine_id,
            kernel,
            os: std::env::consts::OS.to_string(),
        }
    }
}

impl From<&ExtractionInfo> for ExtractionData {
    fn from(extraction: &ExtractionInfo) -> Self {
        Self {
            id: 0, // Will be set by the exporter
            binary_hash: extraction.binary_hash.clone(),
            start_address: extraction.start_address,
            end_address: extraction.end_address,
            assembly_block: extraction.assembly_block.clone(),
            created_at: extraction.created_at.clone(),
        }
    }
}

impl From<&BlockAnalysis> for AnalysisData {
    fn from(analysis: &BlockAnalysis) -> Self {
        Self {
            extraction_id: 0, // Will be set by the exporter
            instructions_count: analysis.instructions_count as u32,
            live_in_registers: analysis.live_in_registers.iter().cloned().collect(),
            live_out_registers: analysis.live_out_registers.iter().cloned().collect(),
            exit_points: analysis.exit_points.iter().map(|ep| ep.offset).collect(),
            memory_accesses: analysis
                .memory_accesses
                .iter()
                .map(|ma| format!("{:?}", ma))
                .collect(),
            analyzed_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

impl From<&SimulationResult> for SimulationData {
    fn from(simulation: &SimulationResult) -> Self {
        Self {
            extraction_id: 0, // Will be set by the exporter
            simulation_id: simulation.simulation_id.clone(),
            initial_registers: simulation.initial_state.registers.clone(),
            initial_memory: simulation.initial_state.memory_locations.clone(),
            final_registers: simulation.final_state.registers.clone(),
            final_memory: simulation.final_state.memory_locations.clone(),
            final_flags: simulation.final_state.flags,
            execution_time_ns: simulation.execution_time.as_nanos() as u64,
            exit_code: simulation.exit_code,
            emulator_used: simulation
                .emulator_used
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            assembly_file_path: simulation.assembly_file_path.clone(),
            binary_file_path: simulation.binary_file_path.clone(),
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

fn get_machine_id() -> String {
    // Try to get a unique machine identifier
    if let Ok(hostname) = std::process::Command::new("hostname")
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
    {
        if !hostname.is_empty() {
            return hostname;
        }
    }

    // Fallback: use a hash of available system info
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    std::env::consts::OS.hash(&mut hasher);
    std::env::consts::ARCH.hash(&mut hasher);
    if let Ok(user) = std::env::var("USER") {
        user.hash(&mut hasher);
    }

    format!("host-{:x}", hasher.finish())
}

fn get_kernel_version() -> String {
    if let Ok(output) = std::process::Command::new("uname").arg("-r").output() {
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    } else {
        "unknown".to_string()
    }
}
