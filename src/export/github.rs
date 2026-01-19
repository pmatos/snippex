//! GitHub issue creation for FEX-Emu bug reports.
//!
//! This module provides templates and utilities for creating GitHub issues
//! from validation failures detected by snippex.

#![allow(dead_code)]

use crate::db::ExtractionInfo;
use crate::export::{AnalysisData, HostInfo};
use crate::simulator::SimulationResult;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Write;

/// Configuration for GitHub issue creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubConfig {
    /// Target repository (e.g., "FEX-Emu/FEX")
    pub repository: String,
    /// Labels to apply to created issues
    pub labels: Vec<String>,
    /// Optional assignees
    pub assignees: Vec<String>,
    /// Personal access token (stored separately for security)
    pub token_env_var: String,
}

impl Default for GitHubConfig {
    fn default() -> Self {
        Self {
            repository: "FEX-Emu/FEX".to_string(),
            labels: vec![
                "bug".to_string(),
                "snippex".to_string(),
                "needs-triage".to_string(),
            ],
            assignees: vec![],
            token_env_var: "GITHUB_TOKEN".to_string(),
        }
    }
}

/// Data needed to create a GitHub issue from a validation failure.
#[derive(Debug, Clone)]
pub struct IssueData {
    /// Block extraction info
    pub extraction: ExtractionInfo,
    /// Block analysis (instructions, registers, etc.)
    pub analysis: Option<AnalysisData>,
    /// Native simulation result (ground truth)
    pub native_result: SimulationResult,
    /// FEX-Emu simulation result (to compare)
    pub fex_result: SimulationResult,
    /// Host information where validation was run
    pub host_info: HostInfo,
    /// Additional notes or context
    pub notes: Option<String>,
}

/// Template for GitHub issue creation.
#[derive(Debug, Clone)]
pub struct IssueTemplate {
    pub title: String,
    pub body: String,
    pub labels: Vec<String>,
}

/// Generates a unique signature for an issue to detect duplicates.
pub fn generate_issue_signature(extraction: &ExtractionInfo, differences: &[String]) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(&extraction.assembly_block);
    for diff in differences {
        hasher.update(diff.as_bytes());
    }
    format!("{:x}", hasher.finalize())[..16].to_string()
}

/// Generates a descriptive title for the issue.
pub fn generate_issue_title(extraction: &ExtractionInfo, differences: &[String]) -> String {
    let block_size = extraction.assembly_block.len();
    let signature = generate_issue_signature(extraction, differences);

    let diff_summary = if differences.len() == 1 {
        differences[0].clone()
    } else if differences.len() <= 3 {
        differences.join(", ")
    } else {
        format!("{} and {} more differences", differences[0], differences.len() - 1)
    };

    format!(
        "[snippex] Validation failure: {} ({} bytes, sig:{})",
        diff_summary, block_size, signature
    )
}

/// Builds the full issue body from validation failure data.
pub fn build_issue_body(data: &IssueData) -> String {
    let mut body = String::new();

    // Header
    writeln!(body, "## Summary").unwrap();
    writeln!(body).unwrap();
    writeln!(
        body,
        "Snippex detected a validation failure when comparing native x86 execution \
        against FEX-Emu emulation for an assembly block."
    ).unwrap();
    writeln!(body).unwrap();

    // Block Information
    writeln!(body, "## Block Information").unwrap();
    writeln!(body).unwrap();
    writeln!(body, "| Property | Value |").unwrap();
    writeln!(body, "|----------|-------|").unwrap();
    writeln!(body, "| Binary Hash | `{}` |", data.extraction.binary_hash).unwrap();
    writeln!(
        body,
        "| Address Range | `0x{:016x}` - `0x{:016x}` |",
        data.extraction.start_address, data.extraction.end_address
    ).unwrap();
    writeln!(body, "| Block Size | {} bytes |", data.extraction.assembly_block.len()).unwrap();
    if let Some(ref analysis) = data.analysis {
        writeln!(body, "| Instructions | {} |", analysis.instructions_count).unwrap();
    }
    writeln!(body).unwrap();

    // Disassembly
    writeln!(body, "## Assembly Code").unwrap();
    writeln!(body).unwrap();
    writeln!(body, "<details>").unwrap();
    writeln!(body, "<summary>Click to expand disassembly</summary>").unwrap();
    writeln!(body).unwrap();
    writeln!(body, "```asm").unwrap();
    // Note: Actual disassembly would be added here by the caller
    writeln!(body, "; (Disassembly would be inserted here)").unwrap();
    writeln!(body, "```").unwrap();
    writeln!(body).unwrap();
    writeln!(body, "</details>").unwrap();
    writeln!(body).unwrap();

    // Raw bytes
    writeln!(body, "## Raw Bytes").unwrap();
    writeln!(body).unwrap();
    writeln!(body, "```").unwrap();
    write_hex_dump(&mut body, &data.extraction.assembly_block);
    writeln!(body, "```").unwrap();
    writeln!(body).unwrap();

    // State Comparison
    writeln!(body, "## State Comparison").unwrap();
    writeln!(body).unwrap();

    // Register differences
    writeln!(body, "### Register Differences").unwrap();
    writeln!(body).unwrap();
    let reg_diffs = find_register_differences(&data.native_result, &data.fex_result);
    if reg_diffs.is_empty() {
        writeln!(body, "No register differences detected.").unwrap();
    } else {
        writeln!(body, "| Register | Native | FEX-Emu |").unwrap();
        writeln!(body, "|----------|--------|---------|").unwrap();
        for (reg, native_val, fex_val) in &reg_diffs {
            writeln!(body, "| {} | `0x{:016x}` | `0x{:016x}` |", reg, native_val, fex_val).unwrap();
        }
    }
    writeln!(body).unwrap();

    // Flag differences
    writeln!(body, "### Flag Differences").unwrap();
    writeln!(body).unwrap();
    let native_flags = data.native_result.final_state.flags;
    let fex_flags = data.fex_result.final_state.flags;
    if native_flags == fex_flags {
        writeln!(body, "No flag differences detected.").unwrap();
    } else {
        writeln!(body, "| Flags | Native | FEX-Emu |").unwrap();
        writeln!(body, "|-------|--------|---------|").unwrap();
        writeln!(
            body,
            "| RFLAGS | `0x{:016x}` | `0x{:016x}` |",
            native_flags, fex_flags
        ).unwrap();
        write_flag_breakdown(&mut body, native_flags, fex_flags);
    }
    writeln!(body).unwrap();

    // Memory differences
    writeln!(body, "### Memory Differences").unwrap();
    writeln!(body).unwrap();
    let mem_diffs = find_memory_differences(&data.native_result, &data.fex_result);
    if mem_diffs.is_empty() {
        writeln!(body, "No memory differences detected.").unwrap();
    } else {
        writeln!(body, "Found {} memory region(s) with differences.", mem_diffs.len()).unwrap();
        writeln!(body).unwrap();
        for (addr, native_bytes, fex_bytes) in &mem_diffs {
            writeln!(body, "**Address `0x{:016x}`:**", addr).unwrap();
            writeln!(body, "- Native: `{}`", bytes_to_hex(native_bytes)).unwrap();
            writeln!(body, "- FEX-Emu: `{}`", bytes_to_hex(fex_bytes)).unwrap();
            writeln!(body).unwrap();
        }
    }

    // Initial State (collapsed)
    writeln!(body, "## Initial State").unwrap();
    writeln!(body).unwrap();
    writeln!(body, "<details>").unwrap();
    writeln!(body, "<summary>Click to expand initial state</summary>").unwrap();
    writeln!(body).unwrap();
    write_state_section(&mut body, "Initial Registers", &data.native_result.initial_state.registers);
    write_memory_section(&mut body, "Initial Memory", &data.native_result.initial_state.memory_locations);
    writeln!(body, "</details>").unwrap();
    writeln!(body).unwrap();

    // Reproduction Steps
    writeln!(body, "## Reproduction").unwrap();
    writeln!(body).unwrap();
    writeln!(body, "To reproduce this issue:").unwrap();
    writeln!(body).unwrap();
    writeln!(body, "1. Extract the block from the database:").unwrap();
    writeln!(body, "   ```bash").unwrap();
    writeln!(body, "   snippex show --id <extraction_id> --format nasm > block.asm").unwrap();
    writeln!(body, "   ```").unwrap();
    writeln!(body).unwrap();
    writeln!(body, "2. Run native simulation:").unwrap();
    writeln!(body, "   ```bash").unwrap();
    writeln!(body, "   snippex simulate --id <extraction_id>").unwrap();
    writeln!(body, "   ```").unwrap();
    writeln!(body).unwrap();
    writeln!(body, "3. Run FEX-Emu simulation:").unwrap();
    writeln!(body, "   ```bash").unwrap();
    writeln!(body, "   snippex simulate --id <extraction_id> --emulator fex").unwrap();
    writeln!(body, "   ```").unwrap();
    writeln!(body).unwrap();

    // Environment
    writeln!(body, "## Environment").unwrap();
    writeln!(body).unwrap();
    writeln!(body, "| Property | Value |").unwrap();
    writeln!(body, "|----------|-------|").unwrap();
    writeln!(body, "| Architecture | {} |", data.host_info.architecture).unwrap();
    writeln!(body, "| OS | {} |", data.host_info.os).unwrap();
    writeln!(body, "| Kernel | {} |", data.host_info.kernel).unwrap();
    writeln!(body, "| Machine ID | {} |", data.host_info.machine_id).unwrap();
    writeln!(body).unwrap();

    // Signature
    let differences = collect_all_differences(data);
    let signature = generate_issue_signature(&data.extraction, &differences);
    writeln!(body, "---").unwrap();
    writeln!(body, "*Issue signature: `{}`*", signature).unwrap();
    writeln!(body, "*Generated by snippex*").unwrap();

    body
}

/// Creates an IssueTemplate from validation failure data.
pub fn create_issue_template(data: &IssueData) -> IssueTemplate {
    let differences = collect_all_differences(data);
    let title = generate_issue_title(&data.extraction, &differences);
    let body = build_issue_body(data);

    IssueTemplate {
        title,
        body,
        labels: GitHubConfig::default().labels,
    }
}

// Helper functions

fn write_hex_dump(output: &mut String, bytes: &[u8]) {
    for (i, chunk) in bytes.chunks(16).enumerate() {
        write!(output, "{:08x}  ", i * 16).unwrap();
        for (j, byte) in chunk.iter().enumerate() {
            if j == 8 {
                write!(output, " ").unwrap();
            }
            write!(output, "{:02x} ", byte).unwrap();
        }
        // Pad if less than 16 bytes
        for j in chunk.len()..16 {
            if j == 8 {
                write!(output, " ").unwrap();
            }
            write!(output, "   ").unwrap();
        }
        write!(output, " |").unwrap();
        for byte in chunk {
            let c = if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '.'
            };
            write!(output, "{}", c).unwrap();
        }
        writeln!(output, "|").unwrap();
    }
}

fn find_register_differences(
    native: &SimulationResult,
    fex: &SimulationResult,
) -> Vec<(String, u64, u64)> {
    let mut diffs = Vec::new();

    for (reg, native_val) in &native.final_state.registers {
        if let Some(fex_val) = fex.final_state.registers.get(reg) {
            if native_val != fex_val {
                diffs.push((reg.clone(), *native_val, *fex_val));
            }
        }
    }

    // Sort by register name for consistent output
    diffs.sort_by(|a, b| a.0.cmp(&b.0));
    diffs
}

fn find_memory_differences(
    native: &SimulationResult,
    fex: &SimulationResult,
) -> Vec<(u64, Vec<u8>, Vec<u8>)> {
    let mut diffs = Vec::new();

    for (addr, native_bytes) in &native.final_state.memory_locations {
        if let Some(fex_bytes) = fex.final_state.memory_locations.get(addr) {
            if native_bytes != fex_bytes {
                diffs.push((*addr, native_bytes.clone(), fex_bytes.clone()));
            }
        }
    }

    // Sort by address
    diffs.sort_by_key(|d| d.0);
    diffs
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
}

fn write_state_section(output: &mut String, title: &str, registers: &HashMap<String, u64>) {
    writeln!(output, "**{}:**", title).unwrap();
    writeln!(output).unwrap();
    writeln!(output, "| Register | Value |").unwrap();
    writeln!(output, "|----------|-------|").unwrap();

    let mut sorted_regs: Vec<_> = registers.iter().collect();
    sorted_regs.sort_by_key(|(k, _)| *k);

    for (reg, val) in sorted_regs {
        writeln!(output, "| {} | `0x{:016x}` |", reg, val).unwrap();
    }
    writeln!(output).unwrap();
}

fn write_memory_section(output: &mut String, title: &str, memory: &HashMap<u64, Vec<u8>>) {
    writeln!(output, "**{}:**", title).unwrap();
    writeln!(output).unwrap();

    if memory.is_empty() {
        writeln!(output, "No memory regions.").unwrap();
        return;
    }

    let mut sorted_mem: Vec<_> = memory.iter().collect();
    sorted_mem.sort_by_key(|(k, _)| *k);

    for (addr, bytes) in sorted_mem {
        writeln!(output, "- `0x{:016x}`: `{}`", addr, bytes_to_hex(bytes)).unwrap();
    }
    writeln!(output).unwrap();
}

fn write_flag_breakdown(output: &mut String, native: u64, fex: u64) {
    let flags = [
        ("CF", 0),
        ("PF", 2),
        ("AF", 4),
        ("ZF", 6),
        ("SF", 7),
        ("TF", 8),
        ("IF", 9),
        ("DF", 10),
        ("OF", 11),
    ];

    writeln!(output).unwrap();
    writeln!(output, "Flag breakdown:").unwrap();
    for (name, bit) in flags {
        let native_bit = (native >> bit) & 1;
        let fex_bit = (fex >> bit) & 1;
        if native_bit != fex_bit {
            writeln!(output, "- **{}**: Native={}, FEX-Emu={}", name, native_bit, fex_bit).unwrap();
        }
    }
}

fn collect_all_differences(data: &IssueData) -> Vec<String> {
    let mut differences = Vec::new();

    let reg_diffs = find_register_differences(&data.native_result, &data.fex_result);
    for (reg, _, _) in &reg_diffs {
        differences.push(format!("{} mismatch", reg));
    }

    if data.native_result.final_state.flags != data.fex_result.final_state.flags {
        differences.push("flags mismatch".to_string());
    }

    let mem_diffs = find_memory_differences(&data.native_result, &data.fex_result);
    if !mem_diffs.is_empty() {
        differences.push(format!("{} memory diff(s)", mem_diffs.len()));
    }

    if differences.is_empty() {
        differences.push("unknown difference".to_string());
    }

    differences
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::simulator::{FinalState, InitialState};
    use std::time::Duration;

    fn create_test_extraction() -> ExtractionInfo {
        ExtractionInfo {
            id: 1,
            binary_path: "/test/binary".to_string(),
            binary_hash: "abc123def456".to_string(),
            binary_format: "ELF".to_string(),
            binary_architecture: "x86_64".to_string(),
            binary_base_address: 0,
            start_address: 0x1000,
            end_address: 0x1020,
            assembly_block: vec![0x48, 0x89, 0xc3, 0x48, 0x83, 0xc0, 0x01],
            created_at: "2024-01-15T10:00:00Z".to_string(),
            analysis_status: "complete".to_string(),
            analysis_results: None,
        }
    }

    fn create_test_initial_state(rax: u64, rbx: u64) -> InitialState {
        let mut registers = HashMap::new();
        registers.insert("rax".to_string(), rax);
        registers.insert("rbx".to_string(), rbx);

        InitialState {
            registers,
            memory_locations: HashMap::new(),
            stack_setup: Vec::new(),
        }
    }

    fn create_test_final_state(rax: u64, rbx: u64, flags: u64) -> FinalState {
        let mut registers = HashMap::new();
        registers.insert("rax".to_string(), rax);
        registers.insert("rbx".to_string(), rbx);

        FinalState {
            registers,
            memory_locations: HashMap::new(),
            flags,
        }
    }

    fn create_test_result(initial: InitialState, final_state: FinalState) -> SimulationResult {
        SimulationResult {
            simulation_id: "test-sim-001".to_string(),
            initial_state: initial,
            final_state,
            execution_time: Duration::from_millis(10),
            exit_code: 0,
            emulator_used: Some("native".to_string()),
            assembly_file_path: None,
            binary_file_path: None,
        }
    }

    #[test]
    fn test_generate_issue_signature() {
        let extraction = create_test_extraction();
        let differences = vec!["rax mismatch".to_string()];

        let sig = generate_issue_signature(&extraction, &differences);
        assert_eq!(sig.len(), 16);

        // Same input should produce same signature
        let sig2 = generate_issue_signature(&extraction, &differences);
        assert_eq!(sig, sig2);

        // Different differences should produce different signature
        let sig3 = generate_issue_signature(&extraction, &vec!["rbx mismatch".to_string()]);
        assert_ne!(sig, sig3);
    }

    #[test]
    fn test_generate_issue_title() {
        let extraction = create_test_extraction();
        let differences = vec!["rax mismatch".to_string()];

        let title = generate_issue_title(&extraction, &differences);
        assert!(title.starts_with("[snippex]"));
        assert!(title.contains("rax mismatch"));
        assert!(title.contains("7 bytes"));
    }

    #[test]
    fn test_generate_issue_title_multiple_diffs() {
        let extraction = create_test_extraction();
        let differences = vec![
            "rax mismatch".to_string(),
            "rbx mismatch".to_string(),
            "flags mismatch".to_string(),
            "memory diff".to_string(),
        ];

        let title = generate_issue_title(&extraction, &differences);
        assert!(title.contains("and 3 more differences"));
    }

    #[test]
    fn test_find_register_differences() {
        let initial = create_test_initial_state(100, 200);
        let native_final = create_test_final_state(101, 200, 0);
        let fex_final = create_test_final_state(102, 200, 0);

        let native = create_test_result(initial.clone(), native_final);
        let fex = create_test_result(initial, fex_final);

        let diffs = find_register_differences(&native, &fex);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].0, "rax");
        assert_eq!(diffs[0].1, 101); // native
        assert_eq!(diffs[0].2, 102); // fex
    }

    #[test]
    fn test_bytes_to_hex() {
        assert_eq!(bytes_to_hex(&[0x48, 0x89, 0xc3]), "48 89 c3");
        assert_eq!(bytes_to_hex(&[]), "");
    }

    #[test]
    fn test_build_issue_body() {
        let extraction = create_test_extraction();
        let initial = create_test_initial_state(100, 200);
        let native_final = create_test_final_state(101, 200, 0);
        let fex_final = create_test_final_state(102, 200, 0);

        let native = create_test_result(initial.clone(), native_final);
        let fex = create_test_result(initial, fex_final);

        let data = IssueData {
            extraction,
            analysis: None,
            native_result: native,
            fex_result: fex,
            host_info: HostInfo::current(),
            notes: None,
        };

        let body = build_issue_body(&data);

        assert!(body.contains("## Summary"));
        assert!(body.contains("## Block Information"));
        assert!(body.contains("## State Comparison"));
        assert!(body.contains("## Reproduction"));
        assert!(body.contains("## Environment"));
        assert!(body.contains("Issue signature:"));
    }

    #[test]
    fn test_github_config_default() {
        let config = GitHubConfig::default();
        assert_eq!(config.repository, "FEX-Emu/FEX");
        assert!(config.labels.contains(&"bug".to_string()));
        assert!(config.labels.contains(&"snippex".to_string()));
    }
}
