use std::fs;
use tempfile::NamedTempFile;

use snippex::analyzer::Analyzer;
use snippex::db::{BinaryInfo, Database};

fn create_test_binary() -> Vec<u8> {
    // Create a minimal ELF binary with some x86_64 instructions
    // This is a simplified ELF header + program header + simple code
    let mut binary = Vec::new();

    // ELF header (64 bytes)
    binary.extend_from_slice(&[
        0x7f, 0x45, 0x4c, 0x46, // ELF magic
        0x02, // 64-bit
        0x01, // little endian
        0x01, // version
        0x00, // System V ABI
    ]);
    binary.resize(64, 0); // Fill rest of ELF header with zeros for simplicity

    // Set some key ELF header fields
    binary[16] = 0x02; // ET_EXEC
    binary[18] = 0x3e; // EM_X86_64
    binary[24] = 0x78;
    binary[25] = 0x10; // entry point at 0x1078

    // Skip to offset 0x78 where we'll put our code
    binary.resize(0x78, 0);

    // Add some simple x86_64 instructions
    binary.extend_from_slice(&[
        0x48, 0x89, 0xd8, // mov rax, rbx
        0x48, 0x83, 0xc0, 0x2a, // add rax, 0x2a (42 in decimal)
        0x48, 0x89, 0xc1, // mov rcx, rax
        0xc3, // ret
    ]);

    binary
}

#[test]
fn test_end_to_end_simulation_workflow() {
    // Create test binary
    let binary_data = create_test_binary();
    let temp_binary = NamedTempFile::new().unwrap();
    fs::write(temp_binary.path(), &binary_data).unwrap();

    // Create test database
    let temp_db = NamedTempFile::new().unwrap();
    let mut db = Database::new(temp_db.path()).unwrap();
    db.init().unwrap();

    // Create binary info
    let binary_info = BinaryInfo {
        path: temp_binary.path().to_string_lossy().to_string(),
        size: binary_data.len() as u64,
        hash: "test_hash_12345".to_string(),
        format: "ELF".to_string(),
        architecture: "x86_64".to_string(),
        endianness: "little".to_string(),
    };

    // Extract a block from the test binary
    let start_addr = 0x1078;
    let end_addr = 0x1081;
    let assembly_block = &binary_data[0x78..0x81]; // Extract the instructions we added

    // Store extraction
    db.store_extraction(&binary_info, start_addr, end_addr, assembly_block)
        .unwrap();

    // Analyze the block
    let analyzer = Analyzer::new("x86_64");
    let analysis = analyzer.analyze_block(assembly_block, start_addr).unwrap();

    // Verify analysis found our instructions
    println!(
        "Analysis found {} instructions",
        analysis.instructions_count
    );
    println!("Live-in registers: {:?}", analysis.live_in_registers);
    println!("Live-out registers: {:?}", analysis.live_out_registers);

    // We should have at least some instructions
    assert!(analysis.instructions_count >= 2);
    assert!(analysis.live_in_registers.contains("rbx"));
    assert!(
        analysis.live_out_registers.contains("rax") || analysis.live_out_registers.contains("rcx")
    );

    // Store analysis
    db.store_analysis(start_addr, end_addr, &binary_info.hash, &analysis)
        .unwrap();

    // Test that we can create simulation components
    let extraction_info = db.list_extractions().unwrap();
    assert_eq!(extraction_info.len(), 1);
    assert_eq!(extraction_info[0].analysis_status, "analyzed");

    println!("✓ End-to-end simulation workflow test completed successfully");
    println!("  - Created test binary with x86_64 instructions");
    println!("  - Extracted and stored assembly block");
    println!(
        "  - Analyzed block and found {} instructions",
        analysis.instructions_count
    );
    println!("  - Live-in registers: {:?}", analysis.live_in_registers);
    println!("  - Live-out registers: {:?}", analysis.live_out_registers);
}

#[test]
fn test_cli_simulate_command_basic() {
    use std::process::Command;

    // Test that the simulate command exists and shows help
    let output = Command::new("cargo")
        .args(["run", "--", "simulate", "--help"])
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify simulate command help contains expected options
    assert!(stdout.contains("Block number to simulate"));
    assert!(stdout.contains("--database"));
    assert!(stdout.contains("--runs"));
    assert!(stdout.contains("--seed"));
    assert!(stdout.contains("--emulator"));
    assert!(stdout.contains("--verbose"));
    assert!(stdout.contains("--keep-files"));

    println!("✓ CLI simulate command is properly integrated");
}

#[test]
fn test_simulate_command_error_handling() {
    use std::process::Command;

    // Test simulate command with no database (should fail gracefully)
    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "simulate",
            "1",
            "--database",
            "/tmp/nonexistent.db",
        ])
        .output()
        .expect("Failed to execute command");

    // Should exit with error code
    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Print actual output for debugging
    println!("STDERR: {}", stderr);
    println!("STDOUT: {}", stdout);

    // Should contain an error about simulation failure (which is expected for complex blocks)
    assert!(
        stderr.contains("Error:")
            || stdout.contains("Error:")
            || stdout.contains("✗ Simulation failed")
    );

    println!("✓ Simulate command error handling works correctly");
}
