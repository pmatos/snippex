#[cfg(test)]
mod tests {
    use crate::analyzer::{BlockAnalysis, ExitPoint, ExitType};
    use crate::db::ExtractionInfo;
    use crate::simulator::*;
    use std::collections::HashSet;

    fn create_mock_extraction() -> ExtractionInfo {
        ExtractionInfo {
            id: 1,
            binary_path: "/test/binary".to_string(),
            binary_hash: "abcdef123456".to_string(),
            binary_format: "ELF".to_string(),
            binary_architecture: "x86_64".to_string(),
            start_address: 0x1000,
            end_address: 0x1008,
            assembly_block: vec![
                0x48, 0x89, 0xd8, // mov rax, rbx
                0x48, 0x83, 0xc0, 0x2a, // add rax, 0x2a
                0xc3, // ret
            ],
            created_at: "2023-01-01 00:00:00".to_string(),
            analysis_status: "analyzed".to_string(),
            analysis_results: Some("{}".to_string()),
        }
    }

    fn create_mock_analysis() -> BlockAnalysis {
        let mut live_in_registers = HashSet::new();
        live_in_registers.insert("rax".to_string());
        live_in_registers.insert("rbx".to_string());

        let mut live_out_registers = HashSet::new();
        live_out_registers.insert("rax".to_string());

        BlockAnalysis {
            instructions_count: 3,
            live_in_registers,
            live_out_registers,
            exit_points: vec![ExitPoint {
                offset: 0x7,
                exit_type: ExitType::Return,
                target: None,
            }],
            memory_accesses: vec![],
        }
    }

    #[test]
    fn test_random_state_generator() {
        let mut generator = RandomStateGenerator::with_seed(12345);
        let analysis = create_mock_analysis();

        let initial_state = generator.generate_initial_state(&analysis);

        assert_eq!(initial_state.registers.len(), 2);
        assert!(initial_state.registers.contains_key("rax"));
        assert!(initial_state.registers.contains_key("rbx"));
        assert!(!initial_state.stack_setup.is_empty());
    }

    #[test]
    fn test_assembly_generator() {
        let generator = AssemblyGenerator::new();
        let extraction = create_mock_extraction();
        let analysis = create_mock_analysis();

        let mut initial_state = InitialState::new();
        initial_state.set_register("rax", 0x1234567890abcdef);
        initial_state.set_register("rbx", 0xdeadbeefcafebabe);

        let result = generator.generate_simulation_file(&extraction, &analysis, &initial_state);

        assert!(result.is_ok());
        let assembly = result.unwrap();

        // Check that the assembly contains expected sections
        assert!(assembly.contains("BITS 64"));
        assert!(assembly.contains("_start:"));
        assert!(assembly.contains("mov rax, 0x1234567890abcdef"));
        assert!(assembly.contains("mov rbx, 0xdeadbeefcafebabe"));
        assert!(assembly.contains("syscall"));
    }

    #[test]
    fn test_final_state_parsing() {
        // Create a mock output buffer
        let mut output = vec![0u8; 4096];

        // Set some register values (first 16 registers * 8 bytes each)
        let test_rax = 0x1234567890abcdef_u64;
        let test_rbx = 0xdeadbeefcafebabe_u64;

        // Write rax (offset 0)
        output[0..8].copy_from_slice(&test_rax.to_le_bytes());
        // Write rbx (offset 8)
        output[8..16].copy_from_slice(&test_rbx.to_le_bytes());

        // Set flags (offset 128)
        let test_flags = 0x246_u64;
        output[128..136].copy_from_slice(&test_flags.to_le_bytes());

        let result = FinalState::parse_from_output(&output);
        assert!(result.is_ok());

        let final_state = result.unwrap();
        assert_eq!(final_state.get_register("rax"), Some(test_rax));
        assert_eq!(final_state.get_register("rbx"), Some(test_rbx));
        assert_eq!(final_state.flags, test_flags);
    }

    #[test]
    fn test_emulator_config_parsing() {
        use std::str::FromStr;

        let native = EmulatorConfig::from_str("native").unwrap();
        assert!(matches!(native, EmulatorConfig::Native));

        let qemu = EmulatorConfig::from_str("qemu-x86_64").unwrap();
        assert!(matches!(qemu, EmulatorConfig::Qemu { .. }));

        let invalid = EmulatorConfig::from_str("invalid");
        assert!(invalid.is_err());
    }

    #[test]
    fn test_compilation_pipeline_creation() {
        // This test will fail if NASM is not installed, which is expected
        match CompilationPipeline::new() {
            Ok(pipeline) => {
                // If NASM is available, test basic functionality
                let temp_dir = pipeline.get_temp_dir();
                assert!(temp_dir.exists());
            }
            Err(e) => {
                // Expected if NASM is not installed
                assert!(e.to_string().contains("NASM") || e.to_string().contains("ld"));
            }
        }
    }

    #[test]
    fn test_initial_state_creation() {
        let mut state = InitialState::new();

        state.set_register("rax", 0x1234);
        state.set_memory(0x7fff0000, vec![0xaa, 0xbb, 0xcc, 0xdd]);
        state.add_stack_value(0x5678);

        assert_eq!(state.get_register("rax"), Some(0x1234));
        assert_eq!(
            state.get_memory(0x7fff0000),
            Some(&vec![0xaa, 0xbb, 0xcc, 0xdd])
        );
        assert_eq!(state.stack_setup.len(), 1);
        assert_eq!(state.stack_setup[0], 0x5678);
    }

    #[test]
    fn test_execution_harness_creation() {
        let harness = ExecutionHarness::new();
        assert_eq!(harness.timeout_seconds, 5);

        let harness_with_timeout = ExecutionHarness::with_timeout(10);
        assert_eq!(harness_with_timeout.timeout_seconds, 10);
    }
}
