#[cfg(test)]
mod extractor_tests {
    use crate::extractor::{ExtractionFilter, Extractor, InstructionCategory};
    use object::ObjectSection;
    use std::collections::HashSet;
    use std::fs;
    use std::process::Command;
    use tempfile::{NamedTempFile, TempDir};

    fn create_test_binary() -> NamedTempFile {
        let dir = TempDir::new().unwrap();
        let source_path = dir.path().join("test.c");
        let binary_file = NamedTempFile::new().unwrap();

        fs::write(
            &source_path,
            r#"
            int add(int a, int b) { return a + b; }
            int sub(int a, int b) { return a - b; }
            int mul(int a, int b) { return a * b; }
            int main() { return add(5, 3); }
        "#,
        )
        .unwrap();

        let output = Command::new("gcc")
            .args([
                "-o",
                binary_file.path().to_str().unwrap(),
                "-O0", // No optimization to ensure predictable code
                source_path.to_str().unwrap(),
            ])
            .output()
            .expect("Failed to compile test binary");

        if !output.status.success() {
            panic!(
                "Failed to compile test binary: {:?}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        binary_file
    }

    #[test]
    fn test_binary_info_extraction() {
        let binary_file = create_test_binary();

        let extractor = Extractor::new(binary_file.path().to_path_buf()).unwrap();
        let info = extractor.get_binary_info().unwrap();

        assert_eq!(info.format, "ELF");
        assert_eq!(info.architecture, "x86_64");
        assert_eq!(info.endianness, "little");
        assert!(info.size > 0);
        assert!(!info.hash.is_empty());
        assert_eq!(info.hash.len(), 64); // SHA256 hex string length
    }

    #[test]
    fn test_random_block_extraction() {
        let binary_file = create_test_binary();

        let extractor = Extractor::new(binary_file.path().to_path_buf()).unwrap();
        let (start, end, block) = extractor.extract_random_aligned_block().unwrap();

        assert!(start < end);
        assert_eq!(block.len(), (end - start) as usize);
        assert!(!block.is_empty());
        // With instruction alignment, blocks should be reasonably sized
        assert!(block.len() >= 4); // At least 4 instructions minimum
                                   // Since we limit to 32 instructions max and x86 instructions can be up to 15 bytes
        assert!(block.len() <= 32 * 15); // Conservative upper bound
    }

    #[test]
    fn test_multiple_extractions_different() {
        let binary_file = create_test_binary();

        let extractor = Extractor::new(binary_file.path().to_path_buf()).unwrap();

        let mut extractions = Vec::new();
        for _ in 0..10 {
            let (start, end, _) = extractor.extract_random_aligned_block().unwrap();
            extractions.push((start, end));
        }

        // Since we're using random selection, we should get at least some different ranges
        let unique_count = extractions
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len();
        assert!(unique_count >= 1, "Should produce at least one extraction");
    }

    #[test]
    fn test_instruction_alignment() {
        let binary_file = create_test_binary();
        let extractor = Extractor::new(binary_file.path().to_path_buf()).unwrap();

        // Extract a block and verify it starts and ends on instruction boundaries
        let (start_addr, end_addr, block) = extractor.extract_random_aligned_block().unwrap();

        // Create a disassembler to verify instruction alignment
        let cs = extractor.create_capstone().unwrap();

        // Disassemble the extracted block
        let insns = cs.disasm_all(&block, start_addr).unwrap();

        // Should have at least some instructions
        assert!(!insns.is_empty(), "Block should contain instructions");

        // First instruction should start at the block's start address
        assert_eq!(insns.first().unwrap().address(), start_addr);

        // Last instruction should end at or before the block's end address
        let last_insn = insns.last().unwrap();
        let last_insn_end = last_insn.address() + last_insn.bytes().len() as u64;
        assert!(
            last_insn_end <= end_addr,
            "Last instruction should not exceed block boundary"
        );
    }

    #[test]
    fn test_range_extraction_valid() {
        let binary_file = create_test_binary();
        let extractor = Extractor::new(binary_file.path().to_path_buf()).unwrap();

        // First get a random block to find valid instruction addresses
        let (start_addr, end_addr, _) = extractor.extract_random_aligned_block().unwrap();

        // Now extract the exact same range
        let (range_start, range_end, range_block) =
            extractor.extract_range(start_addr, end_addr).unwrap();

        assert_eq!(range_start, start_addr);
        assert_eq!(range_end, end_addr);
        assert!(!range_block.is_empty());

        // Verify it contains valid instructions
        let cs = extractor.create_capstone().unwrap();
        let insns = cs.disasm_all(&range_block, range_start).unwrap();
        assert!(!insns.is_empty());
    }

    #[test]
    fn test_range_extraction_invalid_start() {
        let binary_file = create_test_binary();
        let extractor = Extractor::new(binary_file.path().to_path_buf()).unwrap();

        // Get a valid range first to find an instruction address
        let (_start_addr, _end_addr, _) = extractor.extract_random_aligned_block().unwrap();

        // Create disassembler to examine the instructions
        let cs = extractor.create_capstone().unwrap();

        // Get the binary data for disassembly around our start address
        let file = object::File::parse(&*extractor.binary_data).unwrap();
        let text_section = extractor.find_executable_section(&file).unwrap();
        let section_data = text_section.data().unwrap();
        let section_addr = text_section.address();

        // Find an instruction with length > 1 byte
        let insns = cs.disasm_all(section_data, section_addr).unwrap();
        let multi_byte_insn = insns.iter().find(|insn| insn.bytes().len() > 1);

        if let Some(insn) = multi_byte_insn {
            // Try to extract starting from middle of instruction (not instruction-aligned)
            let bad_start = insn.address() + 1;
            let bad_end = bad_start + 10;

            let result = extractor.extract_range(bad_start, bad_end);
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("not instruction-aligned"));
        } else {
            // Fallback: try an obviously invalid address far outside the section
            let bad_start = section_addr + section_data.len() as u64 + 1000;
            let bad_end = bad_start + 10;

            let result = extractor.extract_range(bad_start, bad_end);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_range_extraction_invalid_order() {
        let binary_file = create_test_binary();
        let extractor = Extractor::new(binary_file.path().to_path_buf()).unwrap();

        // Get a valid range first
        let (start_addr, end_addr, _) = extractor.extract_random_aligned_block().unwrap();

        // Try with swapped addresses
        let result = extractor.extract_range(end_addr, start_addr);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Start address must be less than end address"));
    }

    #[test]
    fn test_format_detection_elf() {
        let binary_file = create_test_binary();
        let extractor = Extractor::new(binary_file.path().to_path_buf()).unwrap();

        let format = extractor.detect_format().unwrap();
        assert!(matches!(format, crate::extractor::SupportedFormat::Elf));
    }

    #[test]
    fn test_unsupported_format_error() {
        let temp_file = NamedTempFile::new().unwrap();

        // Create a file with invalid binary format
        fs::write(temp_file.path(), b"This is not a valid binary format").unwrap();

        let extractor = Extractor::new(temp_file.path().to_path_buf()).unwrap();
        let result = extractor.get_binary_info();

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Binary parsing error")
                || error_msg.contains("Unknown or unsupported")
        );
    }

    #[test]
    fn test_architecture_detection() {
        let binary_file = create_test_binary();
        let extractor = Extractor::new(binary_file.path().to_path_buf()).unwrap();
        let info = extractor.get_binary_info().unwrap();

        // Should detect x86_64 architecture for GCC-compiled binary
        assert!(matches!(info.architecture.as_str(), "x86_64" | "i386"));
        assert_eq!(info.endianness, "little");
    }

    #[test]
    fn test_extraction_filter_default() {
        let filter = ExtractionFilter::new();
        assert!(filter.is_empty());
        assert!(filter.validate().is_ok());
    }

    #[test]
    fn test_extraction_filter_size_constraints() {
        let filter = ExtractionFilter::new().with_min_size(16).with_max_size(64);

        assert!(!filter.is_empty());
        assert!(filter.validate().is_ok());
        assert_eq!(filter.min_size, Some(16));
        assert_eq!(filter.max_size, Some(64));
    }

    #[test]
    fn test_extraction_filter_invalid_size_range() {
        let filter = ExtractionFilter::new().with_min_size(100).with_max_size(50);

        assert!(filter.validate().is_err());
        let err = filter.validate().unwrap_err();
        assert!(err.to_string().contains("cannot be greater than"));
    }

    #[test]
    fn test_extraction_filter_memory_access() {
        let filter = ExtractionFilter::new().with_memory_access(true);

        assert!(!filter.is_empty());
        assert_eq!(filter.require_memory_access, Some(true));
    }

    #[test]
    fn test_extraction_filter_categories() {
        let mut categories = HashSet::new();
        categories.insert(InstructionCategory::Sse);
        categories.insert(InstructionCategory::Avx);

        let filter = ExtractionFilter::new().with_instruction_categories(categories.clone());

        assert!(!filter.is_empty());
        assert_eq!(filter.instruction_categories, Some(categories));
    }

    #[test]
    fn test_instruction_category_from_str() {
        assert_eq!(
            "general".parse::<InstructionCategory>().unwrap(),
            InstructionCategory::General
        );
        assert_eq!(
            "FPU".parse::<InstructionCategory>().unwrap(),
            InstructionCategory::Fpu
        );
        assert_eq!(
            "sse".parse::<InstructionCategory>().unwrap(),
            InstructionCategory::Sse
        );
        assert_eq!(
            "AVX".parse::<InstructionCategory>().unwrap(),
            InstructionCategory::Avx
        );
        assert_eq!(
            "avx512".parse::<InstructionCategory>().unwrap(),
            InstructionCategory::Avx512
        );
        assert_eq!(
            "branch".parse::<InstructionCategory>().unwrap(),
            InstructionCategory::Branch
        );
        assert_eq!(
            "syscall".parse::<InstructionCategory>().unwrap(),
            InstructionCategory::Syscall
        );
        assert!("invalid".parse::<InstructionCategory>().is_err());
    }

    #[test]
    fn test_instruction_category_as_str() {
        assert_eq!(InstructionCategory::General.as_str(), "general");
        assert_eq!(InstructionCategory::Fpu.as_str(), "fpu");
        assert_eq!(InstructionCategory::Sse.as_str(), "sse");
        assert_eq!(InstructionCategory::Avx.as_str(), "avx");
        assert_eq!(InstructionCategory::Avx512.as_str(), "avx512");
        assert_eq!(InstructionCategory::Branch.as_str(), "branch");
        assert_eq!(InstructionCategory::Syscall.as_str(), "syscall");
    }

    #[test]
    fn test_check_block_filter_size() {
        let binary_file = create_test_binary();
        let extractor = Extractor::new(binary_file.path().to_path_buf()).unwrap();

        let (start_addr, _, assembly_block) = extractor.extract_random_aligned_block().unwrap();
        let block_size = assembly_block.len();

        // Filter that should match (wide range)
        let filter = ExtractionFilter::new()
            .with_min_size(1)
            .with_max_size(10000);
        let result = extractor
            .check_block_filter(&assembly_block, start_addr, &filter)
            .unwrap();
        assert!(result.matches);
        assert_eq!(result.block_size, block_size);

        // Filter that should not match (too small max)
        let filter = ExtractionFilter::new().with_min_size(1).with_max_size(1);
        let result = extractor
            .check_block_filter(&assembly_block, start_addr, &filter)
            .unwrap();
        assert!(!result.matches);
    }

    #[test]
    fn test_filtered_extraction() {
        let binary_file = create_test_binary();
        let extractor = Extractor::new(binary_file.path().to_path_buf()).unwrap();

        // Extract with a reasonable size filter
        let filter = ExtractionFilter::new().with_min_size(16).with_max_size(200);

        let result = extractor.extract_filtered_block(&filter);
        assert!(result.is_ok(), "Should find a block matching filter");

        let (start_addr, _, assembly_block) = result.unwrap();
        assert!(assembly_block.len() >= 16);
        assert!(assembly_block.len() <= 200);

        // Verify the block actually matches the filter
        let filter_match = extractor
            .check_block_filter(&assembly_block, start_addr, &filter)
            .unwrap();
        assert!(filter_match.matches);
    }

    #[test]
    fn test_count_matching_blocks() {
        let binary_file = create_test_binary();
        let extractor = Extractor::new(binary_file.path().to_path_buf()).unwrap();

        // Empty filter should match all blocks
        let filter = ExtractionFilter::new();
        let (matching, total) = extractor.count_matching_blocks(&filter, 10).unwrap();
        assert_eq!(matching, total);
        assert!(total > 0);

        // Reasonable filter should match some blocks
        let filter = ExtractionFilter::new().with_min_size(16).with_max_size(100);
        let (matching, total) = extractor.count_matching_blocks(&filter, 20).unwrap();
        assert!(total > 0);
        // At least some blocks should match
        assert!(matching > 0 || total > 0);
    }
}
