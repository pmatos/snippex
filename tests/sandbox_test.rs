use object::{Object, ObjectSegment};
use snippex::extractor::section_loader::{BinarySectionLoader, SectionMetadata};
use snippex::simulator::{SandboxMemoryLayout, SANDBOX_BASE};
use std::path::Path;

#[test]
fn test_base_address_parsing_from_elf() {
    // Use /bin/ls as a real ELF binary
    let binary_path = Path::new("/bin/ls");

    if !binary_path.exists() {
        eprintln!("Skipping test: /bin/ls not found");
        return;
    }

    // Parse ELF to get base address
    let binary_data = std::fs::read(binary_path).expect("Failed to read /bin/ls");
    let file = object::File::parse(&*binary_data).expect("Failed to parse ELF");

    // Get the first segment's virtual address as base (usually .text)
    let base_address = file
        .segments()
        .find(|seg| seg.address() > 0)
        .map(|seg| seg.address())
        .unwrap_or(0x400000);

    // Verify base address is reasonable (any non-zero address is valid)
    assert!(
        base_address > 0,
        "Base address {:#x} should be greater than 0",
        base_address
    );
}

#[test]
fn test_section_loading() {
    let binary_path = Path::new("/bin/ls");

    if !binary_path.exists() {
        eprintln!("Skipping test: /bin/ls not found");
        return;
    }

    let loader = BinarySectionLoader::new(binary_path).expect("Failed to create loader");

    // Test loading .text section
    let text_result = loader.extract_text_section();
    assert!(text_result.is_ok(), "Failed to load .text section");
    let (text_metadata, text_data) = text_result.unwrap();
    assert_eq!(text_metadata.name, ".text");
    assert!(!text_data.is_empty(), ".text section should have data");
    assert!(text_metadata.is_executable, ".text should be executable");

    // Test loading .data section (might not exist in all binaries)
    let data_result = loader.extract_data_section();
    if let Ok((data_metadata, data_data)) = data_result {
        assert_eq!(data_metadata.name, ".data");
        assert!(data_metadata.is_writable, ".data should be writable");
        assert!(!data_data.is_empty(), ".data section should have data");
    }

    // Test loading .rodata section
    let rodata_result = loader.extract_rodata_section();
    if let Ok((rodata_metadata, rodata_data)) = rodata_result {
        assert_eq!(rodata_metadata.name, ".rodata");
        assert!(rodata_metadata.is_readable, ".rodata should be readable");
        assert!(
            !rodata_metadata.is_writable,
            ".rodata should not be writable"
        );
        assert!(!rodata_data.is_empty(), ".rodata section should have data");
    }
}

#[test]
fn test_address_translation_math() {
    // Test with typical x86_64 binary base addresses

    // Test 1: Non-PIE binary (base = 0x400000)
    let binary_base = 0x400000;
    let sandbox = SandboxMemoryLayout::new(binary_base);

    let original_text = 0x401000;
    let translated_text = sandbox.translate_to_sandbox(original_text).unwrap();
    assert_eq!(translated_text, SANDBOX_BASE + 0x1000);

    let original_data = 0x404000;
    let translated_data = sandbox.translate_to_sandbox(original_data).unwrap();
    assert_eq!(translated_data, SANDBOX_BASE + 0x4000);

    // Test 2: PIE binary (base = 0x555555554000)
    let pie_base = 0x555555554000;
    let pie_sandbox = SandboxMemoryLayout::new(pie_base);

    let pie_text = 0x555555555000;
    let pie_translated = pie_sandbox.translate_to_sandbox(pie_text).unwrap();
    assert_eq!(pie_translated, SANDBOX_BASE + 0x1000);
}

#[test]
fn test_sandbox_with_real_binary_sections() {
    let binary_path = Path::new("/bin/ls");

    if !binary_path.exists() {
        eprintln!("Skipping test: /bin/ls not found");
        return;
    }

    // Load the binary
    let loader = BinarySectionLoader::new(binary_path).expect("Failed to create loader");

    // Get binary base address
    let binary_data = std::fs::read(binary_path).expect("Failed to read binary");
    let file = object::File::parse(&*binary_data).expect("Failed to parse ELF");

    let base_address = file
        .segments()
        .find(|seg| seg.address() > 0)
        .map(|seg| seg.address())
        .unwrap_or(0x400000);

    // Create sandbox
    let mut sandbox = SandboxMemoryLayout::new(base_address);

    // Load .text section into sandbox
    if let Ok((text_metadata, text_data)) = loader.extract_text_section() {
        sandbox
            .add_section(text_metadata.clone(), Some(text_data.clone()))
            .expect("Failed to add .text");

        // Verify the section was added
        let found = sandbox.get_section_by_name(".text");
        assert!(found.is_some(), ".text section should be in sandbox");

        let section = found.unwrap();
        assert_eq!(section.section_metadata.name, ".text");
        assert_eq!(section.original_address, text_metadata.virtual_address);

        // Verify address translation
        let sandbox_addr = sandbox
            .translate_to_sandbox(text_metadata.virtual_address)
            .unwrap();
        assert_eq!(sandbox_addr, section.sandbox_address);
    }
}

#[test]
fn test_memory_region_allocation() {
    let binary_path = Path::new("/bin/ls");

    if !binary_path.exists() {
        eprintln!("Skipping test: /bin/ls not found");
        return;
    }

    let loader = BinarySectionLoader::new(binary_path).expect("Failed to create loader");
    let binary_data = std::fs::read(binary_path).expect("Failed to read binary");
    let file = object::File::parse(&*binary_data).expect("Failed to parse ELF");

    let base_address = file
        .segments()
        .find(|seg| seg.address() > 0)
        .map(|seg| seg.address())
        .unwrap_or(0x400000);

    let mut sandbox = SandboxMemoryLayout::new(base_address);

    // Add .text section
    if let Ok((text_metadata, text_data)) = loader.extract_text_section() {
        sandbox
            .add_section(text_metadata, Some(text_data))
            .expect("Failed to add .text");
    }

    // Add .rodata section if it exists
    if let Ok((rodata_metadata, rodata_data)) = loader.extract_rodata_section() {
        sandbox
            .add_section(rodata_metadata, Some(rodata_data))
            .expect("Failed to add .rodata");
    }

    // Allocate memory region
    let memory = sandbox
        .allocate_memory_region()
        .expect("Failed to allocate memory");

    // Verify memory was allocated
    assert!(!memory.is_empty(), "Memory should be allocated");

    // Verify each section has memory allocated at the correct sandbox address
    for section in sandbox.sections() {
        if section.data.is_some() {
            assert!(
                memory.contains_key(&section.sandbox_address),
                "Memory should be allocated for section {} at {:#x}",
                section.section_metadata.name,
                section.sandbox_address
            );
        }
    }
}

#[test]
fn test_rip_relative_addressing_scenario() {
    // Simulate a RIP-relative instruction scenario
    // Example: mov rax, [rip + 0x1000]
    // If RIP is at 0x401000, it accesses 0x402000

    let binary_base = 0x400000;
    let sandbox = SandboxMemoryLayout::new(binary_base);

    // RIP is at 0x401000
    let rip = 0x401000;
    // Access is [rip + 0x1000] = 0x402000
    let access_addr = rip + 0x1000;

    // Translate both addresses
    let translated_rip = sandbox.translate_to_sandbox(rip).unwrap();
    let translated_access = sandbox.translate_to_sandbox(access_addr).unwrap();

    // The relative offset should be preserved
    assert_eq!(
        translated_access - translated_rip,
        0x1000,
        "RIP-relative offset should be preserved after translation"
    );
}

#[test]
fn test_data_section_access() {
    // Simulate accessing a .data section
    let binary_base = 0x400000;
    let mut sandbox = SandboxMemoryLayout::new(binary_base);

    // Create a mock .data section
    let data_metadata = SectionMetadata {
        name: ".data".to_string(),
        offset: 0x3000,
        size: 0x100,
        virtual_address: binary_base + 0x3000,
        alignment: 0x1000,
        is_executable: false,
        is_writable: true,
        is_readable: true,
    };

    let data_bytes = vec![0x42; 0x100];
    sandbox
        .add_section(data_metadata, Some(data_bytes.clone()))
        .expect("Failed to add .data");

    // Access address in .data section
    let data_addr = binary_base + 0x3000 + 0x50;
    let translated = sandbox.translate_to_sandbox(data_addr).unwrap();

    // Verify translation
    assert_eq!(translated, SANDBOX_BASE + 0x3000 + 0x50);

    // Verify we can find the section by address
    let section = sandbox.find_section_by_address(data_addr);
    assert!(section.is_some());
    assert_eq!(section.unwrap().section_metadata.name, ".data");
}

#[test]
fn test_rodata_string_reference() {
    // Simulate accessing a string in .rodata
    let binary_base = 0x400000;
    let mut sandbox = SandboxMemoryLayout::new(binary_base);

    // Create a mock .rodata section with a string
    let rodata_metadata = SectionMetadata {
        name: ".rodata".to_string(),
        offset: 0x2000,
        size: 0x100,
        virtual_address: binary_base + 0x2000,
        alignment: 0x1000,
        is_executable: false,
        is_writable: false,
        is_readable: true,
    };

    // String: "Hello, World!\0"
    let mut rodata_bytes = vec![0u8; 0x100];
    let hello_world = b"Hello, World!\0";
    rodata_bytes[0..hello_world.len()].copy_from_slice(hello_world);

    sandbox
        .add_section(rodata_metadata, Some(rodata_bytes.clone()))
        .expect("Failed to add .rodata");

    // Access string address
    let string_addr = binary_base + 0x2000;
    let translated = sandbox.translate_to_sandbox(string_addr).unwrap();

    // Verify translation
    assert_eq!(translated, SANDBOX_BASE + 0x2000);

    // Allocate memory and verify string is present
    let memory = sandbox
        .allocate_memory_region()
        .expect("Failed to allocate memory");
    let allocated_data = memory.get(&translated).expect("String should be in memory");
    assert_eq!(&allocated_data[0..hello_world.len()], hello_world);
}
