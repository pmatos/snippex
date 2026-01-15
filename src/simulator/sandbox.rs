use anyhow::Result;
use std::collections::HashMap;

use crate::error::SnippexError;
use crate::extractor::section_loader::SectionMetadata;

pub const SANDBOX_BASE: u64 = 0x1000_0000;
pub const SANDBOX_SIZE: u64 = 0x1000_0000; // 256MB

#[derive(Debug, Clone)]
pub struct SandboxMemoryLayout {
    sandbox_base: u64,
    binary_base: u64,
    sections: Vec<SectionMapping>,
}

#[derive(Debug, Clone)]
pub struct SectionMapping {
    pub section_metadata: SectionMetadata,
    pub original_address: u64,
    pub sandbox_address: u64,
    pub data: Option<Vec<u8>>,
}

impl SandboxMemoryLayout {
    pub fn new(binary_base: u64) -> Self {
        Self {
            sandbox_base: SANDBOX_BASE,
            binary_base,
            sections: Vec::new(),
        }
    }

    pub fn add_section(
        &mut self,
        section_metadata: SectionMetadata,
        data: Option<Vec<u8>>,
    ) -> Result<()> {
        let original_address = section_metadata.virtual_address;
        let sandbox_address = self.translate_to_sandbox(original_address)?;

        if sandbox_address + section_metadata.size > self.sandbox_base + SANDBOX_SIZE {
            return Err(SnippexError::InvalidBinary(format!(
                "Section {} would exceed sandbox bounds: sandbox_addr={:#x}, size={:#x}",
                section_metadata.name, sandbox_address, section_metadata.size
            ))
            .into());
        }

        self.sections.push(SectionMapping {
            section_metadata,
            original_address,
            sandbox_address,
            data,
        });

        Ok(())
    }

    pub fn translate_to_sandbox(&self, original_addr: u64) -> Result<u64> {
        if !self.is_in_original_range(original_addr) {
            return Err(SnippexError::AddressOutOfRange(format!(
                "Address {:#x} is not within binary's address space (base: {:#x})",
                original_addr, self.binary_base
            ))
            .into());
        }

        let offset = original_addr.saturating_sub(self.binary_base);
        let sandbox_addr = self.sandbox_base + offset;

        if sandbox_addr >= self.sandbox_base + SANDBOX_SIZE {
            return Err(SnippexError::AddressOutOfRange(format!(
                "Translated address {:#x} exceeds sandbox bounds",
                sandbox_addr
            ))
            .into());
        }

        Ok(sandbox_addr)
    }

    pub fn is_in_original_range(&self, addr: u64) -> bool {
        addr >= self.binary_base && addr < self.binary_base + SANDBOX_SIZE
    }

    pub fn sandbox_base(&self) -> u64 {
        self.sandbox_base
    }

    pub fn binary_base(&self) -> u64 {
        self.binary_base
    }

    pub fn sections(&self) -> &[SectionMapping] {
        &self.sections
    }

    pub fn find_section_by_address(&self, original_addr: u64) -> Option<&SectionMapping> {
        self.sections.iter().find(|section| {
            let section_start = section.original_address;
            let section_end = section_start + section.section_metadata.size;
            original_addr >= section_start && original_addr < section_end
        })
    }

    pub fn get_section_by_name(&self, name: &str) -> Option<&SectionMapping> {
        self.sections
            .iter()
            .find(|section| section.section_metadata.name == name)
    }

    pub fn allocate_memory_region(&self) -> Result<HashMap<u64, Vec<u8>>> {
        let mut memory = HashMap::new();

        for section in &self.sections {
            if let Some(ref data) = section.data {
                memory.insert(section.sandbox_address, data.clone());
            } else if section.section_metadata.name == ".bss" {
                let zeros = vec![0u8; section.section_metadata.size as usize];
                memory.insert(section.sandbox_address, zeros);
            }
        }

        Ok(memory)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_creation() {
        let binary_base = 0x5555_5555_0000;
        let layout = SandboxMemoryLayout::new(binary_base);

        assert_eq!(layout.sandbox_base(), SANDBOX_BASE);
        assert_eq!(layout.binary_base(), binary_base);
        assert_eq!(layout.sections().len(), 0);
    }

    #[test]
    fn test_address_translation() {
        let binary_base = 0x5555_5555_0000;
        let layout = SandboxMemoryLayout::new(binary_base);

        let original_addr = 0x5555_5555_1000;
        let expected_sandbox = SANDBOX_BASE + 0x1000;

        let translated = layout.translate_to_sandbox(original_addr).unwrap();
        assert_eq!(translated, expected_sandbox);
    }

    #[test]
    fn test_address_translation_out_of_range() {
        let binary_base = 0x5555_5555_0000;
        let layout = SandboxMemoryLayout::new(binary_base);

        let out_of_range_addr = 0x1234_5678_0000;
        let result = layout.translate_to_sandbox(out_of_range_addr);

        assert!(result.is_err());
    }

    #[test]
    fn test_is_in_original_range() {
        let binary_base = 0x5555_5555_0000;
        let layout = SandboxMemoryLayout::new(binary_base);

        assert!(layout.is_in_original_range(binary_base));
        assert!(layout.is_in_original_range(binary_base + 0x1000));
        assert!(!layout.is_in_original_range(binary_base - 1));
    }

    #[test]
    fn test_add_section() {
        let binary_base = 0x5555_5555_0000;
        let mut layout = SandboxMemoryLayout::new(binary_base);

        let section_metadata = SectionMetadata {
            name: ".text".to_string(),
            offset: 0x1000,
            size: 0x1000,
            virtual_address: binary_base + 0x1000,
            alignment: 0x1000,
            is_executable: true,
            is_writable: false,
            is_readable: true,
        };

        let data = vec![0x90, 0x90, 0x90]; // NOP instructions
        let result = layout.add_section(section_metadata, Some(data));

        assert!(result.is_ok());
        assert_eq!(layout.sections().len(), 1);
    }

    #[test]
    fn test_find_section_by_address() {
        let binary_base = 0x5555_5555_0000;
        let mut layout = SandboxMemoryLayout::new(binary_base);

        let section_metadata = SectionMetadata {
            name: ".text".to_string(),
            offset: 0x1000,
            size: 0x1000,
            virtual_address: binary_base + 0x1000,
            alignment: 0x1000,
            is_executable: true,
            is_writable: false,
            is_readable: true,
        };

        layout.add_section(section_metadata, None).unwrap();

        let addr_in_section = binary_base + 0x1500;
        let found = layout.find_section_by_address(addr_in_section);

        assert!(found.is_some());
        assert_eq!(found.unwrap().section_metadata.name, ".text");
    }

    #[test]
    fn test_get_section_by_name() {
        let binary_base = 0x5555_5555_0000;
        let mut layout = SandboxMemoryLayout::new(binary_base);

        let section_metadata = SectionMetadata {
            name: ".data".to_string(),
            offset: 0x2000,
            size: 0x1000,
            virtual_address: binary_base + 0x2000,
            alignment: 0x1000,
            is_executable: false,
            is_writable: true,
            is_readable: true,
        };

        layout.add_section(section_metadata, None).unwrap();

        let found = layout.get_section_by_name(".data");
        assert!(found.is_some());
        assert_eq!(found.unwrap().section_metadata.name, ".data");

        let not_found = layout.get_section_by_name(".rodata");
        assert!(not_found.is_none());
    }

    #[test]
    fn test_allocate_memory_region() {
        let binary_base = 0x5555_5555_0000;
        let mut layout = SandboxMemoryLayout::new(binary_base);

        // Add .text section with data
        let text_metadata = SectionMetadata {
            name: ".text".to_string(),
            offset: 0x1000,
            size: 0x10,
            virtual_address: binary_base + 0x1000,
            alignment: 0x1000,
            is_executable: true,
            is_writable: false,
            is_readable: true,
        };
        let text_data = vec![0x90; 0x10];
        layout.add_section(text_metadata, Some(text_data.clone())).unwrap();

        // Add .bss section (no data, should be zero-initialized)
        let bss_metadata = SectionMetadata {
            name: ".bss".to_string(),
            offset: 0,
            size: 0x100,
            virtual_address: binary_base + 0x3000,
            alignment: 0x1000,
            is_executable: false,
            is_writable: true,
            is_readable: true,
        };
        layout.add_section(bss_metadata, None).unwrap();

        let memory = layout.allocate_memory_region().unwrap();

        assert_eq!(memory.len(), 2);

        let text_sandbox_addr = layout.translate_to_sandbox(binary_base + 0x1000).unwrap();
        assert_eq!(memory.get(&text_sandbox_addr).unwrap(), &text_data);

        let bss_sandbox_addr = layout.translate_to_sandbox(binary_base + 0x3000).unwrap();
        assert_eq!(memory.get(&bss_sandbox_addr).unwrap().len(), 0x100);
        assert!(memory.get(&bss_sandbox_addr).unwrap().iter().all(|&b| b == 0));
    }
}
