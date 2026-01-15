use anyhow::Result;
use object::{Object, ObjectSection};
use std::path::Path;

use crate::error::SnippexError;

#[derive(Debug, Clone)]
pub struct SectionMetadata {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub virtual_address: u64,
    pub alignment: u64,
    pub is_executable: bool,
    pub is_writable: bool,
    pub is_readable: bool,
}

#[derive(Debug)]
pub struct BinarySectionLoader {
    binary_data: Vec<u8>,
}

impl BinarySectionLoader {
    pub fn new(binary_path: &Path) -> Result<Self> {
        let binary_data = std::fs::read(binary_path)?;

        Ok(BinarySectionLoader { binary_data })
    }

    pub fn from_bytes(binary_data: Vec<u8>) -> Self {
        BinarySectionLoader { binary_data }
    }

    pub fn extract_text_section(&self) -> Result<(SectionMetadata, Vec<u8>)> {
        self.extract_section_by_name(".text")
    }

    pub fn extract_data_section(&self) -> Result<(SectionMetadata, Vec<u8>)> {
        self.extract_section_by_name(".data")
    }

    pub fn extract_rodata_section(&self) -> Result<(SectionMetadata, Vec<u8>)> {
        self.extract_section_by_name(".rodata")
    }

    pub fn extract_bss_section(&self) -> Result<SectionMetadata> {
        let file = object::File::parse(&*self.binary_data)
            .map_err(|e| SnippexError::BinaryParsing(e.to_string()))?;

        let section = file
            .section_by_name(".bss")
            .ok_or_else(|| SnippexError::InvalidBinary(".bss section not found".into()))?;

        let metadata = self.create_section_metadata(&section)?;
        Ok(metadata)
    }

    pub fn extract_all_sections(&self) -> Result<Vec<(SectionMetadata, Option<Vec<u8>>)>> {
        let file = object::File::parse(&*self.binary_data)
            .map_err(|e| SnippexError::BinaryParsing(e.to_string()))?;

        let mut sections = Vec::new();

        for section in file.sections() {
            let name = section.name().unwrap_or("");

            // Skip empty or unnamed sections
            if name.is_empty() {
                continue;
            }

            let metadata = self.create_section_metadata(&section)?;

            // .bss section has no data in the file (uninitialized)
            let data = if name == ".bss" {
                None
            } else {
                Some(section.data()
                    .map_err(|e| SnippexError::BinaryParsing(e.to_string()))?
                    .to_vec())
            };

            sections.push((metadata, data));
        }

        Ok(sections)
    }

    fn extract_section_by_name(&self, section_name: &str) -> Result<(SectionMetadata, Vec<u8>)> {
        let file = object::File::parse(&*self.binary_data)
            .map_err(|e| SnippexError::BinaryParsing(e.to_string()))?;

        let section = file
            .section_by_name(section_name)
            .ok_or_else(|| {
                SnippexError::InvalidBinary(format!("{} section not found", section_name))
            })?;

        let metadata = self.create_section_metadata(&section)?;
        let data = section
            .data()
            .map_err(|e| SnippexError::BinaryParsing(e.to_string()))?
            .to_vec();

        Ok((metadata, data))
    }

    fn create_section_metadata<'a>(&self, section: &object::Section<'a, 'a>) -> Result<SectionMetadata> {
        let name = section.name().unwrap_or("").to_string();
        let offset = section.file_range().map(|(off, _)| off).unwrap_or(0);
        let size = section.size();
        let virtual_address = section.address();
        let alignment = section.align();

        // Determine permissions based on section name and kind
        // This is a simplified approach that works for common sections
        let is_executable = name == ".text" || section.kind() == object::SectionKind::Text;
        let is_writable = name == ".data" || name == ".bss" || section.kind() == object::SectionKind::Data;
        let is_readable = true; // Most sections are readable

        Ok(SectionMetadata {
            name,
            offset,
            size,
            virtual_address,
            alignment,
            is_executable,
            is_writable,
            is_readable,
        })
    }

    pub fn load_section_bytes(&self, offset: u64, size: u64) -> Result<Vec<u8>> {
        let start = offset as usize;
        let end = start + size as usize;

        if end > self.binary_data.len() {
            return Err(SnippexError::InvalidBinary(
                format!("Section extends beyond file bounds: offset={}, size={}", offset, size)
            ).into());
        }

        Ok(self.binary_data[start..end].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_test_elf() -> NamedTempFile {
        let mut temp = NamedTempFile::new().unwrap();

        // Write a minimal ELF header and sections
        // This is a simplified x86_64 ELF for testing
        let elf_data = include_bytes!("/bin/ls");
        temp.write_all(elf_data).unwrap();
        temp.flush().unwrap();

        temp
    }

    #[test]
    fn test_section_loader_creation() {
        let temp = create_test_elf();
        let loader = BinarySectionLoader::new(temp.path());
        assert!(loader.is_ok());
    }

    #[test]
    fn test_extract_text_section() {
        let temp = create_test_elf();
        let loader = BinarySectionLoader::new(temp.path()).unwrap();
        let result = loader.extract_text_section();
        assert!(result.is_ok());

        let (metadata, data) = result.unwrap();
        assert_eq!(metadata.name, ".text");
        assert!(data.len() > 0);
        assert!(metadata.is_executable);
    }

    #[test]
    fn test_extract_all_sections() {
        let temp = create_test_elf();
        let loader = BinarySectionLoader::new(temp.path()).unwrap();
        let result = loader.extract_all_sections();
        assert!(result.is_ok());

        let sections = result.unwrap();
        assert!(sections.len() > 0);

        // Check that .text section is present
        let has_text = sections.iter().any(|(meta, _)| meta.name == ".text");
        assert!(has_text);
    }
}
