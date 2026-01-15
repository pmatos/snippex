//! Sandbox memory management for safe assembly block execution.
//!
//! This module implements address translation to map binary address spaces into a
//! controlled sandbox memory region. This enables simulation of extracted assembly
//! blocks that reference memory addresses from their original binary context.
//!
//! # Overview
//!
//! The sandbox solves a critical problem: extracted assembly blocks often contain
//! memory references tied to the original binary's address space (e.g., 0x555555000000
//! for PIE binaries). Without translation, these references fail during simulation
//! because the simulator uses a different address space.
//!
//! # Key Features
//!
//! - **Linear Address Translation**: Maps original addresses to sandbox space while
//!   preserving relative offsets (critical for RIP-relative addressing)
//! - **Section Management**: Tracks .text, .data, .rodata, .bss sections with metadata
//! - **Memory Allocation**: Prepares memory regions for simulator execution
//! - **Bounds Checking**: Validates all addresses stay within sandbox limits
//!
//! # Architecture
//!
//! ```text
//! Original Binary (0x555555554000):     Sandbox (0x10000000):
//! ┌──────────────────────────┐         ┌──────────────────────────┐
//! │ 0x555555555000: .text    │   -->   │ 0x10001000: .text        │
//! │ 0x555555565000: .data    │   -->   │ 0x10011000: .data        │
//! │ 0x555555575000: .rodata  │   -->   │ 0x10021000: .rodata      │
//! └──────────────────────────┘         └──────────────────────────┘
//! ```
//!
//! # Limitations
//!
//! The sandbox has important constraints that users should understand:
//!
//! ## 1. System Calls Not Supported
//!
//! Assembly blocks that execute system calls (syscall, int 0x80) will fail or
//! produce incorrect results. The sandbox cannot intercept or emulate system calls.
//!
//! **Impact**: Blocks with I/O operations, memory allocation (mmap, brk), or
//! process control will not simulate correctly.
//!
//! **Workaround**: Focus on computational blocks without system calls for testing.
//!
//! ## 2. External Function Calls
//!
//! Calls to library functions (libc, etc.) are not resolved. The sandbox only
//! contains the extracted block's code and data sections.
//!
//! **Impact**: Blocks calling printf, malloc, or any external function will crash.
//!
//! **Workaround**: Only test self-contained blocks without external dependencies.
//!
//! ## 3. Thread-Local Storage (TLS)
//!
//! TLS accesses (%fs, %gs segment registers) are not set up. Modern binaries
//! often use TLS for stack canaries and other security features.
//!
//! **Impact**: Blocks accessing TLS will segfault or produce incorrect results.
//!
//! **Workaround**: Avoid blocks with stack protector or TLS-dependent code.
//!
//! ## 4. Size Limitations
//!
//! The sandbox is limited to 256MB (SANDBOX_SIZE). Binaries with large sections
//! or high base addresses may exceed this limit.
//!
//! **Impact**: Address translation may fail for large binaries or those loaded
//! at very high addresses.
//!
//! **Workaround**: Test with reasonably-sized binaries (most typical programs work).
//!
//! ## 5. Dynamic Memory
//!
//! Heap allocations (new, malloc) that occurred before extraction are not captured.
//! Only static sections (.data, .rodata, .bss) are available.
//!
//! **Impact**: Blocks accessing heap data will fail unless the data is in static sections.
//!
//! **Workaround**: Focus on blocks operating on static data or registers.
//!
//! # Usage Example
//!
//! ```ignore
//! use snippex::simulator::{SandboxMemoryLayout, SANDBOX_BASE};
//! use snippex::extractor::section_loader::BinarySectionLoader;
//!
//! // Load binary and get base address
//! let loader = BinarySectionLoader::new("/bin/ls")?;
//! let base_address = /* parse from ELF headers */;
//!
//! // Create sandbox
//! let mut sandbox = SandboxMemoryLayout::new(base_address);
//!
//! // Load sections
//! let (text_meta, text_data) = loader.extract_text_section()?;
//! sandbox.add_section(text_meta, Some(text_data))?;
//!
//! // Translate addresses for simulation
//! let original_addr = 0x555555555000;
//! let sandbox_addr = sandbox.translate_to_sandbox(original_addr)?;
//!
//! // Allocate memory for simulator
//! let memory = sandbox.allocate_memory_region()?;
//! ```
//!
//! # Safety Guarantees
//!
//! The sandbox provides isolation through:
//! - Address validation (all translations checked against bounds)
//! - No direct memory access outside sandbox range
//! - Section-based access control (read-only .rodata, executable .text)
//!
//! However, the sandbox cannot prevent:
//! - Buffer overflows within a section
//! - Incorrect memory accesses due to bugs in the assembly block
//! - Side effects from system calls (if attempted)

use anyhow::Result;
use std::collections::HashMap;

use crate::error::SnippexError;
use crate::extractor::section_loader::SectionMetadata;

/// Sandbox memory base address: 0x10000000 (256MB safe zone start)
///
/// This constant defines the starting address of the sandbox memory region where
/// binary sections are mapped during simulation. The sandbox provides a controlled
/// memory environment for executing extracted assembly blocks.
pub const SANDBOX_BASE: u64 = 0x1000_0000;

/// Sandbox memory size: 256MB (0x10000000 bytes)
///
/// This defines the total size of the sandbox memory region. All binary sections
/// must fit within this range (SANDBOX_BASE to SANDBOX_BASE + SANDBOX_SIZE).
pub const SANDBOX_SIZE: u64 = 0x1000_0000; // 256MB

/// Address translation layout for mapping binary address spaces to sandbox memory.
///
/// # Address Translation Algorithm
///
/// The `SandboxMemoryLayout` implements a linear address translation scheme:
///
/// ```text
/// Original Binary Layout:          Simulation Sandbox:
/// ┌─────────────────────────┐     ┌─────────────────────────┐
/// │ 0x555555000000: .text   │ --> │ 0x10000000: .text       │
/// │ 0x555555010000: .data   │ --> │ 0x10010000: .data       │
/// │ 0x555555020000: .rodata │ --> │ 0x10020000: .rodata     │
/// └─────────────────────────┘     └─────────────────────────┘
///
/// Translation formula:
///   sandbox_addr = SANDBOX_BASE + (original_addr - binary_base)
///
/// Example (PIE binary at base 0x555555554000):
///   - Original: 0x555555555000 (.text at +0x1000)
///   - Sandbox:  0x10001000 (SANDBOX_BASE + 0x1000)
///
/// Example (non-PIE binary at base 0x400000):
///   - Original: 0x401000 (.text at +0x1000)
///   - Sandbox:  0x10001000 (SANDBOX_BASE + 0x1000)
/// ```
///
/// ## Key Properties
///
/// 1. **Relative offsets preserved**: If two addresses are N bytes apart in the
///    original binary, they remain N bytes apart in the sandbox.
///
/// 2. **RIP-relative addressing works**: Since relative offsets are preserved,
///    instructions like `mov rax, [rip + 0x1000]` continue to work correctly.
///
/// 3. **Bounds checking**: All translated addresses must fall within
///    [SANDBOX_BASE, SANDBOX_BASE + SANDBOX_SIZE).
///
/// ## Why This Solves the Address Space Problem
///
/// Extracted assembly blocks often contain memory references tied to the original
/// binary's address space (e.g., 0x555555000000). Without translation, these
/// references fail during simulation because the simulator uses a different
/// address space. By mapping the original addresses to the sandbox, we enable
/// native execution of blocks with memory references.
#[derive(Debug, Clone)]
pub struct SandboxMemoryLayout {
    sandbox_base: u64,
    binary_base: u64,
    sections: Vec<SectionMapping>,
}

/// Represents a binary section mapped into the sandbox.
///
/// Each section maintains both its original address (from the binary) and its
/// translated sandbox address, along with the section's metadata and optional data.
#[derive(Debug, Clone)]
pub struct SectionMapping {
    /// Metadata about the section (name, size, permissions, alignment)
    pub section_metadata: SectionMetadata,
    /// Original virtual address in the binary's address space
    pub original_address: u64,
    /// Translated address in the sandbox memory space
    pub sandbox_address: u64,
    /// Optional section data (None for .bss which is zero-initialized)
    pub data: Option<Vec<u8>>,
}

impl SandboxMemoryLayout {
    /// Creates a new sandbox memory layout for a binary with the given base address.
    ///
    /// # Arguments
    ///
    /// * `binary_base` - The original virtual address where the binary is loaded
    ///   (typically from the first LOAD segment in ELF headers)
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // For PIE binary at 0x555555554000
    /// let sandbox = SandboxMemoryLayout::new(0x555555554000);
    ///
    /// // For non-PIE binary at 0x400000
    /// let sandbox = SandboxMemoryLayout::new(0x400000);
    /// ```
    pub fn new(binary_base: u64) -> Self {
        Self {
            sandbox_base: SANDBOX_BASE,
            binary_base,
            sections: Vec::new(),
        }
    }

    /// Adds a binary section to the sandbox memory layout.
    ///
    /// This method:
    /// 1. Translates the section's original address to sandbox space
    /// 2. Validates the section fits within sandbox bounds
    /// 3. Stores the section mapping for later memory allocation
    ///
    /// # Arguments
    ///
    /// * `section_metadata` - Metadata about the section (name, size, address, permissions)
    /// * `data` - Optional section data (Some for .text/.data/.rodata, None for .bss)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The section's original address cannot be translated (out of range)
    /// - The translated section would exceed sandbox bounds
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let mut sandbox = SandboxMemoryLayout::new(0x400000);
    /// let text_metadata = /* section metadata */;
    /// let text_data = vec![0x90, 0x90, 0x90]; // assembly bytes
    /// sandbox.add_section(text_metadata, Some(text_data))?;
    /// ```
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

    /// Translates an address from the original binary's address space to sandbox memory.
    ///
    /// This is the core address translation method that implements the linear mapping:
    /// `sandbox_addr = SANDBOX_BASE + (original_addr - binary_base)`
    ///
    /// # Arguments
    ///
    /// * `original_addr` - An address from the binary's original virtual address space
    ///
    /// # Returns
    ///
    /// * `Ok(u64)` - The translated sandbox address
    /// * `Err(_)` - If the address is out of range or translation would exceed sandbox bounds
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // PIE binary at 0x555555554000
    /// let sandbox = SandboxMemoryLayout::new(0x555555554000);
    /// let text_addr = 0x555555555000; // .text at +0x1000
    /// let sandbox_addr = sandbox.translate_to_sandbox(text_addr)?;
    /// assert_eq!(sandbox_addr, 0x10001000); // SANDBOX_BASE + 0x1000
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The address is not within the binary's address space (checked by `is_in_original_range`)
    /// - The translated address would exceed sandbox bounds (SANDBOX_BASE + SANDBOX_SIZE)
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

    /// Checks if an address falls within the original binary's expected address range.
    ///
    /// This validates that an address is within the translatable range before attempting
    /// translation. The range is [binary_base, binary_base + SANDBOX_SIZE).
    ///
    /// # Arguments
    ///
    /// * `addr` - The address to check
    ///
    /// # Returns
    ///
    /// `true` if the address is within the binary's address space, `false` otherwise
    pub fn is_in_original_range(&self, addr: u64) -> bool {
        addr >= self.binary_base && addr < self.binary_base + SANDBOX_SIZE
    }

    /// Returns the sandbox base address (always SANDBOX_BASE = 0x10000000).
    pub fn sandbox_base(&self) -> u64 {
        self.sandbox_base
    }

    /// Returns the original binary's base address.
    ///
    /// This is the address where the binary is loaded in its original address space,
    /// typically obtained from the first LOAD segment in ELF headers.
    pub fn binary_base(&self) -> u64 {
        self.binary_base
    }

    /// Returns a slice of all section mappings in the sandbox.
    ///
    /// Each mapping contains both the original address and translated sandbox address,
    /// along with the section metadata and optional data.
    pub fn sections(&self) -> &[SectionMapping] {
        &self.sections
    }

    /// Finds the section that contains a given original address.
    ///
    /// Useful for determining which section (e.g., .text, .data) an address belongs to,
    /// which can help with debugging or understanding memory access patterns.
    ///
    /// # Arguments
    ///
    /// * `original_addr` - An address in the original binary's address space
    ///
    /// # Returns
    ///
    /// `Some(&SectionMapping)` if the address falls within a mapped section,
    /// `None` if no section contains this address
    pub fn find_section_by_address(&self, original_addr: u64) -> Option<&SectionMapping> {
        self.sections.iter().find(|section| {
            let section_start = section.original_address;
            let section_end = section_start + section.section_metadata.size;
            original_addr >= section_start && original_addr < section_end
        })
    }

    /// Retrieves a section mapping by section name.
    ///
    /// # Arguments
    ///
    /// * `name` - The section name (e.g., ".text", ".data", ".rodata", ".bss")
    ///
    /// # Returns
    ///
    /// `Some(&SectionMapping)` if a section with this name exists,
    /// `None` if no such section has been added
    pub fn get_section_by_name(&self, name: &str) -> Option<&SectionMapping> {
        self.sections
            .iter()
            .find(|section| section.section_metadata.name == name)
    }

    /// Allocates and initializes the sandbox memory region with section data.
    ///
    /// Creates a HashMap mapping sandbox addresses to section data bytes. This is
    /// used by the simulator to set up memory before executing assembly blocks.
    ///
    /// # Behavior
    ///
    /// - Sections with data (Some): Data is copied to sandbox address
    /// - .bss sections (None): Zero-initialized to section size
    /// - Other sections without data: Skipped (not allocated)
    ///
    /// # Returns
    ///
    /// `Ok(HashMap<u64, Vec<u8>>)` - Map from sandbox addresses to section data
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let mut sandbox = SandboxMemoryLayout::new(0x400000);
    /// // ... add sections ...
    /// let memory = sandbox.allocate_memory_region()?;
    /// // Use memory map for simulator memory setup
    /// ```
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
