use anyhow::Result;
use capstone::prelude::*;
use object::{Architecture, BinaryFormat, Object, ObjectSection, ObjectSegment, SectionKind};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::cell::OnceCell;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use crate::db::BinaryInfo;
use crate::error::SnippexError;

const MIN_BLOCK_SIZE: usize = 16;

/// Instruction categories for filtering
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InstructionCategory {
    General,
    Fpu,
    Sse,
    Avx,
    Avx512,
    Branch,
    Syscall,
    /// Skipped/invalid bytes (from SKIPDATA mode) - never matches filters
    Invalid,
}

impl std::str::FromStr for InstructionCategory {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "general" => Ok(Self::General),
            "fpu" | "x87" => Ok(Self::Fpu),
            "sse" | "sse2" | "sse3" | "sse4" | "ssse3" => Ok(Self::Sse),
            "avx" | "avx2" => Ok(Self::Avx),
            "avx512" => Ok(Self::Avx512),
            "branch" | "jump" => Ok(Self::Branch),
            "syscall" | "system" => Ok(Self::Syscall),
            "invalid" => Ok(Self::Invalid),
            _ => Err(format!("Unknown instruction category: {}", s)),
        }
    }
}

impl InstructionCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::General => "general",
            Self::Fpu => "fpu",
            Self::Sse => "sse",
            Self::Avx => "avx",
            Self::Avx512 => "avx512",
            Self::Branch => "branch",
            Self::Syscall => "syscall",
            Self::Invalid => "invalid",
        }
    }
}

/// Extraction filter configuration
#[derive(Debug, Clone, Default)]
pub struct ExtractionFilter {
    /// Minimum block size in bytes
    pub min_size: Option<usize>,
    /// Maximum block size in bytes
    pub max_size: Option<usize>,
    /// Require memory access instructions
    pub require_memory_access: Option<bool>,
    /// Require control flow instructions (jumps, calls, returns)
    pub require_control_flow: Option<bool>,
    /// Required instruction categories (any match)
    pub instruction_categories: Option<HashSet<InstructionCategory>>,
}

impl ExtractionFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_min_size(mut self, size: usize) -> Self {
        self.min_size = Some(size);
        self
    }

    pub fn with_max_size(mut self, size: usize) -> Self {
        self.max_size = Some(size);
        self
    }

    pub fn with_memory_access(mut self, require: bool) -> Self {
        self.require_memory_access = Some(require);
        self
    }

    pub fn with_control_flow(mut self, require: bool) -> Self {
        self.require_control_flow = Some(require);
        self
    }

    pub fn with_instruction_categories(mut self, categories: HashSet<InstructionCategory>) -> Self {
        self.instruction_categories = Some(categories);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.min_size.is_none()
            && self.max_size.is_none()
            && self.require_memory_access.is_none()
            && self.require_control_flow.is_none()
            && self.instruction_categories.is_none()
    }

    pub fn validate(&self) -> Result<()> {
        if let (Some(min), Some(max)) = (self.min_size, self.max_size) {
            if min > max {
                return Err(anyhow::anyhow!(
                    "min-size ({}) cannot be greater than max-size ({})",
                    min,
                    max
                ));
            }
        }
        Ok(())
    }
}

/// Result of checking if a block matches filter criteria
#[derive(Debug)]
pub struct FilterMatch {
    pub matches: bool,
    #[allow(dead_code)]
    pub block_size: usize,
    #[allow(dead_code)]
    pub has_memory_access: bool,
    #[allow(dead_code)]
    pub has_control_flow: bool,
    pub categories_found: HashSet<InstructionCategory>,
    #[allow(dead_code)]
    pub instruction_count: usize,
}

pub mod section_loader;

#[cfg(test)]
mod tests;

#[derive(Debug, Clone)]
pub enum SupportedFormat {
    Elf,
    Pe,
}

impl SupportedFormat {
    fn as_str(&self) -> &'static str {
        match self {
            SupportedFormat::Elf => "ELF",
            SupportedFormat::Pe => "PE",
        }
    }
}

/// Cached instruction metadata for efficient filtering
#[derive(Clone)]
struct InstructionMeta {
    address: u64,
    size: usize,
    has_memory_access: bool,
    category: InstructionCategory,
}

/// Cached disassembly data for the .text section
struct DisassemblyCache {
    section_addr: u64,
    section_data: Vec<u8>,
    instructions: Vec<InstructionMeta>,
}

pub struct Extractor {
    binary_path: PathBuf,
    binary_data: Vec<u8>,
    /// Cached binary info to avoid recomputing SHA256 hash on every call
    cached_binary_info: OnceCell<BinaryInfo>,
    /// Cached disassembly for efficient filtered extraction
    cached_disassembly: OnceCell<DisassemblyCache>,
}

impl Extractor {
    pub fn new(binary_path: PathBuf) -> Result<Self> {
        let binary_data = fs::read(&binary_path)?;
        Ok(Extractor {
            binary_path,
            binary_data,
            cached_binary_info: OnceCell::new(),
            cached_disassembly: OnceCell::new(),
        })
    }

    fn detect_format(&self) -> Result<SupportedFormat> {
        let file = object::File::parse(&*self.binary_data)
            .map_err(|e| SnippexError::BinaryParsing(e.to_string()))?;

        match file.format() {
            BinaryFormat::Elf => Ok(SupportedFormat::Elf),
            BinaryFormat::Pe => Ok(SupportedFormat::Pe),
            BinaryFormat::Coff => Err(SnippexError::InvalidBinary(
                "COFF format is not supported. Please use PE format for Windows binaries.".into(),
            )
            .into()),
            BinaryFormat::MachO => Err(SnippexError::InvalidBinary(
                "Mach-O format is not supported. Only ELF and PE formats are supported.".into(),
            )
            .into()),
            BinaryFormat::Wasm => Err(SnippexError::InvalidBinary(
                "WebAssembly format is not supported. Only ELF and PE formats are supported."
                    .into(),
            )
            .into()),
            BinaryFormat::Xcoff => Err(SnippexError::InvalidBinary(
                "XCOFF format is not supported. Only ELF and PE formats are supported.".into(),
            )
            .into()),
            _ => Err(SnippexError::InvalidBinary(
                "Unknown or unsupported binary format. Only ELF and PE formats are supported."
                    .into(),
            )
            .into()),
        }
    }

    fn get_architecture_info(&self, file: &object::File) -> Result<(String, String)> {
        let architecture =
            match file.architecture() {
                Architecture::X86_64 => "x86_64",
                Architecture::I386 => "i386",
                _ => return Err(SnippexError::InvalidBinary(
                    "Unsupported architecture. Only x86 and x86_64 architectures are supported."
                        .into(),
                )
                .into()),
            };

        let endianness = if file.is_little_endian() {
            "little"
        } else {
            "big"
        };

        Ok((architecture.to_string(), endianness.to_string()))
    }

    pub fn get_binary_info(&self) -> Result<BinaryInfo> {
        // Use cached value if available
        if let Some(info) = self.cached_binary_info.get() {
            return Ok(info.clone());
        }

        // Compute and cache
        let info = self.compute_binary_info()?;
        // Ignore error if another thread set it first
        let _ = self.cached_binary_info.set(info.clone());
        Ok(info)
    }

    fn compute_binary_info(&self) -> Result<BinaryInfo> {
        let file = object::File::parse(&*self.binary_data)
            .map_err(|e| SnippexError::BinaryParsing(e.to_string()))?;

        let format = self.detect_format()?;
        let (architecture, endianness) = self.get_architecture_info(&file)?;

        let mut hasher = Sha256::new();
        hasher.update(&self.binary_data);
        let hash = format!("{:x}", hasher.finalize());

        // Extract base address from ELF (first LOAD segment virtual address)
        // Default to 0x400000 (common non-PIE base) if not found
        let base_address = file
            .segments()
            .filter_map(|segment| {
                // Get the first segment with a non-zero address
                let addr = segment.address();
                if addr > 0 {
                    Some(addr)
                } else {
                    None
                }
            })
            .min() // Get the lowest non-zero address
            .unwrap_or(0x400000);

        // Extract entry point address from ELF header
        let entry_point = file.entry();

        Ok(BinaryInfo {
            path: self.binary_path.to_string_lossy().to_string(),
            size: self.binary_data.len() as u64,
            hash,
            format: format.as_str().to_string(),
            architecture,
            endianness,
            base_address,
            entry_point,
        })
    }

    fn find_executable_section<'a>(
        &self,
        file: &'a object::File<'a>,
    ) -> Result<object::Section<'a, 'a>> {
        // For PE files, prefer the section containing the entry point
        // This handles packed/protected executables where .text may contain encrypted data
        let entry = file.entry();
        if entry != 0 {
            for section in file.sections() {
                let start = section.address();
                let end = start + section.size();
                if entry >= start && entry < end {
                    // Found section containing entry point
                    if section.kind() == SectionKind::Text
                        || section.name().map(|n| n.contains("CODE") || n.contains("code") || n == ".bind").unwrap_or(false)
                    {
                        return Ok(section);
                    }
                }
            }
        }

        // Fallback: try common executable section names in order of preference
        let section_names = match self.detect_format()? {
            SupportedFormat::Elf => vec![".text"],
            SupportedFormat::Pe => vec![".text", "CODE", ".code"],
        };

        for section_name in section_names {
            if let Some(section) = file.section_by_name(section_name) {
                return Ok(section);
            }
        }

        // If no named section found, look for the first executable section
        for section in file.sections() {
            // Check if section is executable by looking at section kind
            if section.kind() == SectionKind::Text {
                return Ok(section);
            }
        }

        Err(SnippexError::InvalidBinary("No executable section found".into()).into())
    }

    pub fn create_capstone(&self) -> Result<capstone::Capstone> {
        let binary_info = self.get_binary_info()?;

        let cs = match binary_info.architecture.as_str() {
            "i386" => capstone::Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode32)
                .detail(false)
                .build()
                .map_err(|e| {
                    SnippexError::BinaryParsing(format!("Failed to create x86 capstone: {e}"))
                })?,
            "x86_64" => capstone::Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .detail(false)
                .build()
                .map_err(|e| {
                    SnippexError::BinaryParsing(format!("Failed to create x86_64 capstone: {e}"))
                })?,
            _ => {
                return Err(SnippexError::InvalidBinary(format!(
                    "Unsupported architecture for disassembly: {}",
                    binary_info.architecture
                ))
                .into())
            }
        };

        Ok(cs)
    }

    pub fn extract_random_aligned_block(&self) -> Result<(u64, u64, Vec<u8>)> {
        let file = object::File::parse(&*self.binary_data)
            .map_err(|e| SnippexError::BinaryParsing(e.to_string()))?;

        let text_section = self.find_executable_section(&file)?;

        let section_data = text_section
            .data()
            .map_err(|e| SnippexError::BinaryParsing(e.to_string()))?;

        if section_data.is_empty() {
            return Err(SnippexError::InvalidBinary("Empty executable section".into()).into());
        }

        let section_addr = text_section.address();
        let cs = self.create_capstone()?;

        // Disassemble the entire section to get instruction boundaries
        let insns = cs.disasm_all(section_data, section_addr).map_err(|e| {
            SnippexError::BinaryParsing(format!("Failed to disassemble section: {e}"))
        })?;

        if insns.len() < 2 {
            return Err(
                SnippexError::InvalidBinary("Not enough instructions in section".into()).into(),
            );
        }

        let mut rng = rand::rng();

        // Define block size in terms of instruction count
        let min_instructions = std::cmp::min(4, insns.len() / 2);
        let max_instructions = std::cmp::min(32, insns.len() - 1);

        if min_instructions >= max_instructions {
            return Err(SnippexError::InvalidBinary(
                "Section too small for block extraction".into(),
            )
            .into());
        }

        let instruction_count = rng.random_range(min_instructions..=max_instructions);

        // Pick a random starting instruction
        let max_start_idx = insns.len() - instruction_count;
        let start_idx = if max_start_idx > 0 {
            rng.random_range(0..max_start_idx)
        } else {
            0
        };

        let mut end_idx = start_idx + instruction_count;

        // Get the address range and ensure minimum block size
        let start_addr = insns[start_idx].address();

        // Calculate initial block size and extend if needed to meet MIN_BLOCK_SIZE
        loop {
            let tentative_end_addr = if end_idx < insns.len() {
                insns[end_idx].address()
            } else {
                let last_insn = &insns[insns.len() - 1];
                last_insn.address() + last_insn.bytes().len() as u64
            };

            let block_size = (tentative_end_addr - start_addr) as usize;

            // If block is large enough or we can't extend further, break
            if block_size >= MIN_BLOCK_SIZE || end_idx >= insns.len() {
                break;
            }

            // Extend by one more instruction
            end_idx += 1;
        }

        // Final validation: ensure we have at least MIN_BLOCK_SIZE
        let final_end_addr = if end_idx < insns.len() {
            insns[end_idx].address()
        } else {
            let last_insn = &insns[insns.len() - 1];
            last_insn.address() + last_insn.bytes().len() as u64
        };

        if (final_end_addr - start_addr) < MIN_BLOCK_SIZE as u64 {
            return Err(SnippexError::InvalidBinary(format!(
                "Cannot extract block of at least {MIN_BLOCK_SIZE} bytes from section"
            ))
            .into());
        }

        let end_addr = final_end_addr;

        // Extract the bytes from the section data
        let start_offset = (start_addr - section_addr) as usize;
        let end_offset = (end_addr - section_addr) as usize;

        if end_offset > section_data.len() {
            return Err(SnippexError::InvalidBinary("Block extends beyond section".into()).into());
        }

        let assembly_block = section_data[start_offset..end_offset].to_vec();

        Ok((start_addr, end_addr, assembly_block))
    }

    pub fn extract_range(&self, start_addr: u64, end_addr: u64) -> Result<(u64, u64, Vec<u8>)> {
        if start_addr >= end_addr {
            return Err(SnippexError::InvalidBinary(
                "Start address must be less than end address".into(),
            )
            .into());
        }

        let file = object::File::parse(&*self.binary_data)
            .map_err(|e| SnippexError::BinaryParsing(e.to_string()))?;

        let text_section = self.find_executable_section(&file)?;

        let section_data = text_section
            .data()
            .map_err(|e| SnippexError::BinaryParsing(e.to_string()))?;

        if section_data.is_empty() {
            return Err(SnippexError::InvalidBinary("Empty executable section".into()).into());
        }

        let section_addr = text_section.address();
        let section_end = section_addr + section_data.len() as u64;

        // Validate that addresses are within the section
        if start_addr < section_addr || end_addr > section_end {
            return Err(SnippexError::InvalidBinary(format!(
                "Address range 0x{start_addr:x}-0x{end_addr:x} is outside executable section (0x{section_addr:x}-0x{section_end:x})"
            ))
            .into());
        }

        let cs = self.create_capstone()?;

        // Disassemble the entire section to verify instruction alignment
        let insns = cs.disasm_all(section_data, section_addr).map_err(|e| {
            SnippexError::BinaryParsing(format!("Failed to disassemble section: {e}"))
        })?;

        // Verify start address is instruction-aligned
        let start_instruction = insns.iter().find(|insn| insn.address() == start_addr);
        if start_instruction.is_none() {
            return Err(SnippexError::InvalidBinary(format!(
                "Start address 0x{start_addr:x} is not instruction-aligned"
            ))
            .into());
        }

        // Find the instruction that should end the block
        let mut end_instruction = None;
        for insn in insns.iter() {
            let insn_end = insn.address() + insn.bytes().len() as u64;
            if insn_end == end_addr {
                end_instruction = Some(insn);
                break;
            }
            // Also check if this is an instruction that starts at the end address
            if insn.address() == end_addr {
                end_instruction = Some(insn);
                break;
            }
        }

        // If we didn't find an exact match, check if end_addr is a valid instruction boundary
        if end_instruction.is_none() {
            // Allow end_addr to be at any instruction boundary within the range
            let valid_end = insns.iter().any(|insn| {
                let insn_start = insn.address();
                let insn_end = insn.address() + insn.bytes().len() as u64;
                (insn_start == end_addr || insn_end == end_addr) && insn_start >= start_addr
            });

            if !valid_end {
                return Err(SnippexError::InvalidBinary(format!(
                    "End address 0x{end_addr:x} is not instruction-aligned"
                ))
                .into());
            }
        }

        // Extract the bytes from the section data
        let start_offset = (start_addr - section_addr) as usize;
        let end_offset = (end_addr - section_addr) as usize;

        let assembly_block = section_data[start_offset..end_offset].to_vec();

        // Verify the extracted block contains valid instructions
        let block_insns = cs.disasm_all(&assembly_block, start_addr).map_err(|e| {
            SnippexError::BinaryParsing(format!(
                "Extracted block contains invalid instructions: {e}"
            ))
        })?;

        if block_insns.is_empty() {
            return Err(SnippexError::InvalidBinary(
                "Extracted range contains no valid instructions".into(),
            )
            .into());
        }

        Ok((start_addr, end_addr, assembly_block))
    }

    /// Extract a random block that matches the given filter criteria.
    /// Uses a "seed and grow" strategy for restrictive filters.
    pub fn extract_filtered_block(&self, filter: &ExtractionFilter) -> Result<(u64, u64, Vec<u8>)> {
        filter.validate()?;

        if filter.is_empty() {
            return self.extract_random_aligned_block();
        }

        // Use seed-and-grow strategy: find matching instruction runs
        self.extract_filtered_block_growing(filter)
    }

    /// Get or compute the disassembly cache for the .text section.
    fn get_disassembly_cache(&self) -> Result<&DisassemblyCache> {
        if let Some(cache) = self.cached_disassembly.get() {
            return Ok(cache);
        }

        // Compute and cache
        let file = object::File::parse(&*self.binary_data)
            .map_err(|e| SnippexError::BinaryParsing(e.to_string()))?;

        let text_section = self.find_executable_section(&file)?;
        let section_data = text_section.data().map_err(|e| {
            SnippexError::BinaryParsing(format!("Failed to read section data: {e}"))
        })?;
        let section_addr = text_section.address();

        let cs = self.create_capstone_with_detail()?;

        // Disassemble the entire section
        let insns = cs.disasm_all(section_data, section_addr).map_err(|e| {
            SnippexError::BinaryParsing(format!("Failed to disassemble section: {e}"))
        })?;

        // Build instruction metadata
        let instructions: Vec<InstructionMeta> = insns
            .iter()
            .map(|insn| {
                let mnemonic = insn.mnemonic().unwrap_or("");
                let op_str = insn.op_str().unwrap_or("");
                InstructionMeta {
                    address: insn.address(),
                    size: insn.bytes().len(),
                    has_memory_access: op_str.contains('['),
                    category: Self::categorize_instruction(mnemonic),
                }
            })
            .collect();

        let cache = DisassemblyCache {
            section_addr,
            section_data: section_data.to_vec(),
            instructions,
        };

        // Store in cache (ignore if another thread set it first)
        let _ = self.cached_disassembly.set(cache);
        Ok(self.cached_disassembly.get().unwrap())
    }

    /// Extract a block using the "seed and grow" strategy.
    /// This is much more efficient for restrictive filters like "no memory, no control flow".
    ///
    /// Strategy:
    /// 1. Disassemble the entire .text section once (cached)
    /// 2. Classify each instruction (matches filter or not)
    /// 3. Find all maximal runs of matching instructions
    /// 4. Filter runs by size constraints
    /// 5. Randomly select from valid runs
    fn extract_filtered_block_growing(
        &self,
        filter: &ExtractionFilter,
    ) -> Result<(u64, u64, Vec<u8>)> {
        let cache = self.get_disassembly_cache()?;
        let instructions = &cache.instructions;

        if instructions.is_empty() {
            return Err(SnippexError::InvalidBinary("No instructions in section".into()).into());
        }

        // Find all maximal runs of instructions that match the filter
        let mut valid_runs: Vec<(usize, usize)> = Vec::new(); // (start_idx, end_idx exclusive)
        let mut run_start: Option<usize> = None;

        for (idx, meta) in instructions.iter().enumerate() {
            let matches = self.instruction_meta_matches_filter(meta, filter);

            if matches {
                if run_start.is_none() {
                    run_start = Some(idx);
                }
            } else if let Some(start) = run_start {
                // End of a run
                valid_runs.push((start, idx));
                run_start = None;
            }
        }

        // Don't forget the last run if it extends to the end
        if let Some(start) = run_start {
            valid_runs.push((start, instructions.len()));
        }

        // Filter runs by minimum size (runs must be at least min_size to be valid)
        // Note: max_size is applied later when selecting the final sub-block
        let min_size = filter.min_size.unwrap_or(MIN_BLOCK_SIZE);
        let max_size = filter.max_size;

        let valid_runs: Vec<_> = valid_runs
            .into_iter()
            .filter(|(start, end)| {
                // Calculate byte size of this run
                let start_addr = instructions[*start].address;
                let end_addr = if *end < instructions.len() {
                    instructions[*end].address
                } else {
                    let last = &instructions[instructions.len() - 1];
                    last.address + last.size as u64
                };
                let size = (end_addr - start_addr) as usize;

                // Run must be at least min_size (larger runs will be trimmed later)
                size >= min_size
            })
            .collect();

        if valid_runs.is_empty() {
            return Err(anyhow::anyhow!(
                "No instruction runs matching filter criteria found. \
                 The filter may be too restrictive for this binary."
            ));
        }

        // Randomly select one of the valid runs
        let mut rng = rand::rng();
        let (run_start, run_end) = valid_runs[rng.random_range(0..valid_runs.len())];

        // For runs larger than max_size, we need to extract a sub-range
        let start_addr = instructions[run_start].address;
        let run_end_addr = if run_end < instructions.len() {
            instructions[run_end].address
        } else {
            let last = &instructions[instructions.len() - 1];
            last.address + last.size as u64
        };
        let run_size = (run_end_addr - start_addr) as usize;

        // If the run is larger than max_size, select a random sub-block
        let (final_start_idx, final_end_idx) = if let Some(max) = max_size {
            if run_size > max {
                // Find a random starting point within the run
                let available_start_range = run_end - run_start;
                let start_offset = rng.random_range(0..available_start_range);
                let new_start = run_start + start_offset;
                let new_start_addr = instructions[new_start].address;

                // Find the largest end_idx such that block size <= max
                // Start with at least one instruction
                let mut best_end = new_start + 1;
                for candidate_end in (new_start + 1)..=run_end {
                    let end_addr = if candidate_end < instructions.len() {
                        instructions[candidate_end].address
                    } else {
                        let last = &instructions[instructions.len() - 1];
                        last.address + last.size as u64
                    };
                    let size = (end_addr - new_start_addr) as usize;
                    if size <= max {
                        best_end = candidate_end;
                    } else {
                        break; // Further candidates will only be larger
                    }
                }
                (new_start, best_end)
            } else {
                (run_start, run_end)
            }
        } else {
            (run_start, run_end)
        };

        // Extract the bytes
        let final_start_addr = instructions[final_start_idx].address;
        let final_end_addr = if final_end_idx < instructions.len() {
            instructions[final_end_idx].address
        } else {
            let last = &instructions[instructions.len() - 1];
            last.address + last.size as u64
        };

        let start_offset = (final_start_addr - cache.section_addr) as usize;
        let end_offset = (final_end_addr - cache.section_addr) as usize;
        let assembly_block = cache.section_data[start_offset..end_offset].to_vec();

        Ok((final_start_addr, final_end_addr, assembly_block))
    }

    /// Check if instruction metadata matches the filter criteria.
    fn instruction_meta_matches_filter(
        &self,
        meta: &InstructionMeta,
        filter: &ExtractionFilter,
    ) -> bool {
        // Invalid/skipped data never matches
        if meta.category == InstructionCategory::Invalid {
            return false;
        }

        // Check memory access
        if let Some(require_mem) = filter.require_memory_access {
            if require_mem != meta.has_memory_access {
                return false;
            }
        }

        // Check control flow
        let is_control_flow = meta.category == InstructionCategory::Branch;
        if let Some(require_cf) = filter.require_control_flow {
            if require_cf != is_control_flow {
                return false;
            }
        }

        // Check instruction categories (if specified, at least one must match)
        if let Some(ref required_categories) = filter.instruction_categories {
            if !required_categories.contains(&meta.category) {
                return false;
            }
        }

        true
    }

    /// Check if a block matches the given filter criteria.
    pub fn check_block_filter(
        &self,
        assembly_block: &[u8],
        start_addr: u64,
        filter: &ExtractionFilter,
    ) -> Result<FilterMatch> {
        let cs = self.create_capstone_with_detail()?;
        self.check_block_filter_with_capstone(&cs, assembly_block, start_addr, filter)
    }

    /// Check if a block matches filter criteria using a pre-created Capstone instance.
    /// This is more efficient when checking multiple blocks.
    pub fn check_block_filter_with_capstone(
        &self,
        cs: &capstone::Capstone,
        assembly_block: &[u8],
        start_addr: u64,
        filter: &ExtractionFilter,
    ) -> Result<FilterMatch> {
        let insns = cs.disasm_all(assembly_block, start_addr).map_err(|e| {
            SnippexError::BinaryParsing(format!("Failed to disassemble block: {e}"))
        })?;

        let block_size = assembly_block.len();
        let instruction_count = insns.len();
        let mut has_memory_access = false;
        let mut categories_found = HashSet::new();

        for insn in insns.iter() {
            let mnemonic = insn.mnemonic().unwrap_or("");
            let op_str = insn.op_str().unwrap_or("");

            // Detect memory access from operand string
            if op_str.contains('[') {
                has_memory_access = true;
            }

            // Categorize instruction by mnemonic
            let category = Self::categorize_instruction(mnemonic);
            categories_found.insert(category);
        }

        // Detect control flow by checking if Branch category is present
        let has_control_flow = categories_found.contains(&InstructionCategory::Branch);

        // Check size constraints
        let size_match = match (filter.min_size, filter.max_size) {
            (Some(min), Some(max)) => block_size >= min && block_size <= max,
            (Some(min), None) => block_size >= min,
            (None, Some(max)) => block_size <= max,
            (None, None) => true,
        };

        // Check memory access constraint
        let memory_match = match filter.require_memory_access {
            Some(true) => has_memory_access,
            Some(false) => !has_memory_access,
            None => true,
        };

        // Check control flow constraint
        let control_flow_match = match filter.require_control_flow {
            Some(true) => has_control_flow,
            Some(false) => !has_control_flow,
            None => true,
        };

        // Check instruction category constraint
        let category_match = match &filter.instruction_categories {
            Some(required) => !categories_found.is_disjoint(required),
            None => true,
        };

        let matches = size_match && memory_match && control_flow_match && category_match;

        Ok(FilterMatch {
            matches,
            block_size,
            has_memory_access,
            has_control_flow,
            categories_found,
            instruction_count,
        })
    }

    /// Create a Capstone instance with detail mode enabled for instruction analysis.
    fn create_capstone_with_detail(&self) -> Result<capstone::Capstone> {
        let binary_info = self.get_binary_info()?;

        let mut cs = match binary_info.architecture.as_str() {
            "i386" => capstone::Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode32)
                .detail(true)
                .build()
                .map_err(|e| {
                    SnippexError::BinaryParsing(format!("Failed to create x86 capstone: {e}"))
                })?,
            "x86_64" => capstone::Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .detail(true)
                .build()
                .map_err(|e| {
                    SnippexError::BinaryParsing(format!("Failed to create x86_64 capstone: {e}"))
                })?,
            _ => {
                return Err(SnippexError::InvalidBinary(format!(
                    "Unsupported architecture for disassembly: {}",
                    binary_info.architecture
                ))
                .into())
            }
        };

        // Enable SKIPDATA to continue past invalid byte sequences
        // This is important for packed/protected executables with encrypted regions
        cs.set_skipdata(true).map_err(|e| {
            SnippexError::BinaryParsing(format!("Failed to enable SKIPDATA: {e}"))
        })?;

        Ok(cs)
    }

    /// Categorize an instruction by its mnemonic.
    fn categorize_instruction(mnemonic: &str) -> InstructionCategory {
        // SKIPDATA pseudo-instructions (invalid/skipped bytes)
        if mnemonic.starts_with('.') || mnemonic == "db" {
            return InstructionCategory::Invalid;
        }

        let mnemonic_upper = mnemonic.to_uppercase();

        // Syscall instructions
        if mnemonic_upper == "SYSCALL" || mnemonic_upper == "SYSENTER" || mnemonic_upper == "INT" {
            return InstructionCategory::Syscall;
        }

        // Branch/jump instructions
        if mnemonic_upper.starts_with('J')
            || mnemonic_upper == "CALL"
            || mnemonic_upper == "RET"
            || mnemonic_upper == "LOOP"
            || mnemonic_upper == "LOOPE"
            || mnemonic_upper == "LOOPNE"
        {
            return InstructionCategory::Branch;
        }

        // FPU instructions
        if mnemonic_upper.starts_with('F')
            && (mnemonic_upper.starts_with("FLD")
                || mnemonic_upper.starts_with("FST")
                || mnemonic_upper.starts_with("FADD")
                || mnemonic_upper.starts_with("FSUB")
                || mnemonic_upper.starts_with("FMUL")
                || mnemonic_upper.starts_with("FDIV")
                || mnemonic_upper.starts_with("FCOM")
                || mnemonic_upper.starts_with("FINIT")
                || mnemonic_upper.starts_with("FCHS")
                || mnemonic_upper.starts_with("FABS")
                || mnemonic_upper.starts_with("FSQRT")
                || mnemonic_upper.starts_with("FSIN")
                || mnemonic_upper.starts_with("FCOS")
                || mnemonic_upper.starts_with("FPTAN")
                || mnemonic_upper.starts_with("FYL2X"))
        {
            return InstructionCategory::Fpu;
        }

        // AVX-512 instructions
        if mnemonic_upper.starts_with("VP")
            && (mnemonic_upper.contains("512")
                || mnemonic_upper.starts_with("VPMOVQ")
                || mnemonic_upper.starts_with("VPMOVM"))
        {
            return InstructionCategory::Avx512;
        }

        // AVX instructions
        if mnemonic_upper.starts_with('V')
            && !mnemonic_upper.starts_with("VERR")
            && !mnemonic_upper.starts_with("VERW")
        {
            // Check if it's AVX-512 based on mask register usage
            if mnemonic_upper.contains("MASK") {
                return InstructionCategory::Avx512;
            }
            return InstructionCategory::Avx;
        }

        // SSE instructions
        if mnemonic_upper.starts_with("MOVAP")
            || mnemonic_upper.starts_with("MOVUP")
            || mnemonic_upper.starts_with("MOVSS")
            || mnemonic_upper.starts_with("MOVSD")
            || mnemonic_upper.starts_with("MOVHP")
            || mnemonic_upper.starts_with("MOVLP")
            || mnemonic_upper.starts_with("ADDSS")
            || mnemonic_upper.starts_with("ADDSD")
            || mnemonic_upper.starts_with("ADDPS")
            || mnemonic_upper.starts_with("ADDPD")
            || mnemonic_upper.starts_with("SUBSS")
            || mnemonic_upper.starts_with("SUBSD")
            || mnemonic_upper.starts_with("SUBPS")
            || mnemonic_upper.starts_with("SUBPD")
            || mnemonic_upper.starts_with("MULSS")
            || mnemonic_upper.starts_with("MULSD")
            || mnemonic_upper.starts_with("MULPS")
            || mnemonic_upper.starts_with("MULPD")
            || mnemonic_upper.starts_with("DIVSS")
            || mnemonic_upper.starts_with("DIVSD")
            || mnemonic_upper.starts_with("DIVPS")
            || mnemonic_upper.starts_with("DIVPD")
            || mnemonic_upper.starts_with("SQRTSS")
            || mnemonic_upper.starts_with("SQRTSD")
            || mnemonic_upper.starts_with("SQRTPS")
            || mnemonic_upper.starts_with("SQRTPD")
            || mnemonic_upper.starts_with("MAXSS")
            || mnemonic_upper.starts_with("MAXSD")
            || mnemonic_upper.starts_with("MINSS")
            || mnemonic_upper.starts_with("MINSD")
            || mnemonic_upper.starts_with("CMPSS")
            || mnemonic_upper.starts_with("CMPSD")
            || mnemonic_upper.starts_with("CMPPS")
            || mnemonic_upper.starts_with("CMPPD")
            || mnemonic_upper.starts_with("CVTSS")
            || mnemonic_upper.starts_with("CVTSD")
            || mnemonic_upper.starts_with("CVTPS")
            || mnemonic_upper.starts_with("CVTPD")
            || mnemonic_upper.starts_with("CVTSI")
            || mnemonic_upper.starts_with("CVTTSS")
            || mnemonic_upper.starts_with("CVTTSD")
            || mnemonic_upper.starts_with("PMOVMSK")
            || mnemonic_upper.starts_with("MOVMSK")
            || mnemonic_upper.starts_with("MOVDQ")
            || mnemonic_upper.starts_with("PUNPCK")
            || mnemonic_upper.starts_with("PACK")
            || mnemonic_upper.starts_with("PADD")
            || mnemonic_upper.starts_with("PSUB")
            || mnemonic_upper.starts_with("PMUL")
            || mnemonic_upper.starts_with("PSLL")
            || mnemonic_upper.starts_with("PSRL")
            || mnemonic_upper.starts_with("PSRA")
            || mnemonic_upper.starts_with("PAND")
            || mnemonic_upper.starts_with("POR")
            || mnemonic_upper.starts_with("PXOR")
            || mnemonic_upper.starts_with("PCMP")
            || mnemonic_upper.starts_with("PMIN")
            || mnemonic_upper.starts_with("PMAX")
            || mnemonic_upper.starts_with("SHUFPS")
            || mnemonic_upper.starts_with("SHUFPD")
            || mnemonic_upper.starts_with("UNPCKHPS")
            || mnemonic_upper.starts_with("UNPCKHPD")
            || mnemonic_upper.starts_with("UNPCKLPS")
            || mnemonic_upper.starts_with("UNPCKLPD")
            || mnemonic_upper.starts_with("XORPS")
            || mnemonic_upper.starts_with("XORPD")
            || mnemonic_upper.starts_with("ORPS")
            || mnemonic_upper.starts_with("ORPD")
            || mnemonic_upper.starts_with("ANDPS")
            || mnemonic_upper.starts_with("ANDPD")
            || mnemonic_upper.starts_with("ANDNPS")
            || mnemonic_upper.starts_with("ANDNPD")
            || mnemonic_upper.starts_with("COMISS")
            || mnemonic_upper.starts_with("COMISD")
            || mnemonic_upper.starts_with("UCOMISS")
            || mnemonic_upper.starts_with("UCOMISD")
        {
            return InstructionCategory::Sse;
        }

        InstructionCategory::General
    }

    /// Count how many blocks would match the filter in the binary.
    /// This is useful for --dry-run to preview filter effectiveness.
    pub fn count_matching_blocks(
        &self,
        filter: &ExtractionFilter,
        sample_size: usize,
    ) -> Result<(usize, usize)> {
        filter.validate()?;

        // Create Capstone instance once and reuse for all filter checks
        let cs = self.create_capstone_with_detail()?;

        let mut matching = 0;
        let mut total = 0;

        for _ in 0..sample_size {
            if let Ok((start_addr, _, assembly_block)) = self.extract_random_aligned_block() {
                total += 1;
                if let Ok(filter_match) =
                    self.check_block_filter_with_capstone(&cs, &assembly_block, start_addr, filter)
                {
                    if filter_match.matches {
                        matching += 1;
                    }
                }
            }
        }

        Ok((matching, total))
    }
}
