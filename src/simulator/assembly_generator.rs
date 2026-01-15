use super::sandbox::SandboxMemoryLayout;
use super::state::InitialState;
use crate::analyzer::BlockAnalysis;
use crate::db::ExtractionInfo;
use crate::error::{Error, Result};

const OUTPUT_BUFFER_SIZE: usize = 4096;

/// Pointer buffer region within the sandbox (must match random_generator.rs)
const POINTER_BUFFER_BASE: u64 = super::sandbox::SANDBOX_BASE + 0x0800_0000;
const POINTER_BUFFER_END: u64 = super::sandbox::SANDBOX_BASE + super::sandbox::SANDBOX_SIZE;

pub struct AssemblyGenerator {
    #[allow(dead_code)]
    pub target_arch: String,
}

impl Default for AssemblyGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl AssemblyGenerator {
    pub fn new() -> Self {
        Self {
            target_arch: "x86_64".to_string(),
        }
    }

    pub fn generate_simulation_file(
        &self,
        extraction: &ExtractionInfo,
        analysis: &BlockAnalysis,
        initial_state: &InitialState,
        sandbox: Option<&SandboxMemoryLayout>,
    ) -> Result<String> {
        let mut assembly = String::new();

        // File header
        assembly.push_str("; Generated assembly file for block simulation\n");
        assembly.push_str(&format!(
            "; Block: 0x{:08x} - 0x{:08x}\n",
            extraction.start_address, extraction.end_address
        ));
        assembly.push_str(&format!(
            "; Architecture: {}\n",
            extraction.binary_architecture
        ));
        assembly.push('\n');

        // Assembly directives
        assembly.push_str("BITS 64\n");
        assembly.push_str("SECTION .data\n");
        assembly.push_str("    ; Output buffer for register/memory state\n");
        assembly.push_str(&format!(
            "    output_buffer times {OUTPUT_BUFFER_SIZE} db 0\n"
        ));
        assembly.push('\n');
        assembly.push_str("SECTION .text\n");
        assembly.push_str("    global _start\n");
        assembly.push('\n');
        assembly.push_str("_start:\n");

        // Generate preamble
        assembly.push_str(&self.generate_preamble(initial_state, sandbox)?);

        // Generate the actual block code
        assembly.push_str(&self.generate_block_code(extraction)?);

        // Generate epilogue
        assembly.push_str(&self.generate_epilogue(analysis)?);

        Ok(assembly)
    }

    fn generate_preamble(
        &self,
        initial_state: &InitialState,
        sandbox: Option<&SandboxMemoryLayout>,
    ) -> Result<String> {
        let mut preamble = String::new();

        preamble.push_str("    ; === PREAMBLE: Set up initial state ===\n");

        // First, map memory regions for pointer buffers
        let mmap_code = self.generate_mmap_for_pointer_buffers(initial_state);
        if !mmap_code.is_empty() {
            preamble.push_str(&mmap_code);
        }

        // Set up registers
        for (reg, value) in &initial_state.registers {
            preamble.push_str(&format!("    mov {reg}, 0x{value:016x}\n"));
        }

        // Set up stack values
        for (i, value) in initial_state.stack_setup.iter().enumerate() {
            let offset = (i + 1) * 8;
            preamble.push_str(&format!("    mov qword [rsp-{offset}], 0x{value:016x}\n"));
        }

        // Set up memory locations with address translation
        for (addr, data) in &initial_state.memory_locations {
            // Check if address is already in sandbox range (e.g., pointer buffers)
            // These addresses don't need translation - they're already valid
            use super::sandbox::{SANDBOX_BASE, SANDBOX_SIZE};
            let target_addr = if *addr >= SANDBOX_BASE && *addr < SANDBOX_BASE + SANDBOX_SIZE {
                // Address is already in sandbox range (e.g., pointer register buffers)
                *addr
            } else if let Some(sandbox) = sandbox {
                // Translate original binary address to sandbox address
                match sandbox.translate_to_sandbox(*addr) {
                    Ok(translated) => translated,
                    Err(_) => {
                        // Skip addresses that can't be translated - they're likely outside
                        // the loaded binary sections (e.g., stack, heap, or invalid addresses)
                        continue;
                    }
                }
            } else {
                // No sandbox and address not in sandbox range - skip
                continue;
            };

            match data.len() {
                1 => preamble.push_str(&format!(
                    "    mov byte [0x{target_addr:016x}], 0x{:02x}\n",
                    data[0]
                )),
                2 => preamble.push_str(&format!(
                    "    mov word [0x{target_addr:016x}], 0x{:04x}\n",
                    u16::from_le_bytes([data[0], data[1]])
                )),
                4 => preamble.push_str(&format!(
                    "    mov dword [0x{target_addr:016x}], 0x{:08x}\n",
                    u32::from_le_bytes([data[0], data[1], data[2], data[3]])
                )),
                8 => preamble.push_str(&format!(
                    "    mov qword [0x{target_addr:016x}], 0x{:016x}\n",
                    u64::from_le_bytes([
                        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]
                    ])
                )),
                _ => {
                    // For larger data, write byte by byte
                    for (i, byte) in data.iter().enumerate() {
                        let byte_addr = target_addr + i as u64;
                        preamble.push_str(&format!(
                            "    mov byte [0x{byte_addr:016x}], 0x{byte:02x}\n"
                        ));
                    }
                }
            }
        }

        preamble.push('\n');
        preamble.push_str("    ; === EXTRACTED BLOCK CODE ===\n");

        Ok(preamble)
    }

    /// Generates mmap syscalls to map memory regions for pointer buffers.
    ///
    /// Scans initial_state.memory_locations for addresses in the pointer buffer range
    /// and generates mmap syscalls to allocate those memory regions before use.
    fn generate_mmap_for_pointer_buffers(&self, initial_state: &InitialState) -> String {
        let mut mmap_code = String::new();

        // Find all addresses in the pointer buffer range
        let mut min_addr: Option<u64> = None;
        let mut max_addr: Option<u64> = None;

        for (addr, data) in &initial_state.memory_locations {
            if *addr >= POINTER_BUFFER_BASE && *addr < POINTER_BUFFER_END {
                let end_addr = addr + data.len() as u64;

                match min_addr {
                    Some(m) if *addr < m => min_addr = Some(*addr),
                    None => min_addr = Some(*addr),
                    _ => {}
                }

                match max_addr {
                    Some(m) if end_addr > m => max_addr = Some(end_addr),
                    None => max_addr = Some(end_addr),
                    _ => {}
                }
            }
        }

        // If we have addresses to map, generate mmap syscall
        if let (Some(start), Some(end)) = (min_addr, max_addr) {
            // Page-align the addresses
            let page_size: u64 = 0x1000;
            let aligned_start = (start / page_size) * page_size;
            let aligned_end = end.div_ceil(page_size) * page_size;
            let length = aligned_end - aligned_start;

            mmap_code.push_str("    ; Map pointer buffer memory region\n");
            mmap_code.push_str("    mov rax, 9                    ; sys_mmap\n");
            mmap_code.push_str(&format!("    mov rdi, 0x{aligned_start:016x} ; addr\n"));
            mmap_code.push_str(&format!(
                "    mov rsi, 0x{length:x}              ; length\n"
            ));
            mmap_code.push_str("    mov rdx, 3                    ; PROT_READ | PROT_WRITE\n");
            mmap_code.push_str(
                "    mov r10, 0x32                 ; MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED\n",
            );
            mmap_code.push_str(
                "    xor r8, r8                    ; fd = 0 (will be ignored for anonymous)\n",
            );
            mmap_code.push_str("    sub r8, 1                     ; fd = -1\n");
            mmap_code.push_str("    xor r9, r9                    ; offset = 0\n");
            mmap_code.push_str("    syscall\n");
            mmap_code.push('\n');
        }

        mmap_code
    }

    fn generate_block_code(&self, extraction: &ExtractionInfo) -> Result<String> {
        let mut block_code = String::new();

        // Embed the block as raw bytes instead of disassembling
        // This preserves RIP-relative instructions and avoids NASM symbol errors
        block_code.push_str("block_start:\n");

        // Emit the block bytes in chunks of 16 for readability
        for (i, chunk) in extraction.assembly_block.chunks(16).enumerate() {
            block_code.push_str("    db ");
            let hex_bytes: Vec<String> = chunk.iter().map(|b| format!("0x{:02x}", b)).collect();
            block_code.push_str(&hex_bytes.join(", "));

            // Add comment with offset for debugging
            if i == 0 {
                block_code.push_str(&format!(
                    "  ; Block bytes ({} total)",
                    extraction.assembly_block.len()
                ));
            }
            block_code.push('\n');
        }

        block_code.push('\n');

        Ok(block_code)
    }

    #[allow(dead_code)]
    fn disassemble_block(&self, block: &[u8]) -> Result<Vec<String>> {
        use capstone::prelude::*;

        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()
            .map_err(|e| Error::Simulation(format!("Failed to create disassembler: {e}")))?;

        let insns = cs
            .disasm_all(block, 0x1000)
            .map_err(|e| Error::Simulation(format!("Failed to disassemble block: {e}")))?;

        let mut instructions = Vec::new();
        for insn in insns.iter() {
            let mnemonic = insn.mnemonic().unwrap_or("unknown");
            let op_str = insn.op_str().unwrap_or("");

            if op_str.is_empty() {
                instructions.push(mnemonic.to_string());
            } else {
                instructions.push(format!("{mnemonic} {op_str}"));
            }
        }

        Ok(instructions)
    }

    fn generate_epilogue(&self, _analysis: &BlockAnalysis) -> Result<String> {
        let mut epilogue = String::new();

        epilogue.push_str("    ; === EPILOGUE: Capture final state ===\n");

        // Store all registers to output buffer
        let registers = [
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11",
            "r12", "r13", "r14", "r15",
        ];

        for (i, reg) in registers.iter().enumerate() {
            let offset = i * 8;
            epilogue.push_str(&format!(
                "    mov qword [output_buffer + {offset}], {reg}\n"
            ));
        }

        // Store flags
        epilogue.push_str("    pushfq\n");
        epilogue.push_str("    pop rax\n");
        epilogue.push_str("    mov qword [output_buffer + 128], rax\n");

        // Store memory locations (we'll store them starting at offset 256)
        let mut memory_offset = 256;

        // For now, we'll store stack values as a simple example
        for i in 1..=8 {
            let stack_offset = i * 8;
            epilogue.push_str(&format!("    mov rax, qword [rsp-{stack_offset}]\n"));
            epilogue.push_str(&format!("    mov [output_buffer + {memory_offset}], rax\n"));
            epilogue.push_str(&format!(
                "    mov qword [output_buffer + {}], 0x{:016x}\n",
                memory_offset + 8,
                8u64
            )); // Size
            memory_offset += 16;
        }

        // Add end marker
        epilogue.push_str(&format!(
            "    mov qword [output_buffer + {memory_offset}], 0\n"
        ));
        epilogue.push_str(&format!(
            "    mov qword [output_buffer + {}], 0\n",
            memory_offset + 8
        ));

        // Write output buffer to stdout
        epilogue.push_str("    ; Write output buffer to stdout\n");
        epilogue.push_str("    mov rax, 1                    ; sys_write\n");
        epilogue.push_str("    mov rdi, 1                    ; stdout\n");
        epilogue.push_str("    mov rsi, output_buffer        ; buffer\n");
        epilogue.push_str(&format!(
            "    mov rdx, {OUTPUT_BUFFER_SIZE}                 ; length\n"
        ));
        epilogue.push_str("    syscall\n");
        epilogue.push('\n');

        // Exit cleanly
        epilogue.push_str("    ; Exit cleanly\n");
        epilogue.push_str("    mov rax, 60                   ; sys_exit\n");
        epilogue.push_str("    mov rdi, 0                    ; exit code\n");
        epilogue.push_str("    syscall\n");

        Ok(epilogue)
    }

    #[allow(dead_code)]
    fn convert_to_nasm_syntax(&self, instruction: &str) -> String {
        // Convert Intel syntax to NASM syntax with improved robustness
        let mut result = instruction.to_string();

        // Handle memory size specifiers more robustly
        let size_patterns = [
            ("dword ptr ", "dword "),
            ("qword ptr ", "qword "),
            ("word ptr ", "word "),
            ("byte ptr ", "byte "),
        ];

        for (intel_pattern, nasm_pattern) in &size_patterns {
            result = result.replace(intel_pattern, nasm_pattern);
        }

        // Remove remaining "ptr" keywords that NASM doesn't understand
        result = result.replace(" ptr ", " ");
        result = result.replace(" ptr,", ",");
        result = result.replace(",ptr ", ", ");

        // Handle edge cases with brackets and ptr
        if result.contains("[") && result.contains("ptr") {
            result = result.replace(" ptr", "");
        }

        // Remove any remaining standalone "ptr" tokens
        result = result.replace(" ptr", "");

        result
    }
}
