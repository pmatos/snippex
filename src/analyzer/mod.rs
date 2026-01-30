pub mod complexity;

use anyhow::{anyhow, Result};
use capstone::prelude::*;
use capstone::{Capstone, Insn, InsnGroupId};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[allow(unused_imports)]
pub use complexity::{ComplexityAnalyzer, ComplexityScore};

/// Information about how a register is used as a memory pointer
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PointerRegisterUsage {
    /// Minimum offset used (can be negative, e.g., [rbp-0x20] → -32)
    pub min_offset: i64,
    /// Maximum offset used (e.g., [rsi+100] → 100)
    pub max_offset: i64,
    /// Maximum size of data accessed at any offset
    pub max_access_size: usize,
    /// Whether any instruction reads through this pointer
    pub has_reads: bool,
    /// Whether any instruction writes through this pointer
    pub has_writes: bool,
}

#[derive(Debug, Clone)]
pub struct BlockAnalysis {
    pub live_in_registers: HashSet<String>,
    pub live_out_registers: HashSet<String>,
    pub exit_points: Vec<ExitPoint>,
    pub memory_accesses: Vec<MemoryAccess>,
    pub instructions_count: usize,
    /// Registers used as memory pointers, with their usage patterns
    pub pointer_registers: HashMap<String, PointerRegisterUsage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitPoint {
    pub offset: u64,
    pub exit_type: ExitType,
    pub target: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExitType {
    FallThrough,       // Normal sequential execution
    UnconditionalJump, // JMP
    ConditionalJump,   // Jcc
    Call,              // CALL
    Return,            // RET
    IndirectJump,      // JMP [reg] or JMP [mem]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryAccess {
    pub offset: u64,
    pub access_type: AccessType,
    pub size: usize,
    pub is_stack: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessType {
    Read,
    Write,
    ReadWrite,
}

pub struct Analyzer {
    architecture: String,
}

impl Analyzer {
    pub fn new(architecture: &str) -> Self {
        Analyzer {
            architecture: architecture.to_string(),
        }
    }

    pub fn analyze_block(&self, code: &[u8], base_address: u64) -> Result<BlockAnalysis> {
        let cs = self.create_capstone()?;

        let insns = cs
            .disasm_all(code, base_address)
            .map_err(|e| anyhow!("Failed to disassemble: {}", e))?;

        let mut analysis = BlockAnalysis {
            live_in_registers: HashSet::new(),
            live_out_registers: HashSet::new(),
            exit_points: Vec::new(),
            memory_accesses: Vec::new(),
            instructions_count: insns.len(),
            pointer_registers: HashMap::new(),
        };

        let mut written_before: HashSet<String> = HashSet::new();
        let mut all_written: HashSet<String> = HashSet::new();
        let mut last_offset = base_address;

        for insn in insns.iter() {
            last_offset = insn.address() + insn.bytes().len() as u64;

            // Analyze registers for this instruction
            let mut insn_reads = HashSet::new();
            let mut insn_writes = HashSet::new();
            self.analyze_registers(&cs, insn, &mut insn_reads, &mut insn_writes)?;

            // A register is live-in if it's read before being written in any previous instruction
            // Note: In a single instruction, reads happen before writes, so if a register
            // is both read and written in the same instruction, it's live-in if not written before
            for reg in &insn_reads {
                if !written_before.contains(reg) {
                    analysis.live_in_registers.insert(reg.clone());
                }
            }

            // Update written_before with registers written in this instruction
            // (they won't be live-in for future instructions)
            written_before.extend(insn_writes.iter().cloned());
            all_written.extend(insn_writes);

            // Analyze control flow
            if let Some(exit) = self.analyze_control_flow(
                &cs,
                insn,
                base_address,
                base_address + code.len() as u64,
            )? {
                analysis.exit_points.push(exit);
            }

            // Analyze memory accesses and pointer registers
            if let Some(mem_access) = self.analyze_memory_access(&cs, insn)? {
                analysis.memory_accesses.push(mem_access.clone());

                // Also detect pointer register usage from memory operands
                let op_str = insn.op_str().unwrap_or("");
                self.detect_pointer_registers(op_str, &mem_access, &mut analysis.pointer_registers);
            }
        }

        // All written registers are potentially live-out
        analysis.live_out_registers = all_written;

        // If no explicit exit found, it falls through
        if analysis.exit_points.is_empty() {
            analysis.exit_points.push(ExitPoint {
                offset: last_offset,
                exit_type: ExitType::FallThrough,
                target: None,
            });
        }

        Ok(analysis)
    }

    fn create_capstone(&self) -> Result<Capstone> {
        let cs = match self.architecture.as_str() {
            "x86" | "i386" => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode32)
                .detail(true)
                .build()
                .map_err(|e| anyhow!("Failed to create x86 capstone: {}", e))?,
            "x86_64" => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .detail(true)
                .build()
                .map_err(|e| anyhow!("Failed to create x86_64 capstone: {}", e))?,
            _ => {
                return Err(anyhow!(
                "Unsupported architecture: {}. Only x86 and x86_64 architectures are supported.",
                self.architecture
            ))
            }
        };

        Ok(cs)
    }

    fn analyze_registers(
        &self,
        _cs: &Capstone,
        insn: &Insn,
        read_regs: &mut HashSet<String>,
        written_regs: &mut HashSet<String>,
    ) -> Result<()> {
        let mnemonic = insn.mnemonic().unwrap_or("");
        let operands = insn.op_str().unwrap_or("");

        // Manual register analysis since capstone's register detection isn't reliable
        self.analyze_registers_manual(mnemonic, operands, read_regs, written_regs)?;

        Ok(())
    }

    fn analyze_registers_manual(
        &self,
        mnemonic: &str,
        operands: &str,
        read_regs: &mut HashSet<String>,
        written_regs: &mut HashSet<String>,
    ) -> Result<()> {
        // Split operands by comma
        let ops: Vec<&str> = operands.split(',').map(|s| s.trim()).collect();

        match mnemonic {
            "mov" | "movzx" | "movsx" => {
                // mov dst, src - dst is written, src is read
                if ops.len() >= 2 {
                    // Handle destination
                    if ops[0].contains('[') && ops[0].contains(']') {
                        // Memory destination - extract addressing registers as read
                        self.extract_read_registers(ops[0], read_regs);
                    } else {
                        // Register destination - mark as written
                        self.extract_written_registers(ops[0], written_regs);
                    }

                    // Handle source - always read
                    self.extract_read_registers(ops[1], read_regs);
                }
            }
            "add" | "sub" | "and" | "or" | "xor" => {
                // op dst, src - dst is read and written, src is read
                if ops.len() >= 2 {
                    self.extract_read_registers(ops[0], read_regs); // read before modify
                    self.extract_written_registers(ops[0], written_regs); // written after
                    self.extract_read_registers(ops[1], read_regs);
                }
                // These also affect flags
                written_regs.insert("rflags".to_string());
            }
            "cmp" | "test" => {
                // cmp/test op1, op2 - both operands are read, flags written
                for op in &ops {
                    self.extract_read_registers(op, read_regs);
                }
                written_regs.insert("rflags".to_string());
            }
            "inc" | "dec" | "neg" | "not" => {
                // unary operations - operand is read and written
                if !ops.is_empty() {
                    self.extract_read_registers(ops[0], read_regs);
                    self.extract_written_registers(ops[0], written_regs);
                }
                if mnemonic != "not" {
                    // not doesn't affect flags
                    written_regs.insert("rflags".to_string());
                }
            }
            "jz" | "jnz" | "je" | "jne" | "jl" | "jle" | "jg" | "jge" | "js" | "jns" | "jc"
            | "jnc" | "jo" | "jno" => {
                // conditional jumps read flags
                read_regs.insert("rflags".to_string());
            }
            "push" => {
                // push src - src is read, rsp is read and written
                if !ops.is_empty() {
                    self.extract_read_registers(ops[0], read_regs);
                }
                read_regs.insert("rsp".to_string());
                written_regs.insert("rsp".to_string());
            }
            "pop" => {
                // pop dst - dst is written, rsp is read and written
                if !ops.is_empty() {
                    self.extract_written_registers(ops[0], written_regs);
                }
                read_regs.insert("rsp".to_string());
                written_regs.insert("rsp".to_string());
            }
            "call" => {
                // call affects rsp and potentially many registers
                read_regs.insert("rsp".to_string());
                written_regs.insert("rsp".to_string());
                // Conservative: assume call can modify rax, rcx, rdx (caller-saved)
                written_regs.insert("rax".to_string());
                written_regs.insert("rcx".to_string());
                written_regs.insert("rdx".to_string());
            }
            "ret" => {
                // ret reads rsp and rax (return value)
                read_regs.insert("rsp".to_string());
                read_regs.insert("rax".to_string());
                written_regs.insert("rsp".to_string());
            }
            "lea" => {
                // lea dst, src - dst is written, registers in src are read
                if ops.len() >= 2 {
                    self.extract_written_registers(ops[0], written_regs);
                    self.extract_read_registers(ops[1], read_regs);
                }
            }
            _ => {
                // For unknown instructions, conservatively analyze operands
                for (i, op) in ops.iter().enumerate() {
                    if i == 0 {
                        // First operand is usually destination (written)
                        self.extract_written_registers(op, written_regs);
                    }
                    // All operands are potentially read
                    self.extract_read_registers(op, read_regs);
                }
            }
        }

        Ok(())
    }

    fn extract_read_registers(&self, operand: &str, read_regs: &mut HashSet<String>) {
        // Extract register names from operand string
        for reg in self.find_registers_in_operand(operand) {
            read_regs.insert(reg);
        }
    }

    fn extract_written_registers(&self, operand: &str, written_regs: &mut HashSet<String>) {
        // For memory operands like [reg], the register is read, not written
        if operand.contains('[') && operand.contains(']') {
            // Memory reference - this is a memory write, not a register write
            // The addressing registers should be handled separately
        } else {
            // Direct register operand
            for reg in self.find_registers_in_operand(operand) {
                written_regs.insert(reg);
            }
        }
    }

    fn find_registers_in_operand(&self, operand: &str) -> Vec<String> {
        let mut registers = Vec::new();

        // List of x86/x86_64 registers to look for
        // Note: Order matters for overlapping names - check longer patterns first
        let reg_patterns = [
            // AVX-512 ZMM registers (check first due to length)
            "zmm31", "zmm30", "zmm29", "zmm28", "zmm27", "zmm26", "zmm25", "zmm24", "zmm23",
            "zmm22", "zmm21", "zmm20", "zmm19", "zmm18", "zmm17", "zmm16", "zmm15", "zmm14",
            "zmm13", "zmm12", "zmm11", "zmm10", "zmm9", "zmm8", "zmm7", "zmm6", "zmm5", "zmm4",
            "zmm3", "zmm2", "zmm1", "zmm0", // AVX YMM registers
            "ymm15", "ymm14", "ymm13", "ymm12", "ymm11", "ymm10", "ymm9", "ymm8", "ymm7", "ymm6",
            "ymm5", "ymm4", "ymm3", "ymm2", "ymm1", "ymm0", // SSE XMM registers
            "xmm15", "xmm14", "xmm13", "xmm12", "xmm11", "xmm10", "xmm9", "xmm8", "xmm7", "xmm6",
            "xmm5", "xmm4", "xmm3", "xmm2", "xmm1", "xmm0",
            // 64-bit GPR registers (check r10-r15 before r1 to avoid partial matches)
            "r15", "r14", "r13", "r12", "r11", "r10", "r9", "r8", "rax", "rbx", "rcx", "rdx", "rsi",
            "rdi", "rbp", "rsp", // 32-bit registers
            "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", // 16-bit registers
            "ax", "bx", "cx", "dx", "si", "di", "bp", "sp", // 8-bit registers
            "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh",
        ];

        let operand_lower = operand.to_lowercase();

        for &reg in &reg_patterns {
            if operand_lower.contains(reg) {
                // Check if it's a whole word (not part of another word)
                if let Some(start) = operand_lower.find(reg) {
                    let end = start + reg.len();
                    let before_ok = start == 0
                        || !operand_lower
                            .chars()
                            .nth(start - 1)
                            .unwrap()
                            .is_alphanumeric();
                    let after_ok = end >= operand_lower.len()
                        || !operand_lower.chars().nth(end).unwrap().is_alphanumeric();

                    if before_ok && after_ok {
                        // Normalize to canonical form (prefer 64-bit names)
                        let canonical = self.normalize_register(reg);
                        if !registers.contains(&canonical) {
                            registers.push(canonical);
                        }
                    }
                }
            }
        }

        registers
    }

    fn normalize_register(&self, reg: &str) -> String {
        // For vector registers (xmm, ymm, zmm), keep them as-is because they have
        // different aliasing semantics than GPRs:
        // - Writing to xmm0 zeros upper bits of ymm0/zmm0
        // - Writing to ymm0 zeros upper bits of zmm0
        // So xmm0, ymm0, zmm0 should remain distinct in analysis.
        if reg.starts_with("xmm") || reg.starts_with("ymm") || reg.starts_with("zmm") {
            return reg.to_string();
        }

        // For GPRs, normalize to 64-bit canonical form
        match reg {
            "eax" | "ax" | "al" | "ah" => "rax".to_string(),
            "ebx" | "bx" | "bl" | "bh" => "rbx".to_string(),
            "ecx" | "cx" | "cl" | "ch" => "rcx".to_string(),
            "edx" | "dx" | "dl" | "dh" => "rdx".to_string(),
            "esi" | "si" => "rsi".to_string(),
            "edi" | "di" => "rdi".to_string(),
            "ebp" | "bp" => "rbp".to_string(),
            "esp" | "sp" => "rsp".to_string(),
            _ => reg.to_string(), // Already 64-bit or other register
        }
    }

    fn analyze_control_flow(
        &self,
        cs: &Capstone,
        insn: &Insn,
        block_start: u64,
        block_end: u64,
    ) -> Result<Option<ExitPoint>> {
        let detail = cs
            .insn_detail(insn)
            .map_err(|e| anyhow!("Failed to get instruction details: {}", e))?;
        let groups = detail.groups();

        // Check if it's a call BEFORE checking for jump, because Capstone puts
        // call instructions in both CS_GRP_CALL (2) and CS_GRP_JUMP (7)
        if groups.contains(&InsnGroupId(2)) {
            // CS_GRP_CALL
            return Ok(Some(ExitPoint {
                offset: insn.address(),
                exit_type: ExitType::Call,
                target: self.get_jump_target(cs, insn),
            }));
        }

        // Check if it's a jump
        if groups.contains(&InsnGroupId(7)) {
            // CS_GRP_JUMP
            let exit_type = if insn.mnemonic() == Some("jmp") {
                ExitType::UnconditionalJump
            } else {
                ExitType::ConditionalJump
            };

            // Try to get jump target
            let target = self.get_jump_target(cs, insn);

            // Check if jump is within block
            if let Some(tgt) = target {
                if tgt >= block_start && tgt < block_end {
                    // Jump within block, not an exit
                    return Ok(None);
                }
            }

            return Ok(Some(ExitPoint {
                offset: insn.address(),
                exit_type,
                target,
            }));
        }

        // Check if it's a return
        if groups.contains(&InsnGroupId(3)) {
            // CS_GRP_RET
            return Ok(Some(ExitPoint {
                offset: insn.address(),
                exit_type: ExitType::Return,
                target: None,
            }));
        }

        Ok(None)
    }

    fn get_jump_target(&self, _cs: &Capstone, insn: &Insn) -> Option<u64> {
        // For now, we'll use the instruction operand string to extract jump targets
        // This is a simplified approach
        let op_str = insn.op_str()?;

        // Try to parse hex address (0x...)
        if let Some(hex_start) = op_str.find("0x") {
            let hex_str = &op_str[hex_start + 2..];
            let end = hex_str
                .find(|c: char| !c.is_ascii_hexdigit())
                .unwrap_or(hex_str.len());
            if let Ok(addr) = u64::from_str_radix(&hex_str[..end], 16) {
                return Some(addr);
            }
        }

        None
    }

    fn analyze_memory_access(&self, _cs: &Capstone, insn: &Insn) -> Result<Option<MemoryAccess>> {
        // Simplified memory access detection based on operand string
        let op_str = insn.op_str().unwrap_or("");

        // Check if instruction has memory operand (contains [])
        if !op_str.contains('[') || !op_str.contains(']') {
            return Ok(None);
        }

        // Check if it's a stack access
        let is_stack = op_str.contains("esp")
            || op_str.contains("rsp")
            || op_str.contains("ebp")
            || op_str.contains("rbp");

        // Determine access type based on instruction
        let mnemonic = insn.mnemonic().unwrap_or("");
        let access_type = match mnemonic {
            "mov" | "movzx" | "movsx" => {
                // mov dest, src - if memory is first operand, it's a write
                if op_str.find('[').unwrap_or(usize::MAX) < op_str.find(',').unwrap_or(usize::MAX) {
                    AccessType::Write
                } else {
                    AccessType::Read
                }
            }
            "lea" | "cmp" | "test" => AccessType::Read,
            "push" | "call" => AccessType::Write,
            "pop" | "ret" => AccessType::Read,
            _ if mnemonic.starts_with("st") => AccessType::Write, // store instructions
            _ if mnemonic.starts_with("ld") => AccessType::Read,  // load instructions
            _ => AccessType::ReadWrite,                           // conservative default
        };

        // Estimate size based on operand prefix or instruction suffix
        let size = if op_str.contains("qword") {
            8
        } else if op_str.contains("dword") {
            4
        } else if op_str.contains("word") && !op_str.contains("dword") && !op_str.contains("qword")
        {
            2
        } else if op_str.contains("byte") {
            1
        } else {
            match mnemonic.chars().last() {
                Some('b') => 1,
                Some('w') => 2,
                Some('d') => 4,
                Some('q') => 8,
                _ => 4, // default to 32-bit
            }
        };

        Ok(Some(MemoryAccess {
            offset: insn.address(),
            access_type,
            size,
            is_stack,
        }))
    }

    /// Detect which registers are used as memory pointers and track their offset ranges
    fn detect_pointer_registers(
        &self,
        op_str: &str,
        mem_access: &MemoryAccess,
        pointer_regs: &mut HashMap<String, PointerRegisterUsage>,
    ) {
        // Parse all memory operands in the instruction
        for (base_reg, offset) in self.parse_memory_operands(op_str) {
            let usage = pointer_regs.entry(base_reg).or_default();

            // Update offset range
            usage.min_offset = usage.min_offset.min(offset);
            usage.max_offset = usage.max_offset.max(offset);

            // Update access size
            usage.max_access_size = usage.max_access_size.max(mem_access.size);

            // Update read/write flags
            match mem_access.access_type {
                AccessType::Read => usage.has_reads = true,
                AccessType::Write => usage.has_writes = true,
                AccessType::ReadWrite => {
                    usage.has_reads = true;
                    usage.has_writes = true;
                }
            }
        }
    }

    /// Parse memory operands and extract base registers with their offsets
    /// Examples:
    ///   "[rsi+8]" → [("rsi", 8)]
    ///   "[rbp-0x20]" → [("rbp", -32)]
    ///   "[rdi]" → [("rdi", 0)]
    ///   "[rax+rcx*4+8]" → [("rax", 8)] (ignore scaled index for static analysis)
    fn parse_memory_operands(&self, op_str: &str) -> Vec<(String, i64)> {
        let mut results = Vec::new();

        // Find all memory operands (content within [])
        let mut chars = op_str.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '[' {
                let mut mem_operand = String::new();
                let mut depth = 1;
                while let Some(&next) = chars.peek() {
                    chars.next();
                    if next == '[' {
                        depth += 1;
                    } else if next == ']' {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    mem_operand.push(next);
                }

                // Parse the memory operand content
                if let Some((reg, offset)) = self.parse_single_memory_operand(&mem_operand) {
                    results.push((reg, offset));
                }
            }
        }

        results
    }

    /// Parse a single memory operand (content inside [])
    fn parse_single_memory_operand(&self, operand: &str) -> Option<(String, i64)> {
        let operand = operand.to_lowercase().trim().to_string();

        // Skip RIP-relative addressing (handled differently)
        if operand.contains("rip") || operand.contains("eip") {
            return None;
        }

        // Find the base register (first register that isn't part of scaled index)
        let reg_patterns = [
            "r15", "r14", "r13", "r12", "r11", "r10", "r9", "r8", "rsp", "rbp", "rdi", "rsi",
            "rdx", "rcx", "rbx", "rax", "esp", "ebp", "edi", "esi", "edx", "ecx", "ebx", "eax",
        ];

        let mut base_reg: Option<String> = None;
        let mut base_reg_pos: Option<usize> = None;

        for &reg in &reg_patterns {
            if let Some(pos) = operand.find(reg) {
                // Check if this register is part of a scaled index (has *N after it)
                let after_reg = &operand[pos + reg.len()..];
                let is_scaled = after_reg.trim_start().starts_with('*');

                if !is_scaled {
                    // This is likely the base register
                    if base_reg.is_none() || pos < base_reg_pos.unwrap() {
                        base_reg = Some(self.normalize_register(reg));
                        base_reg_pos = Some(pos);
                    }
                }
            }
        }

        let base_reg = base_reg?;

        // Extract the constant offset
        let offset = self.extract_offset(&operand);

        Some((base_reg, offset))
    }

    /// Extract the constant offset from a memory operand
    fn extract_offset(&self, operand: &str) -> i64 {
        let mut offset: i64 = 0;

        // Look for patterns like +0x20, -0x20, +20, -20
        let mut chars = operand.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '+' || c == '-' {
                let is_negative = c == '-';

                // Skip whitespace
                while chars.peek() == Some(&' ') {
                    chars.next();
                }

                // Check if next part is a register (then skip) or a number
                let mut num_str = String::new();
                let is_hex = chars.peek() == Some(&'0') && {
                    let mut temp = chars.clone();
                    temp.next();
                    temp.peek() == Some(&'x') || temp.peek() == Some(&'X')
                };

                if is_hex {
                    chars.next(); // skip '0'
                    chars.next(); // skip 'x'
                }

                while let Some(&next) = chars.peek() {
                    if next.is_ascii_hexdigit() && (is_hex || next.is_ascii_digit()) {
                        num_str.push(next);
                        chars.next();
                    } else if next == '*' || next.is_alphabetic() {
                        // This is a register or scaled index, not a constant
                        num_str.clear();
                        break;
                    } else {
                        break;
                    }
                }

                if !num_str.is_empty() {
                    let base = if is_hex { 16 } else { 10 };
                    if let Ok(val) = i64::from_str_radix(&num_str, base) {
                        offset = if is_negative { -val } else { val };
                    }
                }
            }
        }

        offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vector_register_live_in_detection() {
        // vpminud xmm3, xmm2, xmm3 - reads xmm2 and xmm3, writes xmm3
        // Both xmm2 and xmm3 should be detected as live-in since they're read
        // before xmm3 is written (the instruction reads both sources first)
        let code: &[u8] = &[0xc4, 0xe2, 0x69, 0x3b, 0xdb]; // vpminud xmm3, xmm2, xmm3
        let analyzer = Analyzer::new("x86_64");
        let analysis = analyzer.analyze_block(code, 0x1000).unwrap();

        // xmm2 should be live-in (read, never written)
        assert!(
            analysis.live_in_registers.contains("xmm2"),
            "xmm2 should be live-in, but got: {:?}",
            analysis.live_in_registers
        );

        // xmm3 should be live-in (read before written in same instruction)
        assert!(
            analysis.live_in_registers.contains("xmm3"),
            "xmm3 should be live-in, but got: {:?}",
            analysis.live_in_registers
        );
    }

    #[test]
    fn test_ymm_register_detection() {
        // vaddps ymm0, ymm1, ymm2 - reads ymm1 and ymm2, writes ymm0
        let code: &[u8] = &[0xc5, 0xf4, 0x58, 0xc2]; // vaddps ymm0, ymm1, ymm2
        let analyzer = Analyzer::new("x86_64");
        let analysis = analyzer.analyze_block(code, 0x1000).unwrap();

        assert!(
            analysis.live_in_registers.contains("ymm1"),
            "ymm1 should be live-in, but got: {:?}",
            analysis.live_in_registers
        );
        assert!(
            analysis.live_in_registers.contains("ymm2"),
            "ymm2 should be live-in, but got: {:?}",
            analysis.live_in_registers
        );
        assert!(
            analysis.live_out_registers.contains("ymm0"),
            "ymm0 should be live-out, but got: {:?}",
            analysis.live_out_registers
        );
    }

    #[test]
    fn test_mixed_gpr_and_vector_registers() {
        // vmovmskps edx, ymm1 - reads ymm1, writes edx
        let code: &[u8] = &[0xc5, 0xfc, 0x50, 0xd1]; // vmovmskps edx, ymm1
        let analyzer = Analyzer::new("x86_64");
        let analysis = analyzer.analyze_block(code, 0x1000).unwrap();

        assert!(
            analysis.live_in_registers.contains("ymm1"),
            "ymm1 should be live-in, but got: {:?}",
            analysis.live_in_registers
        );
        assert!(
            analysis.live_out_registers.contains("rdx"),
            "rdx should be live-out, but got: {:?}",
            analysis.live_out_registers
        );
    }

    #[test]
    fn test_disassemble_to_string() {
        // mov rbx, rax (48 89 c3)
        let bytes = vec![0x48, 0x89, 0xc3];
        let result = super::disassemble_to_string(&bytes, "x86_64", 0x1000).unwrap();
        assert!(result.contains("0x00001000:"));
        assert!(result.contains("mov"));
    }

    #[test]
    fn test_disassemble_to_string_unsupported_arch() {
        let bytes = vec![0x90];
        let result = super::disassemble_to_string(&bytes, "arm", 0);
        assert!(result.is_err());
    }
}

/// Disassemble raw bytes into a plain-text string (no color).
pub fn disassemble_to_string(block: &[u8], arch: &str, start_addr: u64) -> Result<String> {
    let cs = match arch {
        "x86_64" => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()
            .map_err(|e| anyhow!("Failed to create disassembler: {}", e))?,
        "i386" | "x86" => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()
            .map_err(|e| anyhow!("Failed to create disassembler: {}", e))?,
        _ => return Err(anyhow!("Unsupported architecture: {}", arch)),
    };

    let insns = cs
        .disasm_all(block, start_addr)
        .map_err(|e| anyhow!("Disassembly failed: {}", e))?;

    use std::fmt::Write;
    let mut output = String::new();
    for insn in insns.iter() {
        let mnemonic = insn.mnemonic().unwrap_or("???");
        let op_str = insn.op_str().unwrap_or("");
        writeln!(
            output,
            "0x{:08x}: {:<8} {}",
            insn.address(),
            mnemonic,
            op_str
        )
        .unwrap();
    }
    Ok(output)
}
