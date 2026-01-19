//! Instruction complexity scoring for smart block selection.
//!
//! Provides scoring mechanisms to prioritize assembly blocks that are more
//! likely to expose FEX-Emu bugs based on instruction complexity, rarity,
//! and known problematic patterns.

use capstone::Insn;
use std::collections::HashSet;

/// Complexity score for an instruction or block.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct ComplexityScore {
    /// Instruction rarity score (0-10, higher = rarer)
    pub rarity: f64,
    /// Addressing mode complexity (0-10)
    pub addressing: f64,
    /// Operand complexity (0-10)
    pub operands: f64,
    /// Total complexity score (sum of all factors)
    pub total: f64,
}

impl ComplexityScore {
    /// Creates a new complexity score.
    pub fn new(rarity: f64, addressing: f64, operands: f64) -> Self {
        let total = rarity + addressing + operands;
        Self {
            rarity,
            addressing,
            operands,
            total,
        }
    }

    /// Creates a zero complexity score.
    pub fn zero() -> Self {
        Self::new(0.0, 0.0, 0.0)
    }

    /// Combines two complexity scores by summing their components.
    pub fn combine(&self, other: &ComplexityScore) -> Self {
        Self::new(
            self.rarity + other.rarity,
            self.addressing + other.addressing,
            self.operands + other.operands,
        )
    }

    /// Normalizes the score by dividing by the given count.
    pub fn normalize(&self, count: usize) -> Self {
        if count == 0 {
            return Self::zero();
        }
        let count_f = count as f64;
        Self::new(
            self.rarity / count_f,
            self.addressing / count_f,
            self.operands / count_f,
        )
    }
}

/// Block complexity analyzer.
pub struct ComplexityAnalyzer {
    /// Known problematic instruction mnemonics.
    problematic_instructions: HashSet<String>,
    /// Rare instructions (less common in typical code).
    rare_instructions: HashSet<String>,
}

impl ComplexityAnalyzer {
    /// Creates a new complexity analyzer with default patterns.
    pub fn new() -> Self {
        Self {
            problematic_instructions: Self::default_problematic_instructions(),
            rare_instructions: Self::default_rare_instructions(),
        }
    }

    /// Returns default set of problematic instructions for FEX-Emu.
    fn default_problematic_instructions() -> HashSet<String> {
        // Instructions known to have issues in FEX-Emu or generally tricky to emulate
        [
            // SSE/AVX edge cases
            "movdqa",
            "movdqu",
            "pshufb",
            "palignr",
            "pmaddwd",
            "pmulhw",
            "pmullw",
            "pxor",
            "pandn",
            "pcmpeqb",
            "pcmpgtb",
            // FPU operations
            "fld",
            "fst",
            "fstp",
            "fadd",
            "fsub",
            "fmul",
            "fdiv",
            "fsin",
            "fcos",
            "fyl2x",
            "fpatan",
            // Complex addressing and segment operations
            "lea",
            "xlat",
            "lodsb",
            "stosb",
            "scasb",
            "movsb",
            // Bit manipulation
            "bsf",
            "bsr",
            "bt",
            "btc",
            "btr",
            "bts",
            "popcnt",
            "lzcnt",
            "tzcnt",
            // Atomic operations
            "lock",
            "xchg",
            "cmpxchg",
            "cmpxchg8b",
            "cmpxchg16b",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    /// Returns default set of rare instructions.
    fn default_rare_instructions() -> HashSet<String> {
        // Instructions rarely seen in typical code
        [
            // System instructions
            "syscall",
            "sysenter",
            "sysexit",
            "sysret",
            "cpuid",
            "rdtsc",
            "rdtscp",
            // Segment operations
            "lar",
            "lsl",
            "verr",
            "verw",
            // Special string operations
            "cmpsb",
            "cmpsw",
            "cmpsd",
            "lodsb",
            "lodsw",
            "lodsd",
            "stosb",
            "stosw",
            "stosd",
            // Advanced bit manipulation
            "pdep",
            "pext",
            "andn",
            "blsi",
            "blsmsk",
            "blsr",
            // FPU transcendentals
            "fsincos",
            "f2xm1",
            "fptan",
            "fprem",
            "fprem1",
            // AVX special cases
            "vperm2f128",
            "vinsertf128",
            "vextractf128",
            "vmaskmovps",
            "vmaskmovpd",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    /// Scores instruction rarity (0-10).
    fn score_rarity(&self, mnemonic: &str) -> f64 {
        if self.rare_instructions.contains(mnemonic) {
            8.0
        } else if self.problematic_instructions.contains(mnemonic) {
            6.0
        } else {
            2.0
        }
    }

    /// Scores addressing mode complexity (0-10).
    #[allow(dead_code)]
    fn score_addressing(&self, insn: &Insn) -> f64 {
        // Estimate complexity based on operand string
        let op_str = insn.op_str().unwrap_or("");

        let mut score: f64 = 2.0;

        // Check for complex addressing patterns in operand string
        // [base+index*scale+disp] is most complex
        if op_str.contains('[') {
            score += 2.0;

            if op_str.contains('+') {
                score += 2.0;
            }

            if op_str.contains('*') {
                score += 3.0;
            }

            // Check for displacement
            if op_str.matches(|c: char| c.is_ascii_hexdigit() || c == 'x').count() > 2 {
                score += 1.0;
            }
        }

        score.min(10.0)
    }

    /// Scores operand complexity (0-10).
    #[allow(dead_code)]
    fn score_operands(&self, insn: &Insn) -> f64 {
        // Estimate complexity based on operand string
        let op_str = insn.op_str().unwrap_or("");

        // Count commas to estimate operand count
        let op_count = op_str.split(',').count();

        let mut score: f64 = match op_count {
            0 | 1 => 1.0,
            2 => 3.0,
            3 => 6.0,
            _ => 9.0,
        };

        // Check for mixed register sizes (e.g., eax with rax)
        let has_8bit = op_str.contains("al") || op_str.contains("ah") || op_str.contains("bl");
        let has_16bit = op_str.contains("ax") && !op_str.contains("eax") && !op_str.contains("rax");
        let has_32bit = op_str.contains("eax") || op_str.contains("ebx") || op_str.contains("ecx");
        let has_64bit = op_str.contains("rax") || op_str.contains("rbx") || op_str.contains("rcx");

        let size_count = [has_8bit, has_16bit, has_32bit, has_64bit]
            .iter()
            .filter(|&&x| x)
            .count();

        if size_count > 1 {
            score += 2.0;
        }

        score.min(10.0)
    }

    /// Scores a single instruction.
    #[allow(dead_code)]
    pub fn score_instruction(&self, insn: &Insn) -> ComplexityScore {
        let mnemonic = insn.mnemonic().unwrap_or("unknown").to_lowercase();

        let rarity = self.score_rarity(&mnemonic);
        let addressing = self.score_addressing(insn);
        let operands = self.score_operands(insn);

        ComplexityScore::new(rarity, addressing, operands)
    }

    /// Scores a block of instructions.
    #[allow(dead_code)]
    pub fn score_block(&self, instructions: &[Insn]) -> ComplexityScore {
        if instructions.is_empty() {
            return ComplexityScore::zero();
        }

        let mut total_score = ComplexityScore::zero();
        for insn in instructions {
            total_score = total_score.combine(&self.score_instruction(insn));
        }

        total_score.normalize(instructions.len())
    }

    /// Checks if a block contains problematic instructions.
    #[allow(dead_code)]
    pub fn has_problematic_instructions(&self, instructions: &[Insn]) -> bool {
        instructions.iter().any(|insn| {
            let mnemonic = insn.mnemonic().unwrap_or("").to_lowercase();
            self.problematic_instructions.contains(&mnemonic)
        })
    }

    /// Gets the set of unique instruction mnemonics in a block.
    #[allow(dead_code)]
    pub fn get_instruction_variety(&self, instructions: &[Insn]) -> HashSet<String> {
        instructions
            .iter()
            .filter_map(|insn| insn.mnemonic())
            .map(|s| s.to_lowercase())
            .collect()
    }
}

impl Default for ComplexityAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_complexity_score_creation() {
        let score = ComplexityScore::new(5.0, 3.0, 4.0);
        assert_eq!(score.rarity, 5.0);
        assert_eq!(score.addressing, 3.0);
        assert_eq!(score.operands, 4.0);
        assert_eq!(score.total, 12.0);
    }

    #[test]
    fn test_complexity_score_combine() {
        let score1 = ComplexityScore::new(5.0, 3.0, 4.0);
        let score2 = ComplexityScore::new(2.0, 1.0, 3.0);
        let combined = score1.combine(&score2);
        assert_eq!(combined.rarity, 7.0);
        assert_eq!(combined.addressing, 4.0);
        assert_eq!(combined.operands, 7.0);
        assert_eq!(combined.total, 18.0);
    }

    #[test]
    fn test_complexity_score_normalize() {
        let score = ComplexityScore::new(10.0, 6.0, 8.0);
        let normalized = score.normalize(2);
        assert_eq!(normalized.rarity, 5.0);
        assert_eq!(normalized.addressing, 3.0);
        assert_eq!(normalized.operands, 4.0);
        assert_eq!(normalized.total, 12.0);
    }

    #[test]
    fn test_complexity_analyzer_creation() {
        let analyzer = ComplexityAnalyzer::new();
        assert!(!analyzer.problematic_instructions.is_empty());
        assert!(!analyzer.rare_instructions.is_empty());
    }

    #[test]
    fn test_rarity_scoring() {
        let analyzer = ComplexityAnalyzer::new();

        // Rare instruction
        assert_eq!(analyzer.score_rarity("syscall"), 8.0);

        // Problematic instruction
        assert_eq!(analyzer.score_rarity("movdqa"), 6.0);

        // Common instruction
        assert_eq!(analyzer.score_rarity("mov"), 2.0);
    }
}
