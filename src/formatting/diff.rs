//! Register diff formatting with bit-level highlighting.
//!
//! Provides detailed side-by-side comparison of register values with
//! visual highlighting of differences.

use serde::Serialize;
use std::collections::HashMap;

/// Categories for register grouping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum RegisterCategory {
    GeneralPurpose,
    Flags,
    Segment,
    InstructionPointer,
    Vector,
    Control,
    Debug,
    Fpu,
    Other,
}

impl RegisterCategory {
    /// Returns a display name for the category.
    #[allow(dead_code)]
    pub fn display_name(&self) -> &'static str {
        match self {
            RegisterCategory::GeneralPurpose => "General Purpose Registers",
            RegisterCategory::Flags => "Flags Register",
            RegisterCategory::Segment => "Segment Registers",
            RegisterCategory::InstructionPointer => "Instruction Pointer",
            RegisterCategory::Vector => "Vector Registers (XMM/YMM/ZMM)",
            RegisterCategory::Control => "Control Registers",
            RegisterCategory::Debug => "Debug Registers",
            RegisterCategory::Fpu => "FPU Registers",
            RegisterCategory::Other => "Other Registers",
        }
    }

    /// Returns the sort order for categories.
    pub fn sort_order(&self) -> u8 {
        match self {
            RegisterCategory::GeneralPurpose => 0,
            RegisterCategory::InstructionPointer => 1,
            RegisterCategory::Flags => 2,
            RegisterCategory::Segment => 3,
            RegisterCategory::Vector => 4,
            RegisterCategory::Fpu => 5,
            RegisterCategory::Control => 6,
            RegisterCategory::Debug => 7,
            RegisterCategory::Other => 8,
        }
    }
}

/// Categorizes a register name.
pub fn categorize_register(name: &str) -> RegisterCategory {
    let upper = name.to_uppercase();

    // General purpose registers (64-bit, 32-bit, 16-bit, 8-bit)
    let gp_regs = [
        "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "R8", "R9", "R10", "R11", "R12",
        "R13", "R14", "R15", "EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "AX", "BX",
        "CX", "DX", "SI", "DI", "BP", "SP", "AL", "AH", "BL", "BH", "CL", "CH", "DL", "DH", "SIL",
        "DIL", "BPL", "SPL", "R8D", "R9D", "R10D", "R11D", "R12D", "R13D", "R14D", "R15D", "R8W",
        "R9W", "R10W", "R11W", "R12W", "R13W", "R14W", "R15W", "R8B", "R9B", "R10B", "R11B",
        "R12B", "R13B", "R14B", "R15B",
    ];

    if gp_regs.contains(&upper.as_str()) {
        return RegisterCategory::GeneralPurpose;
    }

    // Flags register
    if upper == "RFLAGS" || upper == "EFLAGS" || upper == "FLAGS" {
        return RegisterCategory::Flags;
    }

    // Instruction pointer
    if upper == "RIP" || upper == "EIP" || upper == "IP" {
        return RegisterCategory::InstructionPointer;
    }

    // Segment registers
    let seg_regs = ["CS", "DS", "SS", "ES", "FS", "GS"];
    if seg_regs.contains(&upper.as_str()) {
        return RegisterCategory::Segment;
    }

    // Vector registers
    if upper.starts_with("XMM")
        || upper.starts_with("YMM")
        || upper.starts_with("ZMM")
        || upper == "MXCSR"
    {
        return RegisterCategory::Vector;
    }

    // FPU registers
    if upper.starts_with("ST")
        || upper.starts_with("MM")
        || upper == "FPCW"
        || upper == "FPSW"
        || upper == "FPTAG"
    {
        return RegisterCategory::Fpu;
    }

    // Control registers
    if upper.starts_with("CR") {
        return RegisterCategory::Control;
    }

    // Debug registers
    if upper.starts_with("DR") {
        return RegisterCategory::Debug;
    }

    RegisterCategory::Other
}

/// A single register difference with detailed information.
#[derive(Debug, Clone, Serialize)]
pub struct DetailedRegisterDiff {
    pub register: String,
    pub category: RegisterCategory,
    pub base_value: Option<u64>,
    pub other_value: Option<u64>,
    pub differs: bool,
    pub differing_bits: Option<u64>,
    pub signed_delta: Option<i64>,
}

impl DetailedRegisterDiff {
    /// Creates a new detailed register diff.
    pub fn new(register: String, base_value: Option<u64>, other_value: Option<u64>) -> Self {
        let category = categorize_register(&register);
        let differs = base_value != other_value;

        let differing_bits = match (base_value, other_value) {
            (Some(b), Some(o)) if differs => Some(b ^ o),
            _ => None,
        };

        let signed_delta = match (base_value, other_value) {
            (Some(b), Some(o)) if differs => Some(o.wrapping_sub(b) as i64),
            _ => None,
        };

        Self {
            register,
            category,
            base_value,
            other_value,
            differs,
            differing_bits,
            signed_delta,
        }
    }

    /// Formats the difference as a human-readable delta string.
    #[allow(dead_code)]
    pub fn format_delta(&self) -> String {
        match self.signed_delta {
            Some(delta) if delta >= 0 => format!("+{}", delta),
            Some(delta) => format!("{}", delta),
            None => String::new(),
        }
    }
}

/// Formatter for register differences with various output options.
pub struct RegisterDiffFormatter {
    use_colors: bool,
    show_all_registers: bool,
}

impl Default for RegisterDiffFormatter {
    fn default() -> Self {
        Self::new()
    }
}

impl RegisterDiffFormatter {
    /// Creates a new formatter with default settings.
    pub fn new() -> Self {
        Self {
            use_colors: true,
            show_all_registers: false,
        }
    }

    /// Sets whether to use ANSI colors in output.
    pub fn with_colors(mut self, use_colors: bool) -> Self {
        self.use_colors = use_colors;
        self
    }

    /// Sets whether to show all registers or only differing ones.
    pub fn show_all(mut self, show_all: bool) -> Self {
        self.show_all_registers = show_all;
        self
    }

    /// Creates detailed diffs from two register maps.
    pub fn create_diffs(
        &self,
        base: &HashMap<String, u64>,
        other: &HashMap<String, u64>,
    ) -> Vec<DetailedRegisterDiff> {
        let mut all_registers: std::collections::HashSet<String> = base.keys().cloned().collect();
        all_registers.extend(other.keys().cloned());

        let mut diffs: Vec<DetailedRegisterDiff> = all_registers
            .into_iter()
            .map(|reg| {
                let base_val = base.get(&reg).copied();
                let other_val = other.get(&reg).copied();
                DetailedRegisterDiff::new(reg, base_val, other_val)
            })
            .collect();

        // Sort by category and then by register name
        diffs.sort_by(|a, b| {
            a.category
                .sort_order()
                .cmp(&b.category.sort_order())
                .then_with(|| a.register.cmp(&b.register))
        });

        // Filter to only differing registers if not showing all
        if !self.show_all_registers {
            diffs.retain(|d| d.differs);
        }

        diffs
    }

    /// Formats the register diffs as a side-by-side table.
    #[allow(dead_code)]
    pub fn format_table(
        &self,
        diffs: &[DetailedRegisterDiff],
        base_name: &str,
        other_name: &str,
    ) -> String {
        let mut output = String::new();

        // Table header
        let header = format!(
            "{:<12} {:>20}  {:>20}  {}\n",
            "Register", base_name, other_name, "Status"
        );
        let separator = "─".repeat(header.len().saturating_sub(1));

        output.push_str(&header);
        output.push_str(&separator);
        output.push('\n');

        let mut current_category: Option<RegisterCategory> = None;

        for diff in diffs {
            // Print category header when category changes
            if current_category != Some(diff.category) {
                if current_category.is_some() {
                    output.push('\n');
                }
                let cat_header = format!("  {} \n", diff.category.display_name());
                if self.use_colors {
                    output.push_str(&format!("\x1b[1;34m{}\x1b[0m", cat_header));
                } else {
                    output.push_str(&cat_header);
                }
                current_category = Some(diff.category);
            }

            let base_str = match diff.base_value {
                Some(v) => format!("0x{:016X}", v),
                None => "  (not present)   ".to_string(),
            };

            let other_str = match diff.other_value {
                Some(v) => format!("0x{:016X}", v),
                None => "  (not present)   ".to_string(),
            };

            let (status, delta) = if diff.differs {
                let delta_str = diff.format_delta();
                if self.use_colors {
                    ("\x1b[31m✗\x1b[0m", format!(" ({})", delta_str))
                } else {
                    ("✗", format!(" ({})", delta_str))
                }
            } else if self.use_colors {
                ("\x1b[32m✓\x1b[0m", String::new())
            } else {
                ("✓", String::new())
            };

            let line = format!(
                "{:<12} {:>20}  {:>20}  {}{}\n",
                diff.register, base_str, other_str, status, delta
            );
            output.push_str(&line);
        }

        output
    }

    /// Formats the bit-level difference visualization for a single diff.
    #[allow(dead_code)]
    pub fn format_bit_diff(&self, diff: &DetailedRegisterDiff) -> String {
        match (diff.base_value, diff.other_value, diff.differing_bits) {
            (Some(base), Some(other), Some(xor)) if diff.differs => {
                let mut output = String::new();

                // Format as grouped hex (0000_0000_0000_0000)
                let base_str = Self::format_grouped_hex(base);
                let other_str = Self::format_grouped_hex(other);

                output.push_str(&format!(
                    "  {}: {} vs {}\n",
                    diff.register, base_str, other_str
                ));

                // Create highlight line showing differing nibbles
                let highlight = Self::create_highlight_line(xor);

                if self.use_colors {
                    output.push_str(&format!(
                        "  {:width$}  \x1b[33m{}\x1b[0m\n",
                        "",
                        highlight,
                        width = diff.register.len()
                    ));
                } else {
                    output.push_str(&format!(
                        "  {:width$}  {}\n",
                        "",
                        highlight,
                        width = diff.register.len()
                    ));
                }

                output
            }
            _ => String::new(),
        }
    }

    /// Formats a value as grouped hex (0000_0000_0000_0000).
    fn format_grouped_hex(value: u64) -> String {
        format!(
            "{:04X}_{:04X}_{:04X}_{:04X}",
            (value >> 48) & 0xFFFF,
            (value >> 32) & 0xFFFF,
            (value >> 16) & 0xFFFF,
            value & 0xFFFF
        )
    }

    /// Creates a highlight line showing which nibbles differ.
    fn create_highlight_line(xor: u64) -> String {
        let mut highlight = String::with_capacity(23);

        for group in 0..4 {
            if group > 0 {
                highlight.push(' ');
            }

            for nibble in 0..4 {
                let shift = (3 - group) * 16 + (3 - nibble) * 4;
                let nibble_xor = (xor >> shift) & 0xF;
                if nibble_xor != 0 {
                    highlight.push('^');
                } else {
                    highlight.push(' ');
                }
            }
        }

        highlight
    }

    /// Groups register diffs by category.
    pub fn group_by_category<'a>(
        &self,
        diffs: &'a [DetailedRegisterDiff],
    ) -> HashMap<RegisterCategory, Vec<&'a DetailedRegisterDiff>> {
        let mut grouped: HashMap<RegisterCategory, Vec<&'a DetailedRegisterDiff>> = HashMap::new();

        for diff in diffs {
            grouped.entry(diff.category).or_default().push(diff);
        }

        grouped
    }

    /// Formats diffs as a JSON structure for machine processing.
    pub fn format_json(&self, diffs: &[DetailedRegisterDiff]) -> serde_json::Value {
        let grouped = self.group_by_category(diffs);

        let mut result: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();

        for (category, cat_diffs) in grouped {
            let cat_name = format!("{:?}", category);
            let cat_array: Vec<serde_json::Value> = cat_diffs
                .iter()
                .map(|diff| {
                    serde_json::json!({
                        "register": diff.register,
                        "base_value": diff.base_value,
                        "other_value": diff.other_value,
                        "base_hex": diff.base_value.map(|v| format!("0x{:016X}", v)),
                        "other_hex": diff.other_value.map(|v| format!("0x{:016X}", v)),
                        "differs": diff.differs,
                        "differing_bits": diff.differing_bits,
                        "differing_bits_hex": diff.differing_bits.map(|v| format!("0x{:016X}", v)),
                        "delta": diff.signed_delta,
                    })
                })
                .collect();

            result.insert(cat_name, serde_json::Value::Array(cat_array));
        }

        serde_json::Value::Object(result)
    }

    /// Formats a summary of differences.
    #[allow(dead_code)]
    pub fn format_summary(&self, diffs: &[DetailedRegisterDiff]) -> String {
        let total = diffs.len();
        let differing: Vec<_> = diffs.iter().filter(|d| d.differs).collect();
        let matching = total - differing.len();

        let mut output = String::new();

        output.push_str(&format!(
            "Register comparison: {} total, {} matching, {} differing\n",
            total,
            matching,
            differing.len()
        ));

        if !differing.is_empty() {
            output.push_str("Differing registers: ");
            let names: Vec<&str> = differing.iter().map(|d| d.register.as_str()).collect();
            output.push_str(&names.join(", "));
            output.push('\n');
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_categorize_register() {
        assert_eq!(categorize_register("RAX"), RegisterCategory::GeneralPurpose);
        assert_eq!(categorize_register("rax"), RegisterCategory::GeneralPurpose);
        assert_eq!(categorize_register("R8"), RegisterCategory::GeneralPurpose);
        assert_eq!(categorize_register("RFLAGS"), RegisterCategory::Flags);
        assert_eq!(
            categorize_register("RIP"),
            RegisterCategory::InstructionPointer
        );
        assert_eq!(categorize_register("CS"), RegisterCategory::Segment);
        assert_eq!(categorize_register("XMM0"), RegisterCategory::Vector);
        assert_eq!(categorize_register("ST0"), RegisterCategory::Fpu);
        assert_eq!(categorize_register("CR0"), RegisterCategory::Control);
        assert_eq!(categorize_register("DR0"), RegisterCategory::Debug);
        assert_eq!(categorize_register("UNKNOWN"), RegisterCategory::Other);
    }

    #[test]
    fn test_detailed_register_diff() {
        let diff = DetailedRegisterDiff::new("RAX".to_string(), Some(0x100), Some(0x101));
        assert!(diff.differs);
        assert_eq!(diff.differing_bits, Some(1));
        assert_eq!(diff.signed_delta, Some(1));
        assert_eq!(diff.format_delta(), "+1");

        let diff2 = DetailedRegisterDiff::new("RBX".to_string(), Some(0x100), Some(0x100));
        assert!(!diff2.differs);
        assert_eq!(diff2.differing_bits, None);
    }

    #[test]
    fn test_format_grouped_hex() {
        assert_eq!(
            RegisterDiffFormatter::format_grouped_hex(0x0000_0000_0000_00FF),
            "0000_0000_0000_00FF"
        );
        assert_eq!(
            RegisterDiffFormatter::format_grouped_hex(0xDEAD_BEEF_CAFE_BABE),
            "DEAD_BEEF_CAFE_BABE"
        );
    }

    #[test]
    fn test_create_highlight_line() {
        // Only last nibble differs
        let highlight = RegisterDiffFormatter::create_highlight_line(0x0000_0000_0000_000F);
        assert!(highlight.ends_with("   ^"));

        // First nibble differs
        let highlight = RegisterDiffFormatter::create_highlight_line(0xF000_0000_0000_0000);
        assert!(highlight.starts_with("^"));
    }

    #[test]
    fn test_formatter_create_diffs() {
        let mut base = HashMap::new();
        base.insert("RAX".to_string(), 0x100);
        base.insert("RBX".to_string(), 0x200);

        let mut other = HashMap::new();
        other.insert("RAX".to_string(), 0x100);
        other.insert("RBX".to_string(), 0x201);

        let formatter = RegisterDiffFormatter::new().show_all(false);
        let diffs = formatter.create_diffs(&base, &other);

        // Should only have RBX since it's the only differing one
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].register, "RBX");
    }

    #[test]
    fn test_formatter_show_all() {
        let mut base = HashMap::new();
        base.insert("RAX".to_string(), 0x100);
        base.insert("RBX".to_string(), 0x200);

        let mut other = HashMap::new();
        other.insert("RAX".to_string(), 0x100);
        other.insert("RBX".to_string(), 0x201);

        let formatter = RegisterDiffFormatter::new().show_all(true);
        let diffs = formatter.create_diffs(&base, &other);

        // Should have both registers
        assert_eq!(diffs.len(), 2);
    }
}
