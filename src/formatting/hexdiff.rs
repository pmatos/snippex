//! Memory hex dump diff formatting.
//!
//! Provides side-by-side comparison of memory contents with visual
//! highlighting of differences.

use std::collections::HashMap;

/// Output format for hex diff display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HexDiffFormat {
    /// Side-by-side comparison format.
    #[default]
    Split,
    /// Unified diff format.
    Unified,
    /// JSON structured format.
    Json,
}

/// A single memory region difference.
#[derive(Debug, Clone)]
pub struct MemoryRegionDiff {
    pub address: u64,
    pub base_data: Option<Vec<u8>>,
    pub other_data: Option<Vec<u8>>,
    pub differs: bool,
}

impl MemoryRegionDiff {
    /// Creates a new memory region diff.
    pub fn new(address: u64, base_data: Option<Vec<u8>>, other_data: Option<Vec<u8>>) -> Self {
        let differs = base_data != other_data;
        Self {
            address,
            base_data,
            other_data,
            differs,
        }
    }

    /// Returns the number of differing bytes.
    pub fn differing_byte_count(&self) -> usize {
        match (&self.base_data, &self.other_data) {
            (Some(base), Some(other)) => {
                let len = base.len().min(other.len());
                base.iter()
                    .zip(other.iter())
                    .take(len)
                    .filter(|(b, o)| b != o)
                    .count()
                    + (base.len().abs_diff(other.len()))
            }
            (Some(base), None) => base.len(),
            (None, Some(other)) => other.len(),
            (None, None) => 0,
        }
    }

    /// Returns the offsets of differing bytes.
    pub fn differing_byte_offsets(&self) -> Vec<usize> {
        match (&self.base_data, &self.other_data) {
            (Some(base), Some(other)) => {
                let len = base.len().min(other.len());
                let mut offsets: Vec<usize> = base
                    .iter()
                    .zip(other.iter())
                    .enumerate()
                    .take(len)
                    .filter_map(|(i, (b, o))| if b != o { Some(i) } else { None })
                    .collect();

                // Add offsets for length differences
                if base.len() > other.len() {
                    offsets.extend(other.len()..base.len());
                } else if other.len() > base.len() {
                    offsets.extend(base.len()..other.len());
                }

                offsets
            }
            (Some(base), None) => (0..base.len()).collect(),
            (None, Some(other)) => (0..other.len()).collect(),
            (None, None) => Vec::new(),
        }
    }
}

/// Formatter for memory hex dumps with difference highlighting.
pub struct HexDiffFormatter {
    bytes_per_line: usize,
    use_colors: bool,
    show_ascii: bool,
    format: HexDiffFormat,
}

impl Default for HexDiffFormatter {
    fn default() -> Self {
        Self::new()
    }
}

impl HexDiffFormatter {
    /// Creates a new formatter with default settings.
    pub fn new() -> Self {
        Self {
            bytes_per_line: 16,
            use_colors: true,
            show_ascii: true,
            format: HexDiffFormat::Split,
        }
    }

    /// Sets the number of bytes per line.
    #[allow(dead_code)]
    pub fn with_bytes_per_line(mut self, bytes: usize) -> Self {
        self.bytes_per_line = bytes;
        self
    }

    /// Sets whether to use ANSI colors.
    pub fn with_colors(mut self, use_colors: bool) -> Self {
        self.use_colors = use_colors;
        self
    }

    /// Sets whether to show ASCII representation.
    #[allow(dead_code)]
    pub fn with_ascii(mut self, show_ascii: bool) -> Self {
        self.show_ascii = show_ascii;
        self
    }

    /// Sets the output format.
    pub fn with_format(mut self, format: HexDiffFormat) -> Self {
        self.format = format;
        self
    }

    /// Creates diffs from two memory maps.
    pub fn create_diffs(
        &self,
        base: &HashMap<u64, Vec<u8>>,
        other: &HashMap<u64, Vec<u8>>,
    ) -> Vec<MemoryRegionDiff> {
        let mut all_addresses: Vec<u64> = base.keys().copied().collect();
        all_addresses.extend(other.keys().copied());
        all_addresses.sort_unstable();
        all_addresses.dedup();

        all_addresses
            .into_iter()
            .map(|addr| {
                let base_data = base.get(&addr).cloned();
                let other_data = other.get(&addr).cloned();
                MemoryRegionDiff::new(addr, base_data, other_data)
            })
            .collect()
    }

    /// Filters diffs to only those that differ.
    pub fn filter_differing(diffs: Vec<MemoryRegionDiff>) -> Vec<MemoryRegionDiff> {
        diffs.into_iter().filter(|d| d.differs).collect()
    }

    /// Filters diffs to a specific address range.
    pub fn filter_by_range(
        diffs: Vec<MemoryRegionDiff>,
        start: u64,
        end: u64,
    ) -> Vec<MemoryRegionDiff> {
        diffs
            .into_iter()
            .filter(|d| d.address >= start && d.address < end)
            .collect()
    }

    /// Formats the diffs based on the configured format.
    pub fn format(&self, diffs: &[MemoryRegionDiff], base_name: &str, other_name: &str) -> String {
        match self.format {
            HexDiffFormat::Split => self.format_split(diffs, base_name, other_name),
            HexDiffFormat::Unified => self.format_unified(diffs),
            HexDiffFormat::Json => self.format_json(diffs),
        }
    }

    /// Formats as side-by-side comparison.
    fn format_split(
        &self,
        diffs: &[MemoryRegionDiff],
        base_name: &str,
        other_name: &str,
    ) -> String {
        let mut output = String::new();

        // Header
        let header = format!("{:<18} {:<50} {:<50}\n", "Address", base_name, other_name);
        output.push_str(&header);
        output.push_str(&"─".repeat(header.len().saturating_sub(1)));
        output.push('\n');

        for diff in diffs {
            if !diff.differs {
                continue;
            }

            output.push_str(&self.format_region_split(diff));
            output.push('\n');
        }

        output
    }

    /// Formats a single memory region in split format.
    fn format_region_split(&self, diff: &MemoryRegionDiff) -> String {
        let mut output = String::new();

        let base_data = diff.base_data.as_ref();
        let other_data = diff.other_data.as_ref();

        let max_len = match (base_data, other_data) {
            (Some(b), Some(o)) => b.len().max(o.len()),
            (Some(b), None) => b.len(),
            (None, Some(o)) => o.len(),
            (None, None) => return output,
        };

        let differing_offsets: std::collections::HashSet<usize> =
            diff.differing_byte_offsets().into_iter().collect();

        for offset in (0..max_len).step_by(self.bytes_per_line) {
            let addr = diff.address + offset as u64;
            let end_offset = (offset + self.bytes_per_line).min(max_len);

            // Format base side
            let base_hex = self.format_hex_line(base_data, offset, end_offset, &differing_offsets);
            let base_ascii = if self.show_ascii {
                self.format_ascii_line(base_data, offset, end_offset)
            } else {
                String::new()
            };

            // Format other side
            let other_hex =
                self.format_hex_line(other_data, offset, end_offset, &differing_offsets);
            let other_ascii = if self.show_ascii {
                self.format_ascii_line(other_data, offset, end_offset)
            } else {
                String::new()
            };

            // Status indicator
            let has_diff = (offset..end_offset).any(|i| differing_offsets.contains(&i));
            let status = if has_diff {
                if self.use_colors {
                    "\x1b[31m✗\x1b[0m"
                } else {
                    "✗"
                }
            } else if self.use_colors {
                "\x1b[32m✓\x1b[0m"
            } else {
                "✓"
            };

            output.push_str(&format!(
                "0x{:016X}: {:<48} {:<48} {}\n",
                addr, base_hex, other_hex, status
            ));

            if self.show_ascii {
                output.push_str(&format!(
                    "                    {:<48} {:<48}\n",
                    base_ascii, other_ascii
                ));
            }

            // Show diff highlight if requested and there are differences
            if has_diff && self.use_colors {
                let highlight = self.create_diff_highlight(offset, end_offset, &differing_offsets);
                output.push_str(&format!(
                    "                    \x1b[33m{}\x1b[0m\n",
                    highlight
                ));
            }
        }

        output
    }

    /// Formats a hex line with optional highlighting.
    fn format_hex_line(
        &self,
        data: Option<&Vec<u8>>,
        start: usize,
        end: usize,
        differing: &std::collections::HashSet<usize>,
    ) -> String {
        let mut result = String::new();

        match data {
            Some(bytes) => {
                for i in start..end {
                    if i >= bytes.len() {
                        result.push_str("   ");
                    } else {
                        let byte_str = format!("{:02X} ", bytes[i]);
                        if differing.contains(&i) && self.use_colors {
                            result.push_str(&format!("\x1b[31m{}\x1b[0m", byte_str));
                        } else {
                            result.push_str(&byte_str);
                        }
                    }
                }
            }
            None => {
                result.push_str(&"-- ".repeat(end - start));
            }
        }

        // Pad to expected width
        let expected_chars = (end - start) * 3;
        while result.chars().filter(|c| *c != '\x1b').count() < expected_chars {
            result.push(' ');
        }

        result
    }

    /// Formats an ASCII representation line.
    fn format_ascii_line(&self, data: Option<&Vec<u8>>, start: usize, end: usize) -> String {
        let mut result = String::from("|");

        match data {
            Some(bytes) => {
                for i in start..end {
                    if i >= bytes.len() {
                        result.push(' ');
                    } else {
                        let byte = bytes[i];
                        if byte.is_ascii_graphic() || byte == b' ' {
                            result.push(byte as char);
                        } else {
                            result.push('.');
                        }
                    }
                }
            }
            None => {
                result.push_str(&"-".repeat(end - start));
            }
        }

        result.push('|');
        result
    }

    /// Creates a diff highlight marker line.
    fn create_diff_highlight(
        &self,
        start: usize,
        end: usize,
        differing: &std::collections::HashSet<usize>,
    ) -> String {
        let mut highlight = String::new();

        for i in start..end {
            if differing.contains(&i) {
                highlight.push_str("^^ ");
            } else {
                highlight.push_str("   ");
            }
        }

        highlight
    }

    /// Formats as unified diff.
    fn format_unified(&self, diffs: &[MemoryRegionDiff]) -> String {
        let mut output = String::new();

        for diff in diffs {
            if !diff.differs {
                continue;
            }

            output.push_str(&format!("@@ Memory at 0x{:016X} @@\n", diff.address));

            if let Some(base) = &diff.base_data {
                output.push_str(&format!("- Base:  {}\n", Self::format_hex_bytes(base)));
            }

            if let Some(other) = &diff.other_data {
                output.push_str(&format!("+ Other: {}\n", Self::format_hex_bytes(other)));
            }

            let differing_count = diff.differing_byte_count();
            output.push_str(&format!(
                "  ({} byte{} differ)\n\n",
                differing_count,
                if differing_count == 1 { "" } else { "s" }
            ));
        }

        output
    }

    /// Formats bytes as a hex string.
    fn format_hex_bytes(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Formats as JSON.
    fn format_json(&self, diffs: &[MemoryRegionDiff]) -> String {
        let json_diffs: Vec<serde_json::Value> = diffs
            .iter()
            .filter(|d| d.differs)
            .map(|d| {
                serde_json::json!({
                    "address": format!("0x{:016X}", d.address),
                    "base_data": d.base_data.as_ref().map(|b| Self::format_hex_bytes(b)),
                    "other_data": d.other_data.as_ref().map(|o| Self::format_hex_bytes(o)),
                    "differs": d.differs,
                    "differing_bytes": d.differing_byte_count(),
                    "differing_offsets": d.differing_byte_offsets(),
                })
            })
            .collect();

        serde_json::to_string_pretty(&json_diffs).unwrap_or_default()
    }

    /// Formats a summary of memory differences.
    #[allow(dead_code)]
    pub fn format_summary(&self, diffs: &[MemoryRegionDiff]) -> String {
        let total_regions = diffs.len();
        let differing_regions = diffs.iter().filter(|d| d.differs).count();
        let total_bytes: usize = diffs
            .iter()
            .filter(|d| d.differs)
            .map(|d| d.differing_byte_count())
            .sum();

        format!(
            "Memory comparison: {} total regions, {} differing ({} bytes differ)",
            total_regions, differing_regions, total_bytes
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_region_diff_creation() {
        let base = vec![0x01, 0x02, 0x03, 0x04];
        let other = vec![0x01, 0x02, 0x04, 0x04];

        let diff = MemoryRegionDiff::new(0x1000, Some(base), Some(other));
        assert!(diff.differs);
        assert_eq!(diff.differing_byte_count(), 1);
        assert_eq!(diff.differing_byte_offsets(), vec![2]);
    }

    #[test]
    fn test_memory_region_diff_no_difference() {
        let base = vec![0x01, 0x02, 0x03, 0x04];
        let other = vec![0x01, 0x02, 0x03, 0x04];

        let diff = MemoryRegionDiff::new(0x1000, Some(base), Some(other));
        assert!(!diff.differs);
        assert_eq!(diff.differing_byte_count(), 0);
        assert!(diff.differing_byte_offsets().is_empty());
    }

    #[test]
    fn test_memory_region_diff_length_mismatch() {
        let base = vec![0x01, 0x02, 0x03];
        let other = vec![0x01, 0x02, 0x03, 0x04, 0x05];

        let diff = MemoryRegionDiff::new(0x1000, Some(base), Some(other));
        assert!(diff.differs);
        assert_eq!(diff.differing_byte_count(), 2);
        assert_eq!(diff.differing_byte_offsets(), vec![3, 4]);
    }

    #[test]
    fn test_hex_diff_formatter_creation() {
        let formatter = HexDiffFormatter::new()
            .with_bytes_per_line(8)
            .with_colors(false)
            .with_ascii(true);

        assert_eq!(formatter.bytes_per_line, 8);
        assert!(!formatter.use_colors);
        assert!(formatter.show_ascii);
    }

    #[test]
    fn test_create_diffs() {
        let mut base = HashMap::new();
        base.insert(0x1000, vec![0x01, 0x02, 0x03]);
        base.insert(0x2000, vec![0x04, 0x05, 0x06]);

        let mut other = HashMap::new();
        other.insert(0x1000, vec![0x01, 0x02, 0x03]);
        other.insert(0x2000, vec![0x04, 0xFF, 0x06]);

        let formatter = HexDiffFormatter::new();
        let diffs = formatter.create_diffs(&base, &other);

        assert_eq!(diffs.len(), 2);
        assert!(!diffs[0].differs); // 0x1000
        assert!(diffs[1].differs); // 0x2000
    }

    #[test]
    fn test_filter_differing() {
        let diffs = vec![
            MemoryRegionDiff::new(0x1000, Some(vec![1, 2]), Some(vec![1, 2])),
            MemoryRegionDiff::new(0x2000, Some(vec![1, 2]), Some(vec![1, 3])),
            MemoryRegionDiff::new(0x3000, Some(vec![1, 2]), Some(vec![1, 2])),
        ];

        let filtered = HexDiffFormatter::filter_differing(diffs);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].address, 0x2000);
    }

    #[test]
    fn test_filter_by_range() {
        let diffs = vec![
            MemoryRegionDiff::new(0x1000, Some(vec![1]), Some(vec![2])),
            MemoryRegionDiff::new(0x2000, Some(vec![1]), Some(vec![2])),
            MemoryRegionDiff::new(0x3000, Some(vec![1]), Some(vec![2])),
        ];

        let filtered = HexDiffFormatter::filter_by_range(diffs, 0x1500, 0x2500);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].address, 0x2000);
    }

    #[test]
    fn test_format_hex_bytes() {
        let bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let formatted = HexDiffFormatter::format_hex_bytes(&bytes);
        assert_eq!(formatted, "DE AD BE EF");
    }
}
