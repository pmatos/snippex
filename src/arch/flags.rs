//! x86 CPU flags decomposition and comparison.
//!
//! This module provides functionality for decomposing the RFLAGS register
//! into individual flags and comparing them between simulation results.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Individual x86 CPU flags extracted from RFLAGS register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct X86Flags {
    /// Carry Flag (bit 0) - Set on unsigned overflow
    pub cf: bool,
    /// Parity Flag (bit 2) - Set if low byte has even number of 1s
    pub pf: bool,
    /// Auxiliary Carry Flag (bit 4) - BCD carry
    pub af: bool,
    /// Zero Flag (bit 6) - Set if result is zero
    pub zf: bool,
    /// Sign Flag (bit 7) - Set if result is negative
    pub sf: bool,
    /// Trap Flag (bit 8) - Single-step debugging
    pub tf: bool,
    /// Interrupt Enable Flag (bit 9)
    pub if_: bool,
    /// Direction Flag (bit 10) - String operation direction
    pub df: bool,
    /// Overflow Flag (bit 11) - Set on signed overflow
    pub of: bool,
}

impl X86Flags {
    /// Bit positions for each flag in RFLAGS
    pub const CF_BIT: u64 = 0;
    pub const PF_BIT: u64 = 2;
    pub const AF_BIT: u64 = 4;
    pub const ZF_BIT: u64 = 6;
    pub const SF_BIT: u64 = 7;
    pub const TF_BIT: u64 = 8;
    pub const IF_BIT: u64 = 9;
    pub const DF_BIT: u64 = 10;
    pub const OF_BIT: u64 = 11;

    /// Extracts individual flags from a RFLAGS value.
    pub fn from_rflags(rflags: u64) -> Self {
        Self {
            cf: (rflags >> Self::CF_BIT) & 1 == 1,
            pf: (rflags >> Self::PF_BIT) & 1 == 1,
            af: (rflags >> Self::AF_BIT) & 1 == 1,
            zf: (rflags >> Self::ZF_BIT) & 1 == 1,
            sf: (rflags >> Self::SF_BIT) & 1 == 1,
            tf: (rflags >> Self::TF_BIT) & 1 == 1,
            if_: (rflags >> Self::IF_BIT) & 1 == 1,
            df: (rflags >> Self::DF_BIT) & 1 == 1,
            of: (rflags >> Self::OF_BIT) & 1 == 1,
        }
    }

    /// Converts flags back to a RFLAGS value.
    #[allow(dead_code)]
    #[allow(clippy::wrong_self_convention)]
    pub fn to_rflags(&self) -> u64 {
        let mut rflags = 0u64;
        if self.cf {
            rflags |= 1 << Self::CF_BIT;
        }
        if self.pf {
            rflags |= 1 << Self::PF_BIT;
        }
        if self.af {
            rflags |= 1 << Self::AF_BIT;
        }
        if self.zf {
            rflags |= 1 << Self::ZF_BIT;
        }
        if self.sf {
            rflags |= 1 << Self::SF_BIT;
        }
        if self.tf {
            rflags |= 1 << Self::TF_BIT;
        }
        if self.if_ {
            rflags |= 1 << Self::IF_BIT;
        }
        if self.df {
            rflags |= 1 << Self::DF_BIT;
        }
        if self.of {
            rflags |= 1 << Self::OF_BIT;
        }
        rflags
    }

    /// Returns an iterator over all flag values with their names.
    #[allow(dead_code)]
    pub fn iter(&self) -> impl Iterator<Item = (&'static str, &'static str, bool)> {
        [
            ("CF", "Carry", self.cf),
            ("PF", "Parity", self.pf),
            ("AF", "Auxiliary", self.af),
            ("ZF", "Zero", self.zf),
            ("SF", "Sign", self.sf),
            ("TF", "Trap", self.tf),
            ("IF", "Interrupt", self.if_),
            ("DF", "Direction", self.df),
            ("OF", "Overflow", self.of),
        ]
        .into_iter()
    }
}

impl Default for X86Flags {
    fn default() -> Self {
        Self::from_rflags(0)
    }
}

impl fmt::Display for X86Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut flags = Vec::new();
        if self.cf {
            flags.push("CF");
        }
        if self.pf {
            flags.push("PF");
        }
        if self.af {
            flags.push("AF");
        }
        if self.zf {
            flags.push("ZF");
        }
        if self.sf {
            flags.push("SF");
        }
        if self.tf {
            flags.push("TF");
        }
        if self.if_ {
            flags.push("IF");
        }
        if self.df {
            flags.push("DF");
        }
        if self.of {
            flags.push("OF");
        }

        if flags.is_empty() {
            write!(f, "(none)")
        } else {
            write!(f, "{}", flags.join(" "))
        }
    }
}

/// Comparison result for two sets of x86 flags.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlagComparison {
    pub cf_match: bool,
    pub pf_match: bool,
    pub af_match: bool,
    pub zf_match: bool,
    pub sf_match: bool,
    pub tf_match: bool,
    pub if_match: bool,
    pub df_match: bool,
    pub of_match: bool,
    pub native: X86Flags,
    pub emulated: X86Flags,
}

impl FlagComparison {
    /// Compares two RFLAGS values and returns detailed comparison.
    pub fn compare(native_rflags: u64, emulated_rflags: u64) -> Self {
        let native = X86Flags::from_rflags(native_rflags);
        let emulated = X86Flags::from_rflags(emulated_rflags);

        Self {
            cf_match: native.cf == emulated.cf,
            pf_match: native.pf == emulated.pf,
            af_match: native.af == emulated.af,
            zf_match: native.zf == emulated.zf,
            sf_match: native.sf == emulated.sf,
            tf_match: native.tf == emulated.tf,
            if_match: native.if_ == emulated.if_,
            df_match: native.df == emulated.df,
            of_match: native.of == emulated.of,
            native,
            emulated,
        }
    }

    /// Returns true if all flags match.
    pub fn all_match(&self) -> bool {
        self.cf_match
            && self.pf_match
            && self.af_match
            && self.zf_match
            && self.sf_match
            && self.tf_match
            && self.if_match
            && self.df_match
            && self.of_match
    }

    /// Returns the number of mismatched flags.
    #[allow(dead_code)]
    pub fn mismatch_count(&self) -> usize {
        let mut count = 0;
        if !self.cf_match {
            count += 1;
        }
        if !self.pf_match {
            count += 1;
        }
        if !self.af_match {
            count += 1;
        }
        if !self.zf_match {
            count += 1;
        }
        if !self.sf_match {
            count += 1;
        }
        if !self.tf_match {
            count += 1;
        }
        if !self.if_match {
            count += 1;
        }
        if !self.df_match {
            count += 1;
        }
        if !self.of_match {
            count += 1;
        }
        count
    }

    /// Returns a list of mismatched flag names.
    pub fn mismatched_flags(&self) -> Vec<&'static str> {
        let mut result = Vec::new();
        if !self.cf_match {
            result.push("CF");
        }
        if !self.pf_match {
            result.push("PF");
        }
        if !self.af_match {
            result.push("AF");
        }
        if !self.zf_match {
            result.push("ZF");
        }
        if !self.sf_match {
            result.push("SF");
        }
        if !self.tf_match {
            result.push("TF");
        }
        if !self.if_match {
            result.push("IF");
        }
        if !self.df_match {
            result.push("DF");
        }
        if !self.of_match {
            result.push("OF");
        }
        result
    }

    /// Formats the flag comparison as a detailed table.
    pub fn format_table(&self) -> String {
        let mut output = String::new();
        output.push_str("Flag        Native  Emulated  Status\n");
        output.push_str("──────────────────────────────────────\n");

        let flags = [
            (
                "CF (Carry)",
                self.native.cf,
                self.emulated.cf,
                self.cf_match,
            ),
            (
                "PF (Parity)",
                self.native.pf,
                self.emulated.pf,
                self.pf_match,
            ),
            (
                "AF (Auxiliary)",
                self.native.af,
                self.emulated.af,
                self.af_match,
            ),
            ("ZF (Zero)", self.native.zf, self.emulated.zf, self.zf_match),
            ("SF (Sign)", self.native.sf, self.emulated.sf, self.sf_match),
            ("TF (Trap)", self.native.tf, self.emulated.tf, self.tf_match),
            (
                "IF (Interrupt)",
                self.native.if_,
                self.emulated.if_,
                self.if_match,
            ),
            (
                "DF (Direction)",
                self.native.df,
                self.emulated.df,
                self.df_match,
            ),
            (
                "OF (Overflow)",
                self.native.of,
                self.emulated.of,
                self.of_match,
            ),
        ];

        for (name, native, emulated, matches) in flags {
            let native_str = if native { "1" } else { "0" };
            let emulated_str = if emulated { "1" } else { "0" };
            let status = if matches { "✓" } else { "✗" };
            output.push_str(&format!(
                "{:<14} {:>6}  {:>8}  {}\n",
                name, native_str, emulated_str, status
            ));
        }

        output
    }

    /// Returns a brief summary of the comparison.
    pub fn summary(&self) -> String {
        if self.all_match() {
            "All flags match".to_string()
        } else {
            let mismatched = self.mismatched_flags();
            format!(
                "{} flag(s) differ: {}",
                mismatched.len(),
                mismatched.join(", ")
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flag_extraction() {
        // Test with known flag values
        let rflags = 0x246; // ZF=1, PF=1, IF=1 (typical after cmp equal)
        let flags = X86Flags::from_rflags(rflags);

        assert!(!flags.cf);
        assert!(flags.pf); // bit 2
        assert!(!flags.af);
        assert!(flags.zf); // bit 6
        assert!(!flags.sf);
        assert!(!flags.tf);
        assert!(flags.if_); // bit 9
        assert!(!flags.df);
        assert!(!flags.of);
    }

    #[test]
    fn test_flag_roundtrip() {
        // Use a value that only has tracked bits set (not reserved bits 1, 3, 5)
        let original = 0xED5; // CF, PF, AF, ZF, SF, TF, IF, DF, OF
        let flags = X86Flags::from_rflags(original);
        let reconstructed = flags.to_rflags();
        // Mask for only tracked bits: 0,2,4,6,7,8,9,10,11
        let tracked_mask = (1 << 0)
            | (1 << 2)
            | (1 << 4)
            | (1 << 6)
            | (1 << 7)
            | (1 << 8)
            | (1 << 9)
            | (1 << 10)
            | (1 << 11);
        assert_eq!(original & tracked_mask, reconstructed & tracked_mask);
    }

    #[test]
    fn test_flag_comparison() {
        // 0x246 = bits 1,2,6,9 set: PF=1, ZF=1, IF=1
        // 0x242 = bits 1,6,9 set: PF=0, ZF=1, IF=1 (only PF differs)
        let native = 0x246;
        let emulated = 0x242;

        let comparison = FlagComparison::compare(native, emulated);

        assert!(!comparison.all_match());
        assert_eq!(comparison.mismatch_count(), 1);
        assert_eq!(comparison.mismatched_flags(), vec!["PF"]);
        assert!(!comparison.pf_match);
        assert!(comparison.zf_match);
    }

    #[test]
    fn test_flag_display() {
        let flags = X86Flags::from_rflags(0x246);
        let display = format!("{}", flags);
        assert!(display.contains("PF"));
        assert!(display.contains("ZF"));
        assert!(display.contains("IF"));
    }

    #[test]
    fn test_all_flags_clear() {
        let flags = X86Flags::from_rflags(0);
        assert!(!flags.cf);
        assert!(!flags.pf);
        assert!(!flags.af);
        assert!(!flags.zf);
        assert!(!flags.sf);
        assert!(!flags.tf);
        assert!(!flags.if_);
        assert!(!flags.df);
        assert!(!flags.of);
        assert_eq!(format!("{}", flags), "(none)");
    }

    #[test]
    fn test_all_flags_set() {
        let rflags = 0xFFF; // All lower 12 bits set
        let flags = X86Flags::from_rflags(rflags);
        assert!(flags.cf);
        assert!(flags.pf);
        assert!(flags.af);
        assert!(flags.zf);
        assert!(flags.sf);
        assert!(flags.tf);
        assert!(flags.if_);
        assert!(flags.df);
        assert!(flags.of);
    }
}
