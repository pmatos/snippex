//! Host architecture detection and management.
//!
//! This module provides functionality for detecting the host machine's
//! architecture and routing execution to appropriate targets (local or remote).

pub mod dispatcher;
pub mod flags;

#[allow(unused_imports)]
pub use flags::{FlagComparison, X86Flags};

#[allow(unused_imports)] // Will be used in Phase 3.3 validate command
pub use dispatcher::{EmulatorDispatcher, ExecutionTarget};

use std::fmt;
use std::sync::OnceLock;

/// Global architecture override for testing purposes.
/// When set, `get_effective_architecture()` returns this instead of detecting.
static ARCH_OVERRIDE: OnceLock<HostArch> = OnceLock::new();

/// Represents the supported host architectures for Snippex.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostArch {
    /// x86-64 (AMD64) architecture
    X86_64,
    /// AArch64 (ARM64) architecture
    AArch64,
}

impl HostArch {
    /// Detects the current host machine's architecture.
    ///
    /// Uses `std::env::consts::ARCH` to determine the architecture at runtime.
    /// Returns `None` for unsupported architectures.
    pub fn detect() -> Option<Self> {
        match std::env::consts::ARCH {
            "x86_64" => Some(HostArch::X86_64),
            "aarch64" => Some(HostArch::AArch64),
            _ => None,
        }
    }

    /// Returns the architecture as a string suitable for display and configuration.
    pub fn as_str(&self) -> &'static str {
        match self {
            HostArch::X86_64 => "x86_64",
            HostArch::AArch64 => "aarch64",
        }
    }

    /// Returns a human-readable name for the architecture.
    pub fn display_name(&self) -> &'static str {
        match self {
            HostArch::X86_64 => "x86-64 (AMD64)",
            HostArch::AArch64 => "AArch64 (ARM64)",
        }
    }

    /// Checks if native x86 execution is available on this architecture.
    pub fn can_run_x86_native(&self) -> bool {
        matches!(self, HostArch::X86_64)
    }

    /// Checks if FEX-Emu can run on this architecture (ARM64 only).
    #[allow(dead_code)] // Will be used in Phase 3.2 for smart dispatching
    pub fn can_run_fex(&self) -> bool {
        matches!(self, HostArch::AArch64)
    }

    /// Parses an architecture string into a HostArch.
    ///
    /// Accepts various formats: "x86_64", "amd64", "x86-64", "aarch64", "arm64".
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "x86_64" | "amd64" | "x86-64" | "x64" => Some(HostArch::X86_64),
            "aarch64" | "arm64" => Some(HostArch::AArch64),
            _ => None,
        }
    }
}

impl fmt::Display for HostArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for HostArch {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        HostArch::parse(s)
            .ok_or_else(|| format!("Unknown architecture '{}'. Supported: x86_64, aarch64", s))
    }
}

/// Detects the host architecture and returns it.
///
/// This is the primary entry point for architecture detection.
/// Returns an error message if the architecture is not supported.
pub fn detect_host_architecture() -> Result<HostArch, String> {
    HostArch::detect().ok_or_else(|| {
        format!(
            "Unsupported host architecture '{}'. Snippex requires x86_64 or aarch64.",
            std::env::consts::ARCH
        )
    })
}

/// Sets the global architecture override for testing.
///
/// Once set, `get_effective_architecture()` will return this architecture
/// instead of detecting the actual host architecture. This can only be set once.
///
/// Returns `Err` if an override was already set.
pub fn set_arch_override(arch: HostArch) -> Result<(), HostArch> {
    ARCH_OVERRIDE.set(arch)
}

/// Returns the effective architecture, considering any override.
///
/// If an architecture override has been set via `set_arch_override()` or
/// command-line flag, returns that. Otherwise, detects the actual host architecture.
pub fn get_effective_architecture() -> Result<HostArch, String> {
    if let Some(arch) = ARCH_OVERRIDE.get() {
        Ok(*arch)
    } else {
        detect_host_architecture()
    }
}

/// Checks if an architecture override is currently active.
pub fn has_arch_override() -> bool {
    ARCH_OVERRIDE.get().is_some()
}

/// Returns information about the current host for display in version info.
pub fn host_info() -> String {
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;
    format!("{}-{}", arch, os)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_host_architecture() {
        // This test will pass on x86_64 or aarch64 machines
        let result = detect_host_architecture();
        // We should be running on a supported architecture
        assert!(result.is_ok() || std::env::consts::ARCH == "unknown");
    }

    #[test]
    fn test_arch_as_str() {
        assert_eq!(HostArch::X86_64.as_str(), "x86_64");
        assert_eq!(HostArch::AArch64.as_str(), "aarch64");
    }

    #[test]
    fn test_arch_parse() {
        assert_eq!(HostArch::parse("x86_64"), Some(HostArch::X86_64));
        assert_eq!(HostArch::parse("amd64"), Some(HostArch::X86_64));
        assert_eq!(HostArch::parse("x86-64"), Some(HostArch::X86_64));
        assert_eq!(HostArch::parse("aarch64"), Some(HostArch::AArch64));
        assert_eq!(HostArch::parse("arm64"), Some(HostArch::AArch64));
        assert_eq!(HostArch::parse("unknown"), None);
    }

    #[test]
    fn test_can_run_x86_native() {
        assert!(HostArch::X86_64.can_run_x86_native());
        assert!(!HostArch::AArch64.can_run_x86_native());
    }

    #[test]
    fn test_can_run_fex() {
        assert!(!HostArch::X86_64.can_run_fex());
        assert!(HostArch::AArch64.can_run_fex());
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", HostArch::X86_64), "x86_64");
        assert_eq!(format!("{}", HostArch::AArch64), "aarch64");
    }

    #[test]
    fn test_parse() {
        assert_eq!("x86_64".parse::<HostArch>().unwrap(), HostArch::X86_64);
        assert_eq!("aarch64".parse::<HostArch>().unwrap(), HostArch::AArch64);
        assert!("invalid".parse::<HostArch>().is_err());
    }

    #[test]
    fn test_host_info() {
        let info = host_info();
        // Should contain the architecture
        assert!(info.contains(std::env::consts::ARCH));
        // Should contain the OS
        assert!(info.contains(std::env::consts::OS));
    }
}
