//! Smart emulator dispatching based on host architecture.
//!
//! This module provides functionality for automatically selecting the appropriate
//! execution target (local or remote) for native x86 and FEX-Emu execution based
//! on the current host architecture.

use crate::arch::{get_effective_architecture, HostArch};
use crate::config::{Config, RemoteConfig};

/// Represents where execution should take place.
#[allow(dead_code)] // Will be used in Phase 3.3 validate command
#[derive(Debug, Clone, PartialEq)]
pub enum ExecutionTarget {
    /// Execute locally on this machine
    Local,
    /// Execute remotely via SSH
    Remote(RemoteConfig),
    /// No suitable target available
    Unavailable(String),
}

#[allow(dead_code)] // Will be used in Phase 3.3 validate command
impl ExecutionTarget {
    /// Returns true if this is a local execution target.
    pub fn is_local(&self) -> bool {
        matches!(self, ExecutionTarget::Local)
    }

    /// Returns true if this is a remote execution target.
    pub fn is_remote(&self) -> bool {
        matches!(self, ExecutionTarget::Remote(_))
    }

    /// Returns true if no target is available.
    pub fn is_unavailable(&self) -> bool {
        matches!(self, ExecutionTarget::Unavailable(_))
    }

    /// Returns the remote config if this is a remote target.
    pub fn remote_config(&self) -> Option<&RemoteConfig> {
        match self {
            ExecutionTarget::Remote(config) => Some(config),
            _ => None,
        }
    }

    /// Returns a human-readable description of the target.
    pub fn description(&self) -> String {
        match self {
            ExecutionTarget::Local => "local".to_string(),
            ExecutionTarget::Remote(config) => {
                format!("{}@{}", config.user, config.host)
            }
            ExecutionTarget::Unavailable(reason) => format!("unavailable: {}", reason),
        }
    }
}

/// Dispatches execution to the appropriate target based on architecture.
#[allow(dead_code)] // Will be used in Phase 3.3 validate command
#[derive(Debug)]
pub struct EmulatorDispatcher {
    host_arch: HostArch,
    config: Config,
}

#[allow(dead_code)] // Will be used in Phase 3.3 validate command
impl EmulatorDispatcher {
    /// Creates a new dispatcher with the given configuration.
    pub fn new(config: Config) -> Result<Self, String> {
        let host_arch = get_effective_architecture()?;
        Ok(Self { host_arch, config })
    }

    /// Creates a new dispatcher with an explicit architecture (for testing).
    pub fn with_arch(arch: HostArch, config: Config) -> Self {
        Self {
            host_arch: arch,
            config,
        }
    }

    /// Returns the current host architecture.
    pub fn host_arch(&self) -> HostArch {
        self.host_arch
    }

    /// Selects the target for native x86 execution.
    ///
    /// - On x86_64: Execute locally
    /// - On aarch64: Execute on remote x86 machine
    pub fn select_native_host(&self) -> ExecutionTarget {
        match self.host_arch {
            HostArch::X86_64 => ExecutionTarget::Local,
            HostArch::AArch64 => {
                // Need to find an x86_64 remote
                match self.find_remote_by_arch("x86_64") {
                    Some(remote) => ExecutionTarget::Remote(remote),
                    None => ExecutionTarget::Unavailable(
                        "No x86_64 remote configured. Add one with: snippex config set-remote <name> --arch x86_64 --host <host>".to_string()
                    ),
                }
            }
        }
    }

    /// Selects the target for FEX-Emu execution.
    ///
    /// - On aarch64: Execute locally (FEX-Emu runs on ARM64)
    /// - On x86_64: Execute on remote ARM64 machine
    pub fn select_fex_host(&self) -> ExecutionTarget {
        match self.host_arch {
            HostArch::AArch64 => ExecutionTarget::Local,
            HostArch::X86_64 => {
                // Need to find an aarch64 remote
                match self.find_remote_by_arch("aarch64") {
                    Some(remote) => ExecutionTarget::Remote(remote),
                    None => ExecutionTarget::Unavailable(
                        "No aarch64 remote configured. Add one with: snippex config set-remote <name> --arch aarch64 --host <host>".to_string()
                    ),
                }
            }
        }
    }

    /// Finds a remote machine with the specified architecture.
    fn find_remote_by_arch(&self, arch: &str) -> Option<RemoteConfig> {
        self.config
            .find_remote_by_arch(arch)
            .map(|(_, config)| config.clone())
    }

    /// Returns both execution targets for validation.
    ///
    /// Returns a tuple of (native_target, fex_target).
    pub fn select_validation_targets(&self) -> (ExecutionTarget, ExecutionTarget) {
        (self.select_native_host(), self.select_fex_host())
    }

    /// Checks if full validation is possible (both native and FEX targets available).
    pub fn can_validate(&self) -> bool {
        let (native, fex) = self.select_validation_targets();
        !native.is_unavailable() && !fex.is_unavailable()
    }

    /// Returns a summary of the current dispatch configuration.
    pub fn summary(&self) -> String {
        let (native, fex) = self.select_validation_targets();
        format!(
            "Host: {} | Native: {} | FEX-Emu: {}",
            self.host_arch,
            native.description(),
            fex.description()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RemoteConfig;

    fn make_x86_remote() -> RemoteConfig {
        RemoteConfig::new("x86-server.example.com".to_string(), "testuser".to_string())
            .with_architecture("x86_64".to_string())
    }

    fn make_arm64_remote() -> RemoteConfig {
        RemoteConfig::new(
            "arm64-server.example.com".to_string(),
            "testuser".to_string(),
        )
        .with_architecture("aarch64".to_string())
    }

    #[test]
    fn test_execution_target_is_local() {
        assert!(ExecutionTarget::Local.is_local());
        assert!(!ExecutionTarget::Remote(make_x86_remote()).is_local());
        assert!(!ExecutionTarget::Unavailable("test".into()).is_local());
    }

    #[test]
    fn test_execution_target_is_remote() {
        assert!(!ExecutionTarget::Local.is_remote());
        assert!(ExecutionTarget::Remote(make_x86_remote()).is_remote());
        assert!(!ExecutionTarget::Unavailable("test".into()).is_remote());
    }

    #[test]
    fn test_execution_target_description() {
        assert_eq!(ExecutionTarget::Local.description(), "local");
        let remote = ExecutionTarget::Remote(make_x86_remote());
        assert!(remote.description().contains("x86-server.example.com"));
        let unavail = ExecutionTarget::Unavailable("no config".into());
        assert!(unavail.description().contains("unavailable"));
    }

    #[test]
    fn test_dispatcher_x86_host_no_remotes() {
        let config = Config::default();
        let dispatcher = EmulatorDispatcher::with_arch(HostArch::X86_64, config);

        // Native should be local
        assert!(dispatcher.select_native_host().is_local());

        // FEX should be unavailable (no arm64 remote)
        assert!(dispatcher.select_fex_host().is_unavailable());
    }

    #[test]
    fn test_dispatcher_x86_host_with_arm64_remote() {
        let mut config = Config::default();
        config.set_remote("arm-server".into(), make_arm64_remote());
        let dispatcher = EmulatorDispatcher::with_arch(HostArch::X86_64, config);

        // Native should be local
        assert!(dispatcher.select_native_host().is_local());

        // FEX should be remote
        let fex = dispatcher.select_fex_host();
        assert!(fex.is_remote());
        assert!(fex.description().contains("arm64-server.example.com"));
    }

    #[test]
    fn test_dispatcher_arm64_host_no_remotes() {
        let config = Config::default();
        let dispatcher = EmulatorDispatcher::with_arch(HostArch::AArch64, config);

        // Native should be unavailable (no x86 remote)
        assert!(dispatcher.select_native_host().is_unavailable());

        // FEX should be local
        assert!(dispatcher.select_fex_host().is_local());
    }

    #[test]
    fn test_dispatcher_arm64_host_with_x86_remote() {
        let mut config = Config::default();
        config.set_remote("x86-server".into(), make_x86_remote());
        let dispatcher = EmulatorDispatcher::with_arch(HostArch::AArch64, config);

        // Native should be remote
        let native = dispatcher.select_native_host();
        assert!(native.is_remote());
        assert!(native.description().contains("x86-server.example.com"));

        // FEX should be local
        assert!(dispatcher.select_fex_host().is_local());
    }

    #[test]
    fn test_dispatcher_can_validate_x86_with_arm64_remote() {
        let mut config = Config::default();
        config.set_remote("arm-server".into(), make_arm64_remote());
        let dispatcher = EmulatorDispatcher::with_arch(HostArch::X86_64, config);

        assert!(dispatcher.can_validate());
    }

    #[test]
    fn test_dispatcher_cannot_validate_x86_without_remotes() {
        let config = Config::default();
        let dispatcher = EmulatorDispatcher::with_arch(HostArch::X86_64, config);

        assert!(!dispatcher.can_validate());
    }

    #[test]
    fn test_dispatcher_summary() {
        let mut config = Config::default();
        config.set_remote("arm-server".into(), make_arm64_remote());
        let dispatcher = EmulatorDispatcher::with_arch(HostArch::X86_64, config);

        let summary = dispatcher.summary();
        assert!(summary.contains("x86_64"));
        assert!(summary.contains("local"));
        assert!(summary.contains("arm64-server.example.com"));
    }
}
