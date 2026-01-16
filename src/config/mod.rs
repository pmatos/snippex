//! Configuration management for Snippex.
//!
//! This module handles loading and saving configuration for remote execution,
//! SSH connections, and other user preferences.
//!
//! # Configuration File Location
//!
//! The configuration file is stored at:
//! - Linux: `~/.config/snippex/config.yml`
//! - macOS: `~/Library/Application Support/snippex/config.yml`
//! - Windows: `C:\Users\<User>\AppData\Roaming\snippex\config.yml`
//!
//! # Example Configuration
//!
//! ```yaml
//! remotes:
//!   x86-oracle:
//!     host: "intel-server.example.com"
//!     user: "pmatos"
//!     port: 22
//!     snippex_path: "/usr/local/bin/snippex"
//!     ssh_key: "~/.ssh/id_rsa"
//!   arm64-fex:
//!     host: "arm-server.example.com"
//!     user: "pmatos"
//!     port: 22
//!     snippex_path: "/usr/local/bin/snippex"
//!     ssh_key: "~/.ssh/id_rsa"
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use crate::error::{Error, Result};

/// Default SSH port
const DEFAULT_SSH_PORT: u16 = 22;

/// Default path to snippex binary on remote
const DEFAULT_SNIPPEX_PATH: &str = "snippex";

/// Default SSH connection timeout in seconds
const DEFAULT_TIMEOUT: u64 = 60;

/// Main configuration structure for Snippex.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    /// Remote machine configurations for cross-architecture testing
    #[serde(default)]
    pub remotes: HashMap<String, RemoteConfig>,

    /// Default settings that apply when not overridden
    #[serde(default)]
    pub defaults: DefaultSettings,
}

/// Configuration for a remote machine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RemoteConfig {
    /// Hostname or IP address of the remote machine
    pub host: String,

    /// SSH username for authentication
    pub user: String,

    /// SSH port (default: 22)
    #[serde(default = "default_ssh_port")]
    pub port: u16,

    /// Path to snippex binary on the remote machine
    #[serde(default = "default_snippex_path")]
    pub snippex_path: String,

    /// Path to SSH private key file (optional, uses default SSH key if not specified)
    pub ssh_key: Option<String>,

    /// Architecture of the remote machine (x86_64, aarch64)
    pub architecture: Option<String>,

    /// Connection timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

/// Default settings for the application.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DefaultSettings {
    /// Default remote to use for x86_64 native execution
    pub x86_remote: Option<String>,

    /// Default remote to use for ARM64/FEX-Emu execution
    pub arm64_remote: Option<String>,

    /// Default emulator to use
    pub emulator: Option<String>,
}

fn default_ssh_port() -> u16 {
    DEFAULT_SSH_PORT
}

fn default_snippex_path() -> String {
    DEFAULT_SNIPPEX_PATH.to_string()
}

fn default_timeout() -> u64 {
    DEFAULT_TIMEOUT
}

impl Config {
    /// Returns the default configuration file path for the current platform.
    pub fn default_path() -> Option<PathBuf> {
        dirs::config_dir().map(|p| p.join("snippex").join("config.yml"))
    }

    /// Loads configuration from the default location.
    ///
    /// Returns `Ok(Config::default())` if no config file exists.
    pub fn load() -> Result<Self> {
        match Self::default_path() {
            Some(path) => Self::load_from(&path),
            None => Ok(Config::default()),
        }
    }

    /// Loads configuration from a specific file path.
    ///
    /// Returns `Ok(Config::default())` if the file doesn't exist.
    pub fn load_from(path: &PathBuf) -> Result<Self> {
        if !path.exists() {
            return Ok(Config::default());
        }

        let contents = fs::read_to_string(path).map_err(|e| {
            Error::Io(std::io::Error::new(
                e.kind(),
                format!(
                    "Failed to read config file: {}\n\n\
                     File path: {}\n\n\
                     Suggestions:\n\
                     • Check file permissions: ls -la {}\n\
                     • Verify the file is readable\n\
                     • Try recreating with: snippex config init",
                    e,
                    path.display(),
                    path.display()
                ),
            ))
        })?;

        let config: Config = serde_yaml::from_str(&contents).map_err(|e| {
            Error::InvalidBinary(format!(
                "Failed to parse config file: {}\n\n\
                 File path: {}\n\n\
                 Suggestions:\n\
                 • Check YAML syntax in the config file\n\
                 • Verify indentation uses spaces, not tabs\n\
                 • Backup and recreate: mv {} {}.bak && snippex config init\n\n\
                 Example valid config:\n\
                 remotes:\n\
                   my-remote:\n\
                     host: \"server.example.com\"\n\
                     user: \"username\"\n\
                     port: 22\n\
                     snippex_path: \"snippex\"",
                e,
                path.display(),
                path.display(),
                path.display()
            ))
        })?;

        Ok(config)
    }

    /// Saves configuration to the default location.
    pub fn save(&self) -> Result<()> {
        match Self::default_path() {
            Some(path) => self.save_to(&path),
            None => Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Could not determine config directory\n\n\
                 Suggestions:\n\
                 • Check HOME environment variable is set\n\
                 • Verify XDG_CONFIG_HOME is accessible\n\
                 • Try specifying path manually with snippex config init --path <path>",
            ))),
        }
    }

    /// Saves configuration to a specific file path.
    pub fn save_to(&self, path: &PathBuf) -> Result<()> {
        // Create parent directories if they don't exist
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                Error::Io(std::io::Error::new(
                    e.kind(),
                    format!(
                        "Failed to create config directory: {}\n\n\
                         Directory: {}\n\n\
                         Suggestions:\n\
                         • Check write permissions for parent directory\n\
                         • Create directory manually: mkdir -p {}\n\
                         • Verify disk space is available",
                        e,
                        parent.display(),
                        parent.display()
                    ),
                ))
            })?;
        }

        let contents = serde_yaml::to_string(self)
            .map_err(|e| Error::InvalidBinary(format!("Failed to serialize config: {}", e)))?;

        fs::write(path, contents).map_err(|e| {
            Error::Io(std::io::Error::new(
                e.kind(),
                format!(
                    "Failed to write config file: {}\n\n\
                     File path: {}\n\n\
                     Suggestions:\n\
                     • Check write permissions: ls -la {}\n\
                     • Verify parent directory exists\n\
                     • Ensure sufficient disk space",
                    e,
                    path.display(),
                    path.parent().map(|p| p.display().to_string()).unwrap_or_default()
                ),
            ))
        })?;

        Ok(())
    }

    /// Gets a remote configuration by name.
    pub fn get_remote(&self, name: &str) -> Option<&RemoteConfig> {
        self.remotes.get(name)
    }

    /// Adds or updates a remote configuration.
    pub fn set_remote(&mut self, name: String, config: RemoteConfig) {
        self.remotes.insert(name, config);
    }

    /// Removes a remote configuration.
    pub fn remove_remote(&mut self, name: &str) -> Option<RemoteConfig> {
        self.remotes.remove(name)
    }

    /// Returns true if there are no remotes configured.
    pub fn is_local_only(&self) -> bool {
        self.remotes.is_empty()
    }

    /// Lists all configured remote names.
    #[allow(dead_code)]
    pub fn remote_names(&self) -> Vec<&String> {
        self.remotes.keys().collect()
    }

    /// Finds a remote by architecture (x86_64 or aarch64).
    #[allow(dead_code)]
    pub fn find_remote_by_arch(&self, arch: &str) -> Option<(&String, &RemoteConfig)> {
        self.remotes
            .iter()
            .find(|(_, config)| config.architecture.as_deref() == Some(arch))
    }
}

impl RemoteConfig {
    /// Creates a new remote configuration with required fields.
    pub fn new(host: String, user: String) -> Self {
        Self {
            host,
            user,
            port: DEFAULT_SSH_PORT,
            snippex_path: DEFAULT_SNIPPEX_PATH.to_string(),
            ssh_key: None,
            architecture: None,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Builder method to set the SSH port.
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Builder method to set the snippex path.
    pub fn with_snippex_path(mut self, path: String) -> Self {
        self.snippex_path = path;
        self
    }

    /// Builder method to set the SSH key path.
    pub fn with_ssh_key(mut self, key_path: String) -> Self {
        self.ssh_key = Some(key_path);
        self
    }

    /// Builder method to set the architecture.
    pub fn with_architecture(mut self, arch: String) -> Self {
        self.architecture = Some(arch);
        self
    }

    /// Builder method to set the timeout.
    pub fn with_timeout(mut self, timeout: u64) -> Self {
        self.timeout = timeout;
        self
    }

    /// Returns the SSH connection string (user@host:port).
    pub fn connection_string(&self) -> String {
        if self.port == DEFAULT_SSH_PORT {
            format!("{}@{}", self.user, self.host)
        } else {
            format!("{}@{}:{}", self.user, self.host, self.port)
        }
    }

    /// Expands the SSH key path, replacing ~ with the home directory.
    #[allow(dead_code)]
    pub fn expanded_ssh_key(&self) -> Option<PathBuf> {
        self.ssh_key.as_ref().map(|key| {
            if let Some(stripped) = key.strip_prefix("~/") {
                if let Some(home) = dirs::home_dir() {
                    return home.join(stripped);
                }
            }
            PathBuf::from(key)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert!(config.remotes.is_empty());
        assert!(config.is_local_only());
    }

    #[test]
    fn test_remote_config_new() {
        let remote = RemoteConfig::new("example.com".to_string(), "user".to_string());
        assert_eq!(remote.host, "example.com");
        assert_eq!(remote.user, "user");
        assert_eq!(remote.port, 22);
        assert_eq!(remote.snippex_path, "snippex");
        assert!(remote.ssh_key.is_none());
    }

    #[test]
    fn test_remote_config_builder() {
        let remote = RemoteConfig::new("example.com".to_string(), "user".to_string())
            .with_port(2222)
            .with_snippex_path("/usr/local/bin/snippex".to_string())
            .with_ssh_key("~/.ssh/id_ed25519".to_string())
            .with_architecture("x86_64".to_string())
            .with_timeout(120);

        assert_eq!(remote.port, 2222);
        assert_eq!(remote.snippex_path, "/usr/local/bin/snippex");
        assert_eq!(remote.ssh_key, Some("~/.ssh/id_ed25519".to_string()));
        assert_eq!(remote.architecture, Some("x86_64".to_string()));
        assert_eq!(remote.timeout, 120);
    }

    #[test]
    fn test_connection_string() {
        let remote = RemoteConfig::new("example.com".to_string(), "user".to_string());
        assert_eq!(remote.connection_string(), "user@example.com");

        let remote_custom_port = remote.with_port(2222);
        assert_eq!(
            remote_custom_port.connection_string(),
            "user@example.com:2222"
        );
    }

    #[test]
    fn test_config_set_get_remote() {
        let mut config = Config::default();
        let remote = RemoteConfig::new("example.com".to_string(), "user".to_string());

        config.set_remote("test-server".to_string(), remote);

        assert!(!config.is_local_only());
        assert!(config.get_remote("test-server").is_some());
        assert!(config.get_remote("nonexistent").is_none());
    }

    #[test]
    fn test_config_serialization() {
        let mut config = Config::default();
        config.set_remote(
            "x86-oracle".to_string(),
            RemoteConfig::new("intel.example.com".to_string(), "pmatos".to_string())
                .with_architecture("x86_64".to_string()),
        );

        let yaml = serde_yaml::to_string(&config).unwrap();
        assert!(yaml.contains("x86-oracle"));
        assert!(yaml.contains("intel.example.com"));

        let parsed: Config = serde_yaml::from_str(&yaml).unwrap();
        assert!(parsed.get_remote("x86-oracle").is_some());
    }

    #[test]
    fn test_find_remote_by_arch() {
        let mut config = Config::default();
        config.set_remote(
            "intel-server".to_string(),
            RemoteConfig::new("intel.example.com".to_string(), "user".to_string())
                .with_architecture("x86_64".to_string()),
        );
        config.set_remote(
            "arm-server".to_string(),
            RemoteConfig::new("arm.example.com".to_string(), "user".to_string())
                .with_architecture("aarch64".to_string()),
        );

        let x86_remote = config.find_remote_by_arch("x86_64");
        assert!(x86_remote.is_some());
        assert_eq!(x86_remote.unwrap().0, "intel-server");

        let arm_remote = config.find_remote_by_arch("aarch64");
        assert!(arm_remote.is_some());
        assert_eq!(arm_remote.unwrap().0, "arm-server");

        let unknown = config.find_remote_by_arch("unknown");
        assert!(unknown.is_none());
    }
}
