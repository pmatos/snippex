//! Delta transfer for efficient file synchronization.
//!
//! This module provides rsync-style delta transfers when available,
//! falling back to compressed transfers using zstd or gzip.

#![allow(dead_code)]

use crate::config::RemoteConfig;
use crate::error::{Error, Result};
use log::{debug, info};
use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;

/// Transfer method used for file synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferMethod {
    /// rsync with delta compression (most efficient for updates)
    Rsync,
    /// SCP with zstd compression
    ScpZstd,
    /// SCP with gzip compression
    ScpGzip,
    /// Plain SCP (no compression)
    ScpPlain,
}

impl std::fmt::Display for TransferMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransferMethod::Rsync => write!(f, "rsync"),
            TransferMethod::ScpZstd => write!(f, "scp+zstd"),
            TransferMethod::ScpGzip => write!(f, "scp+gzip"),
            TransferMethod::ScpPlain => write!(f, "scp"),
        }
    }
}

/// Result of a delta transfer operation.
#[derive(Debug, Clone)]
pub struct DeltaTransferResult {
    /// Path to the file/directory on the remote machine
    pub remote_path: PathBuf,
    /// Bytes transferred over the network
    pub bytes_transferred: u64,
    /// Original size of the data
    pub original_size: u64,
    /// Transfer method used
    pub method: TransferMethod,
    /// Whether this was a delta update (rsync) or full transfer
    pub is_delta: bool,
}

impl DeltaTransferResult {
    /// Calculate compression ratio (1.0 = no compression, lower = better)
    pub fn compression_ratio(&self) -> f64 {
        if self.original_size == 0 {
            1.0
        } else {
            self.bytes_transferred as f64 / self.original_size as f64
        }
    }

    /// Calculate bytes saved by compression/delta
    pub fn bytes_saved(&self) -> u64 {
        self.original_size.saturating_sub(self.bytes_transferred)
    }
}

/// Capabilities available on local and remote systems.
#[derive(Debug, Clone, Default)]
pub struct TransferCapabilities {
    /// rsync available locally
    pub local_rsync: bool,
    /// rsync available on remote
    pub remote_rsync: bool,
    /// zstd available locally
    pub local_zstd: bool,
    /// zstd available on remote
    pub remote_zstd: bool,
    /// gzip available locally (assumed true on most systems)
    pub local_gzip: bool,
    /// gzip available on remote (assumed true on most systems)
    pub remote_gzip: bool,
}

impl TransferCapabilities {
    /// Check if rsync is available on both ends.
    pub fn can_rsync(&self) -> bool {
        self.local_rsync && self.remote_rsync
    }

    /// Check if zstd compression is available on both ends.
    pub fn can_zstd(&self) -> bool {
        self.local_zstd && self.remote_zstd
    }

    /// Check if gzip compression is available on both ends.
    pub fn can_gzip(&self) -> bool {
        self.local_gzip && self.remote_gzip
    }

    /// Get the best available transfer method.
    pub fn best_method(&self) -> TransferMethod {
        if self.can_rsync() {
            TransferMethod::Rsync
        } else if self.can_zstd() {
            TransferMethod::ScpZstd
        } else if self.can_gzip() {
            TransferMethod::ScpGzip
        } else {
            TransferMethod::ScpPlain
        }
    }
}

/// Delta transfer handler for efficient file synchronization.
pub struct DeltaTransfer {
    config: RemoteConfig,
    capabilities: TransferCapabilities,
}

impl DeltaTransfer {
    /// Create a new delta transfer handler.
    ///
    /// This will probe for available capabilities on first use.
    pub fn new(config: RemoteConfig) -> Self {
        Self {
            config,
            capabilities: TransferCapabilities::default(),
        }
    }

    /// Create with pre-detected capabilities (for testing).
    pub fn with_capabilities(config: RemoteConfig, capabilities: TransferCapabilities) -> Self {
        Self {
            config,
            capabilities,
        }
    }

    /// Detect available transfer capabilities.
    pub fn detect_capabilities(&mut self) -> Result<&TransferCapabilities> {
        info!("Detecting transfer capabilities...");

        // Check local capabilities
        self.capabilities.local_rsync = Self::command_exists("rsync");
        self.capabilities.local_zstd = Self::command_exists("zstd");
        self.capabilities.local_gzip = Self::command_exists("gzip");

        debug!(
            "Local capabilities: rsync={}, zstd={}, gzip={}",
            self.capabilities.local_rsync,
            self.capabilities.local_zstd,
            self.capabilities.local_gzip
        );

        // Check remote capabilities
        self.capabilities.remote_rsync = self.remote_command_exists("rsync")?;
        self.capabilities.remote_zstd = self.remote_command_exists("zstd")?;
        self.capabilities.remote_gzip = self.remote_command_exists("gzip")?;

        debug!(
            "Remote capabilities: rsync={}, zstd={}, gzip={}",
            self.capabilities.remote_rsync,
            self.capabilities.remote_zstd,
            self.capabilities.remote_gzip
        );

        info!("Best transfer method: {}", self.capabilities.best_method());

        Ok(&self.capabilities)
    }

    /// Get current capabilities (may need detect_capabilities() first).
    pub fn capabilities(&self) -> &TransferCapabilities {
        &self.capabilities
    }

    /// Upload a file or directory using the best available method.
    pub fn upload(&self, local_path: &Path, remote_dir: &str) -> Result<DeltaTransferResult> {
        let method = self.capabilities.best_method();
        info!("Uploading {} using {} method", local_path.display(), method);

        match method {
            TransferMethod::Rsync => self.upload_rsync(local_path, remote_dir),
            TransferMethod::ScpZstd => self.upload_compressed(local_path, remote_dir, "zstd"),
            TransferMethod::ScpGzip => self.upload_compressed(local_path, remote_dir, "gzip"),
            TransferMethod::ScpPlain => self.upload_plain(local_path, remote_dir),
        }
    }

    /// Upload using rsync for delta transfer.
    fn upload_rsync(&self, local_path: &Path, remote_dir: &str) -> Result<DeltaTransferResult> {
        let original_size = Self::get_path_size(local_path)?;
        let file_name = local_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string());
        let remote_path = format!("{}/{}", remote_dir, file_name);

        // Ensure remote directory exists
        self.run_ssh_command(&format!("mkdir -p {}", shell_escape(remote_dir)))?;

        let mut cmd = Command::new("rsync");

        // rsync options:
        // -a: archive mode (preserves permissions, timestamps, etc.)
        // -z: compress during transfer
        // --partial: keep partially transferred files
        // --progress: show progress (captured in output)
        // --stats: show transfer statistics
        cmd.args(["-az", "--partial", "--stats"]);

        // Add SSH options via -e
        let ssh_cmd = self.build_ssh_command_string();
        cmd.arg("-e").arg(&ssh_cmd);

        // Handle trailing slash for directories
        let source = if local_path.is_dir() {
            format!("{}/", local_path.display())
        } else {
            local_path.display().to_string()
        };

        cmd.arg(&source);
        cmd.arg(format!(
            "{}@{}:{}",
            self.config.user, self.config.host, remote_path
        ));

        debug!("Running rsync command: {:?}", cmd);

        let output = cmd
            .output()
            .map_err(|e| Error::Io(std::io::Error::other(format!("rsync failed: {}", e))))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Io(std::io::Error::other(format!(
                "rsync failed: {}",
                stderr.trim()
            ))));
        }

        // Parse rsync stats to get bytes transferred
        let stdout = String::from_utf8_lossy(&output.stdout);
        let bytes_transferred =
            Self::parse_rsync_bytes_transferred(&stdout).unwrap_or(original_size);

        // Determine if this was a delta transfer (transferred less than original)
        let is_delta = bytes_transferred < original_size;

        Ok(DeltaTransferResult {
            remote_path: PathBuf::from(remote_path),
            bytes_transferred,
            original_size,
            method: TransferMethod::Rsync,
            is_delta,
        })
    }

    /// Upload with compression (zstd or gzip).
    fn upload_compressed(
        &self,
        local_path: &Path,
        remote_dir: &str,
        compressor: &str,
    ) -> Result<DeltaTransferResult> {
        let original_size = Self::get_path_size(local_path)?;
        let package_id = Uuid::new_v4();
        let file_name = local_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string());

        let extension = match compressor {
            "zstd" => "zst",
            "gzip" => "gz",
            _ => "compressed",
        };

        let remote_archive = format!("/tmp/snippex-{}.tar.{}", package_id, extension);
        let remote_path = format!("{}/{}", remote_dir, file_name);

        // Create compressed archive locally
        let temp_dir = tempfile::tempdir().map_err(Error::Io)?;
        let local_archive = temp_dir.path().join(format!("archive.tar.{}", extension));

        // Create tar archive with compression
        let tar_cmd = if local_path.is_dir() {
            format!(
                "tar -cf - -C {} . | {} > {}",
                shell_escape(&local_path.display().to_string()),
                compressor,
                shell_escape(&local_archive.display().to_string())
            )
        } else {
            let parent = local_path.parent().unwrap_or(Path::new("."));
            format!(
                "tar -cf - -C {} {} | {} > {}",
                shell_escape(&parent.display().to_string()),
                shell_escape(&file_name),
                compressor,
                shell_escape(&local_archive.display().to_string())
            )
        };

        let output = Command::new("sh")
            .arg("-c")
            .arg(&tar_cmd)
            .output()
            .map_err(|e| Error::Io(std::io::Error::other(format!("Compression failed: {}", e))))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Io(std::io::Error::other(format!(
                "Compression failed: {}",
                stderr.trim()
            ))));
        }

        let compressed_size = std::fs::metadata(&local_archive).map_err(Error::Io)?.len();

        // Upload compressed archive via SCP
        let mut scp_cmd = Command::new("scp");
        self.add_ssh_options(&mut scp_cmd);
        scp_cmd.arg(&local_archive);
        scp_cmd.arg(format!(
            "{}@{}:{}",
            self.config.user, self.config.host, remote_archive
        ));

        let output = scp_cmd
            .output()
            .map_err(|e| Error::Io(std::io::Error::other(format!("SCP failed: {}", e))))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Io(std::io::Error::other(format!(
                "SCP upload failed: {}",
                stderr.trim()
            ))));
        }

        // Extract on remote
        let decompressor = match compressor {
            "zstd" => "zstd -d",
            "gzip" => "gzip -d",
            _ => compressor,
        };

        let extract_cmd = format!(
            "mkdir -p {} && {} < {} | tar -xf - -C {} && rm {}",
            shell_escape(remote_dir),
            decompressor,
            shell_escape(&remote_archive),
            shell_escape(remote_dir),
            shell_escape(&remote_archive)
        );

        self.run_ssh_command(&extract_cmd)?;

        let method = match compressor {
            "zstd" => TransferMethod::ScpZstd,
            "gzip" => TransferMethod::ScpGzip,
            _ => TransferMethod::ScpPlain,
        };

        Ok(DeltaTransferResult {
            remote_path: PathBuf::from(remote_path),
            bytes_transferred: compressed_size,
            original_size,
            method,
            is_delta: false,
        })
    }

    /// Upload without compression (plain SCP).
    fn upload_plain(&self, local_path: &Path, remote_dir: &str) -> Result<DeltaTransferResult> {
        let original_size = Self::get_path_size(local_path)?;
        let file_name = local_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string());
        let remote_path = format!("{}/{}", remote_dir, file_name);

        // Ensure remote directory exists
        self.run_ssh_command(&format!("mkdir -p {}", shell_escape(remote_dir)))?;

        let mut cmd = Command::new("scp");

        if local_path.is_dir() {
            cmd.arg("-r");
        }

        self.add_ssh_options(&mut cmd);
        cmd.arg(local_path);
        cmd.arg(format!(
            "{}@{}:{}",
            self.config.user, self.config.host, remote_path
        ));

        let output = cmd
            .output()
            .map_err(|e| Error::Io(std::io::Error::other(format!("SCP failed: {}", e))))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Io(std::io::Error::other(format!(
                "SCP upload failed: {}",
                stderr.trim()
            ))));
        }

        Ok(DeltaTransferResult {
            remote_path: PathBuf::from(remote_path),
            bytes_transferred: original_size,
            original_size,
            method: TransferMethod::ScpPlain,
            is_delta: false,
        })
    }

    /// Check if a command exists locally.
    fn command_exists(cmd: &str) -> bool {
        Command::new("which")
            .arg(cmd)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Check if a command exists on the remote.
    fn remote_command_exists(&self, cmd: &str) -> Result<bool> {
        let check_cmd = format!("which {} >/dev/null 2>&1 && echo yes || echo no", cmd);
        let result = self.run_ssh_command(&check_cmd)?;
        Ok(result.trim() == "yes")
    }

    /// Run an SSH command on the remote machine.
    fn run_ssh_command(&self, command: &str) -> Result<String> {
        let mut cmd = Command::new("ssh");

        cmd.arg("-o").arg("BatchMode=yes");
        cmd.arg("-o")
            .arg(format!("ConnectTimeout={}", self.config.timeout));

        if let Some(ref key) = self.config.ssh_key {
            let expanded_key = Self::expand_path(key);
            cmd.arg("-i").arg(expanded_key);
        }

        if self.config.port != 22 {
            cmd.arg("-p").arg(self.config.port.to_string());
        }

        cmd.arg(format!("{}@{}", self.config.user, self.config.host));
        cmd.arg(command);

        let output = cmd
            .output()
            .map_err(|e| Error::Io(std::io::Error::other(format!("SSH failed: {}", e))))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Io(std::io::Error::other(format!(
                "SSH command failed: {}",
                stderr.trim()
            ))));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Build SSH command string for rsync -e option.
    fn build_ssh_command_string(&self) -> String {
        let mut parts = vec!["ssh".to_string()];

        parts.push("-o".to_string());
        parts.push("BatchMode=yes".to_string());

        parts.push("-o".to_string());
        parts.push(format!("ConnectTimeout={}", self.config.timeout));

        if let Some(ref key) = self.config.ssh_key {
            let expanded_key = Self::expand_path(key);
            parts.push("-i".to_string());
            parts.push(expanded_key);
        }

        if self.config.port != 22 {
            parts.push("-p".to_string());
            parts.push(self.config.port.to_string());
        }

        parts.join(" ")
    }

    /// Add SSH options to an SCP command.
    fn add_ssh_options(&self, cmd: &mut Command) {
        cmd.arg("-o").arg("BatchMode=yes");
        cmd.arg("-o")
            .arg(format!("ConnectTimeout={}", self.config.timeout));

        if let Some(ref key) = self.config.ssh_key {
            let expanded_key = Self::expand_path(key);
            cmd.arg("-i").arg(expanded_key);
        }

        if self.config.port != 22 {
            cmd.arg("-P").arg(self.config.port.to_string());
        }
    }

    /// Expand ~ in paths to home directory.
    fn expand_path(path: &str) -> String {
        if let Some(stripped) = path.strip_prefix("~/") {
            if let Some(home) = dirs::home_dir() {
                return home.join(stripped).to_string_lossy().to_string();
            }
        }
        path.to_string()
    }

    /// Get size of a path (file or directory).
    fn get_path_size(path: &Path) -> Result<u64> {
        if path.is_file() {
            Ok(std::fs::metadata(path).map_err(Error::Io)?.len())
        } else {
            Self::get_directory_size(path)
        }
    }

    /// Get total size of a directory.
    fn get_directory_size(path: &Path) -> Result<u64> {
        let mut total = 0;
        for entry in std::fs::read_dir(path).map_err(Error::Io)? {
            let entry = entry.map_err(Error::Io)?;
            let metadata = entry.metadata().map_err(Error::Io)?;
            if metadata.is_file() {
                total += metadata.len();
            } else if metadata.is_dir() {
                total += Self::get_directory_size(&entry.path())?;
            }
        }
        Ok(total)
    }

    /// Parse bytes transferred from rsync --stats output.
    fn parse_rsync_bytes_transferred(output: &str) -> Option<u64> {
        // Look for "Total transferred file size:" or "sent X bytes"
        for line in output.lines() {
            if line.contains("sent") && line.contains("bytes") {
                // Format: "sent 1,234 bytes  received 56 bytes  ..."
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(idx) = parts.iter().position(|&s| s == "sent") {
                    if let Some(bytes_str) = parts.get(idx + 1) {
                        let cleaned: String =
                            bytes_str.chars().filter(|c| c.is_ascii_digit()).collect();
                        if let Ok(bytes) = cleaned.parse() {
                            return Some(bytes);
                        }
                    }
                }
            }
        }
        None
    }
}

/// Escape a string for safe use in shell commands.
fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_method_display() {
        assert_eq!(format!("{}", TransferMethod::Rsync), "rsync");
        assert_eq!(format!("{}", TransferMethod::ScpZstd), "scp+zstd");
        assert_eq!(format!("{}", TransferMethod::ScpGzip), "scp+gzip");
        assert_eq!(format!("{}", TransferMethod::ScpPlain), "scp");
    }

    #[test]
    fn test_capabilities_best_method() {
        let mut caps = TransferCapabilities::default();
        assert_eq!(caps.best_method(), TransferMethod::ScpPlain);

        caps.local_gzip = true;
        caps.remote_gzip = true;
        assert_eq!(caps.best_method(), TransferMethod::ScpGzip);

        caps.local_zstd = true;
        caps.remote_zstd = true;
        assert_eq!(caps.best_method(), TransferMethod::ScpZstd);

        caps.local_rsync = true;
        caps.remote_rsync = true;
        assert_eq!(caps.best_method(), TransferMethod::Rsync);
    }

    #[test]
    fn test_capabilities_can_methods() {
        let caps = TransferCapabilities {
            local_rsync: true,
            remote_rsync: false,
            local_zstd: true,
            remote_zstd: true,
            local_gzip: true,
            remote_gzip: true,
        };

        assert!(!caps.can_rsync());
        assert!(caps.can_zstd());
        assert!(caps.can_gzip());
    }

    #[test]
    fn test_delta_transfer_result_compression_ratio() {
        let result = DeltaTransferResult {
            remote_path: PathBuf::from("/tmp/test"),
            bytes_transferred: 500,
            original_size: 1000,
            method: TransferMethod::ScpZstd,
            is_delta: false,
        };

        assert!((result.compression_ratio() - 0.5).abs() < 0.001);
        assert_eq!(result.bytes_saved(), 500);
    }

    #[test]
    fn test_delta_transfer_result_no_compression() {
        let result = DeltaTransferResult {
            remote_path: PathBuf::from("/tmp/test"),
            bytes_transferred: 1000,
            original_size: 1000,
            method: TransferMethod::ScpPlain,
            is_delta: false,
        };

        assert!((result.compression_ratio() - 1.0).abs() < 0.001);
        assert_eq!(result.bytes_saved(), 0);
    }

    #[test]
    fn test_delta_transfer_result_zero_size() {
        let result = DeltaTransferResult {
            remote_path: PathBuf::from("/tmp/test"),
            bytes_transferred: 0,
            original_size: 0,
            method: TransferMethod::ScpPlain,
            is_delta: false,
        };

        assert!((result.compression_ratio() - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_parse_rsync_bytes_transferred() {
        let output = "sent 1,234 bytes  received 56 bytes  2.58K bytes/sec";
        assert_eq!(
            DeltaTransfer::parse_rsync_bytes_transferred(output),
            Some(1234)
        );

        let output2 = "sent 500 bytes  received 10 bytes";
        assert_eq!(
            DeltaTransfer::parse_rsync_bytes_transferred(output2),
            Some(500)
        );

        let output3 = "no matching pattern";
        assert_eq!(DeltaTransfer::parse_rsync_bytes_transferred(output3), None);
    }

    #[test]
    fn test_shell_escape() {
        assert_eq!(shell_escape("simple"), "'simple'");
        assert_eq!(shell_escape("/path/to/file"), "'/path/to/file'");
        assert_eq!(shell_escape("it's a test"), "'it'\\''s a test'");
    }

    #[test]
    fn test_command_exists() {
        // 'sh' should exist on all Unix systems
        assert!(DeltaTransfer::command_exists("sh"));
        // This command should not exist
        assert!(!DeltaTransfer::command_exists("nonexistent_command_12345"));
    }

    #[test]
    fn test_delta_transfer_result_is_delta() {
        let delta_result = DeltaTransferResult {
            remote_path: PathBuf::from("/tmp/test"),
            bytes_transferred: 100,
            original_size: 1000,
            method: TransferMethod::Rsync,
            is_delta: true,
        };

        assert!(delta_result.is_delta);
        assert_eq!(delta_result.bytes_saved(), 900);

        let full_result = DeltaTransferResult {
            remote_path: PathBuf::from("/tmp/test"),
            bytes_transferred: 800,
            original_size: 1000,
            method: TransferMethod::ScpZstd,
            is_delta: false,
        };

        assert!(!full_result.is_delta);
        assert_eq!(full_result.bytes_saved(), 200);
    }

    #[test]
    fn test_transfer_method_priority() {
        // Rsync should be preferred over compressed SCP
        let caps_rsync = TransferCapabilities {
            local_rsync: true,
            remote_rsync: true,
            local_zstd: true,
            remote_zstd: true,
            local_gzip: true,
            remote_gzip: true,
        };
        assert_eq!(caps_rsync.best_method(), TransferMethod::Rsync);

        // zstd should be preferred over gzip
        let caps_zstd = TransferCapabilities {
            local_rsync: false,
            remote_rsync: false,
            local_zstd: true,
            remote_zstd: true,
            local_gzip: true,
            remote_gzip: true,
        };
        assert_eq!(caps_zstd.best_method(), TransferMethod::ScpZstd);

        // gzip should be preferred over plain
        let caps_gzip = TransferCapabilities {
            local_rsync: false,
            remote_rsync: false,
            local_zstd: false,
            remote_zstd: false,
            local_gzip: true,
            remote_gzip: true,
        };
        assert_eq!(caps_gzip.best_method(), TransferMethod::ScpGzip);
    }

    #[test]
    fn test_capabilities_asymmetric() {
        // One side missing a capability should disable that method
        let caps = TransferCapabilities {
            local_rsync: true,
            remote_rsync: false, // Remote doesn't have rsync
            local_zstd: true,
            remote_zstd: true,
            local_gzip: true,
            remote_gzip: true,
        };

        assert!(!caps.can_rsync());
        assert!(caps.can_zstd());
        assert_eq!(caps.best_method(), TransferMethod::ScpZstd);
    }

    #[test]
    fn test_transfer_result_savings_calculation() {
        // Test various scenarios of transfer savings

        // High compression scenario
        let high_compression = DeltaTransferResult {
            remote_path: PathBuf::from("/tmp/test"),
            bytes_transferred: 100,
            original_size: 1000,
            method: TransferMethod::ScpZstd,
            is_delta: false,
        };
        assert_eq!(high_compression.bytes_saved(), 900);
        assert!((high_compression.compression_ratio() - 0.1).abs() < 0.001);

        // No savings scenario
        let no_savings = DeltaTransferResult {
            remote_path: PathBuf::from("/tmp/test"),
            bytes_transferred: 1000,
            original_size: 1000,
            method: TransferMethod::ScpPlain,
            is_delta: false,
        };
        assert_eq!(no_savings.bytes_saved(), 0);
        assert!((no_savings.compression_ratio() - 1.0).abs() < 0.001);

        // Delta transfer with minimal data
        let delta_minimal = DeltaTransferResult {
            remote_path: PathBuf::from("/tmp/test"),
            bytes_transferred: 10,
            original_size: 10000,
            method: TransferMethod::Rsync,
            is_delta: true,
        };
        assert_eq!(delta_minimal.bytes_saved(), 9990);
        assert!((delta_minimal.compression_ratio() - 0.001).abs() < 0.0001);
    }
}
