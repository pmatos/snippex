//! SCP-based transfer of execution packages between machines.
//!
//! This module handles transferring execution packages to remote machines
//! and retrieving results back.

#![allow(dead_code)]

use crate::config::RemoteConfig;
use crate::error::{Error, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;

/// Result of a package transfer operation.
pub struct TransferResult {
    /// Path to the package on the remote machine
    pub remote_path: PathBuf,
    /// Size of the transferred data in bytes
    pub bytes_transferred: u64,
}

/// Handles SCP-based file transfers to/from remote machines.
pub struct SCPTransfer {
    config: RemoteConfig,
}

impl SCPTransfer {
    /// Create a new SCP transfer handler for the given remote.
    pub fn new(config: RemoteConfig) -> Self {
        Self { config }
    }

    /// Upload a local package directory to the remote machine.
    ///
    /// The package is uploaded to `/tmp/snippex-{uuid}/` on the remote.
    pub fn upload_package(&self, local_path: &Path) -> Result<TransferResult> {
        let package_id = Uuid::new_v4();
        let remote_dir = format!("/tmp/snippex-{}", package_id);

        // Create remote directory
        self.run_ssh_command(&format!("mkdir -p {}", remote_dir))?;

        // Get local directory size for progress tracking
        let local_size = Self::get_directory_size(local_path)?;

        // Upload using SCP
        let mut cmd = Command::new("scp");

        cmd.arg("-r"); // Recursive copy

        // Add SSH options
        self.add_ssh_options(&mut cmd);

        // Source: local path
        cmd.arg(local_path);

        // Destination: remote path
        cmd.arg(format!(
            "{}@{}:{}",
            self.config.user, self.config.host, remote_dir
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

        // The package is uploaded as a subdirectory of remote_dir
        let package_name = local_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "package".to_string());

        Ok(TransferResult {
            remote_path: PathBuf::from(format!("{}/{}", remote_dir, package_name)),
            bytes_transferred: local_size,
        })
    }

    /// Upload a tarball to the remote machine.
    ///
    /// The tarball is uploaded to `/tmp/snippex-{uuid}.tar.gz` on the remote.
    pub fn upload_tarball(&self, local_tarball: &Path) -> Result<TransferResult> {
        let package_id = Uuid::new_v4();
        let remote_tarball = format!("/tmp/snippex-{}.tar.gz", package_id);
        let remote_dir = format!("/tmp/snippex-{}", package_id);

        // Get tarball size
        let tarball_size = std::fs::metadata(local_tarball).map_err(Error::Io)?.len();

        // Upload tarball using SCP
        let mut cmd = Command::new("scp");
        self.add_ssh_options(&mut cmd);
        cmd.arg(local_tarball);
        cmd.arg(format!(
            "{}@{}:{}",
            self.config.user, self.config.host, remote_tarball
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

        // Extract tarball on remote
        self.run_ssh_command(&format!(
            "mkdir -p {} && tar -xzf {} -C {} && rm {}",
            remote_dir, remote_tarball, remote_dir, remote_tarball
        ))?;

        Ok(TransferResult {
            remote_path: PathBuf::from(format!("{}/package", remote_dir)),
            bytes_transferred: tarball_size,
        })
    }

    /// Download a file from the remote machine.
    pub fn download_file(&self, remote_path: &Path, local_path: &Path) -> Result<u64> {
        let mut cmd = Command::new("scp");
        self.add_ssh_options(&mut cmd);

        // Source: remote path
        cmd.arg(format!(
            "{}@{}:{}",
            self.config.user,
            self.config.host,
            remote_path.display()
        ));

        // Destination: local path
        cmd.arg(local_path);

        let output = cmd
            .output()
            .map_err(|e| Error::Io(std::io::Error::other(format!("SCP failed: {}", e))))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Io(std::io::Error::other(format!(
                "SCP download failed: {}",
                stderr.trim()
            ))));
        }

        // Return downloaded file size
        let size = std::fs::metadata(local_path).map_err(Error::Io)?.len();
        Ok(size)
    }

    /// Download a directory from the remote machine.
    pub fn download_directory(&self, remote_path: &Path, local_path: &Path) -> Result<u64> {
        let mut cmd = Command::new("scp");

        cmd.arg("-r"); // Recursive copy
        self.add_ssh_options(&mut cmd);

        // Source: remote path
        cmd.arg(format!(
            "{}@{}:{}",
            self.config.user,
            self.config.host,
            remote_path.display()
        ));

        // Destination: local path
        cmd.arg(local_path);

        let output = cmd
            .output()
            .map_err(|e| Error::Io(std::io::Error::other(format!("SCP failed: {}", e))))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Io(std::io::Error::other(format!(
                "SCP download failed: {}",
                stderr.trim()
            ))));
        }

        // Return downloaded directory size
        Self::get_directory_size(local_path)
    }

    /// Clean up a remote directory.
    pub fn cleanup_remote(&self, remote_path: &Path) -> Result<()> {
        self.run_ssh_command(&format!("rm -rf {}", remote_path.display()))?;
        Ok(())
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

    /// Add SSH options to a command (for SCP).
    fn add_ssh_options(&self, cmd: &mut Command) {
        cmd.arg("-o").arg("BatchMode=yes");
        cmd.arg("-o")
            .arg(format!("ConnectTimeout={}", self.config.timeout));

        if let Some(ref key) = self.config.ssh_key {
            let expanded_key = Self::expand_path(key);
            cmd.arg("-i").arg(expanded_key);
        }

        if self.config.port != 22 {
            cmd.arg("-P").arg(self.config.port.to_string()); // Note: SCP uses -P, not -p
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

    /// Get total size of a directory.
    fn get_directory_size(path: &Path) -> Result<u64> {
        let mut total = 0;
        if path.is_file() {
            return Ok(std::fs::metadata(path).map_err(Error::Io)?.len());
        }
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_path() {
        // Test non-tilde path
        assert_eq!(SCPTransfer::expand_path("/usr/bin/test"), "/usr/bin/test");

        // Test tilde path (depends on home dir being set)
        let expanded = SCPTransfer::expand_path("~/.ssh/id_rsa");
        assert!(!expanded.starts_with("~/") || dirs::home_dir().is_none());
    }

    #[test]
    fn test_transfer_result_creation() {
        let result = TransferResult {
            remote_path: PathBuf::from("/tmp/snippex-test/package"),
            bytes_transferred: 1024,
        };
        assert_eq!(
            result.remote_path,
            PathBuf::from("/tmp/snippex-test/package")
        );
        assert_eq!(result.bytes_transferred, 1024);
    }

    #[test]
    fn test_scp_transfer_creation() {
        use crate::config::RemoteConfig;
        let config = RemoteConfig::new("test.example.com".to_string(), "testuser".to_string());
        let transfer = SCPTransfer::new(config);
        assert_eq!(transfer.config.host, "test.example.com");
        assert_eq!(transfer.config.user, "testuser");
    }
}
