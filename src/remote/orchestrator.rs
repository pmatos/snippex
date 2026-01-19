//! High-level orchestration of remote execution workflows.
//!
//! This module provides the glue between packaging, transfer, execution,
//! and result retrieval for remote simulations.

#![allow(dead_code)]

use crate::config::RemoteConfig;
use crate::error::{Error, Result};
use crate::remote::cleanup::CleanupRegistry;
use crate::remote::diagnostics::diagnose_remote_execution_failure;
use crate::remote::executor::SSHExecutor;
use crate::remote::package::ExecutionPackage;
use crate::remote::pool::SSHConnectionPool;
use crate::remote::transfer::SCPTransfer;
use crate::simulator::SimulationResult;
use log::{debug, info};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tempfile::TempDir;

/// Orchestrates remote execution of simulation packages.
pub struct RemoteOrchestrator {
    config: RemoteConfig,
    ssh_executor: SSHExecutor,
    scp_transfer: SCPTransfer,
    cleanup_registry: Option<CleanupRegistry>,
    connection_pool: Option<Arc<SSHConnectionPool>>,
}

impl RemoteOrchestrator {
    /// Creates a new remote orchestrator with the given configuration.
    pub fn new(config: RemoteConfig) -> Self {
        let ssh_executor = SSHExecutor::new(config.clone());
        let scp_transfer = SCPTransfer::new(config.clone());

        Self {
            config,
            ssh_executor,
            scp_transfer,
            cleanup_registry: None,
            connection_pool: None,
        }
    }

    /// Creates a new remote orchestrator with cleanup registry for interrupt handling.
    pub fn with_cleanup_registry(config: RemoteConfig, registry: CleanupRegistry) -> Self {
        let ssh_executor = SSHExecutor::new(config.clone());
        let scp_transfer = SCPTransfer::new(config.clone());

        Self {
            config,
            ssh_executor,
            scp_transfer,
            cleanup_registry: Some(registry),
            connection_pool: None,
        }
    }

    /// Creates a new remote orchestrator with a shared connection pool.
    ///
    /// Using a connection pool allows reusing SSH connections across multiple
    /// executions, which significantly reduces overhead in batch operations.
    pub fn with_connection_pool(
        config: RemoteConfig,
        pool: Arc<SSHConnectionPool>,
        cleanup_registry: Option<CleanupRegistry>,
    ) -> Self {
        let ssh_executor = SSHExecutor::new(config.clone());
        let scp_transfer = SCPTransfer::new(config.clone());

        Self {
            config,
            ssh_executor,
            scp_transfer,
            cleanup_registry,
            connection_pool: Some(pool),
        }
    }

    /// Executes a simulation package on the remote machine and retrieves results.
    ///
    /// This is the main entry point that handles the complete workflow:
    /// 1. Upload package to remote
    /// 2. Execute simulation remotely
    /// 3. Download results
    /// 4. Clean up remote files
    ///
    /// # Arguments
    ///
    /// * `package` - The execution package to run remotely
    ///
    /// # Returns
    ///
    /// The `SimulationResult` from the remote execution
    pub fn execute_remote_simulation(
        &self,
        package: &ExecutionPackage,
    ) -> Result<SimulationResult> {
        info!("Starting remote simulation execution");

        // Create temporary directory for package
        let temp_dir = TempDir::new().map_err(Error::Io)?;
        let package_dir = temp_dir.path().join("package");

        // Save package to temporary directory (include binary for remote execution)
        debug!("Saving package to temporary directory");
        package.save_to_directory(&package_dir, true)?;

        // Create tarball from package directory
        let tarball_path = temp_dir.path().join("package.tar.gz");
        Self::create_tarball(&package_dir, &tarball_path)?;

        // Upload tarball to remote
        info!("Uploading package to remote machine");
        let transfer_result = self.scp_transfer.upload_tarball(&tarball_path)?;
        let remote_package_dir = transfer_result.remote_path;

        debug!(
            "Package uploaded to remote: {}",
            remote_package_dir.display()
        );

        // Register path for cleanup in case of interruption
        if let Some(ref registry) = self.cleanup_registry {
            // Get parent directory (the /tmp/snippex-{uuid} directory)
            if let Some(parent) = remote_package_dir.parent() {
                registry.register(self.config.clone(), parent.to_path_buf());
            }
        }

        // Execute simulation on remote
        let result = match self.execute_simulation_on_remote(&remote_package_dir) {
            Ok(result) => {
                info!("Remote simulation completed successfully");
                result
            }
            Err(e) => {
                // Clean up remote directory even if execution failed
                if let Err(cleanup_err) = self.cleanup_remote(&remote_package_dir) {
                    debug!("Failed to cleanup remote directory: {}", cleanup_err);
                }

                // Unregister from cleanup registry
                if let Some(ref registry) = self.cleanup_registry {
                    if let Some(parent) = remote_package_dir.parent() {
                        registry.unregister(&parent.to_path_buf());
                    }
                }

                return Err(e);
            }
        };

        // Clean up remote directory
        info!("Cleaning up remote files");
        self.cleanup_remote(&remote_package_dir)?;

        // Unregister from cleanup registry after successful cleanup
        if let Some(ref registry) = self.cleanup_registry {
            if let Some(parent) = remote_package_dir.parent() {
                registry.unregister(&parent.to_path_buf());
            }
        }

        Ok(result)
    }

    /// Executes the simulation on the remote machine using the snippex binary.
    fn execute_simulation_on_remote(&self, remote_package_dir: &Path) -> Result<SimulationResult> {
        // Construct remote command
        let remote_command = format!(
            "{} simulate-remote --package {}",
            self.config.snippex_path,
            remote_package_dir.display()
        );

        debug!("Executing remote command: {}", remote_command);

        // Execute command using connection pool if available, otherwise use SSH executor
        let exec_result = if let Some(ref pool) = self.connection_pool {
            debug!("Using connection pool for execution");
            let guard = pool.acquire(&self.config)?;
            guard.execute(&remote_command)?
        } else {
            debug!("Using direct SSH connection for execution");
            self.ssh_executor.execute(&remote_command)?
        };

        if !exec_result.is_success() {
            let diagnosis = diagnose_remote_execution_failure(
                exec_result.exit_code,
                &exec_result.stderr,
                &exec_result.stdout,
                &remote_command,
                &self.config.host,
            );
            return Err(Error::InvalidBinary(diagnosis));
        }

        // Download results.json from remote
        info!("Downloading simulation results");
        let results_path = remote_package_dir.join("results.json");
        let local_temp_dir = TempDir::new().map_err(Error::Io)?;
        let local_results_path = local_temp_dir.path().join("results.json");

        self.scp_transfer
            .download_file(&results_path, &local_results_path)?;

        // Parse results JSON
        debug!("Parsing simulation results");
        let results_json = fs::read_to_string(&local_results_path).map_err(Error::Io)?;
        // Drop local_temp_dir after reading
        drop(local_temp_dir);

        let simulation_result: SimulationResult = serde_json::from_str(&results_json)
            .map_err(|e| Error::InvalidBinary(format!("Failed to parse results JSON: {}", e)))?;

        Ok(simulation_result)
    }

    /// Cleans up remote temporary directory.
    fn cleanup_remote(&self, remote_path: &Path) -> Result<()> {
        debug!("Cleaning up remote directory: {}", remote_path.display());

        // Get parent directory (the /tmp/snippex-{uuid} directory)
        let parent = remote_path
            .parent()
            .ok_or_else(|| Error::InvalidBinary("Invalid remote path".to_string()))?;

        self.scp_transfer.cleanup_remote(parent)?;
        Ok(())
    }

    /// Creates a tarball from a directory.
    fn create_tarball(source_dir: &Path, tarball_path: &Path) -> Result<()> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use tar::Builder;

        debug!(
            "Creating tarball: {} -> {}",
            source_dir.display(),
            tarball_path.display()
        );

        let tar_gz = fs::File::create(tarball_path).map_err(Error::Io)?;
        let enc = GzEncoder::new(tar_gz, Compression::default());
        let mut tar = Builder::new(enc);

        // Add the directory contents to the archive
        tar.append_dir_all("package", source_dir).map_err(|e| {
            Error::Io(std::io::Error::other(format!(
                "Failed to create tarball: {}",
                e
            )))
        })?;

        tar.finish().map_err(|e| {
            Error::Io(std::io::Error::other(format!(
                "Failed to finalize tarball: {}",
                e
            )))
        })?;

        Ok(())
    }

    /// Tests the connection to the remote machine.
    pub fn test_connection(&self) -> Result<()> {
        info!("Testing connection to {}", self.config.connection_string());
        self.ssh_executor.test_connection()
    }

    /// Returns true if connection pooling is enabled.
    pub fn has_connection_pool(&self) -> bool {
        self.connection_pool.is_some()
    }

    /// Gets connection pool statistics if pooling is enabled.
    pub fn pool_stats(&self) -> Option<Result<crate::remote::pool::PoolStats>> {
        self.connection_pool.as_ref().map(|pool| pool.stats())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orchestrator_creation() {
        let config = RemoteConfig::new("localhost".to_string(), "test".to_string());
        let orchestrator = RemoteOrchestrator::new(config);
        assert_eq!(orchestrator.config.host, "localhost");
        assert_eq!(orchestrator.config.user, "test");
    }

    #[test]
    fn test_create_tarball() {
        use std::fs;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let source_dir = temp_dir.path().join("source");
        fs::create_dir(&source_dir).unwrap();
        fs::write(source_dir.join("test.txt"), b"hello").unwrap();

        let tarball_path = temp_dir.path().join("test.tar.gz");
        let result = RemoteOrchestrator::create_tarball(&source_dir, &tarball_path);

        assert!(result.is_ok());
        assert!(tarball_path.exists());
        assert!(tarball_path.metadata().unwrap().len() > 0);
    }
}
