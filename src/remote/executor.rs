//! SSH-based remote command execution.
//!
//! This module provides the `SSHExecutor` for establishing SSH connections
//! and executing commands on remote machines, with support for streaming
//! output and capturing exit codes.

#![allow(dead_code)]

use crate::config::RemoteConfig;
use crate::error::{Error, Result};
use crate::remote::retry::{diagnose_ssh_error, retry_with_backoff, RetryConfig};
use log::{debug, info, warn};
use ssh2::Session;
use std::io::Read;
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

/// Result of executing a remote command.
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// Standard output from the command
    pub stdout: String,
    /// Standard error from the command
    pub stderr: String,
    /// Exit code (0 for success)
    pub exit_code: i32,
}

impl ExecutionResult {
    /// Returns true if the command succeeded (exit code 0).
    pub fn is_success(&self) -> bool {
        self.exit_code == 0
    }
}

/// SSH executor for running commands on remote machines.
pub struct SSHExecutor {
    config: RemoteConfig,
    retry_config: RetryConfig,
}

impl SSHExecutor {
    /// Creates a new SSH executor with the given configuration.
    pub fn new(config: RemoteConfig) -> Self {
        Self {
            config,
            retry_config: RetryConfig::default(),
        }
    }

    /// Creates a new SSH executor with custom retry configuration.
    pub fn with_retry_config(config: RemoteConfig, retry_config: RetryConfig) -> Self {
        Self {
            config,
            retry_config,
        }
    }

    /// Establishes an SSH connection to the remote host with automatic retry.
    ///
    /// # Returns
    ///
    /// A connected `Session` ready for command execution.
    ///
    /// # Errors
    ///
    /// Returns an error with helpful diagnostics if:
    /// - TCP connection fails (after retries)
    /// - SSH handshake fails (after retries)
    /// - Authentication fails (after retries)
    fn connect(&self) -> Result<Session> {
        info!("Connecting to {}:{}", self.config.host, self.config.port);

        let connection_str = format!(
            "SSH connection to {}:{}",
            self.config.host, self.config.port
        );

        // Wrap connection attempt with retry logic
        let result =
            retry_with_backoff(&self.retry_config, || self.connect_once(), &connection_str);

        // If connection failed after all retries, provide helpful diagnostics
        if let Err(ref e) = result {
            let diagnosis = diagnose_ssh_error(
                e,
                &self.config.host,
                self.config.port,
                self.config.ssh_key.as_deref(),
            );
            return Err(Error::InvalidBinary(diagnosis));
        }

        result
    }

    /// Attempts to establish an SSH connection once (without retry).
    fn connect_once(&self) -> Result<Session> {
        use std::net::ToSocketAddrs;

        debug!(
            "Attempting SSH connection to {}:{}",
            self.config.host, self.config.port
        );

        // Resolve hostname to socket address
        let addr_str = format!("{}:{}", self.config.host, self.config.port);
        let addr = addr_str
            .to_socket_addrs()
            .map_err(|e| {
                Error::InvalidBinary(format!(
                    "Failed to resolve host '{}': {}",
                    self.config.host, e
                ))
            })?
            .next()
            .ok_or_else(|| {
                Error::InvalidBinary(format!(
                    "No addresses found for host '{}'",
                    self.config.host
                ))
            })?;

        // Establish TCP connection with timeout
        let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(self.config.timeout))
            .map_err(|e| {
                Error::Io(std::io::Error::new(
                    e.kind(),
                    format!("Failed to connect to {}: {}", self.config.host, e),
                ))
            })?;

        // Set read/write timeouts
        tcp.set_read_timeout(Some(Duration::from_secs(self.config.timeout)))
            .map_err(Error::Io)?;
        tcp.set_write_timeout(Some(Duration::from_secs(self.config.timeout)))
            .map_err(Error::Io)?;

        // Create SSH session
        let mut sess = Session::new()
            .map_err(|e| Error::InvalidBinary(format!("Failed to create SSH session: {}", e)))?;

        sess.set_tcp_stream(tcp);
        sess.handshake()
            .map_err(|e| Error::InvalidBinary(format!("SSH handshake failed: {}", e)))?;

        // Authenticate
        self.authenticate(&mut sess)?;

        debug!("SSH connection attempt successful");
        Ok(sess)
    }

    /// Authenticates the SSH session using configured credentials.
    fn authenticate(&self, sess: &mut Session) -> Result<()> {
        debug!("Authenticating as user: {}", self.config.user);

        // Try public key authentication first if configured
        if let Some(key_path) = &self.config.ssh_key {
            let expanded_path = self.expand_path(key_path);
            debug!(
                "Attempting public key authentication with: {:?}",
                expanded_path
            );

            match sess.userauth_pubkey_file(&self.config.user, None, &expanded_path, None) {
                Ok(_) => {
                    debug!("Public key authentication successful");
                    return Ok(());
                }
                Err(e) => {
                    warn!("Public key authentication failed: {}", e);
                }
            }
        }

        // Try agent authentication as fallback
        debug!("Attempting agent authentication");
        match sess.userauth_agent(&self.config.user) {
            Ok(_) => {
                debug!("Agent authentication successful");
                return Ok(());
            }
            Err(e) => {
                warn!("Agent authentication failed: {}", e);
            }
        }

        // If nothing worked, return error
        Err(Error::InvalidBinary(format!(
            "SSH authentication failed for user {}. Tried: {}, agent",
            self.config.user,
            self.config.ssh_key.as_deref().unwrap_or("no key specified")
        )))
    }

    /// Expands ~ in paths to the home directory.
    fn expand_path(&self, path: &str) -> std::path::PathBuf {
        if let Some(stripped) = path.strip_prefix("~/") {
            if let Some(home) = dirs::home_dir() {
                return home.join(stripped);
            }
        }
        Path::new(path).to_path_buf()
    }

    /// Executes a command on the remote host.
    ///
    /// # Arguments
    ///
    /// * `command` - The command to execute
    ///
    /// # Returns
    ///
    /// An `ExecutionResult` containing stdout, stderr, and exit code.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Connection fails
    /// - Command execution fails
    /// - Output cannot be captured
    pub fn execute(&self, command: &str) -> Result<ExecutionResult> {
        info!("Executing remote command: {}", command);

        let sess = self.connect()?;

        // Create channel and execute command
        let mut channel = sess
            .channel_session()
            .map_err(|e| Error::InvalidBinary(format!("Failed to open channel: {}", e)))?;

        channel
            .exec(command)
            .map_err(|e| Error::InvalidBinary(format!("Failed to execute command: {}", e)))?;

        // Read stdout
        let mut stdout = String::new();
        channel.read_to_string(&mut stdout).map_err(Error::Io)?;

        // Read stderr
        let mut stderr = String::new();
        channel
            .stderr()
            .read_to_string(&mut stderr)
            .map_err(Error::Io)?;

        // Wait for command to complete and get exit status
        channel
            .wait_close()
            .map_err(|e| Error::InvalidBinary(format!("Failed to close channel: {}", e)))?;

        let exit_code = channel
            .exit_status()
            .map_err(|e| Error::InvalidBinary(format!("Failed to get exit status: {}", e)))?;

        debug!("Command exit code: {}", exit_code);
        if !stdout.is_empty() {
            debug!("Command stdout: {}", stdout);
        }
        if !stderr.is_empty() {
            debug!("Command stderr: {}", stderr);
        }

        Ok(ExecutionResult {
            stdout,
            stderr,
            exit_code,
        })
    }

    /// Executes a command with streaming output.
    ///
    /// Output is sent to the provided callback as it arrives, useful for
    /// long-running commands where you want to see progress.
    ///
    /// # Arguments
    ///
    /// * `command` - The command to execute
    /// * `output_callback` - Function called with each line of output
    ///
    /// # Returns
    ///
    /// An `ExecutionResult` containing the complete stdout, stderr, and exit code.
    pub fn execute_streaming<F>(
        &self,
        command: &str,
        mut output_callback: F,
    ) -> Result<ExecutionResult>
    where
        F: FnMut(&str),
    {
        info!("Executing remote command with streaming: {}", command);

        let sess = self.connect()?;

        // Create channel and execute command
        let mut channel = sess
            .channel_session()
            .map_err(|e| Error::InvalidBinary(format!("Failed to open channel: {}", e)))?;

        channel
            .exec(command)
            .map_err(|e| Error::InvalidBinary(format!("Failed to execute command: {}", e)))?;

        // Read stdout line by line
        let mut stdout = String::new();
        let mut buffer = vec![0u8; 4096];

        loop {
            match channel.read(&mut buffer) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    let chunk = String::from_utf8_lossy(&buffer[..n]);
                    stdout.push_str(&chunk);
                    output_callback(&chunk);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Non-blocking read, try again
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => return Err(Error::Io(e)),
            }
        }

        // Read stderr
        let mut stderr = String::new();
        channel
            .stderr()
            .read_to_string(&mut stderr)
            .map_err(Error::Io)?;

        // Wait for command to complete and get exit status
        channel
            .wait_close()
            .map_err(|e| Error::InvalidBinary(format!("Failed to close channel: {}", e)))?;

        let exit_code = channel
            .exit_status()
            .map_err(|e| Error::InvalidBinary(format!("Failed to get exit status: {}", e)))?;

        debug!("Command exit code: {}", exit_code);

        Ok(ExecutionResult {
            stdout,
            stderr,
            exit_code,
        })
    }

    /// Tests the SSH connection without executing a command.
    ///
    /// Returns `Ok(())` if the connection can be established and authenticated.
    pub fn test_connection(&self) -> Result<()> {
        info!(
            "Testing SSH connection to {}",
            self.config.connection_string()
        );
        let sess = self.connect()?;

        // Verify we're authenticated
        if !sess.authenticated() {
            return Err(Error::InvalidBinary(
                "SSH connection established but not authenticated".to_string(),
            ));
        }

        info!("SSH connection test successful");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_result_is_success() {
        let success = ExecutionResult {
            stdout: "ok".to_string(),
            stderr: String::new(),
            exit_code: 0,
        };
        assert!(success.is_success());

        let failure = ExecutionResult {
            stdout: String::new(),
            stderr: "error".to_string(),
            exit_code: 1,
        };
        assert!(!failure.is_success());
    }

    #[test]
    fn test_expand_path() {
        let config = RemoteConfig::new("localhost".to_string(), "test".to_string());
        let executor = SSHExecutor::new(config);

        // Test relative path (unchanged)
        let path = executor.expand_path("path/to/file");
        assert_eq!(path, Path::new("path/to/file"));

        // Test absolute path (unchanged)
        let path = executor.expand_path("/absolute/path");
        assert_eq!(path, Path::new("/absolute/path"));

        // Test ~ expansion (should expand to home dir + rest)
        let path = executor.expand_path("~/.ssh/id_rsa");
        if let Some(home) = dirs::home_dir() {
            assert_eq!(path, home.join(".ssh/id_rsa"));
        }
    }
}
