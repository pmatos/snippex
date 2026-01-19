//! SSH Connection Pool for efficient connection reuse.
//!
//! This module provides connection pooling for SSH sessions to avoid
//! the overhead of establishing new connections for each remote operation.

use crate::config::RemoteConfig;
use crate::error::{Error, Result};
use crate::remote::retry::RetryConfig;
use log::{debug, info, warn};
use ssh2::Session;
use std::collections::HashMap;
use std::net::TcpStream;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Configuration for the connection pool.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum number of connections per host.
    pub max_connections_per_host: usize,
    /// How long an idle connection can remain in the pool before cleanup.
    #[allow(dead_code)]
    pub idle_timeout: Duration,
    /// How often to check connection health before reuse.
    pub health_check_interval: Duration,
    /// Connection timeout for new connections.
    pub connection_timeout: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections_per_host: 4,
            idle_timeout: Duration::from_secs(300), // 5 minutes
            health_check_interval: Duration::from_secs(30), // 30 seconds
            connection_timeout: Duration::from_secs(30),
        }
    }
}

/// A pooled SSH connection with metadata for lifecycle management.
struct PooledConnection {
    session: Session,
    #[allow(dead_code)]
    created_at: Instant,
    last_used: Instant,
    last_health_check: Instant,
    in_use: bool,
}

impl PooledConnection {
    fn new(session: Session) -> Self {
        let now = Instant::now();
        Self {
            session,
            created_at: now,
            last_used: now,
            last_health_check: now,
            in_use: false,
        }
    }

    #[allow(dead_code)]
    fn is_idle(&self, timeout: Duration) -> bool {
        !self.in_use && self.last_used.elapsed() > timeout
    }

    fn needs_health_check(&self, interval: Duration) -> bool {
        self.last_health_check.elapsed() > interval
    }
}

/// Thread-safe SSH connection pool.
pub struct SSHConnectionPool {
    connections: Arc<Mutex<HashMap<String, Vec<PooledConnection>>>>,
    config: PoolConfig,
    #[allow(dead_code)]
    retry_config: RetryConfig,
}

impl SSHConnectionPool {
    /// Creates a new connection pool with default configuration.
    pub fn new() -> Self {
        Self::with_config(PoolConfig::default())
    }

    /// Creates a new connection pool with custom configuration.
    pub fn with_config(config: PoolConfig) -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            config,
            retry_config: RetryConfig::default(),
        }
    }

    /// Sets the retry configuration for connection attempts.
    #[allow(dead_code)]
    pub fn with_retry_config(mut self, retry_config: RetryConfig) -> Self {
        self.retry_config = retry_config;
        self
    }

    /// Gets the pool key for a remote configuration.
    fn pool_key(remote_config: &RemoteConfig) -> String {
        format!(
            "{}@{}:{}",
            remote_config.user, remote_config.host, remote_config.port
        )
    }

    /// Acquires a connection from the pool or creates a new one.
    ///
    /// Returns a connection that's ready for use. The caller must call
    /// `release()` when done to return the connection to the pool.
    pub fn acquire(&self, remote_config: &RemoteConfig) -> Result<PooledSessionGuard> {
        let key = Self::pool_key(remote_config);

        // First, try to get an existing connection from the pool
        {
            let mut connections = self
                .connections
                .lock()
                .map_err(|e| Error::InvalidBinary(format!("Failed to acquire pool lock: {}", e)))?;

            if let Some(pool) = connections.get_mut(&key) {
                // Find an available connection that passes health check using indices
                // We use index-based iteration because we need mutable access to modify
                // individual connections while also continuing the loop on health check failures
                #[allow(clippy::needless_range_loop)]
                for idx in 0..pool.len() {
                    if !pool[idx].in_use {
                        // Check if connection needs health check
                        if pool[idx].needs_health_check(self.config.health_check_interval) {
                            if self.check_connection_health(&pool[idx].session) {
                                pool[idx].last_health_check = Instant::now();
                            } else {
                                debug!("Connection failed health check, will create new one");
                                continue;
                            }
                        }

                        // Mark as in use and return
                        pool[idx].in_use = true;
                        pool[idx].last_used = Instant::now();
                        debug!("Reusing existing connection from pool for {}", key);

                        return Ok(PooledSessionGuard {
                            pool: Arc::clone(&self.connections),
                            key: key.clone(),
                            index: idx,
                        });
                    }
                }
            }
        }

        // No available connection, create a new one
        info!("Creating new SSH connection for {}", key);
        let session = self.create_connection(remote_config)?;

        // Add to pool
        let mut connections = self
            .connections
            .lock()
            .map_err(|e| Error::InvalidBinary(format!("Failed to acquire pool lock: {}", e)))?;

        let pool = connections.entry(key.clone()).or_insert_with(Vec::new);

        // Check if we're at max capacity
        if pool.len() >= self.config.max_connections_per_host {
            // Remove the oldest idle connection
            if let Some(idx) = pool.iter().position(|c| !c.in_use) {
                debug!("Pool full, removing oldest idle connection");
                pool.remove(idx);
            }
        }

        let mut pooled = PooledConnection::new(session);
        pooled.in_use = true;
        let index = pool.len();
        pool.push(pooled);

        Ok(PooledSessionGuard {
            pool: Arc::clone(&self.connections),
            key,
            index,
        })
    }

    /// Creates a new SSH connection.
    fn create_connection(&self, remote_config: &RemoteConfig) -> Result<Session> {
        use std::net::ToSocketAddrs;

        debug!(
            "Establishing SSH connection to {}:{}",
            remote_config.host, remote_config.port
        );

        // Resolve hostname to socket address
        let addr_str = format!("{}:{}", remote_config.host, remote_config.port);
        let addr = addr_str
            .to_socket_addrs()
            .map_err(|e| {
                Error::InvalidBinary(format!(
                    "Failed to resolve host '{}': {}",
                    remote_config.host, e
                ))
            })?
            .next()
            .ok_or_else(|| {
                Error::InvalidBinary(format!(
                    "No addresses found for host '{}'",
                    remote_config.host
                ))
            })?;

        // Establish TCP connection with timeout
        let tcp =
            TcpStream::connect_timeout(&addr, self.config.connection_timeout).map_err(|e| {
                Error::Io(std::io::Error::new(
                    e.kind(),
                    format!("Failed to connect to {}: {}", remote_config.host, e),
                ))
            })?;

        // Set read/write timeouts
        tcp.set_read_timeout(Some(self.config.connection_timeout))
            .map_err(Error::Io)?;
        tcp.set_write_timeout(Some(self.config.connection_timeout))
            .map_err(Error::Io)?;

        // Create SSH session
        let mut session = Session::new()
            .map_err(|e| Error::InvalidBinary(format!("Failed to create SSH session: {}", e)))?;

        session.set_tcp_stream(tcp);
        session
            .handshake()
            .map_err(|e| Error::InvalidBinary(format!("SSH handshake failed: {}", e)))?;

        // Authenticate
        self.authenticate(&mut session, remote_config)?;

        debug!("SSH connection established successfully");
        Ok(session)
    }

    /// Authenticates the SSH session.
    fn authenticate(&self, session: &mut Session, remote_config: &RemoteConfig) -> Result<()> {
        debug!("Authenticating as user: {}", remote_config.user);

        // Try public key authentication first if configured
        if let Some(key_path) = &remote_config.ssh_key {
            let expanded_path = Self::expand_path(key_path);
            debug!(
                "Attempting public key authentication with: {:?}",
                expanded_path
            );

            match session.userauth_pubkey_file(&remote_config.user, None, &expanded_path, None) {
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
        match session.userauth_agent(&remote_config.user) {
            Ok(_) => {
                debug!("Agent authentication successful");
                return Ok(());
            }
            Err(e) => {
                warn!("Agent authentication failed: {}", e);
            }
        }

        Err(Error::InvalidBinary(format!(
            "SSH authentication failed for user {}. Tried: {}, agent",
            remote_config.user,
            remote_config
                .ssh_key
                .as_deref()
                .unwrap_or("no key specified")
        )))
    }

    /// Expands ~ in paths to the home directory.
    fn expand_path(path: &str) -> std::path::PathBuf {
        if let Some(stripped) = path.strip_prefix("~/") {
            if let Some(home) = dirs::home_dir() {
                return home.join(stripped);
            }
        }
        Path::new(path).to_path_buf()
    }

    /// Checks if a connection is still healthy.
    fn check_connection_health(&self, session: &Session) -> bool {
        // Verify the session is still authenticated
        if !session.authenticated() {
            debug!("Connection health check failed: not authenticated");
            return false;
        }

        // Try to open a channel as a lightweight health check
        match session.channel_session() {
            Ok(mut channel) => {
                // Send a simple echo command
                match channel.exec("echo ping") {
                    Ok(_) => {
                        let _ = channel.wait_close();
                        debug!("Connection health check passed");
                        true
                    }
                    Err(e) => {
                        debug!("Connection health check failed: {}", e);
                        false
                    }
                }
            }
            Err(e) => {
                debug!("Connection health check failed to open channel: {}", e);
                false
            }
        }
    }

    /// Closes all idle connections that have exceeded the timeout.
    #[allow(dead_code)]
    pub fn cleanup_idle(&self) -> Result<usize> {
        let mut connections = self
            .connections
            .lock()
            .map_err(|e| Error::InvalidBinary(format!("Failed to acquire pool lock: {}", e)))?;

        let mut total_removed = 0;

        for (key, pool) in connections.iter_mut() {
            let before = pool.len();
            pool.retain(|conn| !conn.is_idle(self.config.idle_timeout));
            let removed = before - pool.len();
            if removed > 0 {
                debug!("Removed {} idle connections for {}", removed, key);
            }
            total_removed += removed;
        }

        // Remove empty pools
        connections.retain(|_, pool| !pool.is_empty());

        Ok(total_removed)
    }

    /// Closes all connections in the pool.
    #[allow(dead_code)]
    pub fn close_all(&self) -> Result<()> {
        let mut connections = self
            .connections
            .lock()
            .map_err(|e| Error::InvalidBinary(format!("Failed to acquire pool lock: {}", e)))?;

        let total = connections.values().map(|v| v.len()).sum::<usize>();
        connections.clear();
        info!("Closed {} pooled SSH connections", total);
        Ok(())
    }

    /// Returns statistics about the connection pool.
    pub fn stats(&self) -> Result<PoolStats> {
        let connections = self
            .connections
            .lock()
            .map_err(|e| Error::InvalidBinary(format!("Failed to acquire pool lock: {}", e)))?;

        let mut total_connections = 0;
        let mut active_connections = 0;
        let mut idle_connections = 0;
        let hosts = connections.len();

        for pool in connections.values() {
            for conn in pool {
                total_connections += 1;
                if conn.in_use {
                    active_connections += 1;
                } else {
                    idle_connections += 1;
                }
            }
        }

        Ok(PoolStats {
            hosts,
            total_connections,
            active_connections,
            idle_connections,
        })
    }
}

impl Default for SSHConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about the connection pool.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PoolStats {
    /// Number of unique hosts in the pool.
    pub hosts: usize,
    /// Total number of connections.
    pub total_connections: usize,
    /// Number of currently active (in-use) connections.
    pub active_connections: usize,
    /// Number of idle connections.
    pub idle_connections: usize,
}

/// Guard that automatically returns a connection to the pool when dropped.
pub struct PooledSessionGuard {
    pool: Arc<Mutex<HashMap<String, Vec<PooledConnection>>>>,
    key: String,
    index: usize,
}

impl PooledSessionGuard {
    /// Executes a command using the pooled connection.
    pub fn execute(&self, command: &str) -> Result<crate::remote::executor::ExecutionResult> {
        let connections = self
            .pool
            .lock()
            .map_err(|e| Error::InvalidBinary(format!("Failed to acquire pool lock: {}", e)))?;

        let pool = connections
            .get(&self.key)
            .ok_or_else(|| Error::InvalidBinary("Connection no longer in pool".to_string()))?;

        let conn = pool
            .get(self.index)
            .ok_or_else(|| Error::InvalidBinary("Connection index out of bounds".to_string()))?;

        use std::io::Read;

        // Create channel and execute command
        let mut channel = conn
            .session
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

        Ok(crate::remote::executor::ExecutionResult {
            stdout,
            stderr,
            exit_code,
        })
    }
}

impl Drop for PooledSessionGuard {
    fn drop(&mut self) {
        // Mark the connection as no longer in use
        if let Ok(mut connections) = self.pool.lock() {
            if let Some(pool) = connections.get_mut(&self.key) {
                if let Some(conn) = pool.get_mut(self.index) {
                    conn.in_use = false;
                    conn.last_used = Instant::now();
                    debug!("Released connection back to pool for {}", self.key);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_config_default() {
        let config = PoolConfig::default();
        assert_eq!(config.max_connections_per_host, 4);
        assert_eq!(config.idle_timeout, Duration::from_secs(300));
    }

    #[test]
    fn test_pool_key() {
        let config = RemoteConfig::new("example.com".to_string(), "testuser".to_string());
        let key = SSHConnectionPool::pool_key(&config);
        assert_eq!(key, "testuser@example.com:22");
    }

    #[test]
    fn test_pool_stats_empty() {
        let pool = SSHConnectionPool::new();
        let stats = pool.stats().unwrap();
        assert_eq!(stats.hosts, 0);
        assert_eq!(stats.total_connections, 0);
    }

    #[test]
    fn test_expand_path() {
        // Test relative path (unchanged)
        let path = SSHConnectionPool::expand_path("path/to/file");
        assert_eq!(path, Path::new("path/to/file"));

        // Test absolute path (unchanged)
        let path = SSHConnectionPool::expand_path("/absolute/path");
        assert_eq!(path, Path::new("/absolute/path"));

        // Test ~ expansion
        let path = SSHConnectionPool::expand_path("~/.ssh/id_rsa");
        if let Some(home) = dirs::home_dir() {
            assert_eq!(path, home.join(".ssh/id_rsa"));
        }
    }
}
