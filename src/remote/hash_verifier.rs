//! Remote hash verification for incremental binary transfer.
//!
//! This module provides functionality to verify if a binary exists on a
//! remote machine with the expected SHA256 hash, enabling skip of redundant
//! transfers when the same binary is already present on the remote.

#![allow(dead_code)]

use crate::config::RemoteConfig;
use crate::error::Result;
use crate::remote::executor::SSHExecutor;
use crate::remote::transfer_cache::{TransferCache, TransferCacheEntry};
use log::{debug, info, warn};
use std::path::Path;

/// Result of a remote hash verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationResult {
    /// Binary exists on remote with matching hash
    Match,
    /// Binary exists on remote but hash differs
    HashMismatch { expected: String, actual: String },
    /// Binary does not exist on remote
    NotFound,
    /// Verification failed due to an error (e.g., SSH issues)
    Error(String),
}

impl VerificationResult {
    /// Returns true if the binary exists on remote with matching hash.
    pub fn is_match(&self) -> bool {
        matches!(self, VerificationResult::Match)
    }

    /// Returns true if transfer is needed (not a match).
    pub fn needs_transfer(&self) -> bool {
        !self.is_match()
    }
}

/// Remote hash verifier for checking binary existence on remote machines.
///
/// Uses SHA256 to verify that a binary exists on the remote with the
/// expected content, enabling incremental transfer optimization.
pub struct RemoteHashVerifier {
    executor: SSHExecutor,
    config: RemoteConfig,
}

impl RemoteHashVerifier {
    /// Create a new remote hash verifier for the given remote configuration.
    pub fn new(config: RemoteConfig) -> Self {
        let executor = SSHExecutor::new(config.clone());
        Self { executor, config }
    }

    /// Get the remote host identifier (user@host:port).
    pub fn remote_host_id(&self) -> String {
        format!(
            "{}@{}:{}",
            self.config.user, self.config.host, self.config.port
        )
    }

    /// Compute SHA256 hash of a file on the remote machine.
    ///
    /// Uses the `sha256sum` command on the remote, which is available on
    /// most Linux systems.
    pub fn compute_remote_hash(&self, remote_path: &str) -> Result<Option<String>> {
        let command = format!("sha256sum {} 2>/dev/null", shell_escape(remote_path));

        debug!("Computing remote hash for: {}", remote_path);
        let result = self.executor.execute(&command)?;

        if result.exit_code != 0 {
            // File doesn't exist or sha256sum failed
            debug!(
                "Remote hash computation failed (exit code {}): {}",
                result.exit_code, result.stderr
            );
            return Ok(None);
        }

        // Parse sha256sum output: "hash  filename"
        let hash = result
            .stdout
            .split_whitespace()
            .next()
            .map(|s| s.to_lowercase());

        if let Some(ref h) = hash {
            debug!("Remote hash for {}: {}", remote_path, h);
        }

        Ok(hash)
    }

    /// Check if a file exists on the remote machine.
    pub fn file_exists(&self, remote_path: &str) -> Result<bool> {
        let command = format!("test -e {} && echo exists", shell_escape(remote_path));

        let result = self.executor.execute(&command)?;
        Ok(result.exit_code == 0 && result.stdout.trim() == "exists")
    }

    /// Verify that a remote file has the expected hash.
    ///
    /// # Arguments
    ///
    /// * `remote_path` - Path to the file on the remote machine
    /// * `expected_hash` - Expected SHA256 hash (lowercase hex)
    ///
    /// # Returns
    ///
    /// A `VerificationResult` indicating whether the file matches.
    pub fn verify(&self, remote_path: &str, expected_hash: &str) -> VerificationResult {
        info!(
            "Verifying remote hash for {} (expected: {}...)",
            remote_path,
            &expected_hash[..8.min(expected_hash.len())]
        );

        match self.compute_remote_hash(remote_path) {
            Ok(Some(actual_hash)) => {
                if actual_hash == expected_hash.to_lowercase() {
                    info!("Remote hash matches for {}", remote_path);
                    VerificationResult::Match
                } else {
                    warn!(
                        "Remote hash mismatch for {}: expected {}, got {}",
                        remote_path, expected_hash, actual_hash
                    );
                    VerificationResult::HashMismatch {
                        expected: expected_hash.to_string(),
                        actual: actual_hash,
                    }
                }
            }
            Ok(None) => {
                info!("Remote file not found: {}", remote_path);
                VerificationResult::NotFound
            }
            Err(e) => {
                warn!("Remote hash verification error for {}: {}", remote_path, e);
                VerificationResult::Error(e.to_string())
            }
        }
    }

    /// Verify a cached transfer entry is still valid on the remote.
    ///
    /// Checks that the binary at the cached remote path still exists with
    /// the expected hash.
    pub fn verify_cache_entry(&self, entry: &TransferCacheEntry) -> VerificationResult {
        // Only verify entries for this remote host
        if entry.remote_host != self.remote_host_id() {
            return VerificationResult::Error(format!(
                "Cache entry is for different host: {} vs {}",
                entry.remote_host,
                self.remote_host_id()
            ));
        }

        self.verify(&entry.remote_path, &entry.hash)
    }

    /// Check if a local file needs to be transferred to the remote.
    ///
    /// This method:
    /// 1. Computes the local file's hash
    /// 2. Checks the transfer cache for an existing entry
    /// 3. If cached, verifies the remote still has the file
    /// 4. Returns whether a transfer is needed
    ///
    /// # Arguments
    ///
    /// * `local_path` - Path to the local file
    /// * `cache` - Transfer cache to check
    ///
    /// # Returns
    ///
    /// A tuple of (needs_transfer, Option<cached_remote_path>)
    pub fn check_transfer_needed(
        &self,
        local_path: &Path,
        cache: &TransferCache,
    ) -> Result<(bool, Option<String>)> {
        let remote_host_id = self.remote_host_id();

        // Check if we have a cached entry for this file
        if let Some(entry) = cache.get_by_path(local_path, &remote_host_id)? {
            // Verify the cached entry is still valid
            match self.verify_cache_entry(entry) {
                VerificationResult::Match => {
                    info!(
                        "Cache hit: {} already exists at {} on {}",
                        local_path.display(),
                        entry.remote_path,
                        remote_host_id
                    );
                    return Ok((false, Some(entry.remote_path.clone())));
                }
                VerificationResult::HashMismatch { .. } | VerificationResult::NotFound => {
                    info!(
                        "Cache miss: {} needs transfer (remote changed or deleted)",
                        local_path.display()
                    );
                }
                VerificationResult::Error(e) => {
                    warn!("Cache verification error, will transfer: {}", e);
                }
            }
        }

        Ok((true, None))
    }

    /// Delete a file on the remote machine.
    ///
    /// Useful for cleaning up after verification finds a hash mismatch.
    pub fn delete_remote(&self, remote_path: &str) -> Result<bool> {
        let command = format!("rm -f {}", shell_escape(remote_path));
        let result = self.executor.execute(&command)?;
        Ok(result.exit_code == 0)
    }
}

/// Escape a string for safe use in shell commands.
fn shell_escape(s: &str) -> String {
    // Use single quotes and escape any single quotes in the string
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Builder for creating transfer operations with hash verification.
pub struct IncrementalTransfer {
    verifier: RemoteHashVerifier,
    cache: TransferCache,
}

impl IncrementalTransfer {
    /// Create a new incremental transfer handler.
    pub fn new(config: RemoteConfig) -> Result<Self> {
        let verifier = RemoteHashVerifier::new(config);
        let cache = TransferCache::load()?;

        Ok(Self { verifier, cache })
    }

    /// Create with a specific cache (for testing).
    pub fn with_cache(config: RemoteConfig, cache: TransferCache) -> Self {
        let verifier = RemoteHashVerifier::new(config);
        Self { verifier, cache }
    }

    /// Get the transfer cache.
    pub fn cache(&self) -> &TransferCache {
        &self.cache
    }

    /// Get mutable access to the transfer cache.
    pub fn cache_mut(&mut self) -> &mut TransferCache {
        &mut self.cache
    }

    /// Check if a local file needs to be transferred.
    ///
    /// Returns (needs_transfer, Option<cached_remote_path>)
    pub fn needs_transfer(&self, local_path: &Path) -> Result<(bool, Option<String>)> {
        self.verifier.check_transfer_needed(local_path, &self.cache)
    }

    /// Record a successful transfer in the cache.
    pub fn record_transfer(&mut self, local_path: &Path, remote_path: String) -> Result<()> {
        let remote_host = self.verifier.remote_host_id();
        self.cache
            .insert_from_path(local_path, remote_path, remote_host)?;
        self.cache.save()?;
        Ok(())
    }

    /// Save the cache to disk.
    pub fn save_cache(&self) -> Result<()> {
        self.cache.save()
    }

    /// Get the remote host identifier.
    pub fn remote_host_id(&self) -> String {
        self.verifier.remote_host_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_result_is_match() {
        assert!(VerificationResult::Match.is_match());
        assert!(!VerificationResult::NotFound.is_match());
        assert!(!VerificationResult::HashMismatch {
            expected: "a".to_string(),
            actual: "b".to_string()
        }
        .is_match());
        assert!(!VerificationResult::Error("test".to_string()).is_match());
    }

    #[test]
    fn test_verification_result_needs_transfer() {
        assert!(!VerificationResult::Match.needs_transfer());
        assert!(VerificationResult::NotFound.needs_transfer());
        assert!(VerificationResult::HashMismatch {
            expected: "a".to_string(),
            actual: "b".to_string()
        }
        .needs_transfer());
        assert!(VerificationResult::Error("test".to_string()).needs_transfer());
    }

    #[test]
    fn test_shell_escape() {
        assert_eq!(shell_escape("simple"), "'simple'");
        assert_eq!(shell_escape("/path/to/file"), "'/path/to/file'");
        assert_eq!(shell_escape("file with spaces"), "'file with spaces'");
        assert_eq!(shell_escape("it's a test"), "'it'\\''s a test'");
        assert_eq!(shell_escape("path/with'quote"), "'path/with'\\''quote'");
    }

    #[test]
    fn test_remote_host_id() {
        let config = RemoteConfig::new("example.com".to_string(), "testuser".to_string());
        let verifier = RemoteHashVerifier::new(config);
        assert_eq!(verifier.remote_host_id(), "testuser@example.com:22");

        let config2 =
            RemoteConfig::new("example.com".to_string(), "testuser".to_string()).with_port(2222);
        let verifier2 = RemoteHashVerifier::new(config2);
        assert_eq!(verifier2.remote_host_id(), "testuser@example.com:2222");
    }

    #[test]
    fn test_incremental_transfer_with_empty_cache() {
        let config = RemoteConfig::new("example.com".to_string(), "testuser".to_string());
        let cache = TransferCache::new();
        let transfer = IncrementalTransfer::with_cache(config, cache);

        assert!(transfer.cache().is_empty());
        assert_eq!(transfer.remote_host_id(), "testuser@example.com:22");
    }

    #[test]
    fn test_same_binary_not_retransferred() {
        use std::fs;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let binary_path = temp_dir.path().join("test.bin");
        fs::write(&binary_path, b"binary content").unwrap();

        let config = RemoteConfig::new("example.com".to_string(), "testuser".to_string());
        let mut cache = TransferCache::new();

        // Calculate hash and insert into cache
        let hash = cache
            .insert_from_path(
                &binary_path,
                "/tmp/remote/test.bin".to_string(),
                "testuser@example.com:22".to_string(),
            )
            .unwrap();

        // Create transfer handler with pre-populated cache
        let transfer = IncrementalTransfer::with_cache(config, cache);

        // Check if the same binary exists in cache
        let entry = transfer.cache().get(&hash, "testuser@example.com:22");
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().remote_path, "/tmp/remote/test.bin");
    }

    #[test]
    fn test_modified_binary_triggers_new_transfer() {
        use std::fs;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let binary_path = temp_dir.path().join("test.bin");

        let _config = RemoteConfig::new("example.com".to_string(), "testuser".to_string());
        let mut cache = TransferCache::new();

        // First version of binary
        fs::write(&binary_path, b"original content").unwrap();
        let hash1 = cache
            .insert_from_path(
                &binary_path,
                "/tmp/remote/test.bin".to_string(),
                "testuser@example.com:22".to_string(),
            )
            .unwrap();

        // Modify the binary
        fs::write(&binary_path, b"modified content").unwrap();
        let hash2 = TransferCache::compute_file_hash(&binary_path).unwrap();

        // Hashes should differ
        assert_ne!(hash1, hash2);

        // Old hash should still be in cache
        assert!(cache.get(&hash1, "testuser@example.com:22").is_some());

        // New hash should not be in cache yet (needs transfer)
        assert!(cache.get(&hash2, "testuser@example.com:22").is_none());
    }

    #[test]
    fn test_cache_entry_expiry_check() {
        use std::time::{SystemTime, UNIX_EPOCH};

        // Test that TransferCacheEntry::is_expired works correctly
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let recent_entry = TransferCacheEntry {
            hash: "recent".to_string(),
            remote_path: "/tmp/recent".to_string(),
            remote_host: "user@host:22".to_string(),
            transferred_at: now,
            size: 1024,
        };
        // Recent entry should not be expired with 7-day TTL
        assert!(!recent_entry.is_expired(7 * 24 * 60 * 60));

        let old_entry = TransferCacheEntry {
            hash: "old".to_string(),
            remote_path: "/tmp/old".to_string(),
            remote_host: "user@host:22".to_string(),
            transferred_at: 0, // Unix epoch - definitely old
            size: 1024,
        };
        // Entry from Unix epoch should be expired with any reasonable TTL
        assert!(old_entry.is_expired(7 * 24 * 60 * 60));

        // Edge case: an entry should expire when age > TTL (strictly greater)
        // Entry 10 seconds old with 5 second TTL should be expired
        let edge_entry = TransferCacheEntry {
            hash: "edge".to_string(),
            remote_path: "/tmp/edge".to_string(),
            remote_host: "user@host:22".to_string(),
            transferred_at: now.saturating_sub(10),
            size: 1024,
        };
        assert!(edge_entry.is_expired(5)); // 10 > 5, so expired
        assert!(!edge_entry.is_expired(15)); // 10 > 15 is false, not expired
    }

    #[test]
    fn test_cache_invalidation_by_host() {
        let mut cache = TransferCache::new();

        // Add entries for two different hosts
        cache.insert(
            "hash1".to_string(),
            "/tmp/1".to_string(),
            "user@host1:22".to_string(),
            1024,
        );
        cache.insert(
            "hash2".to_string(),
            "/tmp/2".to_string(),
            "user@host2:22".to_string(),
            1024,
        );
        cache.insert(
            "hash3".to_string(),
            "/tmp/3".to_string(),
            "user@host1:22".to_string(),
            1024,
        );

        assert_eq!(cache.len(), 3);

        // Invalidate all entries for host1
        let removed = cache.remove_for_host("user@host1:22");
        assert_eq!(removed, 2);
        assert_eq!(cache.len(), 1);

        // Only host2 entry should remain
        assert!(cache.get("hash2", "user@host2:22").is_some());
    }

    #[test]
    fn test_verification_result_match_skips_transfer() {
        // A Match result should indicate no transfer is needed
        let result = VerificationResult::Match;
        assert!(!result.needs_transfer());
        assert!(result.is_match());
    }

    #[test]
    fn test_verification_result_not_found_requires_transfer() {
        // NotFound should require transfer
        let result = VerificationResult::NotFound;
        assert!(result.needs_transfer());
        assert!(!result.is_match());
    }

    #[test]
    fn test_verification_result_mismatch_requires_transfer() {
        // HashMismatch should require transfer (binary changed)
        let result = VerificationResult::HashMismatch {
            expected: "abc123".to_string(),
            actual: "def456".to_string(),
        };
        assert!(result.needs_transfer());
        assert!(!result.is_match());
    }

    #[test]
    fn test_cache_persistence_across_sessions() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let cache_path = temp_dir.path().join("test_cache.json");

        // Session 1: Create and populate cache
        {
            let mut cache = TransferCache::new();
            cache.insert(
                "persistent_hash".to_string(),
                "/tmp/persistent".to_string(),
                "user@host:22".to_string(),
                1024,
            );
            cache.save_to(&cache_path).unwrap();
        }

        // Session 2: Load cache and verify entry exists
        {
            let cache = TransferCache::load_from(&cache_path).unwrap();
            let entry = cache.get("persistent_hash", "user@host:22");
            assert!(entry.is_some());
            assert_eq!(entry.unwrap().remote_path, "/tmp/persistent");
        }
    }
}
