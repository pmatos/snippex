//! Transfer cache for incremental binary transfer optimization.
//!
//! This module tracks SHA256 hashes of transferred binaries to avoid
//! redundant transfers when the same binary is used multiple times.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result};

/// Default TTL for cache entries (7 days in seconds).
const DEFAULT_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// Entry in the transfer cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferCacheEntry {
    /// SHA256 hash of the binary content
    pub hash: String,
    /// Path where the binary exists on the remote machine
    pub remote_path: String,
    /// Remote host identifier (user@host:port)
    pub remote_host: String,
    /// Timestamp when the transfer occurred (Unix epoch seconds)
    pub transferred_at: u64,
    /// Size of the binary in bytes
    pub size: u64,
}

impl TransferCacheEntry {
    /// Check if this entry has expired based on TTL.
    pub fn is_expired(&self, ttl_secs: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        now.saturating_sub(self.transferred_at) > ttl_secs
    }
}

/// Transfer cache for tracking binary transfers to remote machines.
///
/// The cache is stored as JSON in `~/.cache/snippex/transfers.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferCache {
    /// Map from binary hash to cache entry
    entries: HashMap<String, TransferCacheEntry>,
    /// TTL for cache entries in seconds
    #[serde(default = "default_ttl")]
    ttl_secs: u64,
}

fn default_ttl() -> u64 {
    DEFAULT_TTL_SECS
}

impl Default for TransferCache {
    fn default() -> Self {
        Self::new()
    }
}

impl TransferCache {
    /// Create a new empty transfer cache.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            ttl_secs: DEFAULT_TTL_SECS,
        }
    }

    /// Create a new transfer cache with custom TTL.
    pub fn with_ttl(ttl_secs: u64) -> Self {
        Self {
            entries: HashMap::new(),
            ttl_secs,
        }
    }

    /// Get the default cache file path.
    pub fn default_cache_path() -> Option<PathBuf> {
        dirs::cache_dir().map(|p| p.join("snippex").join("transfers.json"))
    }

    /// Load the cache from the default location.
    pub fn load() -> Result<Self> {
        if let Some(path) = Self::default_cache_path() {
            Self::load_from(&path)
        } else {
            Ok(Self::new())
        }
    }

    /// Load the cache from a specific file path.
    pub fn load_from(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }

        let file = File::open(path).map_err(Error::Io)?;
        let reader = BufReader::new(file);
        let cache: TransferCache = serde_json::from_reader(reader).map_err(|e| {
            Error::Io(std::io::Error::other(format!(
                "Failed to parse transfer cache: {}",
                e
            )))
        })?;

        Ok(cache)
    }

    /// Save the cache to the default location.
    pub fn save(&self) -> Result<()> {
        if let Some(path) = Self::default_cache_path() {
            self.save_to(&path)
        } else {
            Ok(())
        }
    }

    /// Save the cache to a specific file path.
    pub fn save_to(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(Error::Io)?;
        }

        let json = serde_json::to_string_pretty(self).map_err(|e| {
            Error::Io(std::io::Error::other(format!(
                "Failed to serialize transfer cache: {}",
                e
            )))
        })?;

        fs::write(path, json).map_err(Error::Io)?;
        Ok(())
    }

    /// Compute SHA256 hash of a file.
    pub fn compute_file_hash(path: &Path) -> Result<String> {
        let file = File::open(path).map_err(Error::Io)?;
        let mut reader = BufReader::new(file);
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];

        loop {
            let bytes_read = reader.read(&mut buffer).map_err(Error::Io)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Compute SHA256 hash of a directory by hashing all files.
    pub fn compute_directory_hash(path: &Path) -> Result<String> {
        let mut hasher = Sha256::new();
        Self::hash_directory_recursive(path, &mut hasher)?;
        Ok(format!("{:x}", hasher.finalize()))
    }

    fn hash_directory_recursive(path: &Path, hasher: &mut Sha256) -> Result<()> {
        let mut entries: Vec<_> = fs::read_dir(path)
            .map_err(Error::Io)?
            .filter_map(|e| e.ok())
            .collect();
        entries.sort_by_key(|e| e.path());

        for entry in entries {
            let entry_path = entry.path();
            let metadata = entry.metadata().map_err(Error::Io)?;

            // Include relative path in hash for structure awareness
            let relative_path = entry_path
                .strip_prefix(path)
                .unwrap_or(&entry_path)
                .to_string_lossy();
            hasher.update(relative_path.as_bytes());

            if metadata.is_file() {
                let file = File::open(&entry_path).map_err(Error::Io)?;
                let mut reader = BufReader::new(file);
                let mut buffer = [0u8; 8192];

                loop {
                    let bytes_read = reader.read(&mut buffer).map_err(Error::Io)?;
                    if bytes_read == 0 {
                        break;
                    }
                    hasher.update(&buffer[..bytes_read]);
                }
            } else if metadata.is_dir() {
                Self::hash_directory_recursive(&entry_path, hasher)?;
            }
        }

        Ok(())
    }

    /// Look up a cached transfer by binary hash for a specific remote host.
    pub fn get(&self, hash: &str, remote_host: &str) -> Option<&TransferCacheEntry> {
        self.entries.get(hash).and_then(|entry| {
            if entry.remote_host == remote_host && !entry.is_expired(self.ttl_secs) {
                Some(entry)
            } else {
                None
            }
        })
    }

    /// Look up a cached transfer by local file path.
    pub fn get_by_path(
        &self,
        local_path: &Path,
        remote_host: &str,
    ) -> Result<Option<&TransferCacheEntry>> {
        let hash = if local_path.is_dir() {
            Self::compute_directory_hash(local_path)?
        } else {
            Self::compute_file_hash(local_path)?
        };
        Ok(self.get(&hash, remote_host))
    }

    /// Record a successful transfer in the cache.
    pub fn insert(&mut self, hash: String, remote_path: String, remote_host: String, size: u64) {
        let entry = TransferCacheEntry {
            hash: hash.clone(),
            remote_path,
            remote_host,
            transferred_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_secs(),
            size,
        };
        self.entries.insert(hash, entry);
    }

    /// Record a transfer from a local file path.
    pub fn insert_from_path(
        &mut self,
        local_path: &Path,
        remote_path: String,
        remote_host: String,
    ) -> Result<String> {
        let (hash, size) = if local_path.is_dir() {
            let hash = Self::compute_directory_hash(local_path)?;
            let size = Self::get_directory_size(local_path)?;
            (hash, size)
        } else {
            let hash = Self::compute_file_hash(local_path)?;
            let size = fs::metadata(local_path).map_err(Error::Io)?.len();
            (hash, size)
        };
        self.insert(hash.clone(), remote_path, remote_host, size);
        Ok(hash)
    }

    /// Remove a specific entry from the cache.
    pub fn remove(&mut self, hash: &str) -> Option<TransferCacheEntry> {
        self.entries.remove(hash)
    }

    /// Remove all entries for a specific remote host.
    pub fn remove_for_host(&mut self, remote_host: &str) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, entry| entry.remote_host != remote_host);
        before - self.entries.len()
    }

    /// Remove all expired entries from the cache.
    pub fn prune_expired(&mut self) -> usize {
        let ttl = self.ttl_secs;
        let before = self.entries.len();
        self.entries.retain(|_, entry| !entry.is_expired(ttl));
        before - self.entries.len()
    }

    /// Clear all entries from the cache.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Get the number of entries in the cache.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get total size of cached transfers.
    pub fn total_size(&self) -> u64 {
        self.entries.values().map(|e| e.size).sum()
    }

    /// Get statistics about the cache.
    pub fn stats(&self) -> TransferCacheStats {
        let total_entries = self.entries.len();
        let total_size = self.total_size();
        let expired_count = self
            .entries
            .values()
            .filter(|e| e.is_expired(self.ttl_secs))
            .count();
        let unique_hosts: std::collections::HashSet<_> =
            self.entries.values().map(|e| &e.remote_host).collect();

        TransferCacheStats {
            total_entries,
            total_size,
            expired_count,
            unique_hosts: unique_hosts.len(),
            ttl_secs: self.ttl_secs,
        }
    }

    fn get_directory_size(path: &Path) -> Result<u64> {
        let mut total = 0;
        for entry in fs::read_dir(path).map_err(Error::Io)? {
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

/// Statistics about the transfer cache.
#[derive(Debug, Clone)]
pub struct TransferCacheStats {
    /// Total number of cache entries
    pub total_entries: usize,
    /// Total size of cached transfers in bytes
    pub total_size: u64,
    /// Number of expired entries
    pub expired_count: usize,
    /// Number of unique remote hosts
    pub unique_hosts: usize,
    /// Current TTL setting in seconds
    pub ttl_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_transfer_cache_new() {
        let cache = TransferCache::new();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_transfer_cache_insert_and_get() {
        let mut cache = TransferCache::new();
        let hash = "abc123".to_string();
        let remote_path = "/tmp/snippex-test/binary".to_string();
        let remote_host = "user@host:22".to_string();

        cache.insert(hash.clone(), remote_path.clone(), remote_host.clone(), 1024);

        let entry = cache.get(&hash, &remote_host);
        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.hash, hash);
        assert_eq!(entry.remote_path, remote_path);
        assert_eq!(entry.remote_host, remote_host);
        assert_eq!(entry.size, 1024);
    }

    #[test]
    fn test_transfer_cache_get_wrong_host() {
        let mut cache = TransferCache::new();
        let hash = "abc123".to_string();
        let remote_path = "/tmp/snippex-test/binary".to_string();
        let remote_host = "user@host:22".to_string();

        cache.insert(hash.clone(), remote_path, remote_host, 1024);

        // Different host should not match
        let entry = cache.get(&hash, "other@host:22");
        assert!(entry.is_none());
    }

    #[test]
    fn test_transfer_cache_entry_expiry() {
        let entry = TransferCacheEntry {
            hash: "abc123".to_string(),
            remote_path: "/tmp/test".to_string(),
            remote_host: "user@host:22".to_string(),
            transferred_at: 0, // Unix epoch - definitely expired
            size: 1024,
        };

        assert!(entry.is_expired(DEFAULT_TTL_SECS));

        let recent_entry = TransferCacheEntry {
            hash: "def456".to_string(),
            remote_path: "/tmp/test2".to_string(),
            remote_host: "user@host:22".to_string(),
            transferred_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            size: 2048,
        };

        assert!(!recent_entry.is_expired(DEFAULT_TTL_SECS));
    }

    #[test]
    fn test_transfer_cache_prune_expired() {
        let mut cache = TransferCache::new();

        // Insert an expired entry directly
        let expired_entry = TransferCacheEntry {
            hash: "old".to_string(),
            remote_path: "/tmp/old".to_string(),
            remote_host: "user@host:22".to_string(),
            transferred_at: 0,
            size: 1024,
        };
        cache.entries.insert("old".to_string(), expired_entry);

        // Insert a fresh entry
        cache.insert(
            "new".to_string(),
            "/tmp/new".to_string(),
            "user@host:22".to_string(),
            2048,
        );

        assert_eq!(cache.len(), 2);
        let pruned = cache.prune_expired();
        assert_eq!(pruned, 1);
        assert_eq!(cache.len(), 1);
        assert!(cache.get("new", "user@host:22").is_some());
        assert!(cache.get("old", "user@host:22").is_none());
    }

    #[test]
    fn test_transfer_cache_remove_for_host() {
        let mut cache = TransferCache::new();

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
        let removed = cache.remove_for_host("user@host1:22");
        assert_eq!(removed, 2);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_transfer_cache_stats() {
        let mut cache = TransferCache::new();

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
            2048,
        );

        let stats = cache.stats();
        assert_eq!(stats.total_entries, 2);
        assert_eq!(stats.total_size, 3072);
        assert_eq!(stats.expired_count, 0);
        assert_eq!(stats.unique_hosts, 2);
    }

    #[test]
    fn test_compute_file_hash() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("test.bin");
        fs::write(&file_path, b"test content").unwrap();

        let hash = TransferCache::compute_file_hash(&file_path).unwrap();
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64); // SHA256 produces 64 hex chars

        // Same content should produce same hash
        let file_path2 = dir.path().join("test2.bin");
        fs::write(&file_path2, b"test content").unwrap();
        let hash2 = TransferCache::compute_file_hash(&file_path2).unwrap();
        assert_eq!(hash, hash2);

        // Different content should produce different hash
        let file_path3 = dir.path().join("test3.bin");
        fs::write(&file_path3, b"different content").unwrap();
        let hash3 = TransferCache::compute_file_hash(&file_path3).unwrap();
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_compute_directory_hash() {
        let dir = TempDir::new().unwrap();
        let subdir = dir.path().join("subdir");
        fs::create_dir(&subdir).unwrap();

        fs::write(dir.path().join("file1.txt"), b"content1").unwrap();
        fs::write(subdir.join("file2.txt"), b"content2").unwrap();

        let hash = TransferCache::compute_directory_hash(dir.path()).unwrap();
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_transfer_cache_save_and_load() {
        let dir = TempDir::new().unwrap();
        let cache_path = dir.path().join("cache.json");

        let mut cache = TransferCache::new();
        cache.insert(
            "hash1".to_string(),
            "/tmp/1".to_string(),
            "user@host:22".to_string(),
            1024,
        );

        cache.save_to(&cache_path).unwrap();
        assert!(cache_path.exists());

        let loaded = TransferCache::load_from(&cache_path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded.get("hash1", "user@host:22").is_some());
    }

    #[test]
    fn test_transfer_cache_insert_from_path() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("binary");
        fs::write(&file_path, b"binary content").unwrap();

        let mut cache = TransferCache::new();
        let hash = cache
            .insert_from_path(
                &file_path,
                "/tmp/remote/binary".to_string(),
                "user@host:22".to_string(),
            )
            .unwrap();

        assert!(!hash.is_empty());
        let entry = cache.get(&hash, "user@host:22");
        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.remote_path, "/tmp/remote/binary");
        assert_eq!(entry.size, 14); // "binary content" = 14 bytes
    }
}
