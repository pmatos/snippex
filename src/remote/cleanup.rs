//! Cleanup handling for remote operations.
//!
//! This module provides mechanisms to ensure remote resources are cleaned up
//! even when operations are interrupted (e.g., via Ctrl+C).

#![allow(dead_code)]

use crate::config::RemoteConfig;
use crate::remote::transfer::SCPTransfer;
use log::{debug, warn};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Registry for tracking remote paths that need cleanup.
///
/// This is used to ensure cleanup happens even when interrupted by Ctrl+C.
#[derive(Clone)]
pub struct CleanupRegistry {
    paths: Arc<Mutex<Vec<(RemoteConfig, PathBuf)>>>,
}

impl CleanupRegistry {
    /// Creates a new cleanup registry.
    pub fn new() -> Self {
        Self {
            paths: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Registers a remote path for cleanup.
    pub fn register(&self, config: RemoteConfig, path: PathBuf) {
        if let Ok(mut paths) = self.paths.lock() {
            debug!("Registered remote path for cleanup: {}", path.display());
            paths.push((config, path));
        }
    }

    /// Unregisters a remote path (successful cleanup).
    pub fn unregister(&self, path: &PathBuf) {
        if let Ok(mut paths) = self.paths.lock() {
            paths.retain(|(_, p)| p != path);
            debug!("Unregistered remote path: {}", path.display());
        }
    }

    /// Performs cleanup on all registered paths.
    ///
    /// This is typically called from a signal handler or on program exit.
    pub fn cleanup_all(&self) {
        if let Ok(paths) = self.paths.lock() {
            if paths.is_empty() {
                return;
            }

            warn!(
                "Performing emergency cleanup of {} remote paths",
                paths.len()
            );

            for (config, path) in paths.iter() {
                debug!("Cleaning up remote path: {}", path.display());
                let transfer = SCPTransfer::new(config.clone());

                if let Err(e) = transfer.cleanup_remote(path) {
                    warn!("Failed to cleanup remote path {}: {}", path.display(), e);
                } else {
                    debug!("Successfully cleaned up: {}", path.display());
                }
            }
        }
    }

    /// Returns the number of registered paths.
    pub fn count(&self) -> usize {
        self.paths.lock().map(|p| p.len()).unwrap_or(0)
    }
}

impl Default for CleanupRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RemoteConfig;
    use std::path::PathBuf;

    #[test]
    fn test_registry_creation() {
        let registry = CleanupRegistry::new();
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn test_register_unregister() {
        let registry = CleanupRegistry::new();
        let config = RemoteConfig::new("localhost".to_string(), "test".to_string());
        let path = PathBuf::from("/tmp/test");

        registry.register(config.clone(), path.clone());
        assert_eq!(registry.count(), 1);

        registry.unregister(&path);
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn test_multiple_paths() {
        let registry = CleanupRegistry::new();
        let config = RemoteConfig::new("localhost".to_string(), "test".to_string());

        registry.register(config.clone(), PathBuf::from("/tmp/test1"));
        registry.register(config.clone(), PathBuf::from("/tmp/test2"));
        registry.register(config.clone(), PathBuf::from("/tmp/test3"));

        assert_eq!(registry.count(), 3);

        registry.unregister(&PathBuf::from("/tmp/test2"));
        assert_eq!(registry.count(), 2);
    }

    #[test]
    fn test_clone_registry() {
        let registry = CleanupRegistry::new();
        let config = RemoteConfig::new("localhost".to_string(), "test".to_string());
        let path = PathBuf::from("/tmp/test");

        registry.register(config, path.clone());
        assert_eq!(registry.count(), 1);

        // Clone should share the same underlying data
        let registry2 = registry.clone();
        assert_eq!(registry2.count(), 1);

        registry2.unregister(&path);
        assert_eq!(registry.count(), 0);
        assert_eq!(registry2.count(), 0);
    }
}
