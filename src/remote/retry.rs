//! Retry logic with exponential backoff for remote operations.
//!
//! This module provides retry mechanisms for SSH connections and remote
//! operations that may fail due to transient network issues.

use crate::error::{Error, Result};
use log::{debug, warn};
use std::thread;
use std::time::Duration;

/// Configuration for retry behavior.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts (not counting the initial attempt)
    pub max_retries: u32,
    /// Initial delay between retries in milliseconds
    pub initial_delay_ms: u64,
    /// Multiplier for exponential backoff (typically 2.0)
    pub backoff_multiplier: f64,
    /// Maximum delay between retries in milliseconds
    pub max_delay_ms: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay_ms: 1000,
            backoff_multiplier: 2.0,
            max_delay_ms: 10000,
        }
    }
}

impl RetryConfig {
    /// Creates a new retry configuration.
    pub fn new(max_retries: u32, initial_delay_ms: u64) -> Self {
        Self {
            max_retries,
            initial_delay_ms,
            backoff_multiplier: 2.0,
            max_delay_ms: 10000,
        }
    }

    /// Calculates the delay for a given retry attempt.
    fn calculate_delay(&self, attempt: u32) -> Duration {
        let delay_ms = (self.initial_delay_ms as f64
            * self.backoff_multiplier.powi(attempt as i32))
            .min(self.max_delay_ms as f64) as u64;

        Duration::from_millis(delay_ms)
    }
}

/// Retries an operation with exponential backoff.
///
/// # Arguments
///
/// * `config` - Retry configuration
/// * `operation` - Function to retry, returns Result<T>
/// * `operation_name` - Name for logging purposes
///
/// # Returns
///
/// The result of the first successful operation attempt.
///
/// # Errors
///
/// Returns the last error if all retry attempts fail.
pub fn retry_with_backoff<T, F>(
    config: &RetryConfig,
    mut operation: F,
    operation_name: &str,
) -> Result<T>
where
    F: FnMut() -> Result<T>,
{
    // Initial attempt
    let mut last_error = match operation() {
        Ok(result) => return Ok(result),
        Err(e) => {
            debug!("{} failed on initial attempt: {}", operation_name, e);
            e
        }
    };

    // Retry attempts
    for attempt in 1..=config.max_retries {
        let delay = config.calculate_delay(attempt - 1);
        warn!(
            "Retrying {} (attempt {}/{}) after {:?}",
            operation_name, attempt, config.max_retries, delay
        );

        thread::sleep(delay);

        match operation() {
            Ok(result) => {
                debug!("{} succeeded on attempt {}", operation_name, attempt);
                return Ok(result);
            }
            Err(e) => {
                debug!("{} failed on attempt {}: {}", operation_name, attempt, e);
                last_error = e;
            }
        }
    }

    // All retries exhausted
    Err(last_error)
}

/// Provides helpful diagnostic information for SSH connection failures.
pub fn diagnose_ssh_error(error: &Error, host: &str, port: u16, ssh_key: Option<&str>) -> String {
    let error_str = error.to_string().to_lowercase();

    let mut suggestions = Vec::new();

    // Network connectivity issues
    if error_str.contains("connection refused")
        || error_str.contains("connection timeout")
        || error_str.contains("no route to host")
    {
        suggestions.push(format!("• Verify the host '{}' is reachable", host));
        suggestions.push(format!(
            "• Check if SSH is running on port {} (try: ssh -p {} {})",
            port, port, host
        ));
        suggestions.push("• Verify your network connection and firewall settings".to_string());
    }

    // Authentication issues
    if error_str.contains("authentication")
        || error_str.contains("permission denied")
        || error_str.contains("publickey")
    {
        suggestions.push("• Verify your SSH key has correct permissions (chmod 600)".to_string());

        if let Some(key) = ssh_key {
            suggestions.push(format!(
                "• Check that the SSH key exists: {}",
                key
            ));
            suggestions.push(format!(
                "• Verify the public key is in ~/.ssh/authorized_keys on {}",
                host
            ));
        } else {
            suggestions.push("• Try specifying an SSH key in the configuration".to_string());
            suggestions.push("• Verify your SSH agent is running (ssh-add -l)".to_string());
        }
    }

    // Host key verification issues
    if error_str.contains("host key") || error_str.contains("known_hosts") {
        suggestions.push(format!(
            "• Add the host to known_hosts: ssh-keyscan -p {} {} >> ~/.ssh/known_hosts",
            port, host
        ));
        suggestions.push("• Or connect manually first to accept the host key".to_string());
    }

    // Generic issues
    if suggestions.is_empty() {
        suggestions.push("• Verify the remote host is accessible".to_string());
        suggestions.push("• Check SSH logs on the remote machine".to_string());
        suggestions.push(format!(
            "• Test the connection manually: ssh -p {} {}",
            port, host
        ));
    }

    format!(
        "SSH connection failed: {}\n\nTroubleshooting suggestions:\n{}",
        error,
        suggestions.join("\n")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retry_config_default() {
        let config = RetryConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.initial_delay_ms, 1000);
        assert_eq!(config.backoff_multiplier, 2.0);
        assert_eq!(config.max_delay_ms, 10000);
    }

    #[test]
    fn test_retry_config_delay_calculation() {
        let config = RetryConfig::default();

        // Attempt 0: 1000ms
        assert_eq!(config.calculate_delay(0), Duration::from_millis(1000));

        // Attempt 1: 2000ms (1000 * 2^1)
        assert_eq!(config.calculate_delay(1), Duration::from_millis(2000));

        // Attempt 2: 4000ms (1000 * 2^2)
        assert_eq!(config.calculate_delay(2), Duration::from_millis(4000));

        // Attempt 3: 8000ms (1000 * 2^3)
        assert_eq!(config.calculate_delay(3), Duration::from_millis(8000));

        // Attempt 4: 10000ms (max, capped at max_delay_ms)
        assert_eq!(config.calculate_delay(4), Duration::from_millis(10000));
    }

    #[test]
    fn test_retry_success_on_first_attempt() {
        let config = RetryConfig::default();
        let mut call_count = 0;

        let result = retry_with_backoff(
            &config,
            || {
                call_count += 1;
                Ok::<i32, Error>(42)
            },
            "test_operation",
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
        assert_eq!(call_count, 1); // Only called once
    }

    #[test]
    fn test_retry_success_after_failures() {
        let config = RetryConfig::new(3, 10); // Fast retries for testing
        let mut call_count = 0;

        let result = retry_with_backoff(
            &config,
            || {
                call_count += 1;
                if call_count < 3 {
                    Err(Error::InvalidBinary("temporary failure".to_string()))
                } else {
                    Ok(42)
                }
            },
            "test_operation",
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
        assert_eq!(call_count, 3); // Initial + 2 retries
    }

    #[test]
    fn test_retry_all_attempts_fail() {
        let config = RetryConfig::new(2, 10); // Fast retries for testing
        let mut call_count = 0;

        let result = retry_with_backoff(
            &config,
            || {
                call_count += 1;
                Err::<i32, Error>(Error::InvalidBinary("persistent failure".to_string()))
            },
            "test_operation",
        );

        assert!(result.is_err());
        assert_eq!(call_count, 3); // Initial + 2 retries
    }

    #[test]
    fn test_diagnose_connection_refused() {
        let error = Error::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "connection refused",
        ));

        let diagnosis = diagnose_ssh_error(&error, "example.com", 22, None);

        assert!(diagnosis.contains("Verify the host 'example.com' is reachable"));
        assert!(diagnosis.contains("SSH is running on port 22"));
    }

    #[test]
    fn test_diagnose_authentication_failure() {
        let error = Error::InvalidBinary("authentication failed: publickey".to_string());

        let diagnosis = diagnose_ssh_error(&error, "example.com", 22, Some("~/.ssh/id_rsa"));

        assert!(diagnosis.contains("SSH key has correct permissions"));
        assert!(diagnosis.contains("~/.ssh/id_rsa"));
        assert!(diagnosis.contains("authorized_keys"));
    }

    #[test]
    fn test_diagnose_generic_error() {
        let error = Error::InvalidBinary("unknown error".to_string());

        let diagnosis = diagnose_ssh_error(&error, "example.com", 22, None);

        assert!(diagnosis.contains("remote host is accessible"));
        assert!(diagnosis.contains("Test the connection manually"));
    }
}
