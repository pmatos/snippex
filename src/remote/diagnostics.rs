//! Diagnostic utilities for remote execution failures.
//!
//! This module provides functions to analyze and diagnose common remote
//! execution failures, providing helpful error messages and suggestions.

use crate::error::Error;
use log::debug;

/// Analyzes remote execution failure and provides helpful diagnostics.
///
/// # Arguments
///
/// * `exit_code` - The exit code from the remote command
/// * `stderr` - The stderr output from the remote command
/// * `stdout` - The stdout output from the remote command
/// * `command` - The command that was executed
/// * `host` - The remote host
///
/// # Returns
///
/// A detailed error message with troubleshooting suggestions
pub fn diagnose_remote_execution_failure(
    exit_code: i32,
    stderr: &str,
    stdout: &str,
    command: &str,
    host: &str,
) -> String {
    let stderr_lower = stderr.to_lowercase();
    let stdout_lower = stdout.to_lowercase();
    let combined = format!("{} {}", stderr_lower, stdout_lower);

    let mut suggestions = Vec::new();

    // Check for command not found (snippex not installed)
    if combined.contains("command not found")
        || combined.contains("no such file")
        || exit_code == 127
    {
        suggestions.push("• Snippex is not installed or not in PATH on the remote machine".to_string());
        suggestions.push(format!(
            "• Install snippex on {} or update the snippex_path in your config",
            host
        ));
        suggestions.push(format!(
            "• Verify the path '{}' is correct",
            extract_command_name(command)
        ));
        suggestions.push(format!(
            "• Test manually: ssh {} 'which {}'",
            host,
            extract_command_name(command)
        ));
    }
    // Check for binary not found on remote
    else if combined.contains("failed to open binary")
        || combined.contains("binary file not found")
        || combined.contains("no such binary")
    {
        suggestions.push("• The original binary file is not present on the remote machine".to_string());
        suggestions.push("• Ensure the binary was correctly uploaded with the package".to_string());
        suggestions.push("• Check that the binary path in the package metadata is correct".to_string());
    }
    // Check for permission issues
    else if combined.contains("permission denied") || exit_code == 126 {
        suggestions.push("• Permission denied when executing the command".to_string());
        suggestions.push(format!(
            "• Verify the user has execute permissions for {}",
            extract_command_name(command)
        ));
        suggestions.push("• Check file permissions on the remote machine".to_string());
    }
    // Check for simulation-specific failures
    else if combined.contains("nasm") && combined.contains("error") {
        suggestions.push("• NASM assembler is not installed on the remote machine".to_string());
        suggestions.push(format!("• Install NASM on {}: sudo apt install nasm", host));
    } else if combined.contains("linker") || combined.contains("ld:") {
        suggestions.push("• Linker (ld) is not available or failed".to_string());
        suggestions.push(format!(
            "• Install build-essential on {}: sudo apt install build-essential",
            host
        ));
    } else if combined.contains("sandbox") || combined.contains("memory allocation") {
        suggestions.push("• Simulation failed due to memory or sandbox issues".to_string());
        suggestions.push("• The assembly block may be accessing invalid memory addresses".to_string());
        suggestions.push("• Try extracting a different assembly block".to_string());
    }
    // Check for package/data issues
    else if combined.contains("failed to read package")
        || combined.contains("failed to parse")
        || combined.contains("invalid package")
    {
        suggestions.push("• The execution package may be corrupted or incomplete".to_string());
        suggestions.push("• Verify the package was uploaded successfully".to_string());
        suggestions.push("• Check available disk space on the remote machine".to_string());
    }
    // Generic simulation failure
    else if exit_code != 0 {
        suggestions.push(format!(
            "• Remote simulation failed with exit code {}",
            exit_code
        ));
        suggestions.push("• Review the stderr output above for specific error details".to_string());
        suggestions.push(format!(
            "• Test the command manually: ssh {} '{}'",
            host, command
        ));
    }

    // If no specific suggestions, provide generic advice
    if suggestions.is_empty() {
        suggestions.push("• Remote command execution failed".to_string());
        suggestions.push("• Check the remote machine logs for more details".to_string());
        suggestions.push(format!(
            "• Verify snippex is working on {}: ssh {} 'snippex --version'",
            host, host
        ));
    }

    // Build the error message
    let mut error_msg = format!("Remote execution failed on {}\n", host);
    error_msg.push_str(&format!("Command: {}\n", command));
    error_msg.push_str(&format!("Exit code: {}\n\n", exit_code));

    if !stderr.is_empty() {
        error_msg.push_str("Stderr:\n");
        error_msg.push_str(&indent_text(stderr, 2));
        error_msg.push_str("\n\n");
    }

    if !stdout.is_empty() && stdout.len() < 500 {
        error_msg.push_str("Stdout:\n");
        error_msg.push_str(&indent_text(stdout, 2));
        error_msg.push_str("\n\n");
    }

    error_msg.push_str("Troubleshooting suggestions:\n");
    error_msg.push_str(&suggestions.join("\n"));

    error_msg
}

/// Extracts the command name from a full command string.
fn extract_command_name(command: &str) -> &str {
    command
        .split_whitespace()
        .next()
        .unwrap_or(command)
}

/// Indents each line of text by the specified number of spaces.
fn indent_text(text: &str, spaces: usize) -> String {
    let indent = " ".repeat(spaces);
    text.lines()
        .map(|line| format!("{}{}", indent, line))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Checks if the snippex binary exists and is executable on the remote machine.
pub fn verify_snippex_installation(
    ssh_executor: &crate::remote::executor::SSHExecutor,
    snippex_path: &str,
) -> Result<String, Error> {
    debug!("Verifying snippex installation at: {}", snippex_path);

    // Try to get version
    let version_cmd = format!("{} --version", snippex_path);
    let result = ssh_executor.execute(&version_cmd)?;

    if !result.is_success() {
        return Err(Error::InvalidBinary(format!(
            "Snippex not found or not executable at '{}'\n\
             Exit code: {}\n\
             Stderr: {}\n\n\
             Suggestions:\n\
             • Install snippex on the remote machine\n\
             • Update the snippex_path in your configuration\n\
             • Verify PATH is set correctly for non-interactive SSH sessions",
            snippex_path,
            result.exit_code,
            result.stderr.trim()
        )));
    }

    Ok(result.stdout.trim().to_string())
}

/// Checks if required dependencies (NASM, linker) are available on the remote machine.
pub fn verify_simulation_dependencies(
    ssh_executor: &crate::remote::executor::SSHExecutor,
) -> Result<(), Error> {
    debug!("Verifying simulation dependencies");

    // Check NASM
    let nasm_result = ssh_executor.execute("which nasm")?;
    if !nasm_result.is_success() {
        return Err(Error::InvalidBinary(
            "NASM assembler not found on remote machine\n\
             Install with: sudo apt install nasm (Ubuntu/Debian) or sudo yum install nasm (RHEL/CentOS)"
                .to_string(),
        ));
    }

    // Check linker (ld)
    let ld_result = ssh_executor.execute("which ld")?;
    if !ld_result.is_success() {
        return Err(Error::InvalidBinary(
            "Linker (ld) not found on remote machine\n\
             Install with: sudo apt install binutils (Ubuntu/Debian) or sudo yum install binutils (RHEL/CentOS)"
                .to_string(),
        ));
    }

    debug!("All simulation dependencies verified");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diagnose_command_not_found() {
        let diagnosis = diagnose_remote_execution_failure(
            127,
            "bash: snippex: command not found",
            "",
            "snippex simulate-remote",
            "remote-host",
        );

        assert!(diagnosis.contains("not installed"));
        assert!(diagnosis.contains("Install snippex"));
        assert!(diagnosis.contains("remote-host"));
    }

    #[test]
    fn test_diagnose_binary_not_found() {
        let diagnosis = diagnose_remote_execution_failure(
            1,
            "Error: Failed to open binary file",
            "",
            "snippex simulate-remote",
            "remote-host",
        );

        assert!(diagnosis.contains("binary file is not present"));
        assert!(diagnosis.contains("uploaded with the package"));
    }

    #[test]
    fn test_diagnose_permission_denied() {
        let diagnosis = diagnose_remote_execution_failure(
            126,
            "Permission denied",
            "",
            "/usr/local/bin/snippex",
            "remote-host",
        );

        assert!(diagnosis.contains("Permission denied"));
        assert!(diagnosis.contains("execute permissions"));
    }

    #[test]
    fn test_diagnose_nasm_missing() {
        let diagnosis = diagnose_remote_execution_failure(
            1,
            "nasm: error: unable to find executable",
            "",
            "snippex simulate-remote",
            "remote-host",
        );

        assert!(diagnosis.contains("NASM"));
        assert!(diagnosis.contains("sudo apt install nasm"));
    }

    #[test]
    fn test_diagnose_linker_error() {
        let diagnosis = diagnose_remote_execution_failure(
            1,
            "ld: cannot find -lc",
            "",
            "snippex simulate-remote",
            "remote-host",
        );

        assert!(diagnosis.contains("Linker"));
        assert!(diagnosis.contains("build-essential"));
    }

    #[test]
    fn test_extract_command_name() {
        assert_eq!(extract_command_name("snippex --version"), "snippex");
        assert_eq!(
            extract_command_name("/usr/local/bin/snippex simulate-remote --package /tmp/foo"),
            "/usr/local/bin/snippex"
        );
        assert_eq!(extract_command_name("ls"), "ls");
    }

    #[test]
    fn test_indent_text() {
        let text = "line1\nline2\nline3";
        let indented = indent_text(text, 2);
        assert_eq!(indented, "  line1\n  line2\n  line3");
    }
}
