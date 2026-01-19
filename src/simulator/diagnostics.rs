//! Diagnostic utilities for local simulation failures.
//!
//! This module provides functions to analyze and diagnose common simulation
//! failures, providing helpful error messages and actionable suggestions.

use std::path::Path;
use std::process::Command;

/// Checks if a required tool is available on the system.
pub fn check_tool_available(tool: &str) -> bool {
    Command::new("which")
        .arg(tool)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Checks if NASM assembler is installed and provides installation guidance.
pub fn check_nasm_installation() -> Result<(), String> {
    if check_tool_available("nasm") {
        return Ok(());
    }

    Err("NASM assembler is not installed\n\n\
         Suggestions:\n\
         • Ubuntu/Debian: sudo apt install nasm\n\
         • RHEL/CentOS: sudo yum install nasm\n\
         • Arch Linux: sudo pacman -S nasm\n\
         • macOS: brew install nasm\n\n\
         Verify installation with: nasm --version"
        .to_string())
}

/// Checks if linker (ld) is available and provides installation guidance.
pub fn check_linker_installation() -> Result<(), String> {
    if check_tool_available("ld") {
        return Ok(());
    }

    Err("Linker (ld) is not installed\n\n\
         Suggestions:\n\
         • Ubuntu/Debian: sudo apt install binutils\n\
         • RHEL/CentOS: sudo yum install binutils\n\
         • Arch Linux: sudo pacman -S binutils\n\
         • macOS: Install Xcode Command Line Tools: xcode-select --install\n\n\
         Verify installation with: ld --version"
        .to_string())
}

/// Checks if cross-compilation tools are available for the target architecture.
pub fn check_cross_compilation_tools(target_arch: &str) -> Result<(), String> {
    let cross_linker = format!("{}-linux-gnu-ld", target_arch);
    if check_tool_available(&cross_linker) {
        return Ok(());
    }

    let package_name = match target_arch {
        "aarch64" => "gcc-aarch64-linux-gnu",
        "x86_64" => "gcc-x86-64-linux-gnu",
        "i686" => "gcc-i686-linux-gnu",
        _ => "gcc-<arch>-linux-gnu",
    };

    Err(format!(
        "Cross-linker '{}' not found for target {}\n\n\
         Suggestions:\n\
         • Ubuntu/Debian: sudo apt install {}\n\
         • RHEL/CentOS: sudo yum install {}\n\
         • Arch Linux: sudo pacman -S {}\n\n\
         Verify installation with: which {}",
        cross_linker, target_arch, package_name, package_name, package_name, cross_linker
    ))
}

/// Diagnoses a binary execution failure and provides helpful suggestions.
pub fn diagnose_execution_failure(
    binary_path: &Path,
    exit_code: Option<i32>,
    stderr: &str,
    emulator: Option<&str>,
) -> String {
    let stderr_lower = stderr.to_lowercase();
    let mut suggestions = Vec::new();

    // Check if binary exists
    if !binary_path.exists() {
        suggestions.push(format!(
            "• Binary file not found: {}",
            binary_path.display()
        ));
        suggestions.push("• Ensure compilation completed successfully".to_string());
        suggestions.push("• Check temporary directory permissions".to_string());
        return format_diagnostic_message(
            "Binary not found",
            binary_path,
            exit_code,
            stderr,
            &suggestions,
        );
    }

    // Check for permission issues
    if stderr_lower.contains("permission denied") {
        suggestions.push("• Binary does not have execute permissions".to_string());
        suggestions.push(format!("• Try: chmod +x {}", binary_path.display()));
        suggestions.push("• Check if filesystem is mounted with noexec option".to_string());
    }
    // Check for architecture mismatch
    else if stderr_lower.contains("cannot execute binary")
        || stderr_lower.contains("exec format error")
    {
        suggestions.push("• Binary architecture does not match host system".to_string());
        if let Some(emu) = emulator {
            suggestions.push(format!("• Ensure {} is correctly configured", emu));
        } else {
            suggestions
                .push("• Consider using an emulator for cross-architecture execution".to_string());
            suggestions.push("• For x86 on ARM64: use FEX-Emu".to_string());
            suggestions.push("• For ARM64 on x86: use QEMU".to_string());
        }
    }
    // Check for missing libraries
    else if stderr_lower.contains("not found") && stderr_lower.contains("lib") {
        suggestions.push("• Required shared library not found".to_string());
        suggestions.push("• The generated binary should be statically linked".to_string());
        suggestions.push("• Check linker command uses -static flag".to_string());
    }
    // Check for segmentation fault
    else if stderr_lower.contains("segfault")
        || stderr_lower.contains("segmentation fault")
        || exit_code == Some(-11)
        || exit_code == Some(139)
    {
        suggestions.push("• Simulation crashed with segmentation fault".to_string());
        suggestions.push("• The assembly block may access invalid memory addresses".to_string());
        suggestions.push("• Try a different block or check memory access patterns".to_string());
        suggestions.push("• Verify sandbox memory is properly initialized".to_string());
    }
    // Check for illegal instruction
    else if stderr_lower.contains("illegal instruction")
        || exit_code == Some(-4)
        || exit_code == Some(132)
    {
        suggestions.push("• Execution failed with illegal instruction".to_string());
        suggestions
            .push("• The block may use CPU instructions not supported on this system".to_string());
        suggestions.push(
            "• Check if the binary was compiled for a different CPU architecture".to_string(),
        );
    }
    // Check for emulator-specific issues
    else if let Some(emu) = emulator {
        if stderr_lower.contains("fex") || stderr_lower.contains("fexemu") {
            suggestions.push("• FEX-Emu execution failed".to_string());
            suggestions.push("• Verify FEX-Emu is installed: FEXInterpreter --version".to_string());
            suggestions.push("• Check FEX-Emu rootfs is configured: FEXRootFSFetcher".to_string());
            suggestions.push("• Ensure the binary is valid x86/x86_64 ELF".to_string());
        } else if emu.contains("qemu") {
            suggestions.push("• QEMU execution failed".to_string());
            suggestions.push("• Verify QEMU is installed: qemu-x86_64 --version".to_string());
            suggestions.push("• Check QEMU user-mode is properly set up".to_string());
        }
    }
    // Generic failure
    else if let Some(code) = exit_code {
        if code != 0 {
            suggestions.push(format!("• Execution failed with exit code {}", code));
            suggestions.push("• Review assembly block for potential issues".to_string());
            suggestions.push("• Try running the binary manually to debug".to_string());
        }
    }

    if suggestions.is_empty() {
        suggestions.push("• Unknown execution error".to_string());
        suggestions.push("• Check stderr output for details".to_string());
    }

    format_diagnostic_message(
        "Execution failed",
        binary_path,
        exit_code,
        stderr,
        &suggestions,
    )
}

/// Diagnoses NASM assembly errors and provides helpful suggestions.
pub fn diagnose_nasm_error(stderr: &str, asm_file: &Path) -> String {
    let stderr_lower = stderr.to_lowercase();
    let mut suggestions = Vec::new();

    if stderr_lower.contains("no such instruction") {
        suggestions.push("• NASM encountered an unknown instruction".to_string());
        suggestions
            .push("• The assembly may contain instructions not supported by NASM".to_string());
        suggestions
            .push("• Check if the instruction is x86-specific and properly encoded".to_string());
    } else if stderr_lower.contains("symbol") && stderr_lower.contains("undefined") {
        suggestions.push("• Undefined symbol in assembly".to_string());
        suggestions.push("• The extracted block may reference external symbols".to_string());
        suggestions.push("• Verify the assembly harness includes all necessary labels".to_string());
    } else if stderr_lower.contains("operand") {
        suggestions.push("• Invalid operand in assembly instruction".to_string());
        suggestions.push("• The extracted block may have encoding issues".to_string());
        suggestions.push("• Check the original binary for potential parsing errors".to_string());
    } else {
        suggestions.push("• NASM assembly failed".to_string());
        suggestions.push("• Review the generated assembly file for errors".to_string());
    }

    suggestions.push(format!("• Inspect assembly file: {}", asm_file.display()));
    suggestions.push("• Verify NASM version: nasm --version".to_string());

    let mut msg = "NASM assembly failed\n\n".to_string();
    msg.push_str(&format!("Assembly file: {}\n\n", asm_file.display()));

    if !stderr.is_empty() {
        msg.push_str("NASM output:\n");
        for line in stderr.lines().take(10) {
            msg.push_str(&format!("  {}\n", line));
        }
        if stderr.lines().count() > 10 {
            msg.push_str("  ... (output truncated)\n");
        }
        msg.push('\n');
    }

    msg.push_str("Suggestions:\n");
    msg.push_str(&suggestions.join("\n"));

    msg
}

/// Diagnoses linker errors and provides helpful suggestions.
pub fn diagnose_linker_error(stderr: &str, obj_file: &Path, output_file: &Path) -> String {
    let stderr_lower = stderr.to_lowercase();
    let mut suggestions = Vec::new();

    if stderr_lower.contains("undefined reference") {
        suggestions.push("• Linker found undefined symbol references".to_string());
        suggestions
            .push("• The assembly may reference symbols not present in the harness".to_string());
    } else if stderr_lower.contains("cannot find") {
        suggestions.push("• Linker cannot find required files or libraries".to_string());
        suggestions.push("• Verify the object file was created successfully".to_string());
        if !obj_file.exists() {
            suggestions.push(format!("• Object file missing: {}", obj_file.display()));
        }
    } else if stderr_lower.contains("multiple definition") {
        suggestions.push("• Multiple definition of symbol".to_string());
        suggestions.push("• The assembly harness may have duplicate labels".to_string());
    } else {
        suggestions.push("• Linker failed to create executable".to_string());
        suggestions.push("• Review linker output for specific errors".to_string());
    }

    suggestions.push("• Verify linker is installed: ld --version".to_string());
    suggestions.push(format!("• Input object file: {}", obj_file.display()));
    suggestions.push(format!("• Output binary: {}", output_file.display()));

    let mut msg = "Linker failed\n\n".to_string();

    if !stderr.is_empty() {
        msg.push_str("Linker output:\n");
        for line in stderr.lines().take(10) {
            msg.push_str(&format!("  {}\n", line));
        }
        if stderr.lines().count() > 10 {
            msg.push_str("  ... (output truncated)\n");
        }
        msg.push('\n');
    }

    msg.push_str("Suggestions:\n");
    msg.push_str(&suggestions.join("\n"));

    msg
}

/// Helper to format a diagnostic message with consistent structure.
fn format_diagnostic_message(
    title: &str,
    binary_path: &Path,
    exit_code: Option<i32>,
    stderr: &str,
    suggestions: &[String],
) -> String {
    let mut msg = format!("{}\n\n", title);
    msg.push_str(&format!("Binary: {}\n", binary_path.display()));

    if let Some(code) = exit_code {
        msg.push_str(&format!("Exit code: {}\n", code));
    }
    msg.push('\n');

    if !stderr.is_empty() {
        msg.push_str("Stderr:\n");
        for line in stderr.lines().take(5) {
            msg.push_str(&format!("  {}\n", line));
        }
        if stderr.lines().count() > 5 {
            msg.push_str("  ... (output truncated)\n");
        }
        msg.push('\n');
    }

    msg.push_str("Suggestions:\n");
    msg.push_str(&suggestions.join("\n"));

    msg
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_check_tool_available() {
        // 'sh' should exist on all Unix systems
        assert!(check_tool_available("sh"));
        // This definitely shouldn't exist
        assert!(!check_tool_available("nonexistent_tool_12345"));
    }

    #[test]
    fn test_diagnose_segfault() {
        let path = PathBuf::from("/tmp/test_binary");
        let diag = diagnose_execution_failure(&path, Some(-11), "", None);
        assert!(diag.contains("segmentation fault"));
        assert!(diag.contains("invalid memory"));
    }

    #[test]
    fn test_diagnose_illegal_instruction() {
        let path = PathBuf::from("/tmp/test_binary");
        let diag = diagnose_execution_failure(&path, Some(-4), "illegal instruction", None);
        assert!(diag.contains("illegal instruction"));
        assert!(diag.contains("CPU instructions"));
    }

    #[test]
    fn test_diagnose_permission_denied() {
        let path = PathBuf::from("/tmp/test_binary");
        let diag = diagnose_execution_failure(&path, Some(1), "Permission denied", None);
        assert!(diag.contains("execute permissions"));
        assert!(diag.contains("chmod"));
    }

    #[test]
    fn test_diagnose_nasm_error() {
        let path = PathBuf::from("/tmp/test.asm");
        let diag = diagnose_nasm_error("error: no such instruction", &path);
        assert!(diag.contains("unknown instruction"));
        assert!(diag.contains("NASM"));
    }

    #[test]
    fn test_diagnose_linker_error() {
        let obj = PathBuf::from("/tmp/test.o");
        let out = PathBuf::from("/tmp/test");
        let diag = diagnose_linker_error("undefined reference to 'main'", &obj, &out);
        assert!(diag.contains("undefined"));
        assert!(diag.contains("symbol"));
    }
}
