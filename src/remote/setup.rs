//! Setup utilities for remote snippex deployment.
//!
//! This module provides functions for cross-compiling snippex for different
//! architectures and verifying remote deployment prerequisites.

use crate::config::RemoteConfig;
use crate::error::{Error, Result};
use crate::remote::executor::SSHExecutor;
use log::{debug, info};
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Target triple for ARM64 Linux.
pub const TARGET_AARCH64: &str = "aarch64-unknown-linux-gnu";

/// Target triple for x86_64 Linux.
pub const TARGET_X86_64: &str = "x86_64-unknown-linux-gnu";

/// Status of a tool on the remote system.
#[derive(Debug, Clone)]
pub enum ToolStatus {
    /// Tool found at the given path
    Found(String),
    /// Tool not found
    NotFound,
    /// Error checking tool status
    Error(String),
}

impl ToolStatus {
    pub fn is_found(&self) -> bool {
        matches!(self, ToolStatus::Found(_))
    }
}

/// Result of setup checks on a remote system.
#[derive(Debug)]
pub struct SetupCheckResult {
    /// Version string from remote snippex
    pub snippex_version: String,
    /// NASM assembler status
    pub nasm: ToolStatus,
    /// Linker (ld) status
    pub linker: ToolStatus,
    /// x86_64 cross-compiler status (for ARM64 remotes)
    pub cross_gcc: ToolStatus,
    /// FEX-Emu status (optional)
    pub fex_emu: ToolStatus,
}

impl SetupCheckResult {
    /// Returns true if all required tools are available.
    pub fn all_required_available(&self) -> bool {
        self.nasm.is_found() && self.linker.is_found()
    }

    /// Returns the number of warnings (missing optional tools).
    pub fn warning_count(&self) -> usize {
        let mut count = 0;
        if !self.cross_gcc.is_found() {
            count += 1;
        }
        if !self.fex_emu.is_found() {
            count += 1;
        }
        count
    }
}

/// Checks if the required cross-compilation prerequisites are installed locally.
///
/// # Arguments
///
/// * `target` - The target triple (e.g., "aarch64-unknown-linux-gnu")
/// * `verbose` - Whether to print detailed output
///
/// # Returns
///
/// Ok(()) if all prerequisites are available, error otherwise.
pub fn check_cross_compile_prerequisites(target: &str, verbose: bool) -> Result<()> {
    info!(
        "Checking cross-compilation prerequisites for target: {}",
        target
    );

    // Check if rustup is available
    let output = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output();

    match output {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::InvalidBinary(format!(
                "rustup not found.\n\n\
                 Cross-compilation requires rustup to manage Rust toolchains.\n\n\
                 To install rustup:\n\
                 \n  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh\n\n\
                 If you installed Rust via system packages, you may need to:\n\
                 1. Uninstall system Rust (e.g., 'sudo pacman -R rust' or 'sudo apt remove rustc')\n\
                 2. Install rustup as shown above\n\
                 3. Re-run this command\n\n\
                 Alternatively, use --use-existing to deploy a pre-built binary:\n\
                 \n  snippex remote-setup {} --use-existing /path/to/snippex-arm64\n",
                target
            )));
        }
        Err(e) => {
            return Err(Error::InvalidBinary(format!(
                "Failed to run rustup: {}\n\n\
                 Ensure rustup is installed and in your PATH.",
                e
            )));
        }
        Ok(output) if !output.status.success() => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::InvalidBinary(format!(
                "rustup failed to list targets: {}\n\n\
                 Try running: rustup target list --installed",
                stderr.trim()
            )));
        }
        Ok(output) => {
            let installed_targets = String::from_utf8_lossy(&output.stdout);
            if !installed_targets.lines().any(|line| line.trim() == target) {
                return Err(Error::InvalidBinary(format!(
                    "Rust target '{}' is not installed.\n\n\
                     Install it with:\n\
                     \n  rustup target add {}\n",
                    target, target
                )));
            }

            if verbose {
                println!("  ✓ Rust target '{}' is installed", target);
            }
        }
    }

    // Check cross-linker
    let linker = match target {
        TARGET_AARCH64 => "aarch64-linux-gnu-gcc",
        TARGET_X86_64 => "x86_64-linux-gnu-gcc",
        _ => return Ok(()), // Unknown target, skip linker check
    };

    check_cross_linker(linker, target, verbose)?;

    Ok(())
}

/// Checks if a cross-linker is available.
fn check_cross_linker(linker: &str, target: &str, verbose: bool) -> Result<()> {
    let output = Command::new("which")
        .arg(linker)
        .output()
        .map_err(|e| Error::InvalidBinary(format!("Failed to run which: {}", e)))?;

    if !output.status.success() {
        let (install_hint, arch_name) = if linker.starts_with("aarch64") {
            (
                "  # Debian/Ubuntu:\n\
                 \n    sudo apt install gcc-aarch64-linux-gnu\n\n\
                 \n  # Fedora:\n\
                 \n    sudo dnf install gcc-aarch64-linux-gnu\n\n\
                 \n  # Arch Linux:\n\
                 \n    sudo pacman -S aarch64-linux-gnu-gcc\n",
                "ARM64",
            )
        } else if linker.starts_with("x86_64") {
            (
                "  # Debian/Ubuntu:\n\
                 \n    sudo apt install gcc-x86-64-linux-gnu\n\n\
                 \n  # Fedora:\n\
                 \n    sudo dnf install gcc-x86_64-linux-gnu\n\n\
                 \n  # Arch Linux:\n\
                 \n    sudo pacman -S x86_64-elf-gcc\n",
                "x86_64",
            )
        } else {
            (
                "  Install the appropriate cross-compiler for your distribution",
                "unknown",
            )
        };

        return Err(Error::InvalidBinary(format!(
            "Cross-linker '{}' not found.\n\n\
             To cross-compile snippex for {}, you need a {} cross-compiler toolchain.\n\n\
             Install it with:\n\
             {}\n\
             Alternatively, use --use-existing to deploy a pre-built binary:\n\
             \n  snippex remote-setup <remote> --use-existing /path/to/snippex-{}\n",
            linker,
            target,
            arch_name,
            install_hint,
            arch_name.to_lowercase()
        )));
    }

    if verbose {
        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        println!("  ✓ Cross-linker '{}' found at {}", linker, path);
    }

    Ok(())
}

/// Cross-compiles snippex for the specified target architecture.
///
/// # Arguments
///
/// * `target` - The target triple (e.g., "aarch64-unknown-linux-gnu")
/// * `force` - Force rebuild even if cached binary exists
/// * `verbose` - Print build output
///
/// # Returns
///
/// Path to the compiled binary.
pub fn cross_compile(target: &str, force: bool, verbose: bool) -> Result<PathBuf> {
    let binary_path = PathBuf::from(format!("target/{}/release/snippex", target));

    // Check if cached binary exists
    if !force && binary_path.exists() {
        info!("Using cached binary at: {}", binary_path.display());
        if verbose {
            println!("  Using cached binary (use --force-rebuild to rebuild)");
        }
        return Ok(binary_path);
    }

    info!("Cross-compiling for target: {}", target);
    if verbose {
        println!("  Cross-compiling for {}...", target);
    }

    // Determine the linker environment variable
    let linker_env_var = match target {
        TARGET_AARCH64 => "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER",
        TARGET_X86_64 => "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER",
        _ => {
            return Err(Error::InvalidBinary(format!(
                "Unsupported target: {}",
                target
            )));
        }
    };

    let linker = match target {
        TARGET_AARCH64 => "aarch64-linux-gnu-gcc",
        TARGET_X86_64 => "x86_64-linux-gnu-gcc",
        _ => unreachable!(),
    };

    // Run cargo build
    let mut cmd = Command::new("cargo");
    cmd.arg("build")
        .arg("--release")
        .arg("--target")
        .arg(target)
        .env(linker_env_var, linker);

    if verbose {
        cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    } else {
        cmd.stdout(Stdio::null()).stderr(Stdio::piped());
    }

    let output = cmd
        .output()
        .map_err(|e| Error::InvalidBinary(format!("Failed to run cargo build: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr_lower = stderr.to_lowercase();

        // Detect specific failure causes and provide targeted advice
        let suggestions = if stderr_lower.contains("openssl") || stderr_lower.contains("libssl") {
            format!(
                "The build failed because OpenSSL cannot be cross-compiled easily.\n\n\
                 Options to resolve this:\n\n\
                 1. Use the 'cross' tool (recommended for cross-compilation):\n\
                 \n    cargo install cross\n\
                 \n    cross build --release --target {}\n\
                 \n    Then use: snippex remote-setup <remote> --use-existing target/{}/release/snippex\n\n\
                 2. Build directly on the remote machine:\n\
                 \n    ssh <remote> 'curl --proto =https --tlsv1.2 -sSf https://sh.rustup.rs | sh'\n\
                 \n    scp -r . <remote>:snippex-src/\n\
                 \n    ssh <remote> 'cd snippex-src && cargo build --release'\n\n\
                 3. Use a pre-built binary if available:\n\
                 \n    snippex remote-setup <remote> --use-existing /path/to/snippex-arm64\n",
                target, target
            )
        } else if stderr_lower.contains("linker") || stderr_lower.contains("cannot find -l") {
            format!(
                "The build failed due to missing libraries for the target architecture.\n\n\
                 Try installing the full cross-compilation toolchain:\n\n\
                 # Arch Linux:\n\
                 \n  sudo pacman -S aarch64-linux-gnu-gcc aarch64-linux-gnu-glibc\n\n\
                 # Debian/Ubuntu:\n\
                 \n  sudo apt install gcc-aarch64-linux-gnu libc6-dev-arm64-cross\n\n\
                 Or use the 'cross' tool which handles this automatically:\n\
                 \n  cargo install cross\n\
                 \n  cross build --release --target {}\n",
                target
            )
        } else {
            "Suggestions:\n\
                 • Run with --verbose to see full build output\n\
                 • Check that all dependencies support the target architecture\n\
                 • Consider using the 'cross' tool: cargo install cross\n\
                 • Or build on the remote machine and use --use-existing"
                .to_string()
        };

        // Only show stderr snippet if not in verbose mode (verbose already showed it)
        let stderr_display = if verbose || stderr.trim().is_empty() {
            String::new()
        } else {
            // Show last 20 lines of error
            let lines: Vec<&str> = stderr.lines().collect();
            let start = lines.len().saturating_sub(20);
            format!(
                "Build output (last {} lines):\n{}\n\n",
                lines.len() - start,
                lines[start..].join("\n")
            )
        };

        return Err(Error::InvalidBinary(format!(
            "Cross-compilation failed for target '{}'.\n\n{}{}\n",
            target, stderr_display, suggestions
        )));
    }

    if !binary_path.exists() {
        return Err(Error::InvalidBinary(format!(
            "Binary not found at expected path: {}",
            binary_path.display()
        )));
    }

    // Report binary size
    if let Ok(metadata) = std::fs::metadata(&binary_path) {
        let size_mb = metadata.len() as f64 / (1024.0 * 1024.0);
        if verbose {
            println!("  ✓ Binary compiled: {:.2} MB", size_mb);
        }
        info!(
            "Binary compiled: {} ({:.2} MB)",
            binary_path.display(),
            size_mb
        );
    }

    Ok(binary_path)
}

/// Runs setup checks on a remote machine.
///
/// # Arguments
///
/// * `executor` - SSH executor for the remote machine
/// * `snippex_path` - Path to snippex on the remote
///
/// # Returns
///
/// SetupCheckResult containing status of all checked tools.
pub fn run_setup_checks(executor: &SSHExecutor, snippex_path: &str) -> Result<SetupCheckResult> {
    debug!("Running setup checks on remote");

    // Check snippex version
    let version_cmd = format!("{} --version", snippex_path);
    let version_result = executor.execute(&version_cmd)?;

    let snippex_version = if version_result.is_success() {
        version_result.stdout.trim().to_string()
    } else {
        return Err(Error::InvalidBinary(format!(
            "Failed to get snippex version: {}",
            version_result.stderr.trim()
        )));
    };

    // Check NASM
    let nasm = check_remote_tool(executor, "nasm");

    // Check linker
    let linker = check_remote_tool(executor, "ld");

    // Check x86_64 cross-compiler (for building x86 test binaries on ARM)
    let cross_gcc = check_remote_tool(executor, "x86_64-linux-gnu-gcc");

    // Check FEX-Emu (try both common binary names)
    let fex_emu = check_fex_emu(executor);

    Ok(SetupCheckResult {
        snippex_version,
        nasm,
        linker,
        cross_gcc,
        fex_emu,
    })
}

/// Checks if a tool is available on the remote system.
fn check_remote_tool(executor: &SSHExecutor, tool: &str) -> ToolStatus {
    let cmd = format!("which {}", tool);
    match executor.execute(&cmd) {
        Ok(result) => {
            if result.is_success() {
                ToolStatus::Found(result.stdout.trim().to_string())
            } else {
                ToolStatus::NotFound
            }
        }
        Err(e) => ToolStatus::Error(e.to_string()),
    }
}

/// Checks for FEX-Emu on the remote system.
fn check_fex_emu(executor: &SSHExecutor) -> ToolStatus {
    // Try FEXInterpreter first
    let cmd = "which FEXInterpreter 2>/dev/null || which FEXLoader 2>/dev/null";
    match executor.execute(cmd) {
        Ok(result) => {
            if result.is_success() && !result.stdout.trim().is_empty() {
                ToolStatus::Found(result.stdout.trim().to_string())
            } else {
                ToolStatus::NotFound
            }
        }
        Err(e) => ToolStatus::Error(e.to_string()),
    }
}

/// Maps architecture string to target triple.
pub fn arch_to_target(arch: &str) -> Result<&'static str> {
    match arch.to_lowercase().as_str() {
        "aarch64" | "arm64" => Ok(TARGET_AARCH64),
        "x86_64" | "x64" | "amd64" => Ok(TARGET_X86_64),
        _ => Err(Error::InvalidBinary(format!(
            "Unsupported architecture: '{}'. Expected 'aarch64' or 'x86_64'.",
            arch
        ))),
    }
}

/// Uploads a binary to the remote machine using SCP.
///
/// # Arguments
///
/// * `config` - Remote configuration
/// * `local_path` - Path to the local binary
/// * `remote_path` - Destination path on the remote
/// * `verbose` - Print progress information
pub fn upload_binary(
    config: &RemoteConfig,
    local_path: &PathBuf,
    remote_path: &str,
    verbose: bool,
) -> Result<()> {
    info!("Uploading binary to {}:{}", config.host, remote_path);
    if verbose {
        println!("  Uploading binary to {}...", remote_path);
    }

    // Get the parent directory of the remote path
    let remote_dir = std::path::Path::new(remote_path)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| "/tmp".to_string());

    // Create remote directory via SSH
    let mut ssh_cmd = Command::new("ssh");
    add_ssh_options(&mut ssh_cmd, config);
    ssh_cmd
        .arg(format!("{}@{}", config.user, config.host))
        .arg(format!("mkdir -p {}", remote_dir));

    let output = ssh_cmd
        .output()
        .map_err(|e| Error::Io(std::io::Error::other(format!("SSH failed: {}", e))))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::InvalidBinary(format!(
            "Failed to create remote directory: {}",
            stderr.trim()
        )));
    }

    // Upload binary via SCP
    let mut scp_cmd = Command::new("scp");
    add_scp_options(&mut scp_cmd, config);
    scp_cmd
        .arg(local_path)
        .arg(format!("{}@{}:{}", config.user, config.host, remote_path));

    let output = scp_cmd
        .output()
        .map_err(|e| Error::Io(std::io::Error::other(format!("SCP failed: {}", e))))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::InvalidBinary(format!(
            "SCP upload failed: {}\n\n\
             Suggestions:\n\
             • Check SSH connectivity: ssh {}@{}\n\
             • Verify disk space on remote: ssh {}@{} 'df -h'\n\
             • Check write permissions for {}",
            stderr.trim(),
            config.user,
            config.host,
            config.user,
            config.host,
            remote_dir
        )));
    }

    // Set executable permissions
    let mut chmod_cmd = Command::new("ssh");
    add_ssh_options(&mut chmod_cmd, config);
    chmod_cmd
        .arg(format!("{}@{}", config.user, config.host))
        .arg(format!("chmod +x {}", remote_path));

    let output = chmod_cmd
        .output()
        .map_err(|e| Error::Io(std::io::Error::other(format!("SSH failed: {}", e))))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::InvalidBinary(format!(
            "Failed to set executable permission: {}",
            stderr.trim()
        )));
    }

    if verbose {
        println!("  ✓ Binary uploaded and made executable");
    }

    Ok(())
}

/// Adds SSH options to a command.
fn add_ssh_options(cmd: &mut Command, config: &RemoteConfig) {
    cmd.arg("-o").arg("BatchMode=yes");
    cmd.arg("-o")
        .arg(format!("ConnectTimeout={}", config.timeout));
    cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");

    if let Some(ref key) = config.ssh_key {
        let expanded_key = expand_path(key);
        cmd.arg("-i").arg(expanded_key);
    }

    if config.port != 22 {
        cmd.arg("-p").arg(config.port.to_string());
    }
}

/// Adds SCP options to a command.
fn add_scp_options(cmd: &mut Command, config: &RemoteConfig) {
    cmd.arg("-o").arg("BatchMode=yes");
    cmd.arg("-o")
        .arg(format!("ConnectTimeout={}", config.timeout));
    cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");

    if let Some(ref key) = config.ssh_key {
        let expanded_key = expand_path(key);
        cmd.arg("-i").arg(expanded_key);
    }

    if config.port != 22 {
        cmd.arg("-P").arg(config.port.to_string()); // SCP uses -P, not -p
    }
}

/// Expands ~ in paths to the home directory.
fn expand_path(path: &str) -> String {
    if let Some(stripped) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(stripped).to_string_lossy().to_string();
        }
    }
    path.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arch_to_target() {
        assert_eq!(arch_to_target("aarch64").unwrap(), TARGET_AARCH64);
        assert_eq!(arch_to_target("arm64").unwrap(), TARGET_AARCH64);
        assert_eq!(arch_to_target("x86_64").unwrap(), TARGET_X86_64);
        assert_eq!(arch_to_target("amd64").unwrap(), TARGET_X86_64);
        assert!(arch_to_target("unsupported").is_err());
    }

    #[test]
    fn test_tool_status_is_found() {
        assert!(ToolStatus::Found("/usr/bin/nasm".to_string()).is_found());
        assert!(!ToolStatus::NotFound.is_found());
        assert!(!ToolStatus::Error("test".to_string()).is_found());
    }

    #[test]
    fn test_expand_path() {
        let expanded = expand_path("~/.ssh/id_rsa");
        if dirs::home_dir().is_some() {
            assert!(!expanded.starts_with("~"));
        }

        let absolute = expand_path("/usr/bin/test");
        assert_eq!(absolute, "/usr/bin/test");
    }
}
