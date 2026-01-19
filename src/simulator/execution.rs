use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use super::diagnostics;
use super::emulator::EmulatorConfig;
use crate::error::{Error, Result};

pub struct ExecutionResult {
    pub output_data: Vec<u8>,
    pub exit_code: i32,
    pub execution_time: Duration,
    #[allow(dead_code)]
    pub stderr: String,
}

pub struct ExecutionHarness {
    pub timeout_seconds: u64,
}

impl Default for ExecutionHarness {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecutionHarness {
    pub fn new() -> Self {
        Self { timeout_seconds: 5 }
    }

    #[allow(dead_code)]
    pub fn with_timeout(timeout_seconds: u64) -> Self {
        Self { timeout_seconds }
    }

    pub fn execute_binary(
        &self,
        binary_path: &Path,
        emulator: Option<&EmulatorConfig>,
    ) -> Result<ExecutionResult> {
        match emulator {
            Some(emulator_config) => self.execute_with_emulator(binary_path, emulator_config),
            None => self.execute_native(binary_path),
        }
    }

    fn execute_native(&self, binary_path: &Path) -> Result<ExecutionResult> {
        let start_time = Instant::now();

        // Verify binary exists before attempting execution
        if !binary_path.exists() {
            return Err(Error::Simulation(format!(
                "Binary file not found: {}\n\n\
                 Suggestions:\n\
                 • Verify the compilation step completed successfully\n\
                 • Check write permissions in the temporary directory\n\
                 • Ensure sufficient disk space is available",
                binary_path.display()
            )));
        }

        // TODO: SECURITY: Implement process sandboxing for code execution
        // This executes generated assembly directly without sandboxing, which poses significant security risks.
        // Recommendation: Implement containerization or chroot jail for execution
        // Alternative: Add strict resource limits and process isolation
        let output = Command::new(binary_path).output().map_err(|e| {
            let err_str = e.to_string();
            if err_str.contains("Permission denied") {
                Error::Simulation(format!(
                    "Failed to execute binary: {}\n\n\
                     Suggestions:\n\
                     • Binary does not have execute permissions\n\
                     • Try: chmod +x {}\n\
                     • Check if filesystem is mounted with noexec option",
                    e,
                    binary_path.display()
                ))
            } else if err_str.contains("No such file or directory") {
                Error::Simulation(format!(
                    "Failed to execute binary: {}\n\n\
                     Suggestions:\n\
                     • The binary or a required interpreter was not found\n\
                     • Verify the binary exists: ls -la {}\n\
                     • Check binary format: file {}",
                    e,
                    binary_path.display(),
                    binary_path.display()
                ))
            } else {
                Error::Simulation(format!(
                    "Failed to execute binary: {}\n\n\
                     Suggestions:\n\
                     • Check system resources (memory, file descriptors)\n\
                     • Verify binary is valid: file {}\n\
                     • Try running manually: {}",
                    e,
                    binary_path.display(),
                    binary_path.display()
                ))
            }
        })?;

        let execution_time = start_time.elapsed();

        // TODO: PERFORMANCE: Implement proper timeout handling
        // Current implementation checks elapsed time after process finishes, not enforcing timeout during execution
        // Consider using timeout-aware spawn API or manually killing process if exceeds timeout
        if execution_time > Duration::from_secs(self.timeout_seconds) {
            return Err(Error::Simulation(format!(
                "Execution timeout: exceeded {} seconds\n\n\
                 Suggestions:\n\
                 • The assembly block may contain an infinite loop\n\
                 • Try extracting a different block\n\
                 • Increase timeout with --timeout option if needed",
                self.timeout_seconds
            )));
        }

        let exit_code = output.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        // Provide diagnostic info for non-zero exit codes
        if exit_code != 0 && !output.stdout.is_empty() {
            // Non-zero exit with output - might still be valid simulation
            // Just log the issue for debugging
        } else if exit_code != 0 {
            let diag = diagnostics::diagnose_execution_failure(
                binary_path,
                Some(exit_code),
                &stderr,
                None,
            );
            return Err(Error::Simulation(diag));
        }

        Ok(ExecutionResult {
            output_data: output.stdout,
            exit_code,
            execution_time,
            stderr,
        })
    }

    fn execute_with_emulator(
        &self,
        binary_path: &Path,
        emulator: &EmulatorConfig,
    ) -> Result<ExecutionResult> {
        let start_time = Instant::now();

        // Verify binary exists before attempting execution
        if !binary_path.exists() {
            return Err(Error::Simulation(format!(
                "Binary file not found: {}\n\n\
                 Suggestions:\n\
                 • Verify the compilation step completed successfully\n\
                 • Check write permissions in the temporary directory\n\
                 • Ensure sufficient disk space is available",
                binary_path.display()
            )));
        }

        let (emulator_name, output) = match emulator {
            EmulatorConfig::Qemu { binary, args } => {
                let mut cmd = Command::new(binary);
                cmd.args(args);
                cmd.arg(binary_path);
                let output = cmd.output().map_err(|e| {
                    let err_str = e.to_string();
                    if err_str.contains("No such file or directory")
                        || err_str.contains("not found")
                    {
                        Error::Simulation(format!(
                            "QEMU not found: {}\n\n\
                             Suggestions:\n\
                             • Install QEMU: sudo apt install qemu-user (Ubuntu/Debian)\n\
                             • Or: sudo yum install qemu-user (RHEL/CentOS)\n\
                             • Verify installation: which {}\n\
                             • Check PATH includes QEMU location",
                            e, binary
                        ))
                    } else {
                        Error::Simulation(format!(
                            "Failed to execute with QEMU: {}\n\n\
                             Suggestions:\n\
                             • Verify QEMU is properly installed: {} --version\n\
                             • Check the binary is valid for the target architecture\n\
                             • Try running manually: {} {}",
                            e,
                            binary,
                            binary,
                            binary_path.display()
                        ))
                    }
                })?;
                ("qemu", output)
            }
            EmulatorConfig::FexEmu { binary, args } => {
                let mut cmd = Command::new(binary);
                cmd.args(args);
                cmd.arg(binary_path);
                let output = cmd.output().map_err(|e| {
                    let err_str = e.to_string();
                    if err_str.contains("No such file or directory")
                        || err_str.contains("not found")
                    {
                        Error::Simulation(format!(
                            "FEX-Emu not found: {}\n\n\
                             Suggestions:\n\
                             • Install FEX-Emu from: https://github.com/FEX-Emu/FEX\n\
                             • Verify installation: FEXInterpreter --version\n\
                             • Set up rootfs: FEXRootFSFetcher\n\
                             • Ensure PATH includes FEX-Emu location",
                            e
                        ))
                    } else {
                        Error::Simulation(format!(
                            "Failed to execute with FEX-Emu: {}\n\n\
                             Suggestions:\n\
                             • Verify FEX-Emu installation: {} --version\n\
                             • Check rootfs is configured: FEXRootFSFetcher\n\
                             • Ensure the binary is valid x86/x86_64 ELF\n\
                             • Try running manually: {} {}",
                            e,
                            binary,
                            binary,
                            binary_path.display()
                        ))
                    }
                })?;
                ("fex-emu", output)
            }
            EmulatorConfig::Native => {
                return self.execute_native(binary_path);
            }
        };

        let execution_time = start_time.elapsed();

        if execution_time > Duration::from_secs(self.timeout_seconds) {
            return Err(Error::Simulation(format!(
                "Execution timeout with {}: exceeded {} seconds\n\n\
                 Suggestions:\n\
                 • The assembly block may contain an infinite loop\n\
                 • Emulator may be stalling on complex instructions\n\
                 • Try a different block or increase timeout",
                emulator_name, self.timeout_seconds
            )));
        }

        let exit_code = output.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        // Provide diagnostic info for non-zero exit codes with emulator
        if exit_code != 0 && output.stdout.is_empty() {
            let diag = diagnostics::diagnose_execution_failure(
                binary_path,
                Some(exit_code),
                &stderr,
                Some(emulator_name),
            );
            return Err(Error::Simulation(diag));
        }

        Ok(ExecutionResult {
            output_data: output.stdout,
            exit_code,
            execution_time,
            stderr,
        })
    }
}
