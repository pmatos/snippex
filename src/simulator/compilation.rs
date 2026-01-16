use std::fs;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

use super::diagnostics;
use crate::error::{Error, Result};

pub struct CompilationPipeline {
    pub nasm_path: PathBuf,
    pub ld_path: PathBuf,
    pub temp_dir: TempDir,
}

impl CompilationPipeline {
    pub fn new() -> Result<Self> {
        Self::for_target("x86_64")
    }

    pub fn for_target(target_arch: &str) -> Result<Self> {
        // Check if NASM is available with detailed error message
        let nasm_path = Self::find_executable("nasm").ok_or_else(|| {
            if let Err(msg) = diagnostics::check_nasm_installation() {
                Error::Simulation(msg)
            } else {
                Error::Simulation(
                    "NASM assembler not found in PATH\n\n\
                     Suggestions:\n\
                     • Ubuntu/Debian: sudo apt install nasm\n\
                     • RHEL/CentOS: sudo yum install nasm\n\
                     • Arch Linux: sudo pacman -S nasm\n\
                     • macOS: brew install nasm\n\n\
                     Verify installation with: nasm --version"
                        .to_string(),
                )
            }
        })?;

        // Determine which linker to use based on host and target architecture
        let ld_path = Self::find_linker_for_target(target_arch)?;

        // Create temporary directory with secure permissions
        let temp_dir = tempfile::Builder::new()
            .prefix("fezinator_sim_")
            .tempdir()
            .map_err(|e| {
                Error::Simulation(format!(
                    "Failed to create temp directory: {}\n\n\
                     Suggestions:\n\
                     • Check disk space: df -h /tmp\n\
                     • Verify /tmp permissions: ls -la /tmp\n\
                     • Check TMPDIR environment variable\n\
                     • Try setting TMPDIR to a writable directory",
                    e
                ))
            })?;

        Ok(Self {
            nasm_path,
            ld_path,
            temp_dir,
        })
    }

    fn find_linker_for_target(target_arch: &str) -> Result<PathBuf> {
        let host_arch = std::env::consts::ARCH;

        // If host matches target, use native linker
        let needs_cross = match (host_arch, target_arch) {
            ("x86_64", "x86_64") => false,
            ("x86_64", "i386") => false,
            ("aarch64", "aarch64") => false,
            ("aarch64", "x86_64") => true,
            ("aarch64", "i386") => true,
            ("x86_64", "aarch64") => true,
            _ => false,
        };

        if needs_cross {
            // Try cross-compilation linker first
            let cross_ld = format!("{}-linux-gnu-ld", target_arch);
            if let Some(path) = Self::find_executable(&cross_ld) {
                log::info!("Using cross-linker: {}", path.display());
                return Ok(path);
            }

            // Alternative naming for i386/i686
            if target_arch == "i386" {
                if let Some(path) = Self::find_executable("i686-linux-gnu-ld") {
                    log::info!("Using cross-linker: {}", path.display());
                    return Ok(path);
                }
            }

            if let Err(msg) = diagnostics::check_cross_compilation_tools(target_arch) {
                return Err(Error::Simulation(msg));
            } else {
                return Err(Error::Simulation(format!(
                    "Cross-linker not found for target {}\n\n\
                     Suggestions:\n\
                     • Ubuntu/Debian: sudo apt install gcc-{}-linux-gnu\n\
                     • RHEL/CentOS: sudo yum install gcc-{}-linux-gnu\n\
                     • Verify with: which {}-linux-gnu-ld",
                    target_arch, target_arch, target_arch, target_arch
                )));
            }
        }

        // Use native linker
        Self::find_executable("ld").ok_or_else(|| {
            if let Err(msg) = diagnostics::check_linker_installation() {
                Error::Simulation(msg)
            } else {
                Error::Simulation(
                    "Linker (ld) not found in PATH\n\n\
                     Suggestions:\n\
                     • Ubuntu/Debian: sudo apt install binutils\n\
                     • RHEL/CentOS: sudo yum install binutils\n\
                     • Arch Linux: sudo pacman -S binutils\n\
                     • macOS: Install Xcode Command Line Tools: xcode-select --install\n\n\
                     Verify installation with: ld --version"
                        .to_string(),
                )
            }
        })
    }

    pub fn compile_and_link(
        &self,
        assembly_source: &str,
        binary_name: &str,
    ) -> Result<(PathBuf, PathBuf)> {
        let asm_file = self.temp_dir.path().join(format!("{binary_name}.asm"));
        let obj_file = self.temp_dir.path().join(format!("{binary_name}.o"));
        let binary_file = self.temp_dir.path().join(binary_name);

        // Write assembly source to file with buffering
        let file = fs::File::create(&asm_file)
            .map_err(|e| Error::Simulation(format!("Failed to create assembly file: {e}")))?;
        let mut writer = BufWriter::new(file);
        writer
            .write_all(assembly_source.as_bytes())
            .map_err(|e| Error::Simulation(format!("Failed to write assembly file: {e}")))?;
        writer
            .flush()
            .map_err(|e| Error::Simulation(format!("Failed to flush assembly file: {e}")))?;

        // Assemble with NASM
        self.assemble_with_nasm(&asm_file, &obj_file)?;

        // Link with ld
        self.link_with_ld(&obj_file, &binary_file)?;

        Ok((binary_file, asm_file))
    }

    fn assemble_with_nasm(&self, asm_file: &Path, obj_file: &Path) -> Result<()> {
        let output = Command::new(&self.nasm_path)
            .args(["-f", "elf64"])
            .arg("-o")
            .arg(obj_file)
            .arg(asm_file)
            .output()
            .map_err(|e| {
                Error::Simulation(format!(
                    "Failed to run NASM: {}\n\n\
                     Suggestions:\n\
                     • Verify NASM is installed: nasm --version\n\
                     • Check NASM path: {}\n\
                     • Reinstall if needed: sudo apt install nasm",
                    e,
                    self.nasm_path.display()
                ))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let diag = diagnostics::diagnose_nasm_error(&stderr, asm_file);
            return Err(Error::Simulation(diag));
        }

        Ok(())
    }

    fn link_with_ld(&self, obj_file: &Path, binary_file: &Path) -> Result<()> {
        let output = Command::new(&self.ld_path)
            .arg("-o")
            .arg(binary_file)
            .arg(obj_file)
            .output()
            .map_err(|e| {
                Error::Simulation(format!(
                    "Failed to run linker: {}\n\n\
                     Suggestions:\n\
                     • Verify linker is installed: ld --version\n\
                     • Check linker path: {}\n\
                     • Reinstall if needed: sudo apt install binutils",
                    e,
                    self.ld_path.display()
                ))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let diag = diagnostics::diagnose_linker_error(&stderr, obj_file, binary_file);
            return Err(Error::Simulation(diag));
        }

        Ok(())
    }

    fn find_executable(name: &str) -> Option<PathBuf> {
        // Use which-style lookup to avoid race conditions
        std::env::var_os("PATH").and_then(|paths| {
            std::env::split_paths(&paths).find_map(|dir| {
                let full_path = dir.join(name);
                // Check if file exists and is executable in a single operation
                if full_path.is_file() {
                    // Test actual execution to avoid race conditions
                    if let Ok(output) = Command::new(&full_path).arg("--version").output() {
                        if output.status.success() {
                            return Some(full_path);
                        }
                    }
                }
                None
            })
        })
    }

    #[allow(dead_code)]
    pub fn get_temp_dir(&self) -> &Path {
        self.temp_dir.path()
    }
}
