//! CLI command for remote snippex deployment.
//!
//! This command cross-compiles snippex for a target architecture, deploys it
//! to a configured remote machine, and runs self-checks to verify the setup.

use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

use crate::config::Config;
use crate::remote::executor::SSHExecutor;
use crate::remote::setup::{self, SetupCheckResult, ToolStatus, TARGET_AARCH64, TARGET_X86_64};

#[derive(Args)]
#[command(about = "Cross-compile and deploy snippex to a remote machine")]
pub struct RemoteSetupCommand {
    /// Name of a configured remote (from `snippex config add-remote`)
    pub remote: String,

    /// Force rebuild even if a cached binary exists
    #[arg(short, long)]
    pub force_rebuild: bool,

    /// Skip dependency verification on remote
    #[arg(long)]
    pub skip_deps_check: bool,

    /// Use existing binary instead of cross-compiling
    #[arg(long)]
    pub use_existing: Option<PathBuf>,

    /// Verbose output showing all steps
    #[arg(short, long)]
    pub verbose: bool,

    /// Dry run - show what would be done without executing
    #[arg(long)]
    pub dry_run: bool,
}

impl RemoteSetupCommand {
    pub fn execute(&self) -> Result<()> {
        // Phase 1: Load and validate remote config
        println!("Phase 1: Loading remote configuration...");
        let config = Config::load()?;

        let remote_config = config.get_remote(&self.remote).ok_or_else(|| {
            anyhow::anyhow!(
                "Remote '{}' not configured.\n\n\
                 Add it with:\n\
                 \n  snippex config add-remote {} --host <hostname> --user <username> --arch aarch64\n\n\
                 Or list existing remotes with:\n\
                 \n  snippex config list-remotes\n",
                self.remote, self.remote
            )
        })?;

        let arch = remote_config.architecture.as_deref().unwrap_or("aarch64");
        let target = setup::arch_to_target(arch)?;

        if self.verbose || self.dry_run {
            println!(
                "  Remote: {} ({}@{})",
                self.remote, remote_config.user, remote_config.host
            );
            println!("  Architecture: {} -> {}", arch, target);
            println!("  Snippex path: {}", remote_config.snippex_path);
        }

        // Test SSH connection
        if !self.dry_run {
            print!("  Testing SSH connection... ");
            let executor = SSHExecutor::new(remote_config.clone());
            executor.test_connection()?;
            println!("✓");
        } else {
            println!("  [DRY RUN] Would test SSH connection");
        }

        // Phase 2: Check local prerequisites
        println!("\nPhase 2: Checking local prerequisites...");
        if !self.dry_run {
            setup::check_cross_compile_prerequisites(target, self.verbose)?;
            if !self.verbose {
                println!("  ✓ All prerequisites available");
            }
        } else {
            println!("  [DRY RUN] Would check for:");
            println!("    - Rust target: {}", target);
            if target == TARGET_AARCH64 {
                println!("    - Cross-linker: aarch64-linux-gnu-gcc");
            } else if target == TARGET_X86_64 {
                println!("    - Cross-linker: x86_64-linux-gnu-gcc");
            }
        }

        // Phase 3: Cross-compile or use existing binary
        println!("\nPhase 3: Preparing binary...");
        let binary_path = if let Some(ref existing) = self.use_existing {
            if !existing.exists() {
                return Err(anyhow::anyhow!(
                    "Specified binary does not exist: {}",
                    existing.display()
                ));
            }
            println!("  Using existing binary: {}", existing.display());
            existing.clone()
        } else if self.dry_run {
            println!("  [DRY RUN] Would cross-compile for {}", target);
            if self.force_rebuild {
                println!("    (force rebuild enabled)");
            }
            PathBuf::from(format!("target/{}/release/snippex", target))
        } else {
            setup::cross_compile(target, self.force_rebuild, self.verbose)?
        };

        if !self.dry_run {
            let metadata = std::fs::metadata(&binary_path)?;
            let size_mb = metadata.len() as f64 / (1024.0 * 1024.0);
            println!("  Binary: {} ({:.2} MB)", binary_path.display(), size_mb);
        }

        // Phase 4: Deploy to remote
        println!("\nPhase 4: Deploying to remote...");
        if self.dry_run {
            println!("  [DRY RUN] Would:");
            println!("    - Create directory for: {}", remote_config.snippex_path);
            println!(
                "    - Upload: {} -> {}",
                binary_path.display(),
                remote_config.snippex_path
            );
            println!("    - Set executable permission");
        } else {
            setup::upload_binary(
                remote_config,
                &binary_path,
                &remote_config.snippex_path,
                self.verbose,
            )?;
            if !self.verbose {
                println!("  ✓ Binary deployed to {}", remote_config.snippex_path);
            }
        }

        // Phase 5: Run self-checks
        println!("\nPhase 5: Running self-checks...");
        if self.dry_run {
            println!("  [DRY RUN] Would verify:");
            println!("    - snippex --version");
            if !self.skip_deps_check {
                println!("    - nasm (assembler)");
                println!("    - ld (linker)");
                println!("    - x86_64-linux-gnu-gcc (cross-compiler)");
                println!("    - FEXInterpreter/FEXLoader (optional)");
            }
        } else {
            let executor = SSHExecutor::new(remote_config.clone());

            // Verify version
            print!("  Checking snippex version... ");
            let check_result = if self.skip_deps_check {
                // Just check version
                let version_cmd = format!("{} --version", remote_config.snippex_path);
                let result = executor.execute(&version_cmd)?;
                if !result.is_success() {
                    return Err(anyhow::anyhow!(
                        "Snippex verification failed: {}",
                        result.stderr.trim()
                    ));
                }
                println!("✓");
                println!("    {}", result.stdout.trim());

                // Create minimal check result
                SetupCheckResult {
                    snippex_version: result.stdout.trim().to_string(),
                    nasm: ToolStatus::NotFound,
                    linker: ToolStatus::NotFound,
                    cross_gcc: ToolStatus::NotFound,
                    fex_emu: ToolStatus::NotFound,
                }
            } else {
                let result = setup::run_setup_checks(&executor, &remote_config.snippex_path)?;
                println!("✓");
                println!("    {}", result.snippex_version);
                result
            };

            // Print dependency status
            if !self.skip_deps_check {
                println!("\n  Dependencies:");
                print_tool_status("nasm", &check_result.nasm, false);
                print_tool_status("ld", &check_result.linker, false);
                print_tool_status("x86_64-linux-gnu-gcc", &check_result.cross_gcc, true);
                print_tool_status("FEX-Emu", &check_result.fex_emu, true);
            }

            // Phase 6: Report summary
            println!("\n{}", "=".repeat(60));
            println!("Setup complete!");
            println!(
                "  Remote: {} ({}@{})",
                self.remote, remote_config.user, remote_config.host
            );
            println!("  Path: {}", remote_config.snippex_path);
            println!("  Version: {}", check_result.snippex_version);

            if !self.skip_deps_check {
                if check_result.all_required_available() {
                    println!("\n✓ All required dependencies available");
                } else {
                    println!("\n⚠ Some required dependencies are missing:");
                    if !check_result.nasm.is_found() {
                        println!("  • nasm: Install with 'sudo apt install nasm'");
                    }
                    if !check_result.linker.is_found() {
                        println!("  • ld: Install with 'sudo apt install binutils'");
                    }
                }

                if check_result.warning_count() > 0 {
                    println!("\nOptional dependencies:");
                    if !check_result.cross_gcc.is_found() {
                        println!("  ⚠ x86_64-linux-gnu-gcc: Not found (needed for cross-compiling x86 tests)");
                    }
                    if !check_result.fex_emu.is_found() {
                        println!("  ⚠ FEX-Emu: Not found (optional - install for x86 emulation)");
                    }
                }
            }

            println!(
                "\nReady for: snippex validate --remote {} <extraction-id>",
                self.remote
            );
        }

        if self.dry_run {
            println!("\n[DRY RUN] No changes were made.");
        }

        Ok(())
    }
}

/// Prints the status of a tool with appropriate formatting.
fn print_tool_status(name: &str, status: &ToolStatus, optional: bool) {
    match status {
        ToolStatus::Found(path) => {
            println!("  ✓ {}: {}", name, path);
        }
        ToolStatus::NotFound => {
            if optional {
                println!("  ⚠ {}: not found (optional)", name);
            } else {
                println!("  ✗ {}: not found", name);
            }
        }
        ToolStatus::Error(e) => {
            println!("  ✗ {}: error checking - {}", name, e);
        }
    }
}
