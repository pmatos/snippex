//! CLI command for managing Snippex configuration.

use anyhow::Result;
use clap::{Args, Subcommand};
use std::process::Command;

use crate::config::{Config, RemoteConfig};

#[derive(Args)]
#[command(about = "Manage Snippex configuration")]
pub struct ConfigCommand {
    #[command(subcommand)]
    pub action: ConfigAction,
}

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Show current configuration
    Show,

    /// Show the configuration file path
    Path,

    /// List all configured remotes
    ListRemotes,

    /// Add a new remote configuration
    AddRemote {
        /// Name for the remote (e.g., "x86-oracle", "arm64-fex")
        name: String,

        /// Hostname or IP address
        #[arg(long)]
        host: String,

        /// SSH username
        #[arg(long)]
        user: String,

        /// SSH port (default: 22)
        #[arg(long, default_value = "22")]
        port: u16,

        /// Path to snippex binary on remote
        #[arg(long, default_value = "snippex")]
        snippex_path: String,

        /// Path to SSH private key
        #[arg(long)]
        ssh_key: Option<String>,

        /// Architecture of remote (x86_64, aarch64)
        #[arg(long)]
        architecture: Option<String>,

        /// Connection timeout in seconds
        #[arg(long, default_value = "60")]
        timeout: u64,

        /// Path to FEX-Emu binary on remote (optional)
        #[arg(long)]
        fex_path: Option<String>,
    },

    /// Remove a remote configuration
    RemoveRemote {
        /// Name of the remote to remove
        name: String,
    },

    /// Show details of a specific remote
    ShowRemote {
        /// Name of the remote to show
        name: String,
    },

    /// Initialize a new configuration file with example remotes
    Init {
        /// Overwrite existing configuration
        #[arg(long)]
        force: bool,
    },

    /// Validate remote configuration and connectivity
    Validate {
        /// Specific remote to validate (validates all if not specified)
        name: Option<String>,

        /// Quick mode: only check SSH connectivity
        #[arg(long, short)]
        quick: bool,

        /// Check build dependencies (nasm, linker, cross-compiler)
        #[arg(long)]
        check_deps: bool,

        /// Verbose output showing command details
        #[arg(long, short)]
        verbose: bool,
    },
}

impl ConfigCommand {
    pub fn execute(&self) -> Result<()> {
        match &self.action {
            ConfigAction::Show => self.show_config(),
            ConfigAction::Path => self.show_path(),
            ConfigAction::ListRemotes => self.list_remotes(),
            ConfigAction::AddRemote {
                name,
                host,
                user,
                port,
                snippex_path,
                ssh_key,
                architecture,
                timeout,
                fex_path,
            } => self.add_remote(
                name,
                host,
                user,
                *port,
                snippex_path,
                ssh_key.clone(),
                architecture.clone(),
                *timeout,
                fex_path.clone(),
            ),
            ConfigAction::RemoveRemote { name } => self.remove_remote(name),
            ConfigAction::ShowRemote { name } => self.show_remote(name),
            ConfigAction::Init { force } => self.init_config(*force),
            ConfigAction::Validate {
                name,
                quick,
                check_deps,
                verbose,
            } => self.validate_remotes(name.as_deref(), *quick, *check_deps, *verbose),
        }
    }

    fn show_config(&self) -> Result<()> {
        let config = Config::load()?;

        if config.is_local_only() {
            println!("No configuration file found or no remotes configured.");
            println!("Running in local-only mode.");
            println!();
            println!("To create a configuration file, run:");
            println!("  snippex config init");
            return Ok(());
        }

        let yaml = serde_yaml::to_string(&config)?;
        println!("{}", yaml);

        Ok(())
    }

    fn show_path(&self) -> Result<()> {
        match Config::default_path() {
            Some(path) => {
                println!("Configuration file path: {}", path.display());
                if path.exists() {
                    println!("Status: File exists");
                } else {
                    println!("Status: File does not exist");
                }
            }
            None => {
                println!("Could not determine configuration directory");
            }
        }

        Ok(())
    }

    fn list_remotes(&self) -> Result<()> {
        let config = Config::load()?;

        if config.is_local_only() {
            println!("No remotes configured.");
            return Ok(());
        }

        println!("Configured remotes:");
        println!();

        for (name, remote) in &config.remotes {
            let arch = remote.architecture.as_deref().unwrap_or("unspecified");
            println!(
                "  {} - {}@{}:{} (arch: {})",
                name, remote.user, remote.host, remote.port, arch
            );
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn add_remote(
        &self,
        name: &str,
        host: &str,
        user: &str,
        port: u16,
        snippex_path: &str,
        ssh_key: Option<String>,
        architecture: Option<String>,
        timeout: u64,
        fex_path: Option<String>,
    ) -> Result<()> {
        let mut config = Config::load()?;

        if config.get_remote(name).is_some() {
            println!("Warning: Remote '{}' already exists, updating...", name);
        }

        let mut remote = RemoteConfig::new(host.to_string(), user.to_string())
            .with_port(port)
            .with_snippex_path(snippex_path.to_string())
            .with_timeout(timeout);

        if let Some(key) = ssh_key {
            remote = remote.with_ssh_key(key);
        }

        if let Some(arch) = architecture {
            remote = remote.with_architecture(arch);
        }

        if let Some(fex) = fex_path {
            remote = remote.with_fex_path(fex);
        }

        config.set_remote(name.to_string(), remote);
        config.save()?;

        println!("Added remote '{}'", name);
        println!("Configuration saved to: {:?}", Config::default_path());

        Ok(())
    }

    fn remove_remote(&self, name: &str) -> Result<()> {
        let mut config = Config::load()?;

        if config.remove_remote(name).is_some() {
            config.save()?;
            println!("Removed remote '{}'", name);
        } else {
            println!("Remote '{}' not found", name);
        }

        Ok(())
    }

    fn show_remote(&self, name: &str) -> Result<()> {
        let config = Config::load()?;

        match config.get_remote(name) {
            Some(remote) => {
                println!("Remote: {}", name);
                println!("  Host: {}", remote.host);
                println!("  User: {}", remote.user);
                println!("  Port: {}", remote.port);
                println!("  Snippex path: {}", remote.snippex_path);
                println!(
                    "  SSH key: {}",
                    remote.ssh_key.as_deref().unwrap_or("(default)")
                );
                println!(
                    "  Architecture: {}",
                    remote.architecture.as_deref().unwrap_or("(unspecified)")
                );
                println!("  Timeout: {}s", remote.timeout);
                println!(
                    "  FEX path: {}",
                    remote.fex_path.as_deref().unwrap_or("(use PATH)")
                );
                println!();
                println!("Connection string: {}", remote.connection_string());
            }
            None => {
                println!("Remote '{}' not found", name);
            }
        }

        Ok(())
    }

    fn init_config(&self, force: bool) -> Result<()> {
        let path = Config::default_path()
            .ok_or_else(|| anyhow::anyhow!("Could not determine configuration directory"))?;

        if path.exists() && !force {
            println!("Configuration file already exists at: {}", path.display());
            println!("Use --force to overwrite");
            return Ok(());
        }

        let mut config = Config::default();

        // Add example remotes (commented out in the actual file)
        config.set_remote(
            "x86-oracle".to_string(),
            RemoteConfig::new("intel-server.example.com".to_string(), "user".to_string())
                .with_snippex_path("/usr/local/bin/snippex".to_string())
                .with_ssh_key("~/.ssh/id_rsa".to_string())
                .with_architecture("x86_64".to_string()),
        );

        config.set_remote(
            "arm64-fex".to_string(),
            RemoteConfig::new("arm-server.example.com".to_string(), "user".to_string())
                .with_snippex_path("/usr/local/bin/snippex".to_string())
                .with_ssh_key("~/.ssh/id_rsa".to_string())
                .with_architecture("aarch64".to_string())
                .with_fex_path("~/dev/FEX/out/install/Release/bin/FEXInterpreter".to_string()),
        );

        config.save()?;

        println!("Created configuration file at: {}", path.display());
        println!();
        println!(
            "Example remotes have been added. Edit the file to configure your actual servers:"
        );
        println!("  snippex config show");
        println!();
        println!("Or add remotes via CLI:");
        println!("  snippex config add-remote my-server --host example.com --user myuser");

        Ok(())
    }

    fn validate_remotes(
        &self,
        name: Option<&str>,
        quick: bool,
        check_deps: bool,
        verbose: bool,
    ) -> Result<()> {
        let config = Config::load()?;

        if config.is_local_only() {
            println!("No remotes configured to validate.");
            return Ok(());
        }

        let remotes_to_validate: Vec<(String, RemoteConfig)> = match name {
            Some(n) => {
                if let Some(remote) = config.get_remote(n) {
                    vec![(n.to_string(), remote.clone())]
                } else {
                    println!("Remote '{}' not found", n);
                    return Ok(());
                }
            }
            None => config
                .remotes
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        };

        let mode = if quick {
            "quick"
        } else if check_deps {
            "full + dependencies"
        } else {
            "standard"
        };
        println!(
            "Validating {} remote(s) ({} mode)...",
            remotes_to_validate.len(),
            mode
        );
        println!();

        let mut total_passed = 0;
        let mut total_failed = 0;
        let mut total_warnings = 0;

        for (remote_name, remote) in &remotes_to_validate {
            println!("Remote: {} ({}@{})", remote_name, remote.user, remote.host);

            // 1. SSH Connection
            print!("  SSH connection... ");
            match self.test_ssh_connection(remote) {
                Ok(()) => {
                    println!("✓ OK");
                    total_passed += 1;
                }
                Err(e) => {
                    println!("✗ FAILED");
                    if verbose {
                        println!("    Error: {}", e);
                    }
                    total_failed += 1;
                    println!();
                    continue; // Skip other checks if SSH fails
                }
            }

            if quick {
                println!();
                continue;
            }

            // 2. Snippex binary
            print!("  snippex ({})... ", remote.snippex_path);
            match self.test_remote_command(remote, &remote.snippex_path, &["--version"], verbose) {
                Ok(output) => {
                    let version = output.lines().next().unwrap_or("unknown").trim();
                    println!("✓ {}", version);
                    total_passed += 1;
                }
                Err(e) => {
                    println!("✗ FAILED");
                    if verbose {
                        println!("    Error: {}", e);
                    }
                    total_failed += 1;
                }
            }

            // 3. FEX-Emu (if configured)
            if let Some(ref fex_path) = remote.fex_path {
                print!("  FEX-Emu ({})... ", fex_path);
                // FEXInterpreter doesn't support --version, check if it exists and is executable
                match self.test_remote_file_exists(remote, fex_path, verbose) {
                    Ok(true) => {
                        println!("✓ exists");
                        total_passed += 1;
                    }
                    Ok(false) => {
                        println!("✗ not found");
                        total_failed += 1;
                    }
                    Err(e) => {
                        println!("✗ FAILED");
                        if verbose {
                            println!("    Error: {}", e);
                        }
                        total_failed += 1;
                    }
                }
            }

            // 4. Build dependencies (optional)
            if check_deps {
                println!("  Build dependencies:");

                // nasm
                print!("    nasm... ");
                match self.test_remote_command(remote, "nasm", &["--version"], verbose) {
                    Ok(output) => {
                        let version = output.lines().next().unwrap_or("").trim();
                        let version_short = version
                            .split_whitespace()
                            .take(3)
                            .collect::<Vec<_>>()
                            .join(" ");
                        println!("✓ {}", version_short);
                        total_passed += 1;
                    }
                    Err(_) => {
                        println!("✗ not found");
                        total_failed += 1;
                    }
                }

                // ld (linker)
                print!("    ld... ");
                match self.test_remote_command(remote, "ld", &["--version"], verbose) {
                    Ok(output) => {
                        let version = output.lines().next().unwrap_or("").trim();
                        println!("✓ {}", version.chars().take(50).collect::<String>());
                        total_passed += 1;
                    }
                    Err(_) => {
                        println!("✗ not found");
                        total_failed += 1;
                    }
                }

                // Cross-compiler (for ARM hosts building x86)
                if remote.architecture.as_deref() == Some("aarch64") {
                    print!("    x86_64-linux-gnu-gcc... ");
                    match self.test_remote_command(
                        remote,
                        "x86_64-linux-gnu-gcc",
                        &["--version"],
                        verbose,
                    ) {
                        Ok(output) => {
                            let version = output.lines().next().unwrap_or("").trim();
                            println!("✓ {}", version.chars().take(40).collect::<String>());
                            total_passed += 1;
                        }
                        Err(_) => {
                            println!("⚠ not found (optional for x86 test binaries)");
                            total_warnings += 1;
                        }
                    }

                    // FEX-Emu availability (if not explicitly configured)
                    if remote.fex_path.is_none() {
                        print!("    FEXInterpreter (PATH)... ");
                        match self.test_remote_command(
                            remote,
                            "which",
                            &["FEXInterpreter"],
                            verbose,
                        ) {
                            Ok(path) => {
                                println!("✓ {}", path.trim());
                                total_passed += 1;
                            }
                            Err(_) => {
                                println!("⚠ not found (optional for x86 emulation)");
                                total_warnings += 1;
                            }
                        }
                    }
                }
            }

            println!();
        }

        // Summary
        println!("═══════════════════════════════════════════");
        println!(
            "Results: {} passed, {} failed, {} warnings",
            total_passed, total_failed, total_warnings
        );

        if total_failed > 0 {
            println!();
            println!("Some checks failed. Use --verbose for more details.");
        }

        Ok(())
    }

    fn test_remote_command(
        &self,
        remote: &RemoteConfig,
        command: &str,
        args: &[&str],
        verbose: bool,
    ) -> Result<String> {
        let mut cmd = Command::new("ssh");
        self.add_ssh_options(&mut cmd, remote);

        // Build the remote command string
        let remote_cmd = if args.is_empty() {
            command.to_string()
        } else {
            format!("{} {}", command, args.join(" "))
        };

        if verbose {
            eprintln!(
                "    Running: ssh {}@{} '{}'",
                remote.user, remote.host, remote_cmd
            );
        }

        cmd.arg(format!("{}@{}", remote.user, remote.host))
            .arg(&remote_cmd);

        let output = cmd
            .output()
            .map_err(|e| anyhow::anyhow!("SSH failed: {}", e))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(anyhow::anyhow!("{}", stderr.trim()))
        }
    }

    fn test_remote_file_exists(
        &self,
        remote: &RemoteConfig,
        path: &str,
        verbose: bool,
    ) -> Result<bool> {
        let mut cmd = Command::new("ssh");
        self.add_ssh_options(&mut cmd, remote);

        let test_cmd = format!("test -x '{}' && echo exists", path);

        if verbose {
            eprintln!(
                "    Running: ssh {}@{} '{}'",
                remote.user, remote.host, test_cmd
            );
        }

        cmd.arg(format!("{}@{}", remote.user, remote.host))
            .arg(&test_cmd);

        let output = cmd
            .output()
            .map_err(|e| anyhow::anyhow!("SSH failed: {}", e))?;

        Ok(output.status.success())
    }

    fn add_ssh_options(&self, cmd: &mut Command, remote: &RemoteConfig) {
        cmd.arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg("ConnectTimeout=10")
            .arg("-o")
            .arg("StrictHostKeyChecking=accept-new");

        if let Some(ref key) = remote.ssh_key {
            let expanded_key = if let Some(stripped) = key.strip_prefix("~/") {
                if let Some(home) = dirs::home_dir() {
                    home.join(stripped).to_string_lossy().to_string()
                } else {
                    key.clone()
                }
            } else {
                key.clone()
            };
            cmd.arg("-i").arg(expanded_key);
        }

        if remote.port != 22 {
            cmd.arg("-p").arg(remote.port.to_string());
        }
    }

    fn test_ssh_connection(&self, remote: &RemoteConfig) -> Result<()> {
        let mut cmd = Command::new("ssh");
        self.add_ssh_options(&mut cmd, remote);

        cmd.arg(format!("{}@{}", remote.user, remote.host))
            .arg("echo ok");

        let output = cmd
            .output()
            .map_err(|e| anyhow::anyhow!("SSH failed: {}", e))?;

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(anyhow::anyhow!("SSH failed: {}", stderr.trim()))
        }
    }
}
