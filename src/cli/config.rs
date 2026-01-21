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

    /// Validate SSH connections to configured remotes
    Validate {
        /// Specific remote to validate (validates all if not specified)
        name: Option<String>,

        /// Also check if snippex is available on remote
        #[arg(long)]
        check_snippex: bool,
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
                check_snippex,
            } => self.validate_remotes(name.as_deref(), *check_snippex),
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

    fn validate_remotes(&self, name: Option<&str>, check_snippex: bool) -> Result<()> {
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

        println!("Validating {} remote(s)...", remotes_to_validate.len());
        println!();

        let mut success_count = 0;
        let mut failure_count = 0;

        for (remote_name, remote) in &remotes_to_validate {
            print!("  {} ({}@{})... ", remote_name, remote.user, remote.host);

            match self.test_ssh_connection(remote) {
                Ok(()) => {
                    println!("✓ SSH OK");

                    if check_snippex {
                        print!("    Checking snippex... ");
                        match self.test_remote_snippex(remote) {
                            Ok(version) => {
                                println!("✓ Found ({})", version);
                                success_count += 1;
                            }
                            Err(e) => {
                                println!("✗ {}", e);
                                failure_count += 1;
                            }
                        }
                    } else {
                        success_count += 1;
                    }
                }
                Err(e) => {
                    println!("✗ {}", e);
                    failure_count += 1;
                }
            }
        }

        println!();
        println!(
            "Results: {} passed, {} failed",
            success_count, failure_count
        );

        Ok(())
    }

    fn test_ssh_connection(&self, remote: &RemoteConfig) -> Result<()> {
        let mut cmd = Command::new("ssh");

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

        cmd.arg(format!("{}@{}", remote.user, remote.host))
            .arg("echo")
            .arg("ok");

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

    fn test_remote_snippex(&self, remote: &RemoteConfig) -> Result<String> {
        let mut cmd = Command::new("ssh");

        cmd.arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg("ConnectTimeout=10");

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

        cmd.arg(format!("{}@{}", remote.user, remote.host))
            .arg(&remote.snippex_path)
            .arg("--version");

        let output = cmd
            .output()
            .map_err(|e| anyhow::anyhow!("SSH failed: {}", e))?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let version = stdout.trim().to_string();
            Ok(if version.is_empty() {
                "version unknown".to_string()
            } else {
                version
            })
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("command not found") || stderr.contains("not found") {
                Err(anyhow::anyhow!(
                    "snippex not found at '{}'",
                    remote.snippex_path
                ))
            } else {
                Err(anyhow::anyhow!("Failed to run snippex: {}", stderr.trim()))
            }
        }
    }
}
