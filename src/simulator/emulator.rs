use crate::error::{Error, Result};
use std::str::FromStr;

#[derive(Debug, Clone, Default)]
pub enum EmulatorConfig {
    #[default]
    Native,
    Qemu {
        binary: String,
        args: Vec<String>,
    },
    FexEmu {
        binary: String,
        args: Vec<String>,
    },
}

impl EmulatorConfig {
    pub fn name(&self) -> String {
        match self {
            EmulatorConfig::Native => "native".to_string(),
            EmulatorConfig::Qemu { .. } => "qemu".to_string(),
            EmulatorConfig::FexEmu { .. } => "fex-emu".to_string(),
        }
    }

    pub fn name_with_host_info(&self) -> String {
        let emulator_name = self.name();
        let host_arch = std::env::consts::ARCH;
        let machine_id = Self::get_machine_id();
        format!("{}@{}#{}", emulator_name, host_arch, machine_id)
    }

    fn get_machine_id() -> String {
        // Try to get a unique machine identifier
        // First try hostname, fallback to a hash of system info
        if let Ok(hostname) = std::process::Command::new("hostname")
            .output()
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        {
            if !hostname.is_empty() {
                return hostname;
            }
        }

        // Fallback: use a hash of available system info
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        std::env::consts::OS.hash(&mut hasher);
        std::env::consts::ARCH.hash(&mut hasher);
        if let Ok(user) = std::env::var("USER") {
            user.hash(&mut hasher);
        }

        format!("host-{:x}", hasher.finish())
    }

    pub fn qemu_x86_64() -> Self {
        Self::Qemu {
            binary: "qemu-x86_64".to_string(),
            args: ["-cpu", "max"].iter().map(|s| s.to_string()).collect(),
        }
    }

    pub fn qemu_i386() -> Self {
        Self::Qemu {
            binary: "qemu-i386".to_string(),
            args: ["-cpu", "max"].iter().map(|s| s.to_string()).collect(),
        }
    }

    pub fn fex_emu() -> Self {
        // Look for FEXInterpreter in common locations
        let binary = Self::find_fex_binary().unwrap_or_else(|| "FEXInterpreter".to_string());
        Self::FexEmu {
            binary,
            args: vec![],
        }
    }

    /// Creates a FEX-Emu configuration with a specific binary path.
    /// Use this when the FEX path is configured explicitly.
    pub fn fex_emu_with_path(path: &str) -> Self {
        // Expand ~ to home directory
        let binary = if let Some(stripped) = path.strip_prefix("~/") {
            if let Ok(home) = std::env::var("HOME") {
                format!("{}/{}", home, stripped)
            } else {
                path.to_string()
            }
        } else {
            path.to_string()
        };
        Self::FexEmu {
            binary,
            args: vec![],
        }
    }

    /// Creates a FEX-Emu configuration, optionally using a configured path.
    /// If path is None, uses auto-discovery to find FEXInterpreter.
    pub fn fex_emu_with_optional_path(path: Option<&str>) -> Self {
        match path {
            Some(p) => Self::fex_emu_with_path(p),
            None => Self::fex_emu(),
        }
    }

    /// Searches for FEXInterpreter in common installation locations
    fn find_fex_binary() -> Option<String> {
        use std::path::Path;

        // Check common FEX installation paths
        let common_paths = [
            // Standard PATH lookup
            "FEXInterpreter",
            // User-local installations
            "~/.local/bin/FEXInterpreter",
            // Common FEX build locations
            "~/dev/FEX/out/install/Release/bin/FEXInterpreter",
            "~/FEX/build/bin/FEXInterpreter",
            // System-wide installations
            "/usr/local/bin/FEXInterpreter",
            "/usr/bin/FEXInterpreter",
            "/opt/FEX/bin/FEXInterpreter",
        ];

        for path in common_paths {
            let expanded = if path.starts_with("~/") {
                if let Ok(home) = std::env::var("HOME") {
                    path.replacen("~", &home, 1)
                } else {
                    path.to_string()
                }
            } else {
                path.to_string()
            };

            if Path::new(&expanded).exists() {
                return Some(expanded);
            }
        }

        // Also check if it's in PATH via which
        if let Ok(output) = std::process::Command::new("which")
            .arg("FEXInterpreter")
            .output()
        {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !path.is_empty() {
                    return Some(path);
                }
            }
        }

        None
    }

    pub fn get_version(&self) -> String {
        match self {
            EmulatorConfig::Native => "native".to_string(),
            EmulatorConfig::Qemu { binary, .. } => std::process::Command::new(binary)
                .arg("--version")
                .output()
                .ok()
                .and_then(|o| {
                    let out = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    if out.is_empty() {
                        None
                    } else {
                        Some(out.lines().next().unwrap_or("").to_string())
                    }
                })
                .unwrap_or_else(|| "unknown".to_string()),
            EmulatorConfig::FexEmu { binary, .. } => {
                // FEXInterpreter doesn't support --version; use FEXServer --version instead
                let fex_dir = std::path::Path::new(binary).parent();
                let fex_server = fex_dir
                    .map(|d| d.join("FEXServer").to_string_lossy().into_owned())
                    .unwrap_or_else(|| "FEXServer".to_string());
                if let Ok(output) = std::process::Command::new(&fex_server)
                    .arg("--version")
                    .output()
                {
                    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                    let text = if stdout.is_empty() { &stderr } else { &stdout };
                    if !text.is_empty() {
                        return text.lines().next().unwrap_or("").to_string();
                    }
                }
                "unknown".to_string()
            }
        }
    }

    pub fn get_version_via_ssh(host: &str, fex_path: Option<&str>) -> String {
        // FEXInterpreter doesn't support --version; use FEXServer --version instead
        let fex_server = match fex_path {
            Some(path) => {
                let p = std::path::Path::new(path);
                p.parent()
                    .map(|d| d.join("FEXServer").to_string_lossy().into_owned())
                    .unwrap_or_else(|| "FEXServer".to_string())
            }
            None => "FEXServer".to_string(),
        };
        let cmd = format!("{} --version", fex_server);
        if let Ok(output) = std::process::Command::new("ssh")
            .args([host, &cmd])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let text = if stdout.is_empty() { &stderr } else { &stdout };
            if !text.is_empty() {
                return text.lines().next().unwrap_or("").to_string();
            }
        }
        "unknown".to_string()
    }

    pub fn is_available(&self) -> bool {
        match self {
            EmulatorConfig::Native => true,
            EmulatorConfig::Qemu { binary, .. } => std::process::Command::new(binary)
                .arg("--version")
                .output()
                .map(|output| output.status.success())
                .unwrap_or(false),
            EmulatorConfig::FexEmu { binary, .. } => {
                // FEXInterpreter doesn't support --version, so just check if binary exists
                std::path::Path::new(binary).exists()
                    || std::process::Command::new("which")
                        .arg(binary)
                        .output()
                        .map(|output| output.status.success())
                        .unwrap_or(false)
            }
        }
    }
}

impl FromStr for EmulatorConfig {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "native" => Ok(EmulatorConfig::Native),
            "qemu" | "qemu-x86_64" => Ok(EmulatorConfig::qemu_x86_64()),
            "qemu-i386" => Ok(EmulatorConfig::qemu_i386()),
            "fex" | "fex-emu" => Ok(EmulatorConfig::fex_emu()),
            _ => Err(Error::Simulation(format!("Unknown emulator: {s}"))),
        }
    }
}
