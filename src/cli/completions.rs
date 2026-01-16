//! Shell completion script generation.

use anyhow::Result;
use clap::{Args, CommandFactory, ValueEnum};
use clap_complete::{generate, Shell};
use std::io;

use crate::Cli;

#[derive(Args)]
pub struct CompletionsCommand {
    /// Shell to generate completions for
    #[arg(value_enum)]
    pub shell: ShellType,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum ShellType {
    /// Bash shell
    Bash,
    /// Zsh shell
    Zsh,
    /// Fish shell
    Fish,
    /// PowerShell
    Powershell,
    /// Elvish shell
    Elvish,
}

impl From<ShellType> for Shell {
    fn from(shell: ShellType) -> Self {
        match shell {
            ShellType::Bash => Shell::Bash,
            ShellType::Zsh => Shell::Zsh,
            ShellType::Fish => Shell::Fish,
            ShellType::Powershell => Shell::PowerShell,
            ShellType::Elvish => Shell::Elvish,
        }
    }
}

impl CompletionsCommand {
    pub fn execute(self) -> Result<()> {
        let mut cmd = Cli::command();
        let shell: Shell = self.shell.into();
        generate(shell, &mut cmd, "snippex", &mut io::stdout());
        Ok(())
    }
}
