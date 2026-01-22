use anyhow::{anyhow, Result};
use capstone::prelude::*;
use clap::Args;
use console::{style, Style};
use std::collections::HashSet;
use std::path::PathBuf;

use crate::db::Database;

#[derive(Args)]
pub struct DisasmCommand {
    #[arg(help = "Block number to disassemble (as shown by list command)")]
    block_number: usize,

    #[arg(
        short,
        long,
        default_value = "snippex.db",
        help = "SQLite database path"
    )]
    database: PathBuf,

    #[arg(long, help = "Disable colored output")]
    no_color: bool,

    #[arg(short, long, help = "Show raw bytes alongside disassembly")]
    bytes: bool,
}

impl DisasmCommand {
    pub fn execute(self) -> Result<()> {
        if !self.database.exists() {
            return Err(anyhow!(
                "Database not found at '{}'\n\n\
                 Suggestions:\n\
                 • Extract blocks first: snippex extract <binary>\n\
                 • Specify a different database: snippex disasm {} -d <path>",
                self.database.display(),
                self.block_number
            ));
        }

        let db = Database::new(&self.database)?;

        let extractions = db.list_extractions()?;
        if self.block_number == 0 || self.block_number > extractions.len() {
            return Err(anyhow!(
                "Invalid block number: {}\n\n\
                 Valid block range: 1-{}\n\n\
                 Suggestions:\n\
                 • List available blocks: snippex list",
                self.block_number,
                extractions.len()
            ));
        }

        let extraction = &extractions[self.block_number - 1];

        // Try to get analysis results if available
        let analysis = db.load_block_analysis(extraction.id).ok().flatten();

        // Print header
        println!(
            "{}",
            style(format!("Block #{}", self.block_number)).bold().cyan()
        );
        println!("  Binary: {}", style(&extraction.binary_path).dim());
        println!(
            "  Range:  {} - {}",
            style(format!("0x{:08x}", extraction.start_address)).yellow(),
            style(format!("0x{:08x}", extraction.end_address)).yellow()
        );
        println!("  Size:   {} bytes", extraction.assembly_block.len());

        // If we have analysis, show a summary
        if let Some(ref a) = analysis {
            println!();
            self.print_analysis_summary(a);
        }

        println!();
        println!("{}", style("Disassembly").bold().underlined());
        println!("{}", style("─".repeat(60)).dim());

        // Disassemble
        let cs = self.create_capstone(&extraction.binary_architecture)?;
        let insns = cs
            .disasm_all(&extraction.assembly_block, extraction.start_address)
            .map_err(|e| anyhow!("Disassembly failed: {}", e))?;

        // Collect sets for coloring
        let (live_in, live_out, exit_addrs, mem_addrs): (
            HashSet<String>,
            HashSet<String>,
            HashSet<u64>,
            HashSet<u64>,
        ) = if let Some(ref a) = analysis {
            let live_in: HashSet<String> = a.live_in_registers.iter().cloned().collect();
            let live_out: HashSet<String> = a.live_out_registers.iter().cloned().collect();
            let exit_addrs: HashSet<u64> = a.exit_points.iter().map(|e| e.offset).collect();
            let mem_addrs: HashSet<u64> = a.memory_accesses.iter().map(|m| m.offset).collect();
            (live_in, live_out, exit_addrs, mem_addrs)
        } else {
            (
                HashSet::new(),
                HashSet::new(),
                HashSet::new(),
                HashSet::new(),
            )
        };

        for insn in insns.iter() {
            let addr = insn.address();
            let mnemonic = insn.mnemonic().unwrap_or("???");
            let op_str = insn.op_str().unwrap_or("");

            // Determine styling
            let is_exit = exit_addrs.contains(&addr);
            let has_mem = mem_addrs.contains(&addr);

            // Style the address
            let addr_style = if is_exit {
                Style::new().red().bold()
            } else if has_mem {
                Style::new().magenta()
            } else {
                Style::new().dim()
            };

            // Format bytes if requested
            let bytes_str = if self.bytes {
                let bytes = insn.bytes();
                let hex: Vec<String> = bytes.iter().map(|b| format!("{:02x}", b)).collect();
                format!("{:<24}", hex.join(" "))
            } else {
                String::new()
            };

            // Style the operands with register coloring
            let styled_ops = if !self.no_color && analysis.is_some() {
                self.colorize_operands(op_str, &live_in, &live_out)
            } else {
                op_str.to_string()
            };

            // Style mnemonic
            let mnemonic_style = if is_exit {
                style(mnemonic).red().bold()
            } else if mnemonic.starts_with('j') || mnemonic == "call" || mnemonic == "ret" {
                style(mnemonic).yellow()
            } else if mnemonic.starts_with('v') {
                style(mnemonic).blue()
            } else {
                style(mnemonic).white()
            };

            if self.bytes {
                println!(
                    "  {} {} {:<8} {}",
                    addr_style.apply_to(format!("0x{:08x}:", addr)),
                    style(&bytes_str).dim(),
                    mnemonic_style,
                    styled_ops
                );
            } else {
                println!(
                    "  {} {:<8} {}",
                    addr_style.apply_to(format!("0x{:08x}:", addr)),
                    mnemonic_style,
                    styled_ops
                );
            }
        }

        // Print legend if we have analysis and colors
        if analysis.is_some() && !self.no_color {
            println!();
            println!("{}", style("─".repeat(60)).dim());
            println!(
                "{}  {} live-in  {} live-out  {} exit  {} memory",
                style("Legend:").dim(),
                style("■").green(),
                style("■").cyan(),
                style("■").red(),
                style("■").magenta(),
            );
        }

        Ok(())
    }

    fn print_analysis_summary(&self, analysis: &crate::analyzer::BlockAnalysis) {
        let live_in_style = Style::new().green();
        let live_out_style = Style::new().cyan();

        // Live-in registers
        if !analysis.live_in_registers.is_empty() {
            let mut regs: Vec<_> = analysis.live_in_registers.iter().collect();
            regs.sort();
            let regs_str: Vec<_> = regs
                .iter()
                .map(|r| live_in_style.apply_to(r).to_string())
                .collect();
            println!("  Live-in:  {}", regs_str.join(", "));
        }

        // Live-out registers
        if !analysis.live_out_registers.is_empty() {
            let mut regs: Vec<_> = analysis.live_out_registers.iter().collect();
            regs.sort();
            let regs_str: Vec<_> = regs
                .iter()
                .map(|r| live_out_style.apply_to(r).to_string())
                .collect();
            println!("  Live-out: {}", regs_str.join(", "));
        }

        // Exit points count
        if !analysis.exit_points.is_empty() {
            println!(
                "  Exits:    {}",
                style(format!("{} exit point(s)", analysis.exit_points.len())).red()
            );
        }

        // Memory accesses count
        if !analysis.memory_accesses.is_empty() {
            println!(
                "  Memory:   {}",
                style(format!("{} access(es)", analysis.memory_accesses.len())).magenta()
            );
        }
    }

    fn colorize_operands(
        &self,
        op_str: &str,
        live_in: &HashSet<String>,
        live_out: &HashSet<String>,
    ) -> String {
        // Split operands and colorize registers
        let parts: Vec<&str> = op_str
            .split(|c: char| {
                c == ',' || c == ' ' || c == '[' || c == ']' || c == '+' || c == '-' || c == '*'
            })
            .collect();

        let mut result = op_str.to_string();

        for part in parts {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                continue;
            }

            let canonical = self.canonical_reg(trimmed);
            let is_live_in = live_in.contains(&canonical);
            let is_live_out = live_out.contains(&canonical);

            if is_live_in || is_live_out {
                let styled = if is_live_in && is_live_out {
                    style(trimmed).green().underlined().to_string()
                } else if is_live_in {
                    style(trimmed).green().to_string()
                } else {
                    style(trimmed).cyan().to_string()
                };
                result = result.replace(trimmed, &styled);
            }
        }

        result
    }

    fn canonical_reg(&self, reg: &str) -> String {
        match reg {
            "eax" | "ax" | "al" | "ah" => "rax".to_string(),
            "ebx" | "bx" | "bl" | "bh" => "rbx".to_string(),
            "ecx" | "cx" | "cl" | "ch" => "rcx".to_string(),
            "edx" | "dx" | "dl" | "dh" => "rdx".to_string(),
            "esi" | "si" | "sil" => "rsi".to_string(),
            "edi" | "di" | "dil" => "rdi".to_string(),
            "ebp" | "bp" | "bpl" => "rbp".to_string(),
            "esp" | "sp" | "spl" => "rsp".to_string(),
            "r8d" | "r8w" | "r8b" => "r8".to_string(),
            "r9d" | "r9w" | "r9b" => "r9".to_string(),
            "r10d" | "r10w" | "r10b" => "r10".to_string(),
            "r11d" | "r11w" | "r11b" => "r11".to_string(),
            "r12d" | "r12w" | "r12b" => "r12".to_string(),
            "r13d" | "r13w" | "r13b" => "r13".to_string(),
            "r14d" | "r14w" | "r14b" => "r14".to_string(),
            "r15d" | "r15w" | "r15b" => "r15".to_string(),
            _ => reg.to_string(),
        }
    }

    fn create_capstone(&self, arch: &str) -> Result<Capstone> {
        match arch {
            "x86_64" => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build()
                .map_err(|e| anyhow!("Failed to create disassembler: {}", e)),
            "i386" | "x86" => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode32)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build()
                .map_err(|e| anyhow!("Failed to create disassembler: {}", e)),
            arch => Err(anyhow!("Unsupported architecture: {}", arch)),
        }
    }
}
