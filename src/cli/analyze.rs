use anyhow::{anyhow, Result};
use capstone::prelude::*;
use clap::Args;
use std::path::PathBuf;

use crate::analyzer::{Analyzer, ExitType};
use crate::cli::block_range::BlockRange;
use crate::db::Database;

#[derive(Args)]
pub struct AnalyzeCommand {
    #[arg(help = "Block(s) to analyze: 5, 1-10, 5-, 3,7,12, or all")]
    blocks: BlockRange,

    #[arg(
        short,
        long,
        default_value = "snippex.db",
        help = "SQLite database path"
    )]
    database: PathBuf,

    #[arg(short, long, help = "Show detailed analysis information")]
    verbose: bool,

    #[arg(short = 'D', long, help = "Show disassembly of the block")]
    disassemble: bool,
}

impl AnalyzeCommand {
    pub fn execute(self) -> Result<()> {
        if !self.database.exists() {
            return Err(anyhow!(
                "Database not found at '{}'\n\n\
                 Suggestions:\n\
                 • Extract blocks first: snippex extract <binary>\n\
                 • Specify a different database: snippex analyze {} -d <path>",
                self.database.display(),
                self.blocks
            ));
        }

        let mut db = Database::new(&self.database)?;

        let extractions = match db.list_extractions() {
            Ok(extractions) => extractions,
            Err(_) => {
                return Err(anyhow!(
                    "No blocks found in database\n\n\
                     Suggestions:\n\
                     • Extract blocks first: snippex extract <binary>\n\
                     • Import NASM file: snippex import <file.asm>"
                ));
            }
        };

        let block_numbers = self.blocks.resolve(extractions.len())?;
        let multiple = block_numbers.len() > 1;

        let mut success_count = 0;
        let mut error_count = 0;

        for (i, block_number) in block_numbers.iter().enumerate() {
            if multiple && i > 0 {
                println!();
                println!("{}", "═".repeat(60));
                println!();
            }

            let extraction = &extractions[block_number - 1];

            println!("Analyzing block #{}...", block_number);
            println!("  Binary: {}", extraction.binary_path);
            println!(
                "  Address range: 0x{:08x} - 0x{:08x}",
                extraction.start_address, extraction.end_address
            );
            println!();

            if self.disassemble {
                if let Err(e) = self.print_disassembly(extraction) {
                    eprintln!("  Disassembly error: {}", e);
                } else {
                    println!();
                }
            }

            let analyzer = Analyzer::new(&extraction.binary_architecture);

            match analyzer.analyze_block(&extraction.assembly_block, extraction.start_address) {
                Ok(analysis) => {
                    self.print_analysis(&analysis);

                    if self.verbose {
                        println!();
                        println!("Storing analysis results in database...");
                    }

                    if let Err(e) = db.store_analysis(
                        extraction.start_address,
                        extraction.end_address,
                        &extraction.binary_hash,
                        &analysis,
                    ) {
                        eprintln!("  Failed to store analysis: {}", e);
                        error_count += 1;
                    } else {
                        println!();
                        println!("✓ Analysis completed and stored successfully");
                        success_count += 1;
                    }
                }
                Err(e) => {
                    eprintln!("✗ Analysis failed: {}", e);
                    error_count += 1;
                }
            }
        }

        if multiple {
            println!();
            println!("{}", "═".repeat(60));
            println!(
                "Summary: {} succeeded, {} failed",
                success_count, error_count
            );
        }

        if error_count > 0 && success_count == 0 {
            Err(anyhow!("All analyses failed"))
        } else {
            Ok(())
        }
    }

    fn print_analysis(&self, analysis: &crate::analyzer::BlockAnalysis) {
        println!("Analysis Results:");
        println!("=================");
        println!("Instructions: {}", analysis.instructions_count);
        println!();

        println!("Live-in Registers ({}):", analysis.live_in_registers.len());
        if analysis.live_in_registers.is_empty() {
            println!("  <none>");
        } else {
            let mut regs: Vec<_> = analysis.live_in_registers.iter().collect();
            regs.sort();
            for reg in regs {
                println!("  - {reg}");
            }
        }
        println!();

        println!(
            "Live-out Registers ({}):",
            analysis.live_out_registers.len()
        );
        if analysis.live_out_registers.is_empty() {
            println!("  <none>");
        } else {
            let mut regs: Vec<_> = analysis.live_out_registers.iter().collect();
            regs.sort();
            for reg in regs {
                println!("  - {reg}");
            }
        }
        println!();

        println!("Exit Points ({}):", analysis.exit_points.len());
        for exit in &analysis.exit_points {
            print!("  - 0x{:08x}: ", exit.offset);
            match exit.exit_type {
                ExitType::FallThrough => println!("Fall through"),
                ExitType::UnconditionalJump => {
                    if let Some(target) = exit.target {
                        println!("Unconditional jump to 0x{target:08x}");
                    } else {
                        println!("Unconditional indirect jump");
                    }
                }
                ExitType::ConditionalJump => {
                    if let Some(target) = exit.target {
                        println!("Conditional jump to 0x{target:08x}");
                    } else {
                        println!("Conditional indirect jump");
                    }
                }
                ExitType::Call => {
                    if let Some(target) = exit.target {
                        println!("Call to 0x{target:08x}");
                    } else {
                        println!("Indirect call");
                    }
                }
                ExitType::Return => println!("Return"),
                ExitType::IndirectJump => println!("Indirect jump"),
            }
        }
        println!();

        println!("Memory Accesses ({}):", analysis.memory_accesses.len());
        if analysis.memory_accesses.is_empty() {
            println!("  <none>");
        } else {
            for mem in &analysis.memory_accesses {
                print!("  - 0x{:08x}: ", mem.offset);
                print!("{:?} ", mem.access_type);
                print!("{} bytes", mem.size);
                if mem.is_stack {
                    print!(" (stack)");
                }
                println!();
            }
        }
        println!();

        println!("Pointer Registers ({}):", analysis.pointer_registers.len());
        if analysis.pointer_registers.is_empty() {
            println!("  <none>");
        } else {
            for (reg, usage) in &analysis.pointer_registers {
                print!("  - {}: ", reg);
                print!("offsets [{}, {}]", usage.min_offset, usage.max_offset);
                print!(", max_size={}", usage.max_access_size);
                if usage.has_reads && usage.has_writes {
                    print!(" (read/write)");
                } else if usage.has_reads {
                    print!(" (read)");
                } else if usage.has_writes {
                    print!(" (write)");
                }
                println!();
            }
        }
    }

    fn print_disassembly(&self, extraction: &crate::db::ExtractionInfo) -> Result<()> {
        let cs = match extraction.binary_architecture.as_str() {
            "x86_64" => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build()
                .map_err(|e| anyhow!("Failed to create disassembler: {}", e))?,
            "i386" | "x86" => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode32)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build()
                .map_err(|e| anyhow!("Failed to create disassembler: {}", e))?,
            arch => {
                return Err(anyhow!(
                    "Unsupported architecture for disassembly: {}",
                    arch
                ))
            }
        };

        let insns = cs
            .disasm_all(&extraction.assembly_block, extraction.start_address)
            .map_err(|e| anyhow!("Disassembly failed: {}", e))?;

        println!(
            "Disassembly ({} bytes, {} instructions):",
            extraction.assembly_block.len(),
            insns.len()
        );
        println!("{}", "─".repeat(50));

        for insn in insns.iter() {
            println!(
                "  0x{:08x}:  {} {}",
                insn.address(),
                insn.mnemonic().unwrap_or("???"),
                insn.op_str().unwrap_or("")
            );
        }

        Ok(())
    }
}
