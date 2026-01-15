use anyhow::Result;
use clap::Args;
use log::debug;
use object::{Object, ObjectSection};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

use crate::db::{BinaryInfo, Database};
use crate::error::SnippexError;
use crate::simulator::compilation::CompilationPipeline;

#[derive(Args)]
pub struct ImportCommand {
    #[arg(help = "Path to the NASM assembly file (.asm or .s)")]
    nasm_file: PathBuf,

    #[arg(
        short,
        long,
        help = "Target architecture (x86 or x86_64). Auto-detected from file if not specified"
    )]
    arch: Option<String>,

    #[arg(short, long, help = "Enable verbose logging")]
    verbose: bool,

    #[arg(short, long, help = "Suppress all output")]
    quiet: bool,

    #[arg(
        short,
        long,
        default_value = "snippex.db",
        help = "SQLite database path"
    )]
    database: PathBuf,
}

impl ImportCommand {
    pub fn execute(self) -> Result<()> {
        if !self.quiet {
            println!("Importing NASM file: {}", self.nasm_file.display());
        }

        if self.verbose {
            debug!("Verbose mode enabled");
        }

        // Validate input file
        if !self.nasm_file.exists() {
            return Err(SnippexError::InvalidBinary(format!(
                "NASM file not found: {}",
                self.nasm_file.display()
            ))
            .into());
        }

        let nasm_content = fs::read_to_string(&self.nasm_file).map_err(|e| {
            SnippexError::InvalidBinary(format!(
                "Failed to read NASM file {}: {}",
                self.nasm_file.display(),
                e
            ))
        })?;

        if nasm_content.trim().is_empty() {
            return Err(SnippexError::InvalidBinary("NASM file is empty".into()).into());
        }

        // Detect architecture
        let architecture = self.detect_architecture(&nasm_content)?;

        if !self.quiet {
            println!("Detected architecture: {}", architecture);
        }

        if self.verbose {
            debug!("NASM file content (first 200 chars): {}", {
                let preview = nasm_content.chars().take(200).collect::<String>();
                if nasm_content.len() > 200 {
                    format!("{}...", preview)
                } else {
                    preview
                }
            });
        }

        // Set up compilation pipeline
        let pipeline = CompilationPipeline::new()?;

        // Prepare NASM source with proper format
        let formatted_nasm = self.format_nasm_source(&nasm_content, &architecture)?;

        if self.verbose {
            debug!("Formatted NASM source prepared for compilation");
        }

        // Compile the assembly
        let (binary_file, _asm_file) = pipeline.compile_and_link(&formatted_nasm, "imported")?;

        if !self.quiet {
            println!("Successfully assembled NASM file");
        }

        // Read the compiled binary to extract machine code
        let binary_data = fs::read(&binary_file).map_err(|e| {
            SnippexError::BinaryParsing(format!("Failed to read compiled binary: {}", e))
        })?;

        // Extract the .text section (machine code) from the ELF
        let assembly_block = self.extract_text_section(&binary_data)?;

        if assembly_block.is_empty() {
            return Err(SnippexError::InvalidBinary(
                "No executable code found in compiled binary".into(),
            )
            .into());
        }

        // Calculate address range based on architecture
        let base_addr = match architecture.as_str() {
            "x86_64" => 0x400000,
            "i386" => 0x8048000,
            _ => return Err(SnippexError::InvalidBinary("Unsupported architecture".into()).into()),
        };

        let start_addr = base_addr;
        let end_addr = base_addr + assembly_block.len() as u64;

        // Create synthetic binary info
        let binary_info = self.create_binary_info(&nasm_content, &architecture)?;

        if !self.quiet {
            println!(
                "Binary info: {} {} (SHA256: {}...)",
                binary_info.format,
                binary_info.architecture,
                &binary_info.hash[..8]
            );
        }

        if self.verbose {
            debug!("Full binary info: {binary_info:?}");
        }

        // Initialize database
        let mut db = Database::new(&self.database)?;
        db.init()?;

        if !self.quiet {
            println!("Database initialized: {}", self.database.display());
        }

        // Store the extraction
        db.store_extraction(&binary_info, start_addr, end_addr, &assembly_block)?;

        if !self.quiet {
            println!(
                "Imported block: 0x{:08x} - 0x{:08x} ({} bytes)",
                start_addr,
                end_addr,
                assembly_block.len()
            );
            println!("✓ Import stored in database successfully");
        }

        if self.verbose {
            debug!(
                "Assembly block first 16 bytes: {:02x?}",
                &assembly_block[..16.min(assembly_block.len())]
            );
            debug!("Temporary files cleaned up");
        }

        Ok(())
    }

    fn detect_architecture(&self, nasm_content: &str) -> Result<String> {
        // 1. Check CLI argument first
        if let Some(arch) = &self.arch {
            let normalized = arch.to_lowercase();
            match normalized.as_str() {
                "x86" | "i386" | "32" => return Ok("i386".to_string()),
                "x86_64" | "amd64" | "64" => return Ok("x86_64".to_string()),
                _ => {
                    return Err(SnippexError::InvalidBinary(format!(
                        "Unsupported architecture: {}. Use 'x86' or 'x86_64'",
                        arch
                    ))
                    .into())
                }
            }
        }

        // 2. Look for BITS directive in file
        let content_lower = nasm_content.to_lowercase();
        if content_lower.contains("bits 64") {
            return Ok("x86_64".to_string());
        }
        if content_lower.contains("bits 32") {
            return Ok("i386".to_string());
        }

        // 3. Look for architecture-specific instructions/registers
        if content_lower.contains("rax")
            || content_lower.contains("rbx")
            || content_lower.contains("rcx")
            || content_lower.contains("rdx")
        {
            return Ok("x86_64".to_string());
        }

        // 4. Default to x86_64
        Ok("x86_64".to_string())
    }

    fn format_nasm_source(&self, nasm_content: &str, architecture: &str) -> Result<String> {
        let bits = match architecture {
            "x86_64" => "64",
            "i386" => "32",
            _ => return Err(SnippexError::InvalidBinary("Unsupported architecture".into()).into()),
        };

        let mut formatted = String::new();

        // Add BITS directive if not present
        let content_lower = nasm_content.to_lowercase();
        if !content_lower.contains("bits") {
            formatted.push_str(&format!("BITS {}\n", bits));
        }

        // Add section directive if not present
        if !content_lower.contains("section") {
            formatted.push_str("section .text\n");
        }

        // Add global _start if not present
        if !content_lower.contains("global") && !content_lower.contains("_start:") {
            formatted.push_str("global _start\n");
        }

        // Add _start label if not present
        if !content_lower.contains("_start:") {
            formatted.push_str("_start:\n");
        }

        // Add original content
        for line in nasm_content.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                // Skip duplicate directives
                let line_lower = trimmed.to_lowercase();
                if line_lower.starts_with("bits")
                    || line_lower.starts_with("section")
                    || line_lower.starts_with("global")
                {
                    continue;
                }

                // Add proper indentation for non-labels
                if trimmed.ends_with(':') {
                    formatted.push_str(&format!("{}\n", trimmed));
                } else {
                    formatted.push_str(&format!("    {}\n", trimmed));
                }
            }
        }

        // Add exit syscall to make it a complete program
        if architecture == "x86_64" {
            formatted.push_str("    mov rax, 60     ; sys_exit\n");
            formatted.push_str("    mov rdi, 0      ; exit status\n");
            formatted.push_str("    syscall\n");
        } else {
            formatted.push_str("    mov eax, 1      ; sys_exit\n");
            formatted.push_str("    mov ebx, 0      ; exit status\n");
            formatted.push_str("    int 0x80\n");
        }

        Ok(formatted)
    }

    fn extract_text_section(&self, binary_data: &[u8]) -> Result<Vec<u8>> {
        // Parse the ELF binary using the object crate
        let file = object::File::parse(binary_data).map_err(|e| {
            SnippexError::BinaryParsing(format!("Failed to parse compiled binary: {}", e))
        })?;

        // Find the .text section
        let text_section = file.section_by_name(".text").ok_or_else(|| {
            SnippexError::BinaryParsing("No .text section found in compiled binary".into())
        })?;

        let section_data = text_section.data().map_err(|e| {
            SnippexError::BinaryParsing(format!("Failed to read .text section: {}", e))
        })?;

        // Remove the exit syscall we added (last few bytes)
        // x86_64: mov rax,60; mov rdi,0; syscall = ~15 bytes
        // i386: mov eax,1; mov ebx,0; int 0x80 = ~10 bytes
        let syscall_size = 15; // Conservative estimate
        let end_pos = section_data.len().saturating_sub(syscall_size).max(1);

        Ok(section_data[..end_pos].to_vec())
    }

    fn create_binary_info(&self, nasm_content: &str, architecture: &str) -> Result<BinaryInfo> {
        // Hash the source content (not the compiled bytes) for traceability
        let mut hasher = Sha256::new();
        hasher.update(nasm_content.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        Ok(BinaryInfo {
            path: self.nasm_file.to_string_lossy().to_string(),
            size: nasm_content.len() as u64,
            hash,
            format: "NASM-Import".to_string(),
            architecture: architecture.to_string(),
            endianness: "little".to_string(), // x86/x86_64 are little endian
            base_address: 0x400000, // Default base address for imported NASM files
        })
    }
}
