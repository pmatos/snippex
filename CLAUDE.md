# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Goal: FEX-Emu Bug Detection

Snippex is designed to find bugs in FEX-Emu, an x86-on-ARM64 dynamic binary translator/emulator.

### Testing Workflow

The testing methodology requires **native x86 execution as ground truth**:

1. **x86 Machine** (or cloud VM with x86/x86_64 CPU):
   - Extract x86/x86_64 assembly blocks from binaries
   - Analyze blocks for register/memory usage patterns
   - Simulate blocks natively to obtain ground truth results
   - Export simulation results to JSON for transfer

2. **ARM64 Machine** (FEX-Emu testing environment):
   - Import native simulation results (ground truth)
   - Simulate same blocks through FEX-Emu
   - Compare FEX-Emu results against native ground truth
   - Discrepancies indicate potential FEX-Emu bugs

### Why Native Execution is Essential

Native x86 execution provides definitive ground truth for correctness. Alternative approaches are problematic:

**❌ Emulator-vs-Emulator Testing (e.g., Unicorn vs FEX-Emu)**:
- Both emulators might have the same bug → false negative (bug missed)
- Both might have different bugs → no way to determine which is correct
- No authoritative reference for edge cases and undefined behavior
- Reduces confidence in bug detection

**✅ Native-vs-Emulator Testing (Native x86 vs FEX-Emu)**:
- Native execution is definitive - no emulator bugs possible
- Clear ground truth for all x86 behavior including edge cases
- High confidence: disagreement = FEX-Emu bug
- Industry standard for emulator validation

### Current Challenge: Simulation Address Space

Many extracted assembly blocks reference memory addresses from the original binary's address space (e.g., `0x555555000000`). The current simulator uses a sandboxed memory range (`0x10000000-0x20000000`) and rejects out-of-range accesses, causing many simulations to fail.

**Solution Required**: Implement address translation to map the original binary's address space into the simulation sandbox:
1. Parse ELF headers to determine binary base address
2. Copy relevant binary sections (.text, .data, .rodata) into sandbox
3. Translate memory accesses from original addresses to sandbox addresses
4. Execute with translated addresses to obtain correct results

This will dramatically improve simulation success rate while maintaining native execution as ground truth.

## Build, Test, and Lint Commands

- **Build**: `cargo build` (debug) or `cargo build --release` (release)
- **Test**: `cargo test` (all tests)
- **Lint**: `cargo clippy -- -D warnings`
- **Format**: `cargo fmt` (auto-format) or `cargo fmt --check` (check only)
- **Quality Checks**: `make check` (comprehensive) or `make quick` (fast checks)

For development workflow, always run `make pre-commit` before committing changes.

### Specific Test Commands
- Assembly tests: `cargo test ann_asm` (requires NASM: `apt install nasm`)
- Specific assembly test: `cargo test ann_asm -- simple_mov`
- Integration tests: `cargo test --test integration_test`
- Simulation tests: `cargo test --test simulation_test`
- Unit tests: `cargo test --bins`
- Run with verbose output: `cargo test -- --nocapture`

## Code Architecture

Snippex is a Rust CLI tool for extracting and analyzing assembly code blocks from ELF and PE binaries, with a git-like interface.

### Core Modules
- **cli/**: Command-line interface with subcommands (extract, import, list, remove, analyze, simulate)
- **extractor/**: Binary parsing and assembly extraction using `object` crate
- **db/**: SQLite database operations with `rusqlite` for storage and deduplication
- **analyzer/**: Assembly code analysis functionality using Capstone disassembler
- **simulator/**: Assembly simulation framework with state generation, compilation, and execution
- **error.rs**: Centralized error handling with `thiserror`

### Data Flow
1. CLI parses commands and delegates to appropriate modules
2. **Extract**: Extractor parses ELF/PE binaries → extracts random assembly blocks → stores in database
3. **Import**: Imports NASM assembly files directly into database
4. **Analyze**: Retrieves extraction from database → disassembles using Capstone → analyzes live registers, memory access, exits
5. **Simulate**: Analyzes extraction → generates random initial state → creates assembly harness → compiles/links → executes (optionally with emulator) → captures final state
6. Database module handles storage with deduplication by SHA256 hash

### Database Schema
- `binaries` table: Stores binary metadata (path, size, hash, format, architecture)
- `extractions` table: Stores assembly blocks with address ranges and references to binaries

### Key Dependencies
- `object`: ELF/PE binary parsing
- `rusqlite`: SQLite database operations with bundled SQLite
- `clap`: CLI argument parsing with derive features
- `capstone`: Assembly disassembly and instruction analysis
- `rand`: Random block selection and state generation
- `tempfile`: Temporary file management for compilation
- `uuid`: Unique simulation identifiers

### Simulator Architecture
The simulator module enables execution of extracted assembly blocks:
- **AssemblyGenerator**: Creates complete assembly harnesses with state setup/capture
- **CompilationPipeline**: Compiles assembly to binary using NASM and ld
- **ExecutionHarness**: Executes binaries natively or through emulators
- **RandomStateGenerator**: Generates random register/memory states for testing
- **EmulatorConfig**: Supports FEX-Emu for cross-architecture execution

## Development Notes

- Assembly test framework requires NASM assembler (`apt install nasm`)
- Integration tests compile test binaries using GCC
- Simulation tests require NASM and ld for runtime compilation
- Pre-commit hooks available via `./scripts/install-hooks.sh`
- Quality assurance tools: cargo-audit, cargo-machete, cargo-outdated, cargo-geiger
- Run build, tests and lint every time, ensuring they are successful before finishing a feature and before committing
- In code and commits, do not mention Claude as Co-author or that code is generated by Claude
