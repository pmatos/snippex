# Snippex Scripts

This directory contains auxiliary scripts for working with snippex.

## analyze-asm.py

A Python utility that assembles an assembly file and analyzes it with snippex without leaving database traces.

### Usage

```bash
# Analyze 64-bit assembly
python3 scripts/analyze-asm.py --64 example.asm

# Analyze 32-bit assembly  
python3 scripts/analyze-asm.py --32 example.asm

# Verbose output
python3 scripts/analyze-asm.py --64 example.asm --verbose
```

### Features

- **Automatic Assembly**: Uses NASM to assemble your code with proper ELF preamble
- **Clean Analysis**: Uses temporary databases, leaves no traces in your main database
- **Cross-Platform**: Supports both 32-bit and 64-bit x86 architectures
- **Error Handling**: Comprehensive error checking and user-friendly messages
- **Verbose Mode**: Optional detailed output for debugging

### Requirements

- Python 3.6+
- NASM assembler (`sudo apt install nasm`)
- ld linker (usually pre-installed)
- snippex binary (built with `cargo build --release`)

### Examples

**Simple assembly code:**
```asm
; example.asm
mov rax, 42
add rax, 10
mov rbx, rax
```

```bash
$ python3 scripts/analyze-asm.py --64 example.asm
Analyzing block #1...
  Binary: /tmp/snippex_analyze_xyz/input
  Address range: 0x00401000 - 0x00401016

Analysis Results:
=================
Instructions: 5

Live-in Registers (0):
  <none>

Live-out Registers (4):
  - rax
  - rbx
  - rdi
  - rflags

Exit Points (1):
  - 0x00401016: Fall through

Memory Accesses (0):
  <none>

✓ Analysis completed and stored successfully
```

**Memory operations:**
```asm
; memory.asm
mov rax, [rsi]
add rax, 10
mov [rdi], rax
```

This will show memory access analysis including load and store operations.

### How It Works

1. **Preprocessing**: Adds NASM preamble with proper section headers and exit syscalls
2. **Assembly**: Uses NASM to create object file with correct architecture
3. **Linking**: Links object file into ELF executable with proper architecture flags
4. **Extraction**: Uses snippex to extract the entire code section as a block
5. **Analysis**: Analyzes the block and displays results
6. **Cleanup**: Automatically removes all temporary files and databases

The script operates entirely in temporary directories and uses temporary database files, ensuring no interference with your main snippex database.

## extract_fex_tests.py

A Python utility that extracts NASM assembly tests from the FEX-Emu project and converts them to Snippex's test format. It removes JSON headers from FEX tests and tracks extracted tests by SHA256 hash to avoid duplicates.

### Usage

```bash
# Extract all FEX tests
./scripts/extract_fex_tests.py

# Dry run - show what would be extracted
./scripts/extract_fex_tests.py --dry-run

# Extract only tests from a specific category
./scripts/extract_fex_tests.py --category TwoByte
./scripts/extract_fex_tests.py --category Primary

# Force re-extraction of already extracted tests
./scripts/extract_fex_tests.py --force

# Custom paths
./scripts/extract_fex_tests.py --fex-path /path/to/FEX --output-dir tests/asm
```

### Features

- **Automatic Conversion**: Removes FEX JSON headers and converts to Snippex format
- **Deduplication**: Tracks extracted tests by SHA256 hash to avoid duplicates
- **Architecture Detection**: Auto-detects 32/64-bit from JSON metadata or assembly code
- **Category Filtering**: Extract only specific test categories (e.g., TwoByte, X87)
- **Incremental Updates**: Only extracts new or modified tests on subsequent runs
- **Source Tracking**: Adds metadata comments with original FEX source path and SHA256

### Requirements

- Python 3.6+
- FEX submodule initialized: `git submodule update --init --recursive`

### FEX Test Format

FEX tests have a JSON header with test expectations:

```asm
%ifdef CONFIG
{
  "RegData": {
    "RAX": "0xFFFFFFFFFFFFFFFF"
  }
}
%endif

mov rax, -1
hlt
```

### Snippex Output Format

Extracted tests have simplified metadata comments:

```asm
; BITS: 64
; SOURCE: FEX mov.asm
; FEX_SHA256: abc123...
mov rax, -1
hlt
```

### Tracking File

The script maintains `tests/asm/.fex_extracted.json` to track extracted tests:

```json
{
  "abc123...": {
    "source_path": "mov.asm",
    "output_file": "tests/asm/fex_mov.asm",
    "extracted_at": "2025-09-29T22:00:00"
  }
}
```

### Output Naming

FEX tests are extracted with `fex_` prefix and category in filename:
- `TwoByte/0F_10.asm` → `fex_twobyte_0f_10.asm`
- `Primary/00_00.asm` → `fex_primary_00_00.asm`
- `mov.asm` → `fex_mov.asm`

### Updating FEX Tests

To get latest FEX tests:

```bash
# Update FEX submodule
git submodule update --remote external/FEX

# Extract new tests
./scripts/extract_fex_tests.py
```

The script automatically skips already-extracted tests based on their SHA256 hash.

## annotate_asm_tests.py

A Python utility that automatically analyzes assembly test files and adds LIVEIN, LIVEOUT, EXITS, and MEMORY annotations using Snippex's analyzer. This is useful for preparing FEX tests (or any assembly tests) for Snippex's test framework.

### Usage

```bash
# Build snippex first
cargo build --release

# Annotate all FEX tests
./scripts/annotate_asm_tests.py --pattern "fex_*.asm"

# Annotate a specific test
./scripts/annotate_asm_tests.py --pattern "fex_mov.asm"

# Dry run to see what would be annotated
./scripts/annotate_asm_tests.py --pattern "fex_*.asm" --dry-run

# Verbose output
./scripts/annotate_asm_tests.py --pattern "fex_*.asm" --verbose
```

### Features

- **Automatic Analysis**: Uses Snippex to analyze assembly and detect live registers
- **Smart Architecture Detection**: Auto-detects 32/64-bit from assembly content
- **Skips Annotated Files**: Won't re-annotate files that already have LIVEIN/LIVEOUT
- **Batch Processing**: Can annotate multiple files at once

### Requirements

- Python 3.6+
- Snippex binary built (`cargo build --release`)
- NASM assembler (`apt install nasm`)

### How It Works

1. **Compilation**: Compiles the assembly file to an ELF binary
2. **Extraction**: Uses `snippex extract` to extract the code block
3. **Analysis**: Uses `snippex analyze` to analyze the block
4. **Annotation**: Parses the analysis output and adds comment annotations

### Output Format

The script adds annotations after existing metadata comments:

```asm
; BITS: 64
; SOURCE: FEX mov.asm
; FEX_SHA256: abc123...
; LIVEIN:
; LIVEOUT: rax, rbx, rcx, rdx
; EXITS: 0x00401000: Fall through
; MEMORY:
mov rax, 42
```

### Note on Accuracy

The automatic annotations provide a good starting point but may need manual verification, especially for:
- Complex control flow
- Memory operations
- Register aliasing

By default, FEX tests (`fex_*.asm`) are excluded from the test framework (`cargo test ann_asm`). To include a FEX test:
1. Run the annotation script on it
2. Manually verify the annotations
3. Rename it to remove the `fex_` prefix

This keeps the test suite clean while preserving FEX tests as reference material.