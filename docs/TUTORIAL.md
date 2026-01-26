# Snippex Tutorial: Finding FEX-Emu Bugs with SuperTuxKart

This tutorial demonstrates how to use Snippex to extract, analyze, simulate, and validate x86 assembly blocks from real binaries like SuperTuxKart, comparing native x86 execution against FEX-Emu on ARM64.

## The Core Workflow

Snippex is designed to find bugs in FEX-Emu by comparing its output against native x86 execution (the oracle):

```
┌─────────────────────────────────────────────────────────────┐
│                     x86 Machine (Ground Truth)              │
├─────────────────────────────────────────────────────────────┤
│  1. snippex extract <binary>     # Extract assembly blocks  │
│  2. snippex analyze <N>          # Analyze register usage   │
│  3. snippex simulate <N> --runs 100  # Run natively (oracle)│
│  4. snippex export -o results.json   # Export for transfer  │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼ (transfer file)
┌─────────────────────────────────────────────────────────────┐
│                   ARM64 Machine (FEX Testing)               │
├─────────────────────────────────────────────────────────────┤
│  5. snippex import-results results.json  # Import oracle    │
│  6. snippex emulate <N>     # Replay through FEX & compare  │
└─────────────────────────────────────────────────────────────┘
```

**Key insight:** Native x86 execution is the ground truth. The `emulate` command takes stored native simulation results (with their initial states), replays them through FEX-Emu, and compares the outputs. Any discrepancy indicates a potential FEX-Emu bug.

## Prerequisites

### Local Machine (x86_64)
- Rust toolchain
- NASM assembler (`apt install nasm`)
- libcapstone-dev (`apt install libcapstone-dev`)
- Build snippex: `cargo build --release`

### Remote ARM64 Machine
- SSH access configured (in this tutorial: `user@fex-arm64.local`)
- FEX-Emu installed at a common location (e.g., `~/dev/FEX/out/install/Release/bin/FEXInterpreter`)
- x86_64 cross-compilation tools (`apt install gcc-x86-64-linux-gnu`)
- NASM assembler
- Snippex built natively for ARM64

## Setup

### 1. Create Working Directory

```bash
mkdir -p ~/snippex-demo
cd ~/snippex-demo
```

### 2. Get a Test Binary

Download or extract an x86_64 binary. For this tutorial, we use SuperTuxKart:

```bash
# Extract SuperTuxKart
tar xzf ~/Downloads/SuperTuxKart-1.5-linux-x86_64.tar.gz -C /tmp/
STK_BINARY="/tmp/SuperTuxKart-1.5-linux-x86_64/bin/supertuxkart"
```

### 3. Configure Remote Machine

#### Option A: Automated Setup (Recommended)

Use the `remote-setup` command to automatically cross-compile and deploy snippex:

```bash
# First, add your remote configuration
snippex config add-remote arm64-fex \
  --host fex-arm64.local \
  --user user \
  --architecture aarch64 \
  --fex-path ~/dev/FEX/out/install/Release/bin/FEXInterpreter

# Cross-compile and deploy to the remote
snippex remote-setup arm64-fex --verbose

# Validate the setup
snippex config validate arm64-fex --check-deps
```

The `remote-setup` command will:
1. Cross-compile snippex for ARM64 (requires `cross` tool: `cargo install cross`)
2. Transfer the binary to the remote machine
3. Verify the installation works

#### Option B: Manual Setup

Build snippex natively on your ARM64 machine:

```bash
# On the local x86 machine
rsync -av --exclude target --exclude .git ~/dev/snippex/ user@arm64-host:~/dev/snippex/

# SSH to ARM64 machine
ssh user@arm64-host

# On ARM64 machine - build natively
cd ~/dev/snippex
cargo build --release
cp target/release/snippex ~/.local/bin/

# Install cross-compilation tools
sudo apt install gcc-x86-64-linux-gnu nasm
```

Then configure the remote locally:

```bash
snippex config add-remote arm64-fex \
  --host fex-arm64.local \
  --user user \
  --architecture aarch64 \
  --snippex-path ~/.local/bin/snippex \
  --fex-path ~/dev/FEX/out/install/Release/bin/FEXInterpreter
```

#### Validating the Remote Configuration

Use `config validate` to verify everything is set up correctly:

```bash
# Quick check (SSH only)
snippex config validate arm64-fex --quick

# Standard check (SSH + snippex + FEX path)
snippex config validate arm64-fex

# Full check including build dependencies
snippex config validate arm64-fex --check-deps --verbose
```

Example output:
```
Validating 1 remote(s) (full + dependencies mode)...

Remote: arm64-fex (user@fex-arm64.local)
  SSH connection... ✓ OK
  snippex (~/.local/bin/snippex)... ✓ snippex 0.1.0
  FEX-Emu (~/dev/FEX/.../FEXInterpreter)... ✓ exists
  Build dependencies:
    nasm... ✓ NASM version 2.16.01
    ld... ✓ GNU ld (GNU Binutils for Debian) 2.40
    x86_64-linux-gnu-gcc... ✓ x86_64-linux-gnu-gcc (Debian 12.2

═══════════════════════════════════════════════
Results: 6 passed, 0 failed, 0 warnings
```

## Core Workflow

### Step 1: Extract Assembly Blocks

Extract random assembly blocks from the binary:

```bash
snippex extract "$STK_BINARY" --count 10
```

Output:
```
Extracting blocks from: /tmp/SuperTuxKart-1.5-linux-x86_64/bin/supertuxkart
Found 10 random block candidates
Successfully stored 10 extractions in database
```

### Step 2: List Extracted Blocks

View all extracted blocks:

```bash
snippex list
```

Output:
```
╔════╦════════════════════════════════════════════════╦══════════════╦══════════════╦══════╦═══════════╦══════════╗
║ ID ║ Binary                                         ║ Start Addr   ║ End Addr     ║ Size ║ Analyzed  ║ Simulated║
╠════╬════════════════════════════════════════════════╬══════════════╬══════════════╬══════╬═══════════╬══════════╣
║ 1  ║ supertuxkart                                   ║ 0x00ad846a   ║ 0x00ad84df   ║ 117  ║ No        ║ No       ║
║ 2  ║ supertuxkart                                   ║ 0x003152c8   ║ 0x00315311   ║ 73   ║ No        ║ No       ║
...
```

### Step 3: Analyze a Block

Disassemble and analyze register/memory usage:

```bash
snippex analyze 8
```

Output:
```
Analyzing block #8...
  Binary: /tmp/SuperTuxKart-1.5-linux-x86_64/bin/supertuxkart
  Address range: 0x00acfd87 - 0x00acfd97

═════════════════════════════════════════════════
Disassembly (16 bytes, 4 instructions):
─────────────────────────────────────────────────
0x00acfd87:  mov r8, rsi
0x00acfd8a:  xor rax, 0x3f
0x00acfd8e:  neg r10
0x00acfd91:  mov r11, [rdi + 0x10]

═════════════════════════════════════════════════
Register Analysis:
─────────────────────────────────────────────────
Live-in registers:  rax, rdi, rsi, r10
Live-out registers: rax, r8, r10, r11, rflags
Pointer registers:  rdi

═════════════════════════════════════════════════
Memory Access Analysis:
─────────────────────────────────────────────────
Total memory accesses: 1
  [rdi + 0x10] (read, 8 bytes)

✓ Analysis completed and stored successfully
```

### Step 4: Simulate Natively

Run the block with random initial state on native x86:

```bash
snippex simulate 8 --verbose
```

Output:
```
Simulating block #8...

Initial State:
  rax: 0x1800007c
  rdi: 0x18000000  (pointer to memory region)
  rsi: 0x50640efb3d410305
  r10: 0x67b0593922acbab5
  ...

Block Execution:
  Exit code: 0
  Execution time: 152.71µs

Final State:
  rax: 0x000000001800003f
  r8:  0x50640efb3d410305
  r10: 0x984ae17bdd534b4b
  r11: 0x8514281e16b826d0
  rflags: 0x0000000000000297
```

### Step 5: Validate Against FEX-Emu

Compare native x86 execution with FEX-Emu on ARM64:

```bash
snippex validate 8 --verbose
```

Output:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Block #8 Validation
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Host: x86-64 (AMD64)
Native execution: local
FEX-Emu execution: user@fex-arm64.local

Running native x86 simulation...
  Exit code: 0
  Execution time: 180.69µs
  Done.
Running FEX-Emu simulation...
  Exit code: 0
  Execution time: 1.059s
  Done.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Results
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Native (x86_64@local):
  Exit code: 0
  Flags: 0x0000000000000297
  rax: 0x000000001800003f
  ...

FEX-Emu (aarch64@user@fex-arm64.local):
  Exit code: 0
  Flags: 0x0000000000000297
  rax: 0x000000001800003f
  ...

Comparison:
  ✓ Exit codes match
  ✓ Flags match
  ✗ Registers differ (15/16)
      rsp: 0x00007ffd4c0f1790 (native) vs 0x00007fffffffeb50 (FEX)
  ✓ Memory match (8/8 locations)
```

**Note:** `rsp` differences are expected since the stack is allocated at different addresses.

## Batch Operations

### Batch Validation

Validate multiple blocks at once:

```bash
# First, analyze all blocks
for i in $(seq 1 10); do snippex analyze $i; done

# Then validate
snippex validate-batch 1-10 --export-csv results.csv
```

Output:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Batch Validation: 10 blocks
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[1/10] Block #1: ! (91.713ms)
[2/10] Block #2: ! (88.042ms)
[3/10] Block #3: ✓ (12.285ms)
...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Batch Summary
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Total blocks:    10
  Passed:        3 ✓
  Failed:        2 ✗
  Native errors: 3
  FEX errors:    2

Success rate:    60.0%
```

Legend:
- `✓` - Both native and FEX succeeded with matching results
- `✗` - Results differ between native and FEX (potential FEX bug!)
- `!` - Native simulation failed (usually memory access issue)
- `F` - FEX simulation failed

### Options

```bash
# Native only (faster, for testing simulation)
snippex validate-batch 1-10 --native-only

# Export to CSV
snippex validate-batch 1-10 --export-csv results.csv

# Parallel execution
snippex validate-batch 1-10 --parallel --threads 4

# Stop on first failure
snippex validate-batch 1-10 --stop-on-failure
```

## Export and Import

### Export Blocks

Export blocks with analyses and simulations:

```bash
snippex export -o exported_blocks.json --simulated-only
```

### Import Results

Import simulation results from another machine:

```bash
snippex import-results results.json --merge
```

## Understanding Results

### Validation Status Meanings

| Status | Meaning |
|--------|---------|
| PASS | Native and FEX results match exactly |
| FAIL | Results differ - potential FEX bug |
| NATIVE_ERROR | Native simulation failed (block may access invalid memory) |
| FEX_ERROR | FEX simulation failed |
| SKIPPED | Block not analyzed or other issue |

### Common Issues

1. **Memory Access Errors**: Many blocks reference memory from the original binary's address space. The simulator uses a sandbox range (0x10000000-0x20000000), so blocks accessing other addresses will fail.

2. **Stack Pointer Differences**: `rsp` will naturally differ between environments as the stack is allocated at different addresses. This is expected and not a bug.

3. **Floating Point State**: FPU/SSE/AVX state may differ due to initialization differences.

## Configuration

### Remote Machine Setup

Configure your remote ARM64 machine:

```bash
# Add a remote
snippex config add-remote arm64-fex \
  --host hostname \
  --user user \
  --architecture aarch64 \
  --snippex-path /home/user/.local/bin/snippex \
  --fex-path ~/dev/FEX/out/install/Release/bin/FEXInterpreter

# View configured remotes
snippex config list-remotes

# Show details of a specific remote
snippex config show-remote arm64-fex

# Validate remote is ready
snippex config validate arm64-fex

# Remove a remote
snippex config remove-remote arm64-fex
```

### Cache Settings

```bash
# Disable cache for debugging
snippex validate 8 --no-cache

# Set cache TTL
snippex validate-batch 1-10 --cache-ttl 30
```

## Tips for Finding FEX Bugs

1. **Start with simple blocks**: Use `--min-size` and `--max-size` when extracting to get smaller, simpler blocks that are more likely to succeed.

2. **Analyze failures**: When a block shows `✗` (FAIL), it means native and FEX produced different results. This is worth investigating as a potential FEX bug.

3. **Use verbose mode**: Add `--verbose` to see detailed register states and identify exactly which registers/flags differ.

4. **Check the assembly**: Use `snippex analyze` to see the actual instructions being tested.

5. **Report bugs**: Use `snippex report` to create GitHub issues with detailed information about failures.

## Complete Example Session

```bash
# Setup
mkdir ~/snippex-demo && cd ~/snippex-demo
STK="/tmp/SuperTuxKart-1.5-linux-x86_64/bin/supertuxkart"

# Extract 20 blocks
snippex extract "$STK" --count 20

# Analyze all blocks
for i in $(seq 1 20); do snippex analyze $i 2>/dev/null; done

# Run batch validation
snippex validate-batch 1-20 --export-csv results.csv

# Investigate failures
snippex validate 8 --verbose

# Export results
snippex export -o session_results.json --simulated-only
```

## Reference

### Block Range Syntax

Commands that operate on blocks (`analyze`, `simulate`, `emulate`) accept flexible block specifications:

| Format | Example | Description |
|--------|---------|-------------|
| Single | `5` | Block number 5 |
| Range | `1-10` | Blocks 1 through 10 (inclusive) |
| Open-ended | `5-` | Blocks 5 to the last block |
| List | `3,7,12` | Specific blocks 3, 7, and 12 |
| All | `all` | All blocks in the database |

Examples:
```bash
# Analyze blocks 1-10
snippex analyze 1-10

# Simulate all blocks with 5 runs each
snippex simulate all --runs 5

# Emulate specific blocks
snippex emulate 3,7,12

# Simulate from block 50 onwards
snippex simulate 50-
```

### Commands

| Command | Description |
|---------|-------------|
| `extract` | Extract assembly blocks from binary |
| `list` | List extracted blocks |
| `analyze` | Disassemble and analyze block(s) |
| `simulate` | Run native simulation (ground truth) |
| `emulate` | Replay stored simulations through FEX-Emu and compare |
| `validate` | Compare native vs FEX-Emu (same machine) |
| `validate-batch` | Batch validation (**deprecated** - use `validate` with range syntax) |
| `export` | Export blocks to JSON |
| `import-results` | Import simulation results |
| `stats` | View validation statistics |
| `regression` | Regression testing |
| `config` | Manage remote configurations |
| `remote-setup` | Cross-compile and deploy snippex to remote |

### Exit Codes

- `0` - Success
- `1` - Validation failed (results differ)
- `2` - Invalid arguments
- Other - Execution error
