# Troubleshooting Simulation Failures

This guide helps diagnose and resolve common simulation failures in Snippex.

## Quick Diagnosis

Run simulation with verbose output to see detailed error information:

```bash
snippex simulate 1 --verbose
```

## Common Errors and Solutions

### 1. Missing Tools

#### NASM Not Found

```
Error: NASM assembler not found. Please install NASM.
```

**Solution**: Install NASM assembler:

```bash
# Ubuntu/Debian
sudo apt install nasm

# Fedora/RHEL
sudo dnf install nasm

# Arch Linux
sudo pacman -S nasm

# macOS
brew install nasm
```

#### ld Linker Not Found

```
Error: ld linker not found. Please install binutils.
```

**Solution**: Install binutils:

```bash
# Ubuntu/Debian
sudo apt install binutils

# Fedora/RHEL
sudo dnf install binutils

# Arch Linux
sudo pacman -S binutils
```

### 2. Assembly Errors

#### NASM Assembly Failed

```
Error: NASM assembly failed: <error details>
```

**Common causes**:

1. **Invalid instruction encoding**: The extracted block contains incomplete or malformed instructions
2. **Unknown instruction**: The block uses an instruction not supported by NASM
3. **Invalid operand**: Malformed memory references or register names

**Diagnosis**: Check the generated assembly file:

```bash
# Run with verbose to see temp file location
snippex simulate 1 --verbose

# Look for "Assembly file:" in output
cat /tmp/fezinator_sim_XXXX/sim_harness.asm
```

**Solutions**:
- Extract a different block from the binary
- Use `snippex analyze <id>` to inspect the block's disassembly
- Some blocks may be data misidentified as code - try another extraction

### 3. Address Space Errors

#### Address Out of Range

```
Error: Address out of range: Address 0x555555555000 is not within binary's address space
```

**Cause**: The assembly block references memory addresses from the original binary that couldn't be translated.

**Solutions**:

1. **Verify binary still exists**: The original binary must be accessible at its stored path
2. **Check base address**: Run `snippex list --verbose` to see stored base addresses
3. **Re-extract**: If the binary was recompiled, re-extract blocks

#### Memory Access Outside Safe Range

```
Error: Memory address 0x7fffffff0000 is outside safe range
```

**Cause**: Block accesses stack, heap, or other addresses not in binary sections.

**This is expected for**:
- Blocks with stack operations (push/pop, stack canaries)
- Blocks accessing heap-allocated data
- Blocks using thread-local storage (TLS)

**Solutions**:
- These blocks cannot be simulated - extract different blocks
- Focus on blocks that operate on registers or static data

### 4. Execution Failures

#### Segmentation Fault (Exit Code 139)

```
Exit code: 139 (SIGSEGV)
```

**Common causes**:

1. **External function calls**: Block calls libc or other library functions
2. **TLS access**: Block uses %fs or %gs segment registers
3. **Invalid memory access**: Block dereferences uninitialized pointers
4. **System calls**: Block attempts syscall/int 0x80

**Diagnosis**: Check analysis for clues:

```bash
snippex analyze <id>
```

Look for:
- `call` instructions (external function calls)
- `fs:` or `gs:` prefixes (TLS access)
- `syscall` or `int 0x80` (system calls)

#### Illegal Instruction (Exit Code 132)

```
Exit code: 132 (SIGILL)
```

**Cause**: Block contains CPU instructions not supported on current hardware.

**Common scenarios**:
- AVX-512 instructions on older CPUs
- Privileged instructions (ring 0 only)
- CPU-specific extensions

#### Execution Timeout

```
Error: Execution timeout
```

**Cause**: Block contains infinite loop or very long-running code.

**Solutions**:
- Increase timeout: Not currently configurable via CLI
- Extract different blocks

### 5. Binary Loading Errors

#### Binary Not Found

```
Error: Binary parsing error: No such file or directory
```

**Cause**: The original binary has been moved, deleted, or renamed.

**Solutions**:
1. Restore the binary to its original location
2. Re-extract blocks from the binary at its new location
3. Use `snippex list` to see stored binary paths

#### Unsupported Binary Format

```
Error: Invalid binary format: Only ELF format is supported
```

**Cause**: Binary is not an ELF file (might be PE, Mach-O, or other format).

**Current support**:
- ✓ ELF (Linux executables and shared libraries)
- ✗ PE (Windows executables) - extraction only, no simulation
- ✗ Mach-O (macOS executables)

### 6. FEX-Emu Specific Errors

#### FEX-Emu Not Found

```
Error: Failed to execute with FEX-Emu: No such file or directory
```

**Solution**: Install FEX-Emu and ensure it's in PATH:

```bash
# Verify FEX-Emu is installed
which FEXInterpreter

# Or use full path
snippex simulate 1 --emulator fex-emu --emulator-path /path/to/FEXInterpreter
```

#### FEX-Emu Execution Failed

```
Error: Failed to execute with FEX-Emu: <error>
```

**Common causes**:
- FEX-Emu not properly configured
- Missing FEX-Emu rootfs
- Binary format not supported by FEX-Emu

## Simulation Limitations

Some assembly blocks will never simulate successfully due to fundamental limitations:

| Category | Why It Fails | Detection |
|----------|--------------|-----------|
| System calls | Sandbox cannot intercept syscalls | Look for `syscall`, `int 0x80` |
| Library calls | libc not loaded in sandbox | Look for `call` to external symbols |
| TLS access | %fs/%gs not configured | Look for `fs:` or `gs:` prefixes |
| Stack canaries | TLS-based security feature | Look for `fs:[0x28]` pattern |
| Heap data | Dynamic allocations not captured | Blocks accessing pointers |
| I/O operations | File/network ops need syscalls | Any I/O-related code |

## Improving Success Rate

To maximize simulation success:

1. **Extract many blocks**: More extractions = more likely to find simulatable ones
2. **Use smaller blocks**: Shorter blocks have fewer dependencies
3. **Target computational code**: Math, crypto, parsing code often works
4. **Avoid startup/shutdown code**: Entry points often have TLS/stack setup

```bash
# Extract 100 blocks from a binary
for i in $(seq 1 100); do
    snippex extract /usr/bin/some_binary
done

# Find which ones simulate successfully
for id in $(snippex list --format=ids); do
    if snippex simulate $id 2>/dev/null; then
        echo "Block $id: SUCCESS"
    fi
done
```

## Getting Help

If you encounter issues not covered here:

1. Run with `--verbose` flag to get detailed output
2. Check the generated assembly file for clues
3. Use `snippex analyze <id>` to understand block contents
4. Report issues at: https://github.com/anthropics/snippex/issues

## Debug Commands

```bash
# List all extractions with details
snippex list --verbose

# Analyze a specific block
snippex analyze 1

# Simulate with verbose output
snippex simulate 1 --verbose

# Check binary info
snippex show-binary 1
```
