# Phase 1 Completion Plan: Achieving 60-80% Simulation Success Rate

## Current Status Assessment

### What We Have ✓
- ✅ ELF parsing and base address extraction
- ✅ Binary section loading (.text, .data, .rodata)
- ✅ SandboxMemoryLayout with address translation logic
- ✅ Integration: sandbox is created and passed to assembly generator
- ✅ Test infrastructure in place

### What's NOT Working ❌
- ❌ **0% simulation success rate** (measured with scripts/measure_success_rate.sh)
- ❌ NASM assembly compilation fails consistently
- ❌ Core objective unfulfilled: blocks still fail due to address space issues

## Root Cause Analysis

### Problem 1: NASM "symbol `rip` not defined" Errors

**Symptom:**
```
error: symbol `rip' not defined
```

**Root Cause:** The assembly generator is likely trying to reference `rip` as a variable/symbol instead of using NASM's built-in RIP-relative addressing syntax.

**Investigation Needed:**
1. Examine generated assembly files (use `--keep-files` flag)
2. Check how `AssemblyGenerator::generate_preamble()` uses sandbox translation
3. Verify NASM syntax for RIP-relative addressing

**Hypothesis:** The preamble generation might be writing something like:
```nasm
mov rax, [rip + offset]  ; WRONG if 'rip' is treated as symbol
```

Instead of:
```nasm
lea rax, [rel symbol]    ; CORRECT NASM syntax
```

### Problem 2: "dword displacement exceeds bounds" Warnings

**Symptom:**
```
warning: dword displacement exceeds bounds
warning: signed dword exceeds bounds
```

**Root Cause:** High addresses (0x555555000000+) don't fit in 32-bit signed displacements. Even after translation to sandbox (0x10000000+), we're generating instructions with 64-bit addresses that need special handling.

**Investigation Needed:**
1. Check if we're using 64-bit addressing modes correctly
2. Verify NASM is assembled with `-felf64` flag
3. Check if immediate values are properly sized

### Problem 3: "Output buffer too small" Errors

**Symptom:**
```
Error: Output buffer too small: 0 bytes, expected at least 4096 bytes
```

**Root Cause:** The execution harness expects the binary to write state output to a buffer, but it's getting 0 bytes. This suggests:
- Binary crashes before writing output
- Binary writes to wrong location
- Output capture mechanism is broken

**Investigation Needed:**
1. Check if binary actually executes
2. Verify output buffer setup in assembly harness
3. Test with `strace` to see syscalls/crashes

### Problem 4: Address Translation Logic Gaps

**Potential Issues:**
- Not all memory references are being translated
- RIP-relative instructions in extracted blocks point to wrong locations
- Stack/heap addresses not handled
- Missing section mappings

## Action Plan: Detailed Steps

### Phase 1A: Debug & Understand Current Failures (2-3 days)

#### Step 1: Inspect Generated Assembly
```bash
# Extract and simulate with kept files
cargo run -- extract /bin/ls --database /tmp/debug.db
cargo run -- analyze --database /tmp/debug.db 1
cargo run -- simulate 1 --database /tmp/debug.db --keep-files --verbose

# Find and examine the generated assembly
find /tmp -name "simulation_*.asm" -mmin -5 -exec cat {} \;
```

**What to look for:**
- How is the extracted block embedded?
- How are memory addresses set up?
- What does the preamble/postamble look like?
- Are there any references to `rip` as a symbol?

#### Step 2: Create Minimal Reproduction Case
```rust
// Create a simple test that should work
#[test]
fn test_simple_arithmetic_block() {
    // mov rax, rbx
    // add rax, 42
    // ret
    let block = vec![0x48, 0x89, 0xd8, 0x48, 0x83, 0xc0, 0x2a, 0xc3];

    // This has NO memory references - should work!
    // If this fails, problem is in harness generation itself
}
```

#### Step 3: Test With Different Block Types

Create tests for:
1. **Pure register operations** (no memory access) - SHOULD work
2. **Stack operations** (push/pop) - might work
3. **RIP-relative loads** - currently failing
4. **Absolute memory references** - currently failing

This will tell us exactly where the problems are.

### Phase 1B: Fix Assembly Generation (3-5 days)

#### Fix 1: Correct RIP-relative Addressing in NASM

**Current code inspection needed:**
```rust
// In src/simulator/assembly_generator.rs
fn generate_preamble(&self, initial_state: &InitialState,
                     sandbox: Option<&SandboxMemoryLayout>) -> Result<String>
```

**Likely fix needed:**
- Don't reference `rip` as a symbol
- Use NASM's `rel` keyword for RIP-relative addressing
- Or use absolute 64-bit addresses with proper addressing modes

**Example correct NASM:**
```nasm
section .data
my_data: dq 0x1234567890abcdef

section .text
global _start
_start:
    ; RIP-relative load (correct)
    mov rax, [rel my_data]

    ; Absolute 64-bit address (also correct)
    mov rbx, qword [0x10000000]

    ; WRONG: treating rip as symbol
    ; mov rax, [rip + my_data]  ; ERROR!
```

#### Fix 2: Handle 64-bit Addresses Properly

**Add to assembly header:**
```nasm
BITS 64
default rel  ; Use RIP-relative addressing by default
```

**Ensure we're using 64-bit registers and addressing:**
```nasm
; Good
mov rax, qword [address]

; Bad
mov eax, dword [address]  ; Might truncate on 64-bit addresses
```

#### Fix 3: Fix Output Buffer Mechanism

**Check ExecutionHarness:**
1. How is output captured?
2. Is there a buffer allocated?
3. Does the assembly write to the right location?

**Typical pattern:**
```nasm
; Reserve output buffer
section .bss
output_buffer: resb 4096

; Write final state
mov rdi, output_buffer
; ... write registers, flags, memory ...

; Exit with buffer address in rax
mov rax, output_buffer
mov rdi, 0
syscall  ; exit
```

### Phase 1C: Iterative Testing & Refinement (2-3 days)

#### Test Strategy

1. **Unit Tests**: Test each component in isolation
   ```rust
   #[test]
   fn test_address_translation_in_preamble()

   #[test]
   fn test_nasm_compilation_without_errors()

   #[test]
   fn test_output_buffer_capture()
   ```

2. **Integration Tests**: Test with progressively complex blocks
   - Start with blocks that have NO memory access
   - Add blocks with stack operations
   - Add blocks with simple data loads
   - Add blocks with RIP-relative addressing

3. **Real Binary Tests**: Run measure_success_rate.sh frequently
   ```bash
   # After each fix
   ./scripts/measure_success_rate.sh
   # Target: see incremental improvement
   # - First goal: >0% (anything working!)
   # - Second goal: >20% (better than baseline)
   # - Final goal: 60-80%
   ```

#### Debugging Checklist

For each failing block:
- [ ] Extract and save assembly with `--keep-files`
- [ ] Try to compile assembly manually: `nasm -felf64 file.asm`
- [ ] Check what error NASM reports
- [ ] Inspect the problematic lines
- [ ] Identify pattern (RIP-relative? absolute address? output buffer?)
- [ ] Fix pattern in assembly generator
- [ ] Retest

### Phase 1D: Edge Case Handling (1-2 days)

#### Handle Special Cases

1. **Blocks with no memory references**: Should work with minimal harness
2. **Blocks with syscalls**: Will fail, document limitation
3. **Blocks with function calls**: Need to handle or skip
4. **Blocks with special instructions**: (CPUID, RDTSC, etc.) - may need emulation

#### Add Validation

```rust
// Before simulation, check if block is likely to succeed
fn can_simulate_block(analysis: &BlockAnalysis) -> (bool, String) {
    if analysis.has_syscalls {
        return (false, "Block contains syscalls".to_string());
    }
    if analysis.has_external_calls {
        return (false, "Block has external function calls".to_string());
    }
    // ... more checks
    (true, "Block appears simulatable".to_string())
}
```

## Success Criteria (MUST MEET to call Phase 1 complete)

### Tier 1: Minimum Viable (Required)
- [ ] >20% simulation success rate (better than current ~10-20% baseline)
- [ ] Zero NASM "symbol `rip` not defined" errors
- [ ] At least 10% of blocks simulate successfully without crashing
- [ ] Clear error messages for blocks that can't be simulated

### Tier 2: Target (Original Goal)
- [ ] 60-80% simulation success rate
- [ ] Blocks with simple memory references work reliably
- [ ] Blocks with RIP-relative addressing work
- [ ] Documentation of limitations (what blocks can't work and why)

### Tier 3: Stretch (Exceeds Expectations)
- [ ] >80% simulation success rate
- [ ] Automated classification of "simulatable" vs "non-simulatable" blocks
- [ ] Performance metrics (simulation speed, memory usage)

## Timeline Estimate

**Realistic Timeline:**
- Week 1: Debug & understand (Phase 1A) - 2-3 days
- Week 1-2: Fix assembly generation (Phase 1B) - 3-5 days
- Week 2: Test & refine (Phase 1C) - 2-3 days
- Week 2: Edge cases (Phase 1D) - 1-2 days

**Total: 8-13 days of focused work**

## Next Immediate Action

**RIGHT NOW**: Run diagnostic on a single failing block

```bash
# 1. Extract one block
rm -f /tmp/diag.db
cargo run -- extract /bin/ls --database /tmp/diag.db

# 2. Analyze it
cargo run -- analyze --database /tmp/diag.db 1

# 3. Try to simulate with files kept
cargo run -- simulate 1 --database /tmp/diag.db --keep-files --verbose 2>&1 | tee /tmp/sim_output.txt

# 4. Find the generated assembly file
ASM_FILE=$(find /tmp -name "simulation_*.asm" -mmin -2 | head -1)

# 5. Examine it
echo "=== GENERATED ASSEMBLY ==="
cat "$ASM_FILE"

# 6. Try to compile it manually
echo "=== MANUAL NASM COMPILATION ==="
nasm -felf64 "$ASM_FILE" -o /tmp/test.o 2>&1

# 7. Report findings
echo "=== FINDINGS ==="
echo "This will show us exactly what's wrong with the assembly generation"
```

This diagnostic will reveal the exact problem in the generated assembly, allowing us to fix it systematically.

## Key Insight

**The infrastructure is built, but the assembly generation isn't using it correctly.**

We need to:
1. **SEE** what assembly is being generated (inspect actual files)
2. **UNDERSTAND** why NASM is rejecting it (manual compilation)
3. **FIX** the assembly generator to produce valid code
4. **TEST** systematically with increasing complexity
5. **MEASURE** success rate improvements

Phase 1 is NOT complete until we hit 60-80% success rate OR document why it's impossible and adjust expectations with evidence.
