# Root Cause Analysis: Simulation Failures

## Date: 2026-01-15

## TL;DR
The simulation infrastructure is built but **address translation is NOT being applied** in the preamble generation. The generated assembly uses original binary addresses (0x555555000000+) instead of translated sandbox addresses (0x10000000+), causing NASM compilation failures.

## Evidence: Generated Assembly Analysis

### File Inspected
`/tmp/debug_simulation_2329fa70-5014-4ad8-a2b0-e6f3e01f3772.asm`

### Problem 1: Untranslated Memory Addresses in Preamble

**Lines 22-27 of generated assembly:**
```nasm
mov dword [0x000055555556316a], 0xd70635f3    ; ❌ WRONG!
mov dword [0x000055555559f058], 0x1f263be0    ; ❌ WRONG!
mov dword [0x00005555555883aa], 0x0ff49eb3    ; ❌ WRONG!
```

**What these addresses are:**
- Original binary virtual addresses from /bin/ls
- These are the addresses from the analysis (memory accesses)
- They should have been translated to sandbox addresses!

**What they should be (with sandbox_base = 0x10000000):**
```nasm
mov dword [0x1005631a], 0xd70635f3    ; ✓ Within 32-bit range
mov dword [0x1009f058], 0x1f263be0    ; ✓ Within 32-bit range
```

**Why NASM fails:**
- 64-bit addresses like `0x000055555556316a` require special addressing modes
- When used directly in mov instructions, NASM needs them within signed 32-bit displacement range
- These addresses exceed that range → "dword displacement exceeds bounds"

### Problem 2: Disassembled Block with RIP-relative Instructions

**Lines 30-54: The extracted block**
```nasm
divss xmm0, xmm1
comiss xmm0, dword [rip + 0xac94]    ; ❌ rip undefined
jae 0xfaf
comiss xmm0, dword [rip + 0xac8f]    ; ❌ rip undefined
```

**The issue:**
- The extracted block is being **disassembled and printed as source code**
- RIP-relative instructions are shown as `[rip + offset]`
- But when NASM tries to reassemble this, `rip` is not a valid symbol → "symbol `rip' not defined"

**What should happen:**
The extracted block should be embedded as **raw bytes**, not disassembled instructions:

```nasm
; === EXTRACTED BLOCK CODE ===
db 0xf3, 0x0f, 0x5e, 0xc1  ; divss xmm0, xmm1
db 0x0f, 0x2f, 0x05, 0x94, 0xac, 0x00, 0x00  ; comiss xmm0, [rip+0xac94]
; ... etc
```

OR positioned at the correct address and executed directly without disassembly.

## Why Address Translation Failed

Looking at the code flow:

1. **Sandbox is created** ✅ (src/simulator/mod.rs:90-118)
2. **Sections are loaded** ✅ (lines 99-108)
3. **Sandbox is passed to generator** ✅ (line 125)
4. **BUT: Generator doesn't use it correctly** ❌

The assembly generator receives the sandbox but:
- In `generate_preamble()`, when setting up memory initialization
- It uses the original addresses from `analysis.memory_accesses`
- It SHOULD call `sandbox.translate_to_sandbox(addr)` but doesn't!

## The Fix

### Fix 1: Apply Translation in Preamble

**File:** `src/simulator/assembly_generator.rs`

**Function:** `generate_preamble()`

**Current code** (approximately):
```rust
for addr in &initial_state.memory {
    preamble.push_str(&format!("    mov dword [0x{:016x}], 0x{:08x}\n",
        addr.address,  // ❌ WRONG: using original address
        addr.value));
}
```

**Should be:**
```rust
for addr in &initial_state.memory {
    let translated_addr = match sandbox {
        Some(sb) => sb.translate_to_sandbox(addr.address).unwrap_or(addr.address),
        None => addr.address,
    };

    preamble.push_str(&format!("    mov dword [0x{:016x}], 0x{:08x}\n",
        translated_addr,  // ✅ CORRECT: using translated address
        addr.value));
}
```

### Fix 2: Embed Block as Raw Bytes

**File:** `src/simulator/assembly_generator.rs`

**Function:** `generate_block_code()` or similar

**Current:** Block is disassembled and printed as instructions

**Should be:** Block is embedded as raw bytes

```rust
// Generate hex dump of block
let mut block_code = String::from("    ; === EXTRACTED BLOCK CODE ===\n");
block_code.push_str("block_start:\n");

// Emit as db (define byte) directives
for (i, chunk) in extraction.assembly_block.chunks(16).enumerate() {
    block_code.push_str("    db ");
    let hex_bytes: Vec<String> = chunk.iter()
        .map(|b| format!("0x{:02x}", b))
        .collect();
    block_code.push_str(&hex_bytes.join(", "));
    block_code.push_str("\n");
}
```

## Expected Impact

**After Fix 1 (translated addresses):**
- NASM warnings about "dword displacement exceeds bounds" → GONE ✅
- Memory initialization will use sandbox addresses (0x10000000 range)
- Success rate improvement: ~20-40%

**After Fix 2 (raw bytes):**
- NASM errors "symbol `rip' not defined" → GONE ✅
- RIP-relative instructions will execute correctly in their embedded form
- Success rate improvement: ~40-60%

**Combined:**
- Target success rate: 60-80% ✅

## Remaining Issues (Expected)

Even after these fixes, some blocks will still fail:
1. **Syscalls** - can't be simulated in userspace
2. **External function calls** - target code not available
3. **Privileged instructions** - not allowed in userspace
4. **Self-modifying code** - would need special handling

These are acceptable limitations and should be documented.

## Next Steps

1. ✅ **DONE:** Diagnose root causes (this document)
2. **TODO:** Implement Fix 1 (translate addresses in preamble)
3. **TODO:** Implement Fix 2 (embed block as raw bytes)
4. **TODO:** Test with measure_success_rate.sh
5. **TODO:** Verify 60-80% success rate achieved
6. **TODO:** Document remaining limitations

## Code Locations to Fix

- `src/simulator/assembly_generator.rs`
  - Function: `generate_preamble()` - add address translation
  - Function: Block embedding logic - use raw bytes instead of disassembly

## Test Strategy

1. **Immediate test:** After Fix 1, run simulation on one block
   - Should see: fewer/no "dword exceeds bounds" warnings
   - Should see: addresses in 0x10000000 range

2. **Immediate test:** After Fix 2, run simulation on same block
   - Should see: no "symbol `rip' not defined" errors
   - Should see: successful compilation or execution

3. **Full validation:** Run `./scripts/measure_success_rate.sh`
   - Target: ≥60% success rate
   - If below target, investigate remaining failures individually
