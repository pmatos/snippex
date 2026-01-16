# Plan: Fix Register-Indirect Memory Access

## Problem Statement

Blocks access memory through registers (e.g., `[rsi+1]`, `[rdi+offset]`, `[rbp-0x20]`), but our random state generator initializes registers with arbitrary values that aren't valid memory addresses. This causes segfaults when the block tries to access memory.

**Example of failure:**
```nasm
; Preamble (current behavior)
mov rsi, 0xd74c926db14a7d50  ; Random garbage - NOT a valid address!

; Block code tries to use rsi as a pointer
mov [rsi+1], al               ; ← SEGFAULT! 0xd74c926db14a7d51 is unmapped
```

## Understanding x86-64 Memory Addressing Modes

### 1. Stack-Relative Accesses (Most Common)
```nasm
mov [rsp+8], rax      ; Write to stack
mov rax, [rsp-16]     ; Read from stack
mov [rbp-0x20], ecx   ; Frame-relative access
```
- **Registers involved**: `rsp`, `rbp`
- **Prevalence**: ~60-70% of blocks
- **Fix priority**: CRITICAL

### 2. Data Pointer Accesses
```nasm
mov [rsi+1], al       ; String/buffer write
mov rax, [rdi+8]      ; Structure field read
mov [rbx], rcx        ; Generic pointer dereference
```
- **Registers involved**: `rsi`, `rdi`, `rbx`, `rcx`, `rdx`, `rax`
- **Prevalence**: ~40-50% of blocks
- **Fix priority**: HIGH

### 3. Index-Scaled Accesses (Arrays)
```nasm
mov rax, [rdi+rcx*8]      ; Array access with index
mov [rbx+rax*4+16], edx   ; Complex array access
```
- **Registers involved**: Base + Index registers
- **Prevalence**: ~20-30% of blocks
- **Fix priority**: MEDIUM

### 4. RIP-Relative Accesses (Global Data)
```nasm
mov rax, [rip+0x1234]     ; Access global variable
```
- **Status**: Already handled by raw byte embedding ✅
- **No additional fix needed**

## Solution Architecture

### Core Idea: Smart Register Initialization

Instead of random values, initialize pointer registers to point to **valid pre-allocated buffers** in the sandbox.

**After fix:**
```nasm
; Preamble (new behavior)
mov rsi, 0x10010200  ; Points to allocated buffer at 0x10010000 + 0x200 offset

; Block code works correctly
mov [rsi+1], al      ; ← SUCCESS! Writes to 0x10010201 (valid sandbox memory)
```

## Detailed Implementation Plan

### Phase 1: Extend Block Analysis to Detect Pointer Registers

**Goal**: When analyzing a block, identify which registers are used for memory addressing and their access patterns.

#### 1.1 Add New Data Structures

**File**: `src/analyzer/mod.rs`

```rust
/// Information about how a register is used as a memory pointer
#[derive(Debug, Clone, Default)]
pub struct PointerRegisterUsage {
    /// Minimum offset used (can be negative, e.g., [rbp-0x20] → -32)
    pub min_offset: i64,
    /// Maximum offset used (e.g., [rsi+100] → 100)
    pub max_offset: i64,
    /// Maximum size of data accessed at any offset
    pub max_access_size: usize,
    /// Whether any instruction reads through this pointer
    pub has_reads: bool,
    /// Whether any instruction writes through this pointer
    pub has_writes: bool,
}

/// Extended BlockAnalysis
pub struct BlockAnalysis {
    // ... existing fields ...

    /// Registers used as memory pointers, with their usage patterns
    pub pointer_registers: HashMap<String, PointerRegisterUsage>,
}
```

#### 1.2 Implement Pointer Detection in Analyzer

**File**: `src/analyzer/mod.rs`

```rust
impl Analyzer {
    /// Parse a memory operand and extract the base register and offset
    /// Examples:
    ///   "[rsi+8]" → Some(("rsi", 8))
    ///   "[rbp-0x20]" → Some(("rbp", -32))
    ///   "[rdi]" → Some(("rdi", 0))
    ///   "[rax+rcx*4+8]" → Some(("rax", 8)) // Base register only
    fn parse_memory_operand(&self, operand: &str) -> Option<(String, i64)> {
        // Implementation details...
    }

    /// Analyze all instructions to find pointer register usage
    fn detect_pointer_registers(&self, instructions: &[Instruction]) -> HashMap<String, PointerRegisterUsage> {
        let mut pointers: HashMap<String, PointerRegisterUsage> = HashMap::new();

        for insn in instructions {
            // Check each operand for memory references
            for operand in &insn.operands {
                if let Some((base_reg, offset)) = self.parse_memory_operand(operand) {
                    let usage = pointers.entry(base_reg).or_default();
                    usage.min_offset = usage.min_offset.min(offset);
                    usage.max_offset = usage.max_offset.max(offset);
                    usage.max_access_size = usage.max_access_size.max(insn.access_size);
                    // Determine read/write based on instruction semantics
                }
            }
        }

        pointers
    }
}
```

#### 1.3 Parsing Strategy

**Memory operand patterns to handle:**
```
Pattern                    | Base Register | Offset
---------------------------|---------------|--------
[rsi]                      | rsi           | 0
[rdi+8]                    | rdi           | 8
[rbp-0x20]                 | rbp           | -32
[rsp+rax]                  | rsp           | 0 (ignore dynamic index)
[rbx+rcx*4]                | rbx           | 0 (ignore scaled index)
[rax+rcx*8+16]             | rax           | 16 (ignore scaled index)
qword ptr [rsi+0x100]      | rsi           | 256
dword [r15+r14*4-0x10]     | r15           | -16
```

**Key insight**: For static analysis, we only care about the **base register** and **constant offset**. Scaled indices (rcx*4, etc.) are dynamic and can't be predicted, so we'll allocate extra buffer space to accommodate them.

### Phase 2: Allocate Pointer Buffers in Sandbox

**Goal**: Add functionality to allocate buffers for pointer registers within the sandbox address space.

#### 2.1 Add Buffer Allocation to Sandbox

**File**: `src/simulator/sandbox.rs`

```rust
impl SandboxMemoryLayout {
    /// Dedicated regions within sandbox
    const STACK_REGION_START: u64 = SANDBOX_BASE + 0x00800000;  // 8MB into sandbox
    const STACK_REGION_SIZE: u64 = 0x00100000;                  // 1MB stack
    const BUFFER_REGION_START: u64 = SANDBOX_BASE + 0x00A00000; // 10MB into sandbox

    /// Next available address for buffer allocation
    next_buffer_addr: u64,

    pub fn new(binary_base: u64) -> Self {
        Self {
            // ... existing fields ...
            next_buffer_addr: Self::BUFFER_REGION_START,
        }
    }

    /// Allocate a buffer for a pointer register
    /// Returns the base address of the allocated buffer
    pub fn allocate_pointer_buffer(&mut self, size: usize) -> Result<u64> {
        let addr = self.next_buffer_addr;
        let aligned_size = (size + 0xFFF) & !0xFFF;  // Page-align

        // Check we don't overflow the sandbox
        if addr + aligned_size as u64 > SANDBOX_BASE + SANDBOX_SIZE {
            return Err(Error::Simulation("Sandbox buffer space exhausted".into()));
        }

        self.next_buffer_addr += aligned_size as u64;
        Ok(addr)
    }

    /// Get the address for stack pointer initialization
    /// Returns address near TOP of stack region (stack grows down)
    pub fn get_stack_pointer(&self) -> u64 {
        Self::STACK_REGION_START + Self::STACK_REGION_SIZE - 0x1000
    }

    /// Get the address for frame pointer initialization
    pub fn get_frame_pointer(&self) -> u64 {
        self.get_stack_pointer()  // Start at same place, will diverge
    }
}
```

### Phase 3: Update Random State Generator

**Goal**: Use pointer register analysis to initialize pointer registers with valid addresses.

#### 3.1 Modify Initial State Generation

**File**: `src/simulator/random_generator.rs`

```rust
impl RandomStateGenerator {
    pub fn generate_initial_state_with_sandbox(
        &mut self,
        analysis: &BlockAnalysis,
        sandbox: &mut SandboxMemoryLayout,
    ) -> Result<InitialState> {
        let mut state = InitialState::default();

        // === STEP 1: Handle Stack Pointer (rsp) ===
        // Always initialize to valid stack, even if not detected as pointer
        // (most code implicitly uses stack)
        let stack_addr = sandbox.get_stack_pointer();
        state.registers.insert("rsp".to_string(), stack_addr);

        // === STEP 2: Handle Frame Pointer (rbp) ===
        // If used for memory access, point to stack region
        if analysis.pointer_registers.contains_key("rbp") {
            state.registers.insert("rbp".to_string(), stack_addr);
        }

        // === STEP 3: Handle Other Pointer Registers ===
        for (reg, usage) in &analysis.pointer_registers {
            if reg == "rsp" || reg == "rbp" {
                continue;  // Already handled
            }

            // Calculate required buffer size
            // Need space for: [reg + min_offset] to [reg + max_offset + access_size]
            let range = (usage.max_offset - usage.min_offset) as usize;
            let buffer_size = range + usage.max_access_size + 512;  // Extra padding

            // Allocate buffer
            let buffer_base = sandbox.allocate_pointer_buffer(buffer_size)?;

            // Calculate register value so that:
            // - [reg + min_offset] is at buffer_base + 256 (padding)
            // - [reg + max_offset] is well within buffer
            let reg_value = if usage.min_offset < 0 {
                // Need room for negative offsets
                buffer_base + 256 + (-usage.min_offset) as u64
            } else {
                buffer_base + 256
            };

            state.registers.insert(reg.clone(), reg_value);
        }

        // === STEP 4: Handle Non-Pointer Registers ===
        let all_regs = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];

        for reg in all_regs {
            if !state.registers.contains_key(reg) {
                // Not a pointer register - use random value
                state.registers.insert(reg.to_string(), self.rng.gen());
            }
        }

        // === STEP 5: Set Up Stack Values ===
        state.stack_setup = self.generate_stack_values();

        // === STEP 6: Memory Locations ===
        // For detected memory accesses, initialize with random data
        state.memory_locations = self.generate_memory_locations(analysis, sandbox)?;

        Ok(state)
    }
}
```

### Phase 4: Update Simulator Integration

**Goal**: Wire everything together in the simulation flow.

#### 4.1 Update Simulator::simulate_block

**File**: `src/simulator/mod.rs`

```rust
impl Simulator {
    pub fn simulate_block(
        &mut self,
        extraction: &ExtractionInfo,
        analysis: &BlockAnalysis,
        emulator: Option<EmulatorConfig>,
        keep_files: bool,
    ) -> Result<SimulationResult> {
        // Create sandbox (mutable so we can allocate buffers)
        let mut sandbox = if extraction.binary_base_address > 0 {
            // ... existing sandbox creation code ...
            Some(sandbox_layout)
        } else {
            None
        };

        // Generate initial state WITH sandbox awareness
        let initial_state = if let Some(ref mut sb) = sandbox {
            self.random_generator.generate_initial_state_with_sandbox(analysis, sb)?
        } else {
            // Fallback to basic random state (will likely fail)
            self.random_generator.generate_initial_state(analysis)
        };

        // Generate assembly file
        let assembly_source = self.assembly_generator.generate_simulation_file(
            extraction,
            analysis,
            &initial_state,
            sandbox.as_ref(),  // Pass immutable reference
        )?;

        // ... rest of simulation ...
    }
}
```

### Phase 5: Handle Memory Initialization in Preamble

**Goal**: Ensure pointer buffers contain valid data that won't cause crashes.

#### 5.1 Initialize Pointer Buffers with Random Data

When we allocate a pointer buffer, we should also add entries to `memory_locations` so the preamble initializes the buffer with valid (if random) data.

```rust
fn generate_memory_locations(
    &mut self,
    analysis: &BlockAnalysis,
    sandbox: &SandboxMemoryLayout,
) -> Result<HashMap<u64, Vec<u8>>> {
    let mut locations = HashMap::new();

    for (reg, usage) in &analysis.pointer_registers {
        if let Some(reg_value) = sandbox.get_register_value(reg) {
            // For each potential access offset, initialize memory
            let start = reg_value as i64 + usage.min_offset;
            let end = reg_value as i64 + usage.max_offset + usage.max_access_size as i64;

            // Initialize in chunks
            for addr in (start..end).step_by(8) {
                if addr > 0 {
                    let data: [u8; 8] = self.rng.gen();
                    locations.insert(addr as u64, data.to_vec());
                }
            }
        }
    }

    locations
}
```

### Phase 6: Special Handling for Complex Cases

#### 6.1 Scaled Index Addressing

For `[rax + rcx*8 + 16]`, the effective address depends on `rcx` which is random. We can't predict all possible addresses, but we can:

1. **Limit the index**: Initialize index registers to small values (0-255)
2. **Allocate large buffers**: Make pointer buffers large enough for reasonable index ranges

```rust
// When we detect scaled index usage:
if has_scaled_index {
    // Initialize the index register to a small value
    let index_reg = detect_index_register(operand);
    state.registers.insert(index_reg, self.rng.gen::<u8>() as u64);

    // Allocate extra buffer space
    buffer_size += 256 * 8;  // For index values 0-255 with scale 8
}
```

#### 6.2 Self-Modifying Code Detection

Some blocks might write to addresses that happen to be their own code. We should detect and skip these.

```rust
fn is_potentially_self_modifying(&self, analysis: &BlockAnalysis, extraction: &ExtractionInfo) -> bool {
    // Check if any write targets could overlap with block address range
    for (reg, usage) in &analysis.pointer_registers {
        if usage.has_writes {
            // Conservative check - if we can't be sure, assume it's safe
        }
    }
    false
}
```

### Phase 7: Testing Strategy

#### 7.1 Unit Tests

```rust
#[test]
fn test_stack_only_block() {
    // Block that only uses [rsp+offset]
    // Should work after Phase 4
}

#[test]
fn test_data_pointer_block() {
    // Block that uses [rsi+offset]
    // Should work after Phase 3
}

#[test]
fn test_negative_offset_block() {
    // Block that uses [rbp-0x20]
    // Should work with proper offset calculation
}

#[test]
fn test_multiple_pointer_registers() {
    // Block that uses [rsi], [rdi], [rbx]
    // Should allocate separate buffers
}
```

#### 7.2 Integration Tests

```bash
# After each phase, run:
./scripts/measure_success_rate.sh

# Track progress:
# Phase 1-2: ~0% (no behavior change yet)
# Phase 3-4: ~20-30% (stack operations work)
# Phase 5-6: ~50-60% (data pointers work)
# Phase 7:   ~60-80% (edge cases handled)
```

### Phase 8: Error Handling and Diagnostics

#### 8.1 Better Error Messages

```rust
pub enum SimulationFailure {
    NasmCompilation(String),
    LinkingFailed(String),
    Segfault { address: u64, register: String },
    Timeout,
    OutputCaptureFailed,
}
```

#### 8.2 Debug Output

Add verbose mode that shows:
- Which registers were detected as pointers
- What buffer addresses were allocated
- What the actual register values are

## Implementation Order

| Step | Description | Expected Success Rate |
|------|-------------|----------------------|
| 1 | Add PointerRegisterUsage struct | 0% (no change) |
| 2 | Implement parse_memory_operand | 0% (no change) |
| 3 | Detect pointer registers in analysis | 0% (no change) |
| 4 | Add buffer allocation to sandbox | 0% (no change) |
| 5 | Initialize rsp to valid stack | 10-20% |
| 6 | Initialize rbp to valid stack | 20-30% |
| 7 | Initialize other pointer registers | 40-50% |
| 8 | Handle negative offsets correctly | 50-60% |
| 9 | Handle scaled index addressing | 55-65% |
| 10 | Initialize pointer buffers with data | 60-70% |
| 11 | Fine-tune and edge cases | 70-80% |

## Files to Modify

1. **src/analyzer/mod.rs** - Add pointer register detection
2. **src/analyzer/types.rs** (new) - Add PointerRegisterUsage struct
3. **src/simulator/sandbox.rs** - Add buffer allocation methods
4. **src/simulator/random_generator.rs** - Smart register initialization
5. **src/simulator/mod.rs** - Integration changes
6. **src/simulator/assembly_generator.rs** - Minor updates for buffer initialization
7. **tests/pointer_register_tests.rs** (new) - Unit tests

## Risk Assessment

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Complex addressing modes not handled | Medium | Fall back to random, document limitation |
| Buffer overflow in sandbox | Low | Bounds checking, generous buffer sizes |
| Performance impact from analysis | Low | Caching, only analyze once |
| Some blocks still fail | High | Accept 70-80% as success, document remaining failures |

## Success Criteria

- **Minimum**: 40% simulation success rate (up from 0%)
- **Target**: 60-80% simulation success rate
- **Stretch**: 85%+ success rate

## Estimated Effort

| Phase | Effort |
|-------|--------|
| Phase 1 (Analysis) | 3-4 hours |
| Phase 2 (Sandbox) | 2-3 hours |
| Phase 3 (State Gen) | 3-4 hours |
| Phase 4 (Integration) | 2-3 hours |
| Phase 5 (Memory Init) | 2-3 hours |
| Phase 6 (Edge Cases) | 3-4 hours |
| Phase 7 (Testing) | 3-4 hours |
| Phase 8 (Diagnostics) | 2-3 hours |
| **Total** | **20-28 hours** |

## Next Immediate Action

Start with Phase 1: Extend the analyzer to detect pointer register usage. This is the foundation for all subsequent phases.

```bash
# First step:
# 1. Read src/analyzer/mod.rs to understand current structure
# 2. Add PointerRegisterUsage struct
# 3. Implement parse_memory_operand()
# 4. Add detection to analyze_block()
# 5. Test with a known block
```
