# Snippex Implementation Plan

## Project Vision

Snippex is a differential testing framework designed to **find bugs in FEX-Emu**, an x86-on-ARM64 dynamic binary translator. By extracting random assembly blocks from real-world x86 binaries and comparing native execution against FEX-Emu emulation, we can systematically uncover translation bugs, instruction edge cases, and behavioral discrepancies.

## Implementation considerations

Leave no warnings in the code. Ensure it's clean. Always test the code after implementing it. Be thorough in your implementation.

## The Problem We're Solving

### Current Challenge: Native Execution Failures

The simulator currently fails on ~80-90% of extracted assembly blocks due to **address space mismatches**:

- **Original binary**: Loaded at `0x555555000000` (or similar high addresses)
- **Simulator sandbox**: Restricted to `0x10000000-0x20000000` (256MB safe zone)
- **Result**: Blocks with RIP-relative addressing or absolute memory references fail immediately

**Example failure:**
```
Error: Memory address 0x00005555555f741a is outside safe range
```

This means we can't execute most blocks natively, which means **we have no ground truth** to compare FEX-Emu against.

### Why Native Execution is Non-Negotiable

We considered using Unicorn Engine (another x86 emulator) as a reference, but **rejected this approach** because:

1. **No authoritative ground truth**: If both Unicorn and FEX-Emu have the same bug, we'll never detect it
2. **Ambiguous failures**: When they disagree, we can't determine which is correct without native execution
3. **Industry standard**: Emulator validation requires comparison against real hardware, not another emulator

**Native x86 execution is the only definitive reference for correctness.**

## Our Solution: Three-Phase Architecture

### Phase 1: Fix Native Execution (Address Translation)

**Implement address translation** to map the original binary's address space into the simulation sandbox:

```
Original Binary Layout:          Simulation Sandbox:
┌─────────────────────────┐     ┌─────────────────────────┐
│ 0x555555000000: .text   │ --> │ 0x10000000: .text       │
│ 0x555555010000: .data   │ --> │ 0x10010000: .data       │
│ 0x555555020000: .rodata │ --> │ 0x10020000: .rodata     │
└─────────────────────────┘     └─────────────────────────┘

Translation: sandbox_addr = sandbox_base + (original_addr - binary_base)
```

This allows RIP-relative addressing and absolute references to work correctly by:
1. Parsing ELF headers to get the binary's base address
2. Loading binary sections (.text, .data, .rodata) into the sandbox
3. Executing with the translated address space

**Expected improvement**: 60-80% simulation success rate (up from current ~10-20%)

### Phase 2: Remote Execution via SSH

**Enable cross-architecture testing** through SSH-based remote execution:

```
┌─────────────────────────────────────────────────────────┐
│ Developer on x86 Machine                                │
│                                                          │
│  1. Extract blocks locally (x86 binaries)               │
│  2. Simulate natively (local) ✓                         │
│  3. SSH to ARM64 server                                 │
│  4. Transfer package (binary + metadata)                │
│  5. Simulate via FEX-Emu (remote)                       │
│  6. Compare results                                     │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ Developer on ARM64 Machine                              │
│                                                          │
│  1. Extract blocks locally (x86 binaries)               │
│  2. SSH to x86 server                                   │
│  3. Transfer package (binary + metadata)                │
│  4. Simulate natively (remote) ✓                        │
│  5. Simulate via FEX-Emu (local)                        │
│  6. Compare results                                     │
└─────────────────────────────────────────────────────────┘
```

**Key insight**: The workflow is **symmetric** - you can work from either architecture and always get native ground truth.

### Phase 3: Smart Dispatching

**Automatic architecture detection** and intelligent routing:

```bash
# User doesn't think about architecture
snippex validate 1

# Auto-detects host architecture
# Automatically runs:
#   - Native execution (local if x86, remote if ARM64)
#   - FEX-Emu (remote if x86, local if ARM64)
# Compares and reports results
```

One command, works everywhere, always gets ground truth.

## Success Criteria

### What "Done" Looks Like

**Phase 1 Complete:**
- ✓ 60-80% of extracted blocks simulate successfully
- ✓ Native execution works with realistic binaries (/bin/ls, /usr/bin/*, etc.)
- ✓ Address translation handles PIE and non-PIE binaries

**Phase 2 Complete:**
- ✓ Can SSH from x86 → ARM64 and run FEX-Emu tests
- ✓ Can SSH from ARM64 → x86 and run native tests
- ✓ Automatic package transfer, remote execution, result retrieval

**Phase 3 Complete:**
- ✓ `snippex validate <block>` works on both x86 and ARM64 hosts
- ✓ Batch validation: `snippex validate --batch 1-100` finds bugs efficiently
- ✓ Clear, actionable bug reports when FEX-Emu disagrees with native

**Ultimate Goal:**
- 🎯 Find real bugs in FEX-Emu
- 🎯 Report bugs to FEX-Emu project with:
  - Extracted assembly block (reproducible test case)
  - Native execution results (ground truth)
  - FEX-Emu results (buggy behavior)
  - Exact registers/flags/memory that differ

## Design Principles

### 1. Native Execution as Ground Truth
Always compare against real x86 hardware, never emulator-vs-emulator.

### 2. Symmetric Architecture Support
Tool works equally well on x86 or ARM64, automatically handling remote execution.

### 3. Reproducible Test Cases
Every bug found includes a minimal, self-contained assembly block that reproduces the issue.

### 4. Batch Processing
Test hundreds/thousands of blocks automatically to maximize bug discovery.

### 5. Clear Failure Attribution
When results differ, clearly show what's wrong (specific register, flag, or memory value).

---

## Implementation Phases

## Phase 1: Address Translation & Native Simulation Fix

**Goal**: Fix native simulation by implementing address translation to map binary address spaces into the simulation sandbox.

**Priority**: CRITICAL - This blocks all subsequent work

### 1.1 ELF Parsing & Binary Context Extraction

- [x] Add `base_address` field to `BinaryInfo` struct (virtual address where binary is loaded)
- [x] Implement ELF header parsing to extract:
  - [x] Program headers (LOAD segments)
  - [x] Virtual address base (first LOAD segment vaddr)
  - [x] Entry point address
- [x] Store base address in database when extracting blocks
- [x] Add migration for existing database entries (default to 0x400000 for backward compat)

### 1.2 Binary Section Loading

- [x] Implement `BinarySectionLoader` to extract sections from ELF files:
  - [x] `.text` section (executable code)
  - [x] `.data` section (initialized data)
  - [x] `.rodata` section (read-only data)
  - [x] `.bss` section (uninitialized data)
- [x] Store section metadata: offset, size, virtual address, permissions
- [x] Add helper to load section bytes from original binary file
- [x] Handle section alignment requirements

### 1.3 Sandbox Memory Manager

- [x] Design `SandboxMemoryLayout`:
  - [x] Sandbox base: `0x10000000` (256MB region)
  - [x] Map original binary base → sandbox base
  - [x] Calculate offsets for each section
- [x] Implement address translation:
  - [x] `translate_to_sandbox(original_addr: u64) -> u64`
  - [x] `is_in_original_range(addr: u64) -> bool`
  - [x] Handle out-of-range addresses gracefully
- [x] Implement sandbox initialization:
  - [x] Allocate sandbox memory region
  - [x] Copy `.text` section to sandbox
  - [x] Copy `.data` section to sandbox
  - [x] Copy `.rodata` section to sandbox
  - [x] Zero-initialize `.bss` section

### 1.4 Assembly Harness Generation Updates

- [x] Modify `AssemblyGenerator` to use translated addresses:
  - [x] Generate harness that sets up sandbox base address
  - [x] Translate memory references in initial state setup
  - [x] Keep extracted block bytes unchanged (they have RIP-relative refs)
- [x] Update memory access validation to accept sandbox addresses
- [x] Remove hard-coded address range rejection (currently `0x10000000-0x20000000`)

### 1.5 Testing & Validation

- [x] Create test cases with known memory references:
  - [x] Simple block with `.data` access
  - [x] Block with `.rodata` string reference
  - [x] Block with RIP-relative addressing
- [x] Test address translation correctness:
  - [x] Verify base address parsing from ELF
  - [x] Verify section loading
  - [x] Verify address translation math
- [x] Integration test: extract, analyze, simulate with address translation
- [x] Measure simulation success rate improvement (target: 60-80% from current ~10-20%)
  - NOTE: Initial integration complete but success rate still low
  - Sandbox infrastructure connected to simulation workflow
  - Binary sections now loaded during simulation
  - Further debugging needed: some blocks fail with NASM errors, others with output capture issues
  - Script created: scripts/measure_success_rate.sh for testing

### 1.6 Documentation

- [x] Document address translation algorithm in code comments
- [x] Update README.md with improved simulation success rates
- [x] Add troubleshooting guide for simulation failures
- [x] Document limitations (e.g., syscalls still won't work)

---

## Phase 2: Remote Execution Infrastructure

**Goal**: Enable SSH-based remote execution for cross-architecture testing.

**Depends on**: Phase 1 completion

### 2.1 Configuration Management

- [x] Design configuration file format (`~/.config/snippex/config.yml`):
  ```yaml
  remotes:
    x86-oracle:
      host: "intel-server.example.com"
      user: "pmatos"
      port: 22
      snippex_path: "/usr/local/bin/snippex"
      ssh_key: "~/.ssh/id_rsa"
    arm64-fex:
      host: "arm-server.example.com"
      user: "pmatos"
      port: 22
      snippex_path: "/usr/local/bin/snippex"
      ssh_key: "~/.ssh/id_rsa"
  ```
- [x] Implement `Config` struct and YAML parsing (use `serde_yaml`)
- [x] Add `snippex config` command to view/edit configuration
- [x] Add `snippex config validate` to test SSH connections
- [x] Handle missing config gracefully (local-only mode)

### 2.2 Data Packaging & Transfer

- [x] Design `ExecutionPackage` format:
  - [x] Binary file (or path if available on remote)
  - [x] Extraction metadata (id, addresses, size)
  - [x] Analysis results
  - [x] Initial state (registers, memory)
  - [x] Emulator configuration
- [x] Implement packaging:
  - [x] Create temporary directory
  - [x] Copy binary to package
  - [x] Serialize metadata to JSON
  - [x] Create tarball
- [x] Implement transfer via SCP:
  - [x] Upload package to remote `/tmp/snippex-{uuid}/`
  - [x] Progress indicator for large binaries
  - [x] Handle transfer errors and retries

### 2.3 Remote Invocation Protocol

- [x] Add `snippex simulate-remote` subcommand:
  - [x] Accepts `--package <path>` argument
  - [x] Unpacks tarball
  - [x] Runs simulation locally on remote machine
  - [x] Writes results to JSON file
- [x] Implement `SSHExecutor`:
  - [x] Establish SSH connection (use `ssh2` crate)
  - [x] Execute remote command
  - [x] Stream stdout/stderr for debugging
  - [x] Capture exit code
- [x] Implement result retrieval:
  - [x] SCP results.json back to local machine
  - [x] Parse result JSON
  - [x] Clean up remote temporary directory

### 2.4 Error Handling & Resilience

- [x] Handle SSH connection failures:
  - [x] Retry with exponential backoff
  - [x] Fallback to local-only mode with warning
  - [x] Helpful error messages (check SSH keys, network, etc.)
- [x] Handle remote execution failures:
  - [x] Binary not found on remote
  - [x] Snippex not installed on remote
  - [x] Simulation failure on remote
- [x] Add timeout for remote operations (configurable, default 60s)
- [x] Cleanup on interruption (Ctrl+C)

### 2.5 Testing

- [x] Unit tests for packaging/unpacking
- [x] Integration test with local SSH (localhost)
  - Note: localhost SSH not available, tested with real remote instead
- [x] Manual test with real remote machines
  - Tested with t14s.local (aarch64) from x86_64 host
  - Remote simulation completed successfully with cross-compilation
- [x] Test error scenarios (bad SSH key, network down, etc.)
  - Non-existent remote: clear error message
  - Unreachable host: meaningful DNS resolution error
  - Host connection failures: retry with backoff + diagnostics

---

## Phase 3: Smart Dispatching & Architecture Detection

**Goal**: Automatic architecture detection and intelligent routing to appropriate execution environment.

**Depends on**: Phase 2 completion

### 3.1 Architecture Detection

- [x] Implement `detect_host_architecture()`:
  - [x] Use `std::env::consts::ARCH`
  - [x] Map to `Arch` enum: `X86_64`, `AArch64`
  - [x] Handle unknown architectures gracefully
- [x] Display current architecture in `snippex --version`
- [x] Add `--arch` override flag for testing

### 3.2 Smart Emulator Selection

- [x] Implement `EmulatorDispatcher`:
  - [x] `select_native_host(arch: Arch, config: &Config) -> ExecutionTarget`
  - [x] `select_fex_host(config: &Config) -> ExecutionTarget`
  - [x] `ExecutionTarget` enum: `Local`, `Remote(RemoteConfig)`
- [x] Selection logic:
  - [x] If current arch is x86_64:
    - [x] Native → Local
    - [x] FEX-Emu → Remote (arm64-fex)
  - [x] If current arch is aarch64:
    - [x] Native → Remote (x86-oracle)
    - [x] FEX-Emu → Local
  - [x] If remote not configured → warn and skip

### 3.3 Unified Validation Command

- [x] Implement `snippex validate <block-id>` command:
  - [x] Auto-detect architecture
  - [x] Run native simulation (local or remote)
  - [x] Run FEX-Emu simulation (local or remote)
  - [x] Compare results
  - [x] Display comparison report
- [x] Add `--verbose` flag to show execution details
- [x] Add `--native-only` and `--fex-only` flags for partial testing
- [x] Pretty-print comparison results:
  ```
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Block #1 Validation Results
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Native (x86_64@local):
    Exit code: 0
    Execution time: 1.2ms

  FEX-Emu (aarch64@arm-server.example.com):
    Exit code: 0
    Execution time: 2.8ms

  Comparison:
    ✓ Exit codes match
    ✓ Flags match (RFLAGS: 0x0246)
    ✓ Registers match (8/8)
    ✓ Memory match (16 bytes)

  VERDICT: PASS ✓
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ```

### 3.4 Batch Validation

- [x] Implement `snippex validate-batch <range>`:
  - [x] Parse range: `1-100`, `1,5,10`, `all`
  - [x] Run validations in sequence
  - [x] Track pass/fail statistics
  - [x] Generate summary report
- [x] Add `--stop-on-failure` flag
- [x] Add `--output-json` for machine-readable results
- [x] Progress indicator for batch operations

### 3.5 Result Caching

- [x] Cache simulation results in database:
  - [x] Track: block_id, emulator, host_info, result, timestamp
  - [x] Reuse cached results if:
    - [x] Block hasn't changed
    - [x] Emulator version matches
    - [x] Recent (configurable TTL)
- [x] Add `--no-cache` flag to force re-execution
- [x] Add `snippex cache clear` command

### 3.6 Documentation & UX Polish

- [x] Update README.md:
  - [x] Document SSH setup requirements
  - [x] Show example workflows from x86 and ARM64 hosts
  - [x] Document configuration file format
- [x] Add `snippex setup` wizard:
  - [x] `snippex config init` creates example configuration
  - [x] `snippex config add-remote` adds remotes via CLI
  - [x] `snippex config validate` tests connections
  - NOTE: Full interactive wizard deferred (existing CLI commands sufficient)
- [x] Add shell completion scripts (bash, zsh, fish)
- [x] Improve error messages with actionable suggestions

---

## Phase 4: Advanced Features (Optional)

**Goal**: Nice-to-have features for production use.

### 4.1 Performance Optimizations

- [ ] Parallel batch validation with thread pool
- [ ] Persistent SSH connections (connection pooling)
- [ ] Incremental binary transfer (rsync or delta compression)
- [ ] Local result caching with TTL

### 4.2 Comparison Enhancements

- [ ] Detailed diff view for register mismatches
- [ ] Memory dump comparison (hexdiff)
- [ ] Flag-by-flag breakdown (CF, ZF, SF, etc.)
- [ ] Statistical analysis across batch runs

### 4.3 Filtering & Selection

- [ ] Extract blocks based on criteria:
  - [ ] `--min-size`, `--max-size`
  - [ ] `--has-memory-access`
  - [ ] `--instruction-types` (e.g., only SSE, only FPU)
- [ ] Smart selection for FEX-Emu testing:
  - [ ] Focus on instruction types known to be problematic
  - [ ] Prioritize blocks with complex addressing modes

### 4.4 Reporting & Observability

- [ ] Export validation results to CSV
- [ ] Generate HTML report with statistics
- [ ] Integration with issue trackers (GitHub issues for FEX-Emu bugs)
- [ ] Metrics dashboard (success rate over time)

### 4.5 CI/CD Integration

- [ ] Docker containers for reproducible environments
- [ ] GitHub Actions workflow for automated testing
- [ ] Regression testing (track known passing/failing blocks)

---

## Success Metrics

### Phase 1 Success Criteria
- [ ] ≥60% simulation success rate (up from current ~10-20%)
- [ ] All integration tests passing
- [ ] Zero address-space-related simulation failures for PIE binaries

### Phase 2 Success Criteria
- [x] Successful remote execution from x86 → ARM64 (tested with t14s.local)
- [ ] Successful remote execution from ARM64 → x86 (SKIPPED - requires x86 remote setup, deferred to end)
- [ ] End-to-end test: extract, validate remotely, compare

### Phase 3 Success Criteria
- [ ] Single `validate` command works on both architectures
- [ ] Batch validation of 100 blocks completes successfully
- [ ] Documentation complete with examples

---

## Timeline Estimate

- **Phase 1**: 1-2 weeks (critical path)
- **Phase 2**: 1-2 weeks (builds on Phase 1)
- **Phase 3**: 1 week (polish and integration)
- **Phase 4**: Optional, ongoing

**Total**: ~4-5 weeks for Phases 1-3

---

## Notes & Decisions

### Why This Order?
1. **Phase 1 first** because nothing works without address translation
2. **Phase 2 next** to enable remote execution infrastructure
3. **Phase 3 last** to add convenience and automation

### Alternative Approaches Considered
- ❌ Unicorn as ground truth: Rejected (see CLAUDE.md - no authoritative reference)
- ❌ Manual export/import: Rejected (SSH is cleaner and more ergonomic)
- ✅ Address translation + SSH remote execution: Current plan

### Open Questions
- [ ] How to handle binaries not available on remote machine?
  - Option A: Always transfer binary in package
  - Option B: Check if binary exists at same path, fallback to transfer
  - **Decision**: Start with Option A, add Option B optimization later

- [ ] Should we support multiple x86 oracles or ARM64 FEX hosts?
  - Use case: Load balancing, redundancy
  - **Decision**: Support multiple in config, use first available for now

- [ ] Cache invalidation strategy?
  - When does a cached result become stale?
  - **Decision**: TTL-based (default 7 days), manual cache clear available
