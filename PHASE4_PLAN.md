# Phase 4: Advanced Features Implementation Plan

## Overview

Phase 4 focuses on production-ready features: performance optimizations, enhanced comparison output, smart filtering, reporting, and CI/CD integration. These are "nice-to-have" features that improve usability and scalability.

**Prerequisites**: Phases 1-3 should be substantially complete before Phase 4 work begins.

---

## 4.1 Performance Optimizations

### 4.1.1 Parallel Batch Validation with Thread Pool

**Goal**: Execute multiple block validations concurrently to reduce total validation time.

**Current State**: `validate-batch` processes blocks sequentially (see `src/cli/validate_batch.rs:154-249`).

**Implementation Tasks**:

- [x] **4.1.1.1** Add `rayon` dependency for work-stealing thread pool
  - File: `Cargo.toml`
  - Add: `rayon = "1.8"`

- [x] **4.1.1.2** Create `ParallelValidator` struct
  - File: `src/cli/validate_batch.rs` (or new `src/parallel/mod.rs`)
  - Fields: thread count, progress tracker, result aggregator
  - Use `rayon::ThreadPoolBuilder` for configurable parallelism

- [x] **4.1.1.3** Implement thread-safe progress reporting
  - Use `std::sync::atomic::AtomicUsize` for counters
  - Use `indicatif` crate for progress bar (already in ecosystem)
  - Aggregate results safely with `Mutex<Vec<BlockValidationResult>>`

- [x] **4.1.1.4** Add `--parallel` and `--threads` CLI options
  - `--parallel`: Enable parallel execution (default: off)
  - `--threads N`: Number of worker threads (default: CPU count)

- [x] **4.1.1.5** Handle shared resources correctly
  - Database connections: Use connection pool or one per thread
  - SSH connections: See 4.1.2 for connection pooling
  - Temporary files: Use unique prefixes per thread

- [x] **4.1.1.6** Write tests for parallel execution
  - Test: No race conditions in result aggregation
  - Test: Progress reporting accuracy
  - Test: Error handling in parallel context

**Estimated Effort**: 4-6 hours (COMPLETED)

---

### 4.1.2 Persistent SSH Connections (Connection Pooling)

**Goal**: Reuse SSH connections across multiple remote executions to avoid reconnection overhead.

**Current State**: Each `SSHExecutor::execute()` creates a new connection (see `src/remote/executor.rs:224-227`).

**Implementation Tasks**:

- [x] **4.1.2.1** Create `SSHConnectionPool` struct
  - File: `src/remote/pool.rs` (new file)
  - Maintain pool of active `Session` objects keyed by host
  - Use `std::sync::Mutex<HashMap<String, PooledConnection>>`

- [x] **4.1.2.2** Implement connection lifecycle management
  - `acquire(remote_config) -> Session`: Get or create connection
  - `release(session)`: Return connection to pool
  - `close_idle(timeout)`: Clean up stale connections
  - Implement keep-alive pings to detect dead connections

- [x] **4.1.2.3** Add connection health checks
  - Verify session is still authenticated before reuse
  - Test connection with lightweight command (`echo ping`)
  - Reconnect automatically if health check fails

- [x] **4.1.2.4** Integrate with `RemoteOrchestrator`
  - Modify `RemoteOrchestrator` to accept optional `ConnectionPool`
  - Fall back to fresh connections if pooling disabled

- [x] **4.1.2.5** Add `--connection-pool` CLI option
  - Enable/disable connection pooling (default: enabled for batch)
  - Add `--pool-size N` option (default: 4)

- [x] **4.1.2.6** Write tests for connection pooling
  - Test: Connection reuse reduces overhead
  - Test: Dead connection detection and recovery
  - Test: Pool cleanup on shutdown

**Estimated Effort**: 6-8 hours (COMPLETED)

---

### 4.1.3 Incremental Binary Transfer (Delta Compression)

**Goal**: Only transfer binary differences when the same binary is used repeatedly.

**Current State**: Full binary is transferred every time via SCP (see `src/remote/transfer.rs`).

**Implementation Tasks**:

- [x] **4.1.3.1** Add binary hash tracking
  - Store SHA256 hash of transferred binaries in local cache
  - Store hash + remote path mapping: `~/.cache/snippex/transfers.json`

- [x] **4.1.3.2** Implement remote hash verification
  - SSH command: `sha256sum /path/to/binary`
  - Compare with local hash to determine if transfer needed

- [x] **4.1.3.3** Add rsync-style delta transfer (optional)
  - Use `rsync` command if available on both ends
  - Fall back to full transfer if rsync unavailable
  - Alternative: Use `zstd` compression for transfers

- [x] **4.1.3.4** Cache remote binary locations
  - Track: binary_hash -> remote_path mapping
  - Skip transfer entirely if binary already exists on remote
  - Add TTL for cache entries (7 days default)

- [x] **4.1.3.5** Add `--skip-cached-transfer` CLI option
  - Enable optimization (default: on for batch, off for single)

- [x] **4.1.3.6** Write tests for incremental transfer
  - Test: Same binary not re-transferred
  - Test: Modified binary triggers new transfer
  - Test: Cache invalidation works correctly

**Estimated Effort**: 4-6 hours

---

### 4.1.4 Local Result Caching with TTL

**Goal**: Cache simulation results to avoid re-running unchanged simulations.

**Current State**: Caching exists in database (`simulation_cache` table) but may need optimization.

**Implementation Tasks**:

- [x] **4.1.4.1** Review and optimize existing cache schema
  - File: `src/db/mod.rs`
  - Ensure indexes on (block_id, emulator, timestamp)
  - Add composite index for fast lookups

- [x] **4.1.4.2** Implement cache key generation
  - Key components: block_hash, emulator_version, initial_state_hash
  - Use fast hashing (xxhash) for cache key

- [x] **4.1.4.3** Add cache statistics command
  - `snippex cache stats`: Show hit rate, size, age distribution
  - `snippex cache prune`: Remove entries older than TTL

- [x] **4.1.4.4** Implement LRU eviction
  - When cache exceeds size limit, remove least recently used
  - Add `--cache-max-size` configuration option

- [x] **4.1.4.5** Add cache warming for batch operations
  - Pre-fetch cache entries for block range
  - Report cache hit ratio at end of batch

**Estimated Effort**: 3-4 hours (COMPLETED)

---

## 4.2 Comparison Enhancements

### 4.2.1 Detailed Diff View for Register Mismatches

**Goal**: Show side-by-side comparison of register values with visual highlighting.

**Current State**: Basic comparison in `src/cli/compare.rs` shows differences but lacks detail.

**Implementation Tasks**:

- [x] **4.2.1.1** Create `RegisterDiffFormatter` struct
  - File: `src/cli/compare.rs` or new `src/formatting/diff.rs`
  - Format register values with alignment
  - Highlight differing bits/bytes

- [x] **4.2.1.2** Implement bit-level difference highlighting
  - Show: `RAX: 0x0000_0000_0000_00FF vs 0x0000_0000_0000_0100`
  - Highlight: `                  ^^         ^^^` (differing positions)
  - Use ANSI colors: red for mismatches, green for matches

- [x] **4.2.1.3** Add register grouping
  - Group by category: General Purpose, Flags, Segment, Vector
  - Show only changed registers by default
  - Add `--show-all-registers` flag

- [x] **4.2.1.4** Implement side-by-side table output
  ```
  Register    Native              FEX-Emu             Status
  ───────────────────────────────────────────────────────────
  RAX         0x0000000000000042  0x0000000000000042  ✓
  RBX         0x0000000000000100  0x0000000000000101  ✗ (+1)
  RFLAGS      0x0000000000000246  0x0000000000000244  ✗ (ZF differs)
  ```

- [x] **4.2.1.5** Add JSON diff output
  - Structured diff for machine processing
  - Include before/after values, bit positions

**Estimated Effort**: 4-5 hours (COMPLETED)

---

### 4.2.2 Memory Dump Comparison (Hexdiff)

**Goal**: Visual hex dump comparison showing memory differences.

**Implementation Tasks**:

- [x] **4.2.2.1** Create `HexDiffFormatter` struct
  - File: `src/formatting/hexdiff.rs` (new)
  - Support configurable bytes per line (default: 16)
  - Show address, hex bytes, ASCII representation

- [x] **4.2.2.2** Implement side-by-side hex diff
  ```
  Address          Native                           FEX-Emu
  ─────────────────────────────────────────────────────────────────
  0x10000000:  48 89 e5 41 54 41 55 41  |H..ATAUA|  48 89 e5 41 54 41 55 41  ✓
  0x10000008:  56 41 57 48 83 ec 28 48  |VAW....(H|  56 41 57 48 83 ec 20 48  ✗
                                   ^^                          ^^
  ```

- [x] **4.2.2.3** Add difference highlighting
  - Inline highlighting for changed bytes
  - Summary: "2 bytes differ at offsets 0x0E, 0x0F"

- [x] **4.2.2.4** Support various output formats
  - `--hex-format unified`: Unified diff format
  - `--hex-format split`: Side-by-side format
  - `--hex-format json`: Machine-readable diff

- [x] **4.2.2.5** Add memory region filtering
  - `--memory-region 0x10000000-0x10001000`: Only show specific range
  - `--memory-diff-only`: Only show regions with differences

**Estimated Effort**: 4-5 hours (COMPLETED)

---

### 4.2.3 Flag-by-Flag Breakdown (CF, ZF, SF, etc.)

**Goal**: Decompose RFLAGS into individual flags and show detailed comparison.

**Implementation Tasks**:

- [x] **4.2.3.1** Define x86 flag bit positions
  - File: `src/simulator/state.rs` or new `src/arch/flags.rs`
  - CF (bit 0), PF (bit 2), AF (bit 4), ZF (bit 6), SF (bit 7), etc.
  - Create `Flags` struct with individual fields

- [x] **4.2.3.2** Implement flag extraction and naming
  ```rust
  pub struct FlagState {
      pub cf: bool,  // Carry
      pub pf: bool,  // Parity
      pub af: bool,  // Auxiliary
      pub zf: bool,  // Zero
      pub sf: bool,  // Sign
      pub tf: bool,  // Trap
      pub if_: bool, // Interrupt
      pub df: bool,  // Direction
      pub of: bool,  // Overflow
  }
  ```

- [x] **4.2.3.3** Create flag comparison display
  ```
  Flags Comparison:
    CF (Carry):     0 vs 0  ✓
    ZF (Zero):      1 vs 0  ✗  <-- MISMATCH
    SF (Sign):      0 vs 0  ✓
    OF (Overflow):  0 vs 0  ✓
  ```

- [x] **4.2.3.4** Add `--flag-detail` CLI option
  - Show flag breakdown in compare/validate output
  - Default: summary only, detailed on request

- [x] **4.2.3.5** Document flag semantics
  - What each flag means
  - Common causes of flag differences (overflow, sign changes)

**Estimated Effort**: 2-3 hours (COMPLETED)

---

### 4.2.4 Statistical Analysis Across Batch Runs

**Goal**: Aggregate statistics and trends across validation batches.

**Implementation Tasks**:

- [x] **4.2.4.1** Design statistics schema
  - File: `src/db/mod.rs`
  - Table: `batch_runs` (id, timestamp, block_count, pass_count, fail_count, duration)
  - Table: `batch_run_details` (batch_id, block_id, status, duration)

- [x] **4.2.4.2** Implement statistics collection
  - Record each batch run with summary statistics
  - Store per-block results for drill-down analysis

- [x] **4.2.4.3** Create `snippex stats` command
  - `snippex stats summary`: Overall pass/fail rates
  - `snippex stats trends`: Show rates over time
  - `snippex stats blocks --failing`: List consistently failing blocks
  - `snippex stats blocks --flaky`: List intermittently failing blocks

- [x] **4.2.4.4** Generate statistical report
  - Success rate by instruction type
  - Most common failure modes
  - Performance trends (execution time)

- [x] **4.2.4.5** Add visualization (ASCII charts)
  - Success rate over time (ASCII bar chart)
  - Failure distribution by category

**Estimated Effort**: 5-6 hours (COMPLETED)

---

## 4.3 Filtering & Selection

### 4.3.1 Extract Blocks Based on Criteria

**Goal**: Allow users to extract blocks matching specific criteria.

**Current State**: Extraction is random with only count/size controls.

**Implementation Tasks**:

- [x] **4.3.1.1** Add size filters to extract command
  - `--min-size N`: Minimum block size in bytes
  - `--max-size N`: Maximum block size in bytes
  - File: `src/cli/extract.rs`

- [x] **4.3.1.2** Add memory access filter
  - `--has-memory-access`: Only blocks with memory operations
  - `--no-memory-access`: Only blocks without memory operations
  - Requires pre-analysis or pattern matching during extraction

- [x] **4.3.1.3** Add instruction type filters
  - `--instruction-types SSE,FPU,AVX`: Filter by instruction categories
  - Categories: `general`, `fpu`, `sse`, `avx`, `avx512`, `branch`, `syscall`
  - Implement category detection using Capstone instruction groups

- [x] **4.3.1.4** Add address range filter
  - `--address-range 0x1000-0x2000`: Extract only from specific range
  - Useful for targeting specific functions/sections

- [x] **4.3.1.5** Implement filter validation
  - Ensure filters are compatible (not mutually exclusive)
  - Warn if filter criteria too restrictive (no matching blocks)

- [x] **4.3.1.6** Add filter preview
  - `--dry-run`: Show how many blocks would match without extracting
  - Helps tune filters before committing to extraction

**Estimated Effort**: 5-6 hours

---

### 4.3.2 Smart Selection for FEX-Emu Testing

**Goal**: Prioritize blocks likely to expose FEX-Emu bugs.

**Implementation Tasks**:

- [x] **4.3.2.1** Create instruction complexity scorer
  - File: `src/analyzer/complexity.rs` (new)
  - Score based on: instruction rarity, addressing mode complexity, operand count

- [x] **4.3.2.2** Identify problematic instruction categories
  - Research FEX-Emu known issues/bugs
  - Categories: SSE/AVX edge cases, FPU operations, complex addressing
  - Create `PROBLEMATIC_INSTRUCTIONS.md` reference

- [x] **4.3.2.3** Implement `--smart-select` option
  - Prioritize blocks with:
    - Complex addressing modes ([base+index*scale+disp])
    - Rare instructions (less common in test suites)
    - Multiple memory operands
    - Mixed register sizes (e.g., 32-bit in 64-bit context)

- [x] **4.3.2.4** Add selection strategy options
  - `--select-strategy diverse`: Maximize instruction variety
  - `--select-strategy complex`: Maximize complexity score
  - `--select-strategy random`: Original random selection (default)

- [x] **4.3.2.5** Create selection report
  - Show why each block was selected
  - List instruction categories covered
  - Show complexity distribution

**Estimated Effort**: 6-8 hours (COMPLETED)

---

## 4.4 Reporting & Observability

### 4.4.1 Export Validation Results to CSV

**Goal**: Allow validation results to be exported for external analysis.

**Implementation Tasks**:

- [x] **4.4.1.1** Create `CsvExporter` struct
  - File: `src/export/csv.rs` (new)
  - Define CSV schema for validation results

- [x] **4.4.1.2** Implement CSV export for batch results
  - Columns: block_id, binary, start_addr, end_addr, native_result, fex_result, status, duration
  - Include register diffs if --detailed
  - Support custom column selection

- [x] **4.4.1.3** Add `--export-csv <path>` option to validate-batch
  - Write results to specified file
  - Support stdout with `--export-csv -`

- [x] **4.4.1.4** Add `snippex export` command
  - `snippex export csv --blocks 1-100`: Export block metadata
  - `snippex export csv --validations`: Export all validation results
  - `snippex export csv --simulations`: Export simulation history

- [x] **4.4.1.5** Support incremental export
  - Append to existing CSV
  - Add timestamp column for incremental runs

**Estimated Effort**: 3-4 hours (COMPLETED)

---

### 4.4.2 Generate HTML Report with Statistics

**Goal**: Create visual HTML reports for sharing and documentation.

**Implementation Tasks**:

- [x] **4.4.2.1** Create HTML report template
  - File: `src/export/html.rs` (new) + templates
  - Use embedded template (askama or tera crate)
  - Include CSS for styling (embedded, no external deps)

- [x] **4.4.2.2** Design report sections
  - Executive summary: pass/fail counts, overall verdict
  - Block details table with expandable rows
  - Diff viewer for failed blocks
  - Charts: success rate, timing distribution

- [x] **4.4.2.3** Implement SVG chart generation
  - Success/failure pie chart
  - Execution time histogram
  - Use simple SVG generation (no heavy charting libs)

- [x] **4.4.2.4** Add `--export-html <path>` option
  - Generate complete standalone HTML file
  - Embed all CSS/JS (no external dependencies)

- [x] **4.4.2.5** Support interactive features
  - Expandable/collapsible sections
  - Filter table by status
  - Search functionality (JS)

**Estimated Effort**: 6-8 hours (COMPLETED)

---

### 4.4.3 Integration with Issue Trackers (GitHub)

**Goal**: Automatically create FEX-Emu bug reports from failed validations.

**Implementation Tasks**:

- [x] **4.4.3.1** Design issue template
  - Title: "[snippex] Block validation failure: <description>"
  - Body: Block info, native vs FEX-Emu results, reproduction steps
  - Include extracted assembly and initial state

- [ ] **4.4.3.2** Implement GitHub issue creation
  - File: `src/export/github.rs` (new)
  - Use `octocrab` crate for GitHub API
  - Support personal access token authentication

- [ ] **4.4.3.3** Add `snippex report` command
  - `snippex report github --block 42`: Create issue for specific block
  - `snippex report github --batch 1-100 --failing`: Create issues for all failures
  - Deduplicate: don't create issue if similar one exists

- [ ] **4.4.3.4** Implement duplicate detection
  - Search existing issues by block hash or signature
  - Link to existing issue instead of creating duplicate
  - Add comment with new reproduction info

- [ ] **4.4.3.5** Add configuration for issue creation
  - Target repo: `FEX-Emu/FEX` (configurable)
  - Labels: `bug`, `snippex`, `needs-triage`
  - Assignees (optional)

**Estimated Effort**: 5-6 hours

---

### 4.4.4 Metrics Dashboard (Success Rate Over Time)

**Goal**: Track and visualize validation metrics over time.

**Implementation Tasks**:

- [ ] **4.4.4.1** Design metrics storage
  - File: Database table or separate metrics file
  - Store: timestamp, block_count, pass_count, fail_count, avg_duration

- [ ] **4.4.4.2** Create `snippex metrics` command
  - `snippex metrics record`: Record current validation state
  - `snippex metrics show`: Display metrics summary
  - `snippex metrics export`: Export to JSON/CSV

- [ ] **4.4.4.3** Implement ASCII dashboard
  ```
  Snippex Validation Metrics
  ══════════════════════════════════════════════════════════════

  Success Rate (last 7 days):
    Mon ████████████████████████████████████████ 95.2%
    Tue █████████████████████████████████████████ 96.1%
    Wed ████████████████████████████████████████ 94.8%
    ...

  Total Validations: 1,247
  Total Pass: 1,189 (95.3%)
  Total Fail: 58 (4.7%)
  ```

- [ ] **4.4.4.4** Add trend analysis
  - Calculate improvement/regression rate
  - Alert if failure rate increases significantly

- [ ] **4.4.4.5** Optional: Prometheus metrics export
  - `snippex metrics prometheus`: Export Prometheus-format metrics
  - Useful for integration with existing monitoring

**Estimated Effort**: 4-5 hours

---

## 4.5 CI/CD Integration

### 4.5.1 Docker Containers for Reproducible Environments

**Goal**: Provide Docker images for consistent testing environments.

**Implementation Tasks**:

- [ ] **4.5.1.1** Create x86_64 Dockerfile
  - File: `docker/Dockerfile.x86_64`
  - Base: Ubuntu 22.04
  - Install: NASM, GCC, Rust toolchain, snippex
  - Include sample binaries for testing

- [ ] **4.5.1.2** Create aarch64 Dockerfile
  - File: `docker/Dockerfile.aarch64`
  - Base: Ubuntu 22.04 (arm64)
  - Install: FEX-Emu, NASM (via FEX), snippex
  - Configure for cross-architecture simulation

- [ ] **4.5.1.3** Create docker-compose for testing
  - File: `docker/docker-compose.yml`
  - Services: x86-native, arm64-fex
  - Volume mounts for database sharing
  - Network configuration for SSH simulation

- [ ] **4.5.1.4** Add container build scripts
  - `scripts/docker-build.sh`: Build all images
  - `scripts/docker-push.sh`: Push to registry (ghcr.io)
  - Multi-architecture support with buildx

- [ ] **4.5.1.5** Document container usage
  - Getting started guide
  - Examples for common workflows
  - Troubleshooting guide

**Estimated Effort**: 4-6 hours

---

### 4.5.2 GitHub Actions Workflow for Automated Testing

**Goal**: Automated testing on every push/PR.

**Implementation Tasks**:

- [ ] **4.5.2.1** Create main CI workflow
  - File: `.github/workflows/ci.yml`
  - Triggers: push, pull_request
  - Steps: lint, test, build

- [ ] **4.5.2.2** Add matrix testing
  - Test on: Ubuntu, macOS, Windows (where applicable)
  - Rust versions: stable, 1.75+ (MSRV)

- [ ] **4.5.2.3** Create validation workflow
  - File: `.github/workflows/validate.yml`
  - Run subset of validation tests on schedule
  - Uses self-hosted runner for ARM64 testing (optional)

- [ ] **4.5.2.4** Add release workflow
  - File: `.github/workflows/release.yml`
  - Triggers on tag push
  - Build release binaries for multiple platforms
  - Create GitHub release with artifacts

- [ ] **4.5.2.5** Add code coverage
  - Use `cargo-tarpaulin` or `llvm-cov`
  - Upload to Codecov/Coveralls
  - Add coverage badge to README

**Estimated Effort**: 4-5 hours

---

### 4.5.3 Regression Testing (Track Known Passing/Failing Blocks)

**Goal**: Prevent regressions by tracking expected results.

**Implementation Tasks**:

- [ ] **4.5.3.1** Design regression test database
  - Table: `expected_results` (block_hash, expected_status, last_verified)
  - Table: `regression_runs` (run_id, timestamp, results)

- [ ] **4.5.3.2** Implement `snippex regression` command
  - `snippex regression record`: Save current results as baseline
  - `snippex regression test`: Compare current vs baseline
  - `snippex regression update`: Update baseline with new results

- [ ] **4.5.3.3** Create regression report format
  ```
  Regression Test Results
  ═══════════════════════════════════════════════

  Previously Passing, Now Failing: 3 blocks ⚠️
    Block #42: Expected PASS, got FAIL
    Block #97: Expected PASS, got FAIL
    Block #156: Expected PASS, got FAIL

  Previously Failing, Now Passing: 7 blocks 🎉
    Block #23: Expected FAIL, got PASS
    ...

  Stable: 990 blocks (unchanged)
  ```

- [ ] **4.5.3.4** Integrate with CI
  - Run regression tests in CI workflow
  - Fail CI if regressions detected
  - Allow approved regressions (with justification)

- [ ] **4.5.3.5** Add regression baseline management
  - `snippex regression export baseline.json`: Export baseline
  - `snippex regression import baseline.json`: Import baseline
  - Store baseline in repo for CI reproducibility

**Estimated Effort**: 5-6 hours

---

## Implementation Order Recommendation

Based on dependencies and value delivered:

### Tier 1: High Impact, Lower Effort (Start Here)
1. **4.2.3** Flag-by-flag breakdown (2-3h) - Quick win, improves debugging
2. **4.4.1** CSV export (3-4h) - Enables external analysis
3. **4.3.1** Size/criteria filters (5-6h) - Improves extraction quality

### Tier 2: Performance (Do Together)
4. **4.1.1** Parallel batch validation (4-6h)
5. **4.1.4** Cache optimization (3-4h)
6. **4.1.2** SSH connection pooling (6-8h)

### Tier 3: Enhanced Reporting
7. **4.2.1** Detailed register diff (4-5h)
8. **4.2.2** Memory hexdiff (4-5h)
9. **4.4.2** HTML reports (6-8h)

### Tier 4: Smart Features
10. **4.3.2** Smart selection (6-8h)
11. **4.2.4** Statistical analysis (5-6h)
12. **4.4.4** Metrics dashboard (4-5h)

### Tier 5: CI/CD & Integration
13. **4.5.2** GitHub Actions (4-5h)
14. **4.5.1** Docker containers (4-6h)
15. **4.5.3** Regression testing (5-6h)
16. **4.4.3** GitHub issue integration (5-6h)

### Tier 6: Nice to Have
17. **4.1.3** Incremental transfer (4-6h)

---

## Total Estimated Effort

| Section | Estimated Hours |
|---------|-----------------|
| 4.1 Performance Optimizations | 17-24 hours |
| 4.2 Comparison Enhancements | 15-19 hours |
| 4.3 Filtering & Selection | 11-14 hours |
| 4.4 Reporting & Observability | 18-23 hours |
| 4.5 CI/CD Integration | 13-17 hours |
| **Total** | **74-97 hours** |

This represents approximately 2-3 weeks of focused development time, but can be spread out as these are "nice-to-have" features.

---

## Dependencies Summary

```
4.1.1 Parallel Batch ──────────────────┬──> 4.1.2 SSH Pooling
                                       │
4.1.4 Cache Optimization ──────────────┤
                                       │
4.3.1 Block Filters ───────> 4.3.2 Smart Selection
                                       │
4.2.1 Register Diff ───┬───> 4.2.4 Statistical Analysis
4.2.2 Memory Hexdiff ──┤               │
4.2.3 Flag Breakdown ──┘               │
                                       │
4.4.1 CSV Export ──────────> 4.4.2 HTML Reports ──> 4.4.3 GitHub Integration
                                       │
4.5.2 GitHub Actions ──────> 4.5.3 Regression Testing
4.5.1 Docker ─────────────────────────┘
```

---

## Notes

- All new features should have corresponding tests
- CLI changes should be documented in README.md
- Consider backward compatibility for database schema changes
- Performance features should be opt-in by default
