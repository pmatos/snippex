# Building Snippex

This document describes how to build and test the Snippex framework.

## Prerequisites

- Rust 1.70 or later
- Cargo (comes with Rust)
- GCC or Clang (for compiling test binaries)
- SQLite (bundled with rusqlite)

## Building

### Debug Build
```bash
cargo build
```

### Release Build
```bash
cargo build --release
```

The compiled binary will be located at:
- Debug: `target/debug/snippex`
- Release: `target/release/snippex`

## Testing

### Run All Tests
```bash
cargo test
```

### Run Unit Tests Only
```bash
cargo test --bins
```

### Run Integration Tests Only
```bash
cargo test --test integration_test
```

### Run Tests with Output
```bash
cargo test -- --nocapture
```

### Assembly Test Framework

The project includes an assembly test framework for validating the analyzer module with manually written assembly code.

#### Running Assembly Tests

```bash
# Run all assembly tests
cargo test ann_asm

# Run a specific assembly test
cargo test ann_asm -- simple_mov
cargo test ann_asm -- conditional_jump
cargo test ann_asm -- memory_access
cargo test ann_asm -- complex_example

# Run with debug output
cargo test ann_asm -- simple_mov --nocapture
```

#### Requirements
- NASM assembler must be installed: `sudo apt install nasm`

#### Test Files
Assembly test files are located in `tests/asm/` with annotations:
```asm
; BITS: 64
; LIVEIN: rdi, rsi
; LIVEOUT: rax, rflags
; EXITS: jz label, ret
; MEMORY: LOAD rsi, STORE rdx
mov rax, [rsi]
test rdi, rdi
jz done
add rax, rdi
done:
    ret
```

## Quality Assurance Tools

### Static Analysis Tools

Snippex uses several complementary tools for code quality:

- **cargo-audit**: Security vulnerability scanner
- **cargo-machete**: Unused dependency detector  
- **cargo-outdated**: Outdated dependency checker
- **cargo-geiger**: Unsafe code detector

#### Install QA Tools
```bash
# Install all tools at once
make install-tools

# Or install individually
cargo install cargo-audit cargo-machete cargo-outdated cargo-geiger
```

### Formatting and Linting

#### Check Code Format
```bash
cargo fmt --check
```

#### Format Code
```bash
cargo fmt
```

#### Run Clippy Linter
```bash
cargo clippy -- -D warnings
```

### Security and Dependencies

#### Security Audit
```bash
cargo audit
```

#### Check for Unused Dependencies
```bash
cargo machete
```

#### Check for Outdated Dependencies
```bash
cargo outdated --root-deps-only
```

#### Check for Unsafe Code
```bash
cargo geiger --forbid-only
```

### Comprehensive Quality Checks

#### Using Make (Recommended)
```bash
# Run all quality checks
make check

# Run quick checks (no security scans)
make quick

# Run pre-commit checks
make pre-commit

# Run security checks only
make security

# Run dependency checks only
make deps
```

#### Using QA Script
```bash
# Run all checks
./scripts/qa.sh

# Run quick checks only
./scripts/qa.sh --quick

# Run security checks only
./scripts/qa.sh --security

# Run dependency checks only
./scripts/qa.sh --deps
```

### Pre-commit Hooks

Install git hooks to run checks automatically before commits:

```bash
./scripts/install-hooks.sh
```

The pre-commit hook runs:
- Code formatting (with auto-fix)
- Clippy lints
- Tests
- Build
- Security audit

To bypass for a specific commit:
```bash
git commit --no-verify
```

## Development Workflow

Before committing any changes, run:

```bash
# Recommended: use make for comprehensive checks
make pre-commit

# Or use the QA script
./scripts/qa.sh --quick

# Or run individual commands
cargo fmt
cargo clippy -- -D warnings
cargo test
cargo build --release
```

The pre-commit hook will automatically run these checks if installed.

## Common Issues

### Test Binary Compilation Fails
Integration tests require GCC to compile test binaries. Ensure GCC is installed:
- Ubuntu/Debian: `sudo apt-get install gcc`
- macOS: `xcode-select --install`
- Arch Linux: `sudo pacman -S gcc`

### SQLite Errors
The project uses bundled SQLite, but if you encounter issues:
- Ensure you have development headers: `sudo apt-get install libsqlite3-dev` (Ubuntu/Debian)
- Or use system SQLite by removing `"bundled"` feature from `rusqlite` in `Cargo.toml`