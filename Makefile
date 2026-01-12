.PHONY: all check format lint test build release audit security clean install-tools help

# Default target
all: check

# Install all required tools
install-tools:
	@echo "Installing quality assurance tools..."
	cargo install --quiet cargo-audit cargo-machete cargo-outdated cargo-geiger 2>/dev/null || true
	@echo "Tools installation completed"

# Format code
format:
	@echo "Formatting code..."
	cargo fmt

# Check code formatting
format-check:
	@echo "Checking code formatting..."
	cargo fmt --check

# Run clippy lints
lint:
	@echo "Running clippy lints..."
	cargo clippy -- -D warnings

# Run tests
test:
	@echo "Running tests..."
	cargo test

# Build debug version
build:
	@echo "Building debug version..."
	cargo build

# Build release version
release:
	@echo "Building release version..."
	cargo build --release

# Security audit
audit:
	@echo "Running security audit..."
	cargo audit

# Check for unused dependencies
machete:
	@echo "Checking for unused dependencies..."
	cargo machete

# Check for outdated dependencies
outdated:
	@echo "Checking for outdated dependencies..."
	@if command -v cargo-outdated >/dev/null 2>&1; then \
		cargo outdated --root-deps-only; \
	else \
		echo "cargo-outdated not installed. Install with: cargo install cargo-outdated"; \
		echo "Skipping outdated dependency check..."; \
	fi

# Check for unsafe code
geiger:
	@echo "Checking for unsafe code..."
	@if command -v cargo-geiger >/dev/null 2>&1; then \
		cargo geiger --forbid-only; \
	else \
		echo "cargo-geiger not installed. Install with: cargo install cargo-geiger"; \
		echo "Skipping unsafe code check..."; \
	fi

# Run all security checks
security: audit geiger
	@echo "All security checks completed"

# Run dependency checks
deps: machete outdated
	@echo "All dependency checks completed"

# Run all quality checks
check: format-check lint test build security deps
	@echo "All quality checks passed!"

# Quick check (without security scans)
quick: format-check lint test build
	@echo "Quick checks passed!"

# Pre-commit checks
pre-commit: format lint test build audit
	@echo "Pre-commit checks completed"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -f snippex.db

# Show help
help:
	@echo "Available targets:"
	@echo "  all         - Run all quality checks (default)"
	@echo "  check       - Run all quality checks"
	@echo "  quick       - Run quick checks (format, lint, test, build)"
	@echo "  pre-commit  - Run pre-commit checks"
	@echo ""
	@echo "Individual checks:"
	@echo "  format      - Format code with rustfmt"
	@echo "  format-check- Check code formatting"
	@echo "  lint        - Run clippy lints"
	@echo "  test        - Run all tests"
	@echo "  build       - Build debug version"
	@echo "  release     - Build release version"
	@echo ""
	@echo "Security & Dependencies:"
	@echo "  audit       - Security audit of dependencies"
	@echo "  machete     - Check for unused dependencies"
	@echo "  outdated    - Check for outdated dependencies"
	@echo "  geiger      - Check for unsafe code"
	@echo "  security    - Run all security checks"
	@echo "  deps        - Run all dependency checks"
	@echo ""
	@echo "Utility:"
	@echo "  install-tools - Install all required tools"
	@echo "  clean       - Clean build artifacts"
	@echo "  help        - Show this help"