#!/bin/bash
set -e

# Snippex Quality Assurance Script
# This script runs all quality checks for the Snippex project

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if cargo tools are installed
check_tools() {
    local missing_tools=()

    if ! command_exists cargo-audit; then
        missing_tools+=("cargo-audit")
    fi

    if ! command_exists cargo-machete; then
        missing_tools+=("cargo-machete")
    fi

    if ! command_exists cargo-outdated; then
        missing_tools+=("cargo-outdated")
    fi

    if ! command_exists cargo-geiger; then
        missing_tools+=("cargo-geiger")
    fi

    if [ ${#missing_tools[@]} -ne 0 ]; then
        print_warning "Missing tools: ${missing_tools[*]}"
        print_status "Installing missing tools..."

        # Try cargo-binstall first for faster installation
        if command_exists cargo-binstall; then
            for tool in "${missing_tools[@]}"; do
                print_status "Installing $tool with cargo-binstall..."
                cargo binstall --no-confirm "$tool" || {
                    print_warning "Failed to binstall $tool, falling back to cargo install..."
                    cargo install "$tool" || {
                        print_error "Failed to install $tool"
                        return 1
                    }
                }
            done
        else
            # Fallback to cargo install
            for tool in "${missing_tools[@]}"; do
                print_status "Installing $tool..."
                cargo install "$tool" || {
                    print_error "Failed to install $tool"
                    return 1
                }
            done
        fi
    fi
}

# Run a command with status reporting
run_check() {
    local name="$1"
    local cmd="$2"
    
    print_status "Running $name..."
    if eval "$cmd"; then
        print_success "$name passed"
        return 0
    else
        print_error "$name failed"
        return 1
    fi
}

# Main execution
main() {
    cd "$PROJECT_DIR"
    
    echo "🔍 Snippex Quality Assurance"
    echo "==============================="
    echo

    # Check and install tools
    if ! check_tools; then
        print_error "Failed to install required tools"
        exit 1
    fi
    echo
    
    local failed_checks=()
    
    # Format check
    if ! run_check "Format check" "cargo fmt --check"; then
        failed_checks+=("format")
        print_warning "Auto-formatting code..."
        cargo fmt
        print_success "Code formatted"
    fi
    
    # Clippy lints
    if ! run_check "Clippy lints" "cargo clippy -- -D warnings"; then
        failed_checks+=("clippy")
    fi
    
    # Tests
    if ! run_check "Tests" "cargo test"; then
        failed_checks+=("tests")
    fi
    
    # Build
    if ! run_check "Build" "cargo build --release"; then
        failed_checks+=("build")
    fi
    
    # Security audit
    if ! run_check "Security audit" "cargo audit"; then
        failed_checks+=("audit")
    fi
    
    # Unused dependencies
    if ! run_check "Unused dependencies" "cargo machete"; then
        failed_checks+=("machete")
    fi
    
    # Outdated dependencies
    print_status "Checking for outdated dependencies..."
    if cargo outdated --root-deps-only --quiet | grep -q "^[^-]"; then
        print_warning "Some dependencies are outdated"
        cargo outdated --root-deps-only
    else
        print_success "All dependencies are up to date"
    fi
    
    # Unsafe code check
    print_status "Checking for unsafe code..."
    if cargo geiger --forbid-only >/dev/null 2>&1; then
        print_success "No unsafe code found"
    else
        print_warning "Unsafe code detected (this may be expected in dependencies)"
        cargo geiger --forbid-only || true
    fi
    
    echo
    echo "==============================="
    
    if [ ${#failed_checks[@]} -eq 0 ]; then
        print_success "All quality checks passed! ✅"
        exit 0
    else
        print_error "Failed checks: ${failed_checks[*]} ❌"
        exit 1
    fi
}

# Help function
show_help() {
    echo "Snippex Quality Assurance Script"
    echo
    echo "Usage: $0 [options]"
    echo
    echo "Options:"
    echo "  -h, --help    Show this help message"
    echo "  --quick       Run quick checks only (skip security scans)"
    echo "  --security    Run security checks only"
    echo "  --deps        Run dependency checks only"
    echo
    echo "This script runs:"
    echo "  - Code formatting check"
    echo "  - Clippy lints"
    echo "  - All tests"
    echo "  - Release build"
    echo "  - Security audit"
    echo "  - Unused dependency check"
    echo "  - Outdated dependency check"
    echo "  - Unsafe code check"
}

# Parse command line arguments
case "${1:-}" in
    -h|--help)
        show_help
        exit 0
        ;;
    --quick)
        print_status "Running quick checks only..."
        run_check "Format check" "cargo fmt --check" || cargo fmt
        run_check "Clippy lints" "cargo clippy -- -D warnings"
        run_check "Tests" "cargo test"
        run_check "Build" "cargo build --release"
        print_success "Quick checks completed"
        ;;
    --security)
        print_status "Running security checks only..."
        run_check "Security audit" "cargo audit"
        run_check "Unsafe code check" "cargo geiger --forbid-only"
        print_success "Security checks completed"
        ;;
    --deps)
        print_status "Running dependency checks only..."
        run_check "Unused dependencies" "cargo machete"
        print_status "Checking outdated dependencies..."
        cargo outdated --root-deps-only
        print_success "Dependency checks completed"
        ;;
    "")
        main
        ;;
    *)
        print_error "Unknown option: $1"
        show_help
        exit 1
        ;;
esac
