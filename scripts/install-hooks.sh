#!/bin/bash
set -e

# Script to install git hooks for Snippex

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
HOOKS_DIR="$PROJECT_DIR/.git/hooks"

echo "Installing git hooks for Snippex..."

# Ensure hooks directory exists
mkdir -p "$HOOKS_DIR"

# Copy pre-commit hook
cp "$SCRIPT_DIR/../.git/hooks/pre-commit" "$HOOKS_DIR/pre-commit"
chmod +x "$HOOKS_DIR/pre-commit"

echo "✅ Pre-commit hook installed successfully!"
echo
echo "The hook will now run the following checks before each commit:"
echo "  - Code formatting (with auto-fix)"
echo "  - Clippy lints"
echo "  - Tests"
echo "  - Build"
echo "  - Security audit (if cargo-audit is available)"
echo
echo "To bypass the hook for a specific commit, use:"
echo "  git commit --no-verify"
echo
echo "To run the checks manually:"
echo "  make pre-commit"
echo "  # or"
echo "  ./scripts/qa.sh --quick"