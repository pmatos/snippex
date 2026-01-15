#!/bin/bash
# Script to measure simulation success rate
# This extracts blocks from real binaries and measures how many simulate successfully

set -euo pipefail

# Configuration
NUM_EXTRACTIONS=50
DB_PATH="/tmp/snippex_success_rate_test.db"
BINARIES=(
    "/bin/ls"
    "/bin/cat"
    "/bin/grep"
    "/bin/sed"
    "/bin/awk"
    "/usr/bin/gcc"
    "/usr/bin/make"
    "/usr/bin/git"
)

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Snippex Simulation Success Rate Measurement"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

# Clean up old database if it exists
rm -f "$DB_PATH"

# Extract blocks from multiple binaries
echo "Step 1: Extracting assembly blocks..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

extraction_count=0
for binary in "${BINARIES[@]}"; do
    if [ ! -f "$binary" ]; then
        echo "⚠ Skipping $binary (not found)"
        continue
    fi

    # Extract multiple blocks from each binary
    extractions_per_binary=$((NUM_EXTRACTIONS / ${#BINARIES[@]}))
    for ((i=1; i<=extractions_per_binary; i++)); do
        if cargo run --quiet -- extract "$binary" --database "$DB_PATH" --quiet; then
            extraction_count=$((extraction_count + 1))
            echo -n "."
        fi
    done
done

echo
echo "✓ Extracted $extraction_count blocks"
echo

# Analyze all blocks
echo "Step 2: Analyzing blocks..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

for ((block_id=1; block_id<=extraction_count; block_id++)); do
    if cargo run --quiet -- analyze "$block_id" --database "$DB_PATH" --quiet 2>/dev/null; then
        echo -n "."
    else
        echo -n "x"
    fi
done

echo
echo "✓ Analysis complete"
echo

# Simulate all blocks and measure success rate
echo "Step 3: Simulating blocks..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

success_count=0
failure_count=0
total_blocks=0

for ((block_id=1; block_id<=extraction_count; block_id++)); do
    total_blocks=$((total_blocks + 1))

    if cargo run --quiet -- simulate "$block_id" --database "$DB_PATH" --runs 1 --quiet 2>&1 | grep -q "✓"; then
        success_count=$((success_count + 1))
        echo -n "✓"
    else
        failure_count=$((failure_count + 1))
        echo -n "✗"
    fi
done

echo
echo

# Calculate success rate
if [ $total_blocks -gt 0 ]; then
    success_rate=$((success_count * 100 / total_blocks))
else
    success_rate=0
fi

# Report results
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Results"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "Total blocks tested:     $total_blocks"
echo "Successful simulations:  $success_count"
echo "Failed simulations:      $failure_count"
echo
echo "Success Rate:            $success_rate%"
echo

if [ $success_rate -ge 60 ]; then
    echo "✓ SUCCESS: Met target of 60-80% success rate!"
elif [ $success_rate -ge 20 ]; then
    echo "⚠ PARTIAL: Better than baseline (~10-20%) but below target (60-80%)"
else
    echo "✗ FAILURE: Below baseline success rate"
fi

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

# Clean up
rm -f "$DB_PATH"

exit 0
