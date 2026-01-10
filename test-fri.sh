#!/bin/bash
# Run FRI pinning tests to validate FRI output matches expected values.
#
# Usage:
#   ./test-fri.sh [--proof-path=<path>]
#
# This script:
#   1. Rebuilds the fri_pinning_test binary
#   2. Runs all FRI validation tests
#
# Prerequisites:
#   Run generate-fri-vectors.sh first to generate proof files, OR
#   provide --proof-path to an existing proof file.

set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GOLDILOCKS_DIR="$ROOT_DIR/pil2-stark/src/goldilocks"
BUILD_DIR="$ROOT_DIR/pil2-components/test/simple/build"

# Try multiple possible proof locations
PROOF_LOCATIONS=(
    "$BUILD_DIR/fri_vectors_output/proofs/SimpleLeft_0.json"
    "$BUILD_DIR/pinning_test_output/proofs/SimpleLeft_0.json"
)

# Parse arguments
PROOF_PATH=""
for arg in "$@"; do
    case $arg in
        --proof-path=*)
            PROOF_PATH="${arg#*=}"
            shift
            ;;
    esac
done

# Find proof file if not specified
if [ -z "$PROOF_PATH" ]; then
    for loc in "${PROOF_LOCATIONS[@]}"; do
        if [ -f "$loc" ]; then
            PROOF_PATH="$loc"
            break
        fi
    done
fi

echo "=== FRI Pinning Test ==="
echo ""

# Check proof file exists
if [ -z "$PROOF_PATH" ] || [ ! -f "$PROOF_PATH" ]; then
    echo "ERROR: Proof file not found."
    echo ""
    echo "Tried:"
    for loc in "${PROOF_LOCATIONS[@]}"; do
        echo "  - $loc"
    done
    echo ""
    echo "Run generate-fri-vectors.sh first to generate proof files, or"
    echo "provide --proof-path=<path> to an existing proof file."
    exit 1
fi

# Step 1: Build the test binary
echo "Building fri_pinning_test..."
cd "$GOLDILOCKS_DIR"
make fri_pinning_test 2>&1 | grep -v "^mkdir\|^g++" || true
echo ""

# Step 2: Run the tests
echo "Running tests with proof: $PROOF_PATH"
echo ""

./fri_pinning_test --proof-path="$PROOF_PATH"
