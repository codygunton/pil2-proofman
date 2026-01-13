#!/bin/bash
# Run FRI pinning tests to validate FRI output matches expected values.
#
# Usage:
#   ./test-fri.sh [simple|lookup|all] [--proof-path=<path>]
#
# This script:
#   1. Rebuilds the fri_pinning_test binary
#   2. Runs FRI validation tests for specified AIRs
#
# Prerequisites:
#   Run generate-fri-vectors.sh first to generate proof files, OR
#   provide --proof-path to an existing proof file.

set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="$ROOT_DIR/pil2-stark/tests"

# Proof locations for each test
SIMPLE_BUILD_DIR="$ROOT_DIR/pil2-components/test/simple/build"
LOOKUP_BUILD_DIR="$ROOT_DIR/pil2-components/test/lookup/build"

# Parse arguments
PROOF_PATH=""
TEST_TARGET=""

for arg in "$@"; do
    case $arg in
        --proof-path=*)
            PROOF_PATH="${arg#*=}"
            ;;
        simple | lookup | all)
            TEST_TARGET="$arg"
            ;;
    esac
done

# Default to all tests
TEST_TARGET="${TEST_TARGET:-all}"

# ===========================================================================
# Find proof file for a test
# ===========================================================================
find_proof_file() {
    local TEST_NAME="$1"
    local AIR_NAME="$2"
    local BUILD_DIR="$3"

    local LOCATIONS=(
        "$BUILD_DIR/fri_vectors_output/proofs/${AIR_NAME}.json"
        "$BUILD_DIR/pinning_test_output/proofs/${AIR_NAME}.json"
    )

    for loc in "${LOCATIONS[@]}"; do
        if [ -f "$loc" ]; then
            echo "$loc"
            return 0
        fi
    done

    return 1
}

# ===========================================================================
# Run FRI test for a specific AIR
# ===========================================================================
run_fri_test() {
    local TEST_NAME="$1"
    local AIR_NAME="$2"
    local BUILD_DIR="$3"
    local PROOF_FILE="$4"

    echo ""
    echo "--- Testing $AIR_NAME ($TEST_NAME) ---"

    if [ -z "$PROOF_FILE" ]; then
        PROOF_FILE=$(find_proof_file "$TEST_NAME" "$AIR_NAME" "$BUILD_DIR") || {
            echo "ERROR: Proof file not found for $AIR_NAME"
            echo "Run generate-fri-vectors.sh $TEST_NAME first."
            return 1
        }
    fi

    echo "Using proof: $PROOF_FILE"
    "$TESTS_DIR/build/fri-pinning-test" --proof-path="$PROOF_FILE" --gtest_filter="*" || return 1
}

# ===========================================================================
# Main
# ===========================================================================

echo "=== FRI Pinning Test ==="
echo ""

# Build the test binary
echo "Building fri-pinning-test..."
make -C "$TESTS_DIR" fri-pinning-test 2>&1 | grep -v "^mkdir\|^g++" || true
echo ""

OVERALL_FAILED=0

# TODO: just simplify this and run them all
case "$TEST_TARGET" in
    simple)
        if [ -n "$PROOF_PATH" ]; then
            run_fri_test "simple" "SimpleLeft_0" "$SIMPLE_BUILD_DIR" "$PROOF_PATH" || OVERALL_FAILED=1
        else
            run_fri_test "simple" "SimpleLeft_0" "$SIMPLE_BUILD_DIR" "" || OVERALL_FAILED=1
        fi
        ;;
    lookup)
        if [ -n "$PROOF_PATH" ]; then
            run_fri_test "lookup" "Lookup2_12_2" "$LOOKUP_BUILD_DIR" "$PROOF_PATH" || OVERALL_FAILED=1
        else
            run_fri_test "lookup" "Lookup2_12_2" "$LOOKUP_BUILD_DIR" "" || OVERALL_FAILED=1
        fi
        ;;
    all)
        run_fri_test "simple" "SimpleLeft_0" "$SIMPLE_BUILD_DIR" "" || OVERALL_FAILED=1
        run_fri_test "lookup" "Lookup2_12_2" "$LOOKUP_BUILD_DIR" "" || OVERALL_FAILED=1
        ;;
    *)
        echo "Usage: $0 [simple|lookup|all] [--proof-path=<path>]"
        exit 1
        ;;
esac

echo ""
if [ $OVERALL_FAILED -eq 0 ]; then
    echo "=== ALL FRI TESTS PASSED ==="
    exit 0
else
    echo "=== SOME FRI TESTS FAILED ==="
    exit 1
fi
