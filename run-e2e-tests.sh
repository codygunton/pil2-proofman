#!/bin/bash
# Run end-to-end proof validation tests
#
# These tests validate that the Python spec produces identical output
# to the C++ implementation by comparing against captured golden values.
#
# Prerequisites:
#   ./setup.sh                    # Build test AIRs
#   ./generate-test-vectors.sh    # Generate golden values from C++

set -e

cd "$(dirname "$0")/executable-spec"

echo "=== STARK E2E Tests ==="
echo "Validates: roots, challenges, evals, FRI polynomial vs C++ golden values"
echo ""

uv run python -m pytest tests/test_stark_e2e.py -v "$@"

echo ""
echo "=== FRI E2E Tests ==="
echo "Validates: FRI folding, final polynomial, nonce vs C++ golden values"
echo ""

uv run python -m pytest tests/test_fri.py -v "$@"

echo ""
echo "=== All E2E tests passed ==="
