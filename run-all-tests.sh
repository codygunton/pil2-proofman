#!/bin/bash
# Run all Python executable spec tests
#
# This runs the complete test suite including:
#   - Unit tests (NTT, field operations, transcript, merkle tree, etc.)
#   - Integration tests (stark_info parsing, proof loading)
#   - E2E tests (full proof generation vs C++ golden values)
#
# Prerequisites:
#   ./setup.sh                    # Build test AIRs
#   ./generate-test-vectors.sh    # Generate golden values from C++

set -e

cd "$(dirname "$0")/executable-spec"

echo "=== Python Executable Spec - Full Test Suite ==="
echo ""

uv run python -m pytest tests/ -v "$@"

echo ""
echo "=== All tests passed ==="
