#!/bin/bash
# Run Python executable spec tests with optional filtering
#
# Usage:
#   ./run-tests.sh                    # Run all tests
#   ./run-tests.sh e2e                # Run E2E tests (prover + verifier)
#   ./run-tests.sh prover             # Run prover E2E tests only
#   ./run-tests.sh verifier           # Run verifier E2E tests only
#   ./run-tests.sh fri                # Run FRI tests only
#   ./run-tests.sh constraints        # Run constraint module tests
#   ./run-tests.sh witness            # Run witness module tests
#   ./run-tests.sh simple             # Run SimpleLeft AIR tests
#   ./run-tests.sh lookup             # Run Lookup2_12 AIR tests
#   ./run-tests.sh permutation        # Run Permutation1_6 AIR tests
#   ./run-tests.sh unit               # Run unit tests (non-E2E)
#   ./run-tests.sh -k "pattern"       # Pass pytest -k filter directly

set -e

cd "$(dirname "$0")"

# Default: run all tests
if [ $# -eq 0 ]; then
    echo "Running all tests..."
    uv run python -m pytest tests/ -v
    exit 0
fi

# Handle named filters
case "$1" in
    e2e)
        echo "Running E2E tests (prover + verifier)..."
        uv run python -m pytest tests/test_stark_e2e.py tests/test_verifier_e2e.py -v
        ;;
    prover)
        echo "Running prover E2E tests..."
        uv run python -m pytest tests/test_stark_e2e.py -v
        ;;
    verifier)
        echo "Running verifier E2E tests..."
        uv run python -m pytest tests/test_verifier_e2e.py -v
        ;;
    fri)
        echo "Running FRI tests..."
        uv run python -m pytest tests/test_fri.py -v
        ;;
    constraints)
        echo "Running constraint module tests..."
        uv run python -m pytest tests/test_constraint_context.py tests/test_constraint_verifier.py \
            tests/test_simple_left_constraints.py tests/test_lookup2_12_constraints.py \
            tests/test_permutation1_6_constraints.py -v
        ;;
    witness)
        echo "Running witness module tests..."
        uv run python -m pytest tests/test_witness_base.py tests/test_simple_left_witness.py \
            tests/test_lookup2_12_witness.py tests/test_permutation1_6_witness.py -v
        ;;
    simple)
        echo "Running SimpleLeft AIR tests..."
        uv run python -m pytest -v -k "simple or SimpleLeft"
        ;;
    lookup)
        echo "Running Lookup2_12 AIR tests..."
        uv run python -m pytest -v -k "lookup or Lookup"
        ;;
    permutation)
        echo "Running Permutation1_6 AIR tests..."
        uv run python -m pytest -v -k "permutation or Permutation"
        ;;
    unit)
        echo "Running unit tests (non-E2E)..."
        uv run python -m pytest tests/ -v --ignore=tests/test_stark_e2e.py --ignore=tests/test_verifier_e2e.py
        ;;
    -k)
        # Pass through to pytest -k
        shift
        echo "Running tests matching: $*"
        uv run python -m pytest tests/ -v -k "$*"
        ;;
    *)
        # Assume it's a file pattern or pytest args
        echo "Running: pytest $*"
        uv run python -m pytest "$@"
        ;;
esac
