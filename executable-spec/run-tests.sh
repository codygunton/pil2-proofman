#!/bin/bash
# Run Python executable spec tests with optional filtering
#
# Usage:
#   ./run-tests.sh                    # Run all tests (including Zisk)
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
#   ./run-tests.sh zisk               # Run Zisk verifier E2E tests only
#   ./run-tests.sh -k "pattern"       # Pass pytest -k filter directly
#
# Environment:
#   PYTEST_WORKERS  Number of parallel workers (default: 32, 0 to disable)

set -e

cd "$(dirname "$0")"

# Parallel execution: default to 32 workers, set to 0 to disable
WORKERS="${PYTEST_WORKERS:-32}"
if [ "$WORKERS" = "0" ]; then
    PARALLEL_ARGS=""
else
    PARALLEL_ARGS="-n $WORKERS"
fi

# Default: run all tests
if [ $# -eq 0 ]; then
    echo "Running all tests..."
    uv run python -m pytest tests/ -v $PARALLEL_ARGS
    exit 0
fi

# Handle named filters
case "$1" in
    e2e)
        echo "Running E2E tests (prover + verifier)..."
        uv run python -m pytest tests/test_stark_e2e.py tests/test_verifier_e2e.py -v $PARALLEL_ARGS
        ;;
    prover)
        echo "Running prover E2E tests..."
        uv run python -m pytest tests/test_stark_e2e.py -v $PARALLEL_ARGS
        ;;
    verifier)
        echo "Running verifier E2E tests..."
        uv run python -m pytest tests/test_verifier_e2e.py -v $PARALLEL_ARGS
        ;;
    fri)
        echo "Running FRI tests..."
        uv run python -m pytest tests/test_fri.py -v $PARALLEL_ARGS
        ;;
    constraints)
        echo "Running constraint module tests..."
        uv run python -m pytest tests/test_constraint_context.py tests/test_constraint_verifier.py \
            tests/test_simple_left_constraints.py tests/test_lookup2_12_constraints.py \
            tests/test_permutation1_6_constraints.py -v $PARALLEL_ARGS
        ;;
    witness)
        echo "Running witness module tests..."
        uv run python -m pytest tests/test_witness_base.py tests/test_simple_left_witness.py \
            tests/test_lookup2_12_witness.py tests/test_permutation1_6_witness.py -v $PARALLEL_ARGS
        ;;
    simple)
        echo "Running SimpleLeft AIR tests..."
        uv run python -m pytest -v -k "simple or SimpleLeft" $PARALLEL_ARGS
        ;;
    lookup)
        echo "Running Lookup2_12 AIR tests..."
        uv run python -m pytest -v -k "lookup or Lookup" $PARALLEL_ARGS
        ;;
    permutation)
        echo "Running Permutation1_6 AIR tests..."
        uv run python -m pytest -v -k "permutation or Permutation" $PARALLEL_ARGS
        ;;
    unit)
        echo "Running unit tests (non-E2E)..."
        uv run python -m pytest tests/ -v --ignore=tests/test_stark_e2e.py --ignore=tests/test_verifier_e2e.py --ignore=tests/test_zisk_verifier_e2e.py $PARALLEL_ARGS
        ;;
    zisk)
        echo "Running Zisk verifier E2E tests..."
        uv run python -m pytest tests/test_zisk_verifier_e2e.py -v $PARALLEL_ARGS
        ;;
    -k)
        # Pass through to pytest -k
        shift
        echo "Running tests matching: $*"
        uv run python -m pytest tests/ -v -k "$*" $PARALLEL_ARGS
        ;;
    *)
        # Assume it's a file pattern or pytest args
        echo "Running: pytest $*"
        uv run python -m pytest "$@"
        ;;
esac
