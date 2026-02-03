#!/bin/bash
# Setup the Python executable spec environment
#
# Usage:
#   ./setup.sh           # Full setup (uv sync + build poseidon2-ffi)
#   ./setup.sh sync      # Only run uv sync
#   ./setup.sh ffi       # Only build poseidon2-ffi

set -e

cd "$(dirname "$0")"

setup_uv() {
    echo "Installing Python dependencies..."
    uv sync
}

setup_ffi() {
    echo "Building poseidon2-ffi Rust library..."
    cd primitives/poseidon2-ffi
    maturin develop --release
    cd ../..
}

case "${1:-all}" in
    sync)
        setup_uv
        ;;
    ffi)
        setup_ffi
        ;;
    all|"")
        setup_uv
        setup_ffi
        echo ""
        echo "Setup complete! Run ./run-tests.sh to verify."
        ;;
    *)
        echo "Usage: ./setup.sh [sync|ffi|all]"
        exit 1
        ;;
esac
