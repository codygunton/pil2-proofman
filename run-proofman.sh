#!/bin/bash
set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$ROOT_DIR/pil2-components/test/simple/build"

# Use GCC 13 for C++ compilation (GCC 14+ has stricter cstdint requirements)
export CC=gcc-13
export CXX=g++-13

# Add Intel OneAPI library path for iomp5
if [ -d "/opt/intel/oneapi/compiler/2025.0/lib" ]; then
    export LIBRARY_PATH="${LIBRARY_PATH:+$LIBRARY_PATH:}/opt/intel/oneapi/compiler/2025.0/lib"
    export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:+$LD_LIBRARY_PATH:}/opt/intel/oneapi/compiler/2025.0/lib"
fi

# BUILD defaults to 1 (true)
BUILD="${BUILD:-1}"

# Build if BUILD is set to 1/true
if [ "$BUILD" = "1" ] || [ "$BUILD" = "true" ]; then
    echo "Building before run..."
    "$ROOT_DIR/build.sh"
fi

echo "Running simple test..."
cargo run --manifest-path "$ROOT_DIR/Cargo.toml" --bin proofman-cli prove \
    --witness-lib "$ROOT_DIR/target/debug/libsimple.so" \
    --proving-key "$BUILD_DIR/provingKey" \
    --output-dir "$BUILD_DIR" \
    --verify-proofs

echo "Run complete!"
