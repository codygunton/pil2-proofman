#!/bin/bash
set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$ROOT_DIR/pil2-components/test/simple/build"
SIMPLE_DIR="$ROOT_DIR/pil2-components/test/simple"

# Use GCC 13 for C++ compilation (GCC 14+ has stricter cstdint requirements)
export CC=gcc-13
export CXX=g++-13

# Add Intel OneAPI library path for iomp5
if [ -d "/opt/intel/oneapi/compiler/2025.0/lib" ]; then
    export LIBRARY_PATH="${LIBRARY_PATH:+$LIBRARY_PATH:}/opt/intel/oneapi/compiler/2025.0/lib"
    export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:+$LD_LIBRARY_PATH:}/opt/intel/oneapi/compiler/2025.0/lib"
fi

echo "Building simple test..."

# Generate PIL helpers
echo "Generating PIL helpers..."
cargo run --manifest-path "$ROOT_DIR/Cargo.toml" --bin proofman-cli pil-helpers \
    --pilout "$BUILD_DIR/build.pilout" \
    --path "$SIMPLE_DIR/rs/src" \
    -o

# Build workspace
echo "Building workspace..."
cargo build --manifest-path "$ROOT_DIR/Cargo.toml" --workspace

echo "Build complete!"
