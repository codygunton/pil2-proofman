#!/bin/bash
set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$ROOT_DIR/pil2-components/test/simple/build"
SIMPLE_DIR="$ROOT_DIR/pil2-components/test/simple"
PIL2_STARK_DIR="$ROOT_DIR/pil2-stark"

# Use GCC 13 for C++ compilation (GCC 14+ has stricter cstdint requirements)
export CC=gcc-13
export CXX=g++-13

# Add Intel OneAPI library path for iomp5
if [ -d "/opt/intel/oneapi/compiler/2025.0/lib" ]; then
    export LIBRARY_PATH="${LIBRARY_PATH:+$LIBRARY_PATH:}/opt/intel/oneapi/compiler/2025.0/lib"
    export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:+$LD_LIBRARY_PATH:}/opt/intel/oneapi/compiler/2025.0/lib"
fi

# Find pil2-compiler: check sibling first, then local
if [ -d "$ROOT_DIR/../pil2-compiler" ]; then
    PIL2_COMPILER="$ROOT_DIR/../pil2-compiler"
elif [ -d "$ROOT_DIR/pil2-compiler" ]; then
    PIL2_COMPILER="$ROOT_DIR/pil2-compiler"
else
    echo "Error: pil2-compiler not found at ../pil2-compiler or ./pil2-compiler"
    echo "Please clone it as a sibling or locally:"
    echo "  git clone https://github.com/0xPolygonHermez/pil2-compiler.git -b develop-0.8.0"
    echo "  cd pil2-compiler && npm install"
    exit 1
fi

# Find pil2-proofman-js: check sibling first, then local
if [ -d "$ROOT_DIR/../pil2-proofman-js" ]; then
    PIL2_PROOFMAN_JS="$ROOT_DIR/../pil2-proofman-js"
elif [ -d "$ROOT_DIR/pil2-proofman-js" ]; then
    PIL2_PROOFMAN_JS="$ROOT_DIR/pil2-proofman-js"
else
    echo "Error: pil2-proofman-js not found at ../pil2-proofman-js or ./pil2-proofman-js"
    echo "Please clone it as a sibling or locally:"
    echo "  git clone https://github.com/0xPolygonHermez/pil2-proofman-js.git -b feature/verify-mt-optimization"
    echo "  cd pil2-proofman-js && npm install"
    exit 1
fi

echo "Using pil2-compiler: $PIL2_COMPILER"
echo "Using pil2-proofman-js: $PIL2_PROOFMAN_JS"

# Ensure npm dependencies are installed
if [ ! -d "$PIL2_COMPILER/node_modules" ]; then
    echo "Installing pil2-compiler dependencies..."
    npm install --prefix "$PIL2_COMPILER"
fi

if [ ! -d "$PIL2_PROOFMAN_JS/node_modules" ]; then
    echo "Installing pil2-proofman-js dependencies..."
    npm install --prefix "$PIL2_PROOFMAN_JS"
fi

echo "Setting up simple test..."

# Create build directory if it doesn't exist
if [ ! -d "$BUILD_DIR" ]; then
    echo "Creating build directory..."
    mkdir -p "$BUILD_DIR"
fi

# Compile PIL (skip if pilout already exists)
if [ ! -f "$BUILD_DIR/build.pilout" ]; then
    echo "Compiling PIL..."
    node "$PIL2_COMPILER/src/pil.js" \
        "$SIMPLE_DIR/simple.pil" \
        -I "$ROOT_DIR/pil2-components/lib/std/pil" \
        -o "$BUILD_DIR/build.pilout"
else
    echo "PIL already compiled, skipping..."
fi

# Generate setup (skip if provingKey already exists)
if [ ! -d "$BUILD_DIR/provingKey" ]; then
    echo "Generating setup..."
    node "$PIL2_PROOFMAN_JS/src/main_setup.js" \
        -a "$BUILD_DIR/build.pilout" \
        -b "$BUILD_DIR"
else
    echo "Setup already generated, skipping..."
fi

# Pre-compile pil2-stark C++ library with correct compiler
# (cargo build.rs doesn't pass CXX to make, so we do it here)
if [ ! -f "$PIL2_STARK_DIR/lib/libstarks.a" ]; then
    echo "Compiling pil2-stark C++ library with g++-13..."
    make -C "$PIL2_STARK_DIR" clean
    make -C "$PIL2_STARK_DIR" CXX=g++-13 -j starks_lib
fi

# Run check-setup to generate constant trees (skip if already done)
if [ ! -f "$BUILD_DIR/provingKey/build/Simple/airs/SimpleLeft/air/SimpleLeft.consttree" ]; then
    echo "Running check-setup..."
    cargo run --manifest-path "$ROOT_DIR/Cargo.toml" --bin proofman-cli check-setup \
        --proving-key "$BUILD_DIR/provingKey"
else
    echo "Check-setup already done, skipping..."
fi

echo "Setup complete!"
