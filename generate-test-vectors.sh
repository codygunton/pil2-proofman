#!/bin/bash
# Generate JSON test vectors by capturing C++ output and processing with Python.
#
# Usage:
#   ./generate-test-vectors.sh [simple|lookup|all]
#
# This script:
#   1. Builds the C++ library with CAPTURE_TEST_VECTORS flag
#   2. Runs proof generation which outputs JSON to stderr
#   3. Parses captured JSON and proof files with Python
#   4. Outputs complete test vector JSON files
#
# Outputs:
#   executable-spec/test-data/simple-left.json
#   executable-spec/test-data/lookup2-12.json

set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXEC_SPEC_DIR="$ROOT_DIR/executable-spec"

# Use GCC 13 for C++ compilation
export CC=gcc-13
export CXX=g++-13

# Add Intel OneAPI library path for iomp5
if [ -d "/opt/intel/oneapi/compiler/2025.0/lib" ]; then
    export LIBRARY_PATH="${LIBRARY_PATH:+$LIBRARY_PATH:}/opt/intel/oneapi/compiler/2025.0/lib"
    export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:+$LD_LIBRARY_PATH:}/opt/intel/oneapi/compiler/2025.0/lib"
fi

# ===========================================================================
# Generate vectors for a specific test
# ===========================================================================
generate_vectors() {
    local TEST_NAME="$1"      # simple | lookup | permutation
    local AIR_NAME="$2"       # SimpleLeft | Lookup2_12 | Permutation1_6
    local BUILD_DIR="$3"      # path to build directory
    local LIB_NAME="$4"       # libsimple.so | liblookup.so | libpermutation.so
    local PROOF_NAME="$5"     # SimpleLeft_0 | Lookup2_12_2 | Permutation1_6_0
    local OUTPUT_FILE="$6"    # simple-left.json | lookup2-12.json | permutation1-6.json
    local STARKINFO_PATH="$7" # relative path from provingKey to starkinfo.json

    # Extract instance number from proof name (last segment after underscore)
    local INSTANCE="${PROOF_NAME##*_}"

    local OUTPUT_DIR="$BUILD_DIR/test_vectors_output"
    local PROOF_FILE="$OUTPUT_DIR/proofs/${PROOF_NAME}.json"

    echo ""
    echo "=== Generating vectors for $AIR_NAME ($TEST_NAME) ==="
    echo ""

    # Check if provingKey exists
    if [ ! -d "$BUILD_DIR/provingKey" ]; then
        echo "ERROR: provingKey not found at $BUILD_DIR/provingKey"
        echo "Run ./setup.sh $TEST_NAME first to generate proving keys."
        return 1
    fi

    # Build library with debug feature for deterministic witness
    echo "Building $LIB_NAME with debug feature..."
    cargo build --manifest-path "$ROOT_DIR/pil2-components/test/$TEST_NAME/rs/Cargo.toml" --features debug 2>/dev/null

    # Build C++ library with CAPTURE_TEST_VECTORS flag
    echo "Building C++ library with FRI capture flag..."
    cd "$ROOT_DIR/pil2-stark"
    make clean > /dev/null 2>&1 || true
    make -j starks_lib EXTRA_CXXFLAGS="-DCAPTURE_TEST_VECTORS" 2>&1 | tail -5
    cd "$ROOT_DIR"

    # Force rebuild of proofman-cli to link against the new library
    echo "Rebuilding proofman-cli..."
    touch "$ROOT_DIR/provers/starks-lib-c/build.rs"
    cargo build --manifest-path "$ROOT_DIR/Cargo.toml" --bin proofman-cli 2>/dev/null

    # Generate proofs and capture stderr (JSON output)
    echo "Generating proofs (capturing FRI vectors to JSON)..."
    rm -rf "$OUTPUT_DIR"
    mkdir -p "$OUTPUT_DIR"

    local CAPTURE_FILE="$OUTPUT_DIR/fri_capture.txt"

    cargo run --manifest-path "$ROOT_DIR/Cargo.toml" --bin proofman-cli prove \
        --witness-lib "$ROOT_DIR/target/debug/$LIB_NAME" \
        --proving-key "$BUILD_DIR/provingKey" \
        --output-dir "$OUTPUT_DIR" \
        --save-proofs \
        --verify-proofs 2> "$CAPTURE_FILE" > /dev/null || true

    # Check proof file exists
    if [ ! -f "$PROOF_FILE" ]; then
        echo "ERROR: Proof file not found: $PROOF_FILE"
        echo "Contents of $OUTPUT_DIR:"
        ls -la "$OUTPUT_DIR" || true
        ls -la "$OUTPUT_DIR/proofs" 2>/dev/null || true
        return 1
    fi

    # Find starkinfo file
    local STARKINFO_FILE="$BUILD_DIR/provingKey/$STARKINFO_PATH"

    if [ ! -f "$STARKINFO_FILE" ]; then
        echo "ERROR: Starkinfo file not found: $STARKINFO_FILE"
        return 1
    fi

    # Run Python script to generate JSON
    echo "Running Python script to generate test vectors..."
    cd "$EXEC_SPEC_DIR"

    # Use uv to manage the virtual environment and poseidon2 FFI
    # First ensure poseidon2-ffi is built
    if ! uv run python -c "import poseidon2" 2>/dev/null; then
        echo "Building poseidon2 FFI module..."
        cd primitives/poseidon2-ffi && uv run maturin develop --release && cd ../..
    fi

    local INSTANCE_ARG=""
    if [ -n "$INSTANCE" ]; then
        INSTANCE_ARG="--instance $INSTANCE"
    fi

    uv run python tests/create-test-vectors.py \
        --capture-file "$CAPTURE_FILE" \
        --proof-file "$PROOF_FILE" \
        --starkinfo-file "$STARKINFO_FILE" \
        --air-name "$AIR_NAME" \
        --output "tests/test-data/$OUTPUT_FILE" \
        $INSTANCE_ARG

    # Copy binary proof file if it exists
    local PROOF_BIN_FILE="${PROOF_FILE%.json}.proof.bin"
    local OUTPUT_BIN_FILE="${OUTPUT_FILE%.json}.proof.bin"
    if [ -f "$PROOF_BIN_FILE" ]; then
        cp "$PROOF_BIN_FILE" "tests/test-data/$OUTPUT_BIN_FILE"
        echo "Copied binary proof: tests/test-data/$OUTPUT_BIN_FILE"
    fi

    cd "$ROOT_DIR"

    echo ""
    echo "Generated: executable-spec/tests/test-data/$OUTPUT_FILE"
    echo "Capture file preserved: $CAPTURE_FILE"
}

# ===========================================================================
# Main
# ===========================================================================

echo "=== Generate JSON Test Vectors ==="

# Build workspace first
echo ""
echo "Building workspace..."
"$ROOT_DIR/build.sh" > /dev/null 2>&1

TEST_TARGET="${1:-all}"

case "$TEST_TARGET" in
    simple)
        generate_vectors "simple" "SimpleLeft" \
            "$ROOT_DIR/pil2-components/test/simple/build" \
            "libsimple.so" "SimpleLeft_0" "simple-left.json" \
            "build/Simple/airs/SimpleLeft/air/SimpleLeft.starkinfo.json"
        ;;
    lookup)
        generate_vectors "lookup" "Lookup2_12" \
            "$ROOT_DIR/pil2-components/test/lookup/build" \
            "liblookup.so" "Lookup2_12_2" "lookup2-12.json" \
            "lookup/Lookup/airs/Lookup2_12/air/Lookup2_12.starkinfo.json"
        ;;
    permutation)
        generate_vectors "permutation" "Permutation1_6" \
            "$ROOT_DIR/pil2-components/test/permutation/build" \
            "libpermutation.so" "Permutation1_6_0" "permutation1-6.json" \
            "permutation/Permutation/airs/Permutation1_6/air/Permutation1_6.starkinfo.json"
        ;;
    all)
        generate_vectors "simple" "SimpleLeft" \
            "$ROOT_DIR/pil2-components/test/simple/build" \
            "libsimple.so" "SimpleLeft_0" "simple-left.json" \
            "build/Simple/airs/SimpleLeft/air/SimpleLeft.starkinfo.json"

        generate_vectors "lookup" "Lookup2_12" \
            "$ROOT_DIR/pil2-components/test/lookup/build" \
            "liblookup.so" "Lookup2_12_2" "lookup2-12.json" \
            "lookup/Lookup/airs/Lookup2_12/air/Lookup2_12.starkinfo.json"

        generate_vectors "permutation" "Permutation1_6" \
            "$ROOT_DIR/pil2-components/test/permutation/build" \
            "libpermutation.so" "Permutation1_6_0" "permutation1-6.json" \
            "permutation/Permutation/airs/Permutation1_6/air/Permutation1_6.starkinfo.json"
        ;;
    *)
        echo "Usage: $0 [simple|lookup|permutation|all]"
        exit 1
        ;;
esac

echo ""
echo "=== Done ==="
echo ""
echo "Test vectors generated in: executable-spec/test-data/"
echo ""
echo "To validate, run:"
echo "  cd executable-spec && uv run python -m pytest test_fri.py -v"
