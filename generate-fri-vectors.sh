#!/bin/bash
# Generate FRI test vectors by running proof generation and extracting values.
#
# Usage:
#   ./generate-fri-vectors.sh [simple|lookup|all]
#
# This script:
#   1. Builds the project and generates proof files
#   2. Extracts FRI values (finalPol, nonce) from proof JSON
#   3. Computes Poseidon2 hash using the C++ binary
#   4. Outputs values ready to paste into fri_pinning_vectors.hpp

set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GOLDILOCKS_DIR="$ROOT_DIR/pil2-stark/src/goldilocks"

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
    local TEST_NAME="$1"
    local BUILD_DIR="$2"
    local LIB_NAME="$3"
    local AIR_NAME="$4"
    local NAMESPACE="$5"

    local TEST_DIR="$BUILD_DIR/fri_vectors_output"
    local PROOF_FILE="$TEST_DIR/proofs/${AIR_NAME}.json"

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

    # Generate proofs
    echo "Generating proofs..."
    rm -rf "$TEST_DIR"
    mkdir -p "$TEST_DIR"

    cargo run --manifest-path "$ROOT_DIR/Cargo.toml" --bin proofman-cli prove \
        --witness-lib "$ROOT_DIR/target/debug/$LIB_NAME" \
        --proving-key "$BUILD_DIR/provingKey" \
        --output-dir "$TEST_DIR" \
        --save-proofs \
        --verify-proofs > /dev/null 2>&1

    # Check proof file exists
    if [ ! -f "$PROOF_FILE" ]; then
        echo "ERROR: Proof file not found: $PROOF_FILE"
        return 1
    fi

    echo "Extracting values from proof..."
    echo ""

    # Extract values using Python
    python3 << EOF
import json

with open("$PROOF_FILE") as f:
    proof = json.load(f)

# Extract finalPol
final_pol = proof['finalPol']
nonce = int(proof['nonce'])
num_elements = len(final_pol) * 3  # 3 components per cubic extension element

print("=== Values for fri_pinning_vectors.hpp (namespace $NAMESPACE) ===")
print("")
print(f"// EXPECTED_FINAL_POL ({num_elements} values):")
print(f"constexpr std::array<uint64_t, {num_elements}> EXPECTED_FINAL_POL = {{")
for i, elem in enumerate(final_pol):
    print(f"    // Element {i}")
    for j, val in enumerate(elem):
        comma = "," if i < len(final_pol) - 1 or j < len(elem) - 1 else ""
        print(f"    {val}ULL{comma}")
print("};")
print("")
print(f"// EXPECTED_NONCE:")
print(f"constexpr uint64_t EXPECTED_NONCE = {nonce};")
print("")
EOF

    # Build and run C++ test to get Poseidon2 hash
    echo "Building fri_pinning_test to compute Poseidon2 hash..."
    cd "$GOLDILOCKS_DIR"
    make fri_pinning_test > /dev/null 2>&1

    echo "Computing Poseidon2 hash..."
    # Run the test and extract the hash from output
    HASH_OUTPUT=$(./fri_pinning_test --proof-path="$PROOF_FILE" --gtest_filter="*OutputSummary" 2>&1 | grep "Poseidon2 hash:")

    if [ -z "$HASH_OUTPUT" ]; then
        echo "WARNING: Could not extract Poseidon2 hash from test output"
        echo "This is expected for new AIRs - add the namespace to fri_pinning_test.cpp first."
    else
        # Parse the hash values
        HASH_VALUES=$(echo "$HASH_OUTPUT" | sed 's/.*\[\(.*\)\]/\1/' | tr -d ' ')

        echo ""
        echo "// EXPECTED_FINAL_POL_HASH (from Poseidon2):"
        echo "constexpr std::array<uint64_t, 4> EXPECTED_FINAL_POL_HASH = {"
        IFS=',' read -ra VALS <<< "$HASH_VALUES"
        for i in "${!VALS[@]}"; do
            comma=","
            if [ $i -eq 3 ]; then comma=""; fi
            echo "    ${VALS[$i]}ULL$comma"
        done
        echo "};"
    fi

    echo ""
    echo "Proof files preserved in: $TEST_DIR"

    cd "$ROOT_DIR"
}

# ===========================================================================
# Main
# ===========================================================================

echo "=== Generate FRI Test Vectors ==="

# Build workspace first
echo ""
echo "Building workspace..."
"$ROOT_DIR/build.sh" > /dev/null 2>&1

TEST_TARGET="${1:-all}"

case "$TEST_TARGET" in
    simple)
        generate_vectors "simple" \
            "$ROOT_DIR/pil2-components/test/simple/build" \
            "libsimple.so" \
            "SimpleLeft_0" \
            "SimpleLeft"
        ;;
    lookup)
        generate_vectors "lookup" \
            "$ROOT_DIR/pil2-components/test/lookup/build" \
            "liblookup.so" \
            "Lookup2_12_2" \
            "Lookup2_12"
        ;;
    all)
        generate_vectors "simple" \
            "$ROOT_DIR/pil2-components/test/simple/build" \
            "libsimple.so" \
            "SimpleLeft_0" \
            "SimpleLeft"

        generate_vectors "lookup" \
            "$ROOT_DIR/pil2-components/test/lookup/build" \
            "liblookup.so" \
            "Lookup2_12_2" \
            "Lookup2_12"
        ;;
    *)
        echo "Usage: $0 [simple|lookup|all]"
        exit 1
        ;;
esac

echo ""
echo "=== Done ==="
echo ""
echo "Copy the above values into:"
echo "  pil2-stark/src/goldilocks/tests/fri_pinning_vectors.hpp"
