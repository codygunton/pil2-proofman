#!/bin/bash
# Generate FRI test vectors by running proof generation and extracting values.
#
# Usage:
#   ./generate-fri-vectors.sh
#
# This script:
#   1. Builds the project and generates proof files
#   2. Extracts FRI values (finalPol, nonce) from SimpleLeft_0.json
#   3. Computes Poseidon2 hash using the C++ binary
#   4. Outputs values ready to paste into fri_pinning_vectors.hpp

set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GOLDILOCKS_DIR="$ROOT_DIR/pil2-stark/src/goldilocks"
BUILD_DIR="$ROOT_DIR/pil2-components/test/simple/build"
TEST_DIR="$BUILD_DIR/fri_vectors_output"
PROOF_FILE="$TEST_DIR/proofs/SimpleLeft_0.json"

# Use GCC 13 for C++ compilation
export CC=gcc-13
export CXX=g++-13

# Add Intel OneAPI library path for iomp5
if [ -d "/opt/intel/oneapi/compiler/2025.0/lib" ]; then
    export LIBRARY_PATH="${LIBRARY_PATH:+$LIBRARY_PATH:}/opt/intel/oneapi/compiler/2025.0/lib"
    export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:+$LD_LIBRARY_PATH:}/opt/intel/oneapi/compiler/2025.0/lib"
fi

echo "=== Generate FRI Test Vectors ==="
echo ""

# Step 1: Build
echo "Step 1: Building..."
"$ROOT_DIR/build.sh" > /dev/null 2>&1

# Rebuild simple with debug feature for deterministic witness
echo "         Rebuilding simple with debug feature (deterministic seed)..."
cargo build --manifest-path "$ROOT_DIR/pil2-components/test/simple/rs/Cargo.toml" --features debug 2>/dev/null

# Step 2: Generate proofs
echo "Step 2: Generating proofs..."
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"

cargo run --manifest-path "$ROOT_DIR/Cargo.toml" --bin proofman-cli prove \
    --witness-lib "$ROOT_DIR/target/debug/libsimple.so" \
    --proving-key "$BUILD_DIR/provingKey" \
    --output-dir "$TEST_DIR" \
    --save-proofs \
    --verify-proofs > /dev/null 2>&1

# Step 3: Check proof file exists
if [ ! -f "$PROOF_FILE" ]; then
    echo "ERROR: Proof file not found: $PROOF_FILE"
    exit 1
fi

echo "Step 3: Extracting values from proof..."
echo ""

# Step 4: Extract values using Python
python3 << EOF
import json

with open("$PROOF_FILE") as f:
    proof = json.load(f)

# Extract finalPol
final_pol = proof['finalPol']
nonce = int(proof['nonce'])

print("=== Values for fri_pinning_vectors.hpp ===")
print("")
print("// EXPECTED_FINAL_POL (48 values):")
print("constexpr std::array<uint64_t, 48> EXPECTED_FINAL_POL = {")
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

# Step 5: Build and run C++ test to get Poseidon2 hash
echo "Step 4: Building fri_pinning_test to compute Poseidon2 hash..."
cd "$GOLDILOCKS_DIR"
make fri_pinning_test > /dev/null 2>&1

echo "Step 5: Computing Poseidon2 hash..."
# Run the test and extract the hash from output
HASH_OUTPUT=$(./fri_pinning_test --proof-path="$PROOF_FILE" --gtest_filter="*OutputSummary" 2>&1 | grep "Poseidon2 hash:")

if [ -z "$HASH_OUTPUT" ]; then
    echo "ERROR: Could not extract Poseidon2 hash from test output"
    exit 1
fi

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
echo ""
echo "=== Done ==="
echo ""
echo "Copy the above values into:"
echo "  pil2-stark/src/goldilocks/tests/fri_pinning_vectors.hpp"
echo ""
echo "Proof files preserved in: $TEST_DIR"
