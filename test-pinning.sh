#!/bin/bash
set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$ROOT_DIR/pil2-components/test/simple/build"
TEST_DIR="$BUILD_DIR/pinning_test_output"

# Use GCC 13 for C++ compilation (GCC 14+ has stricter cstdint requirements)
export CC=gcc-13
export CXX=g++-13

# Add Intel OneAPI library path for iomp5
if [ -d "/opt/intel/oneapi/compiler/2025.0/lib" ]; then
    export LIBRARY_PATH="${LIBRARY_PATH:+$LIBRARY_PATH:}/opt/intel/oneapi/compiler/2025.0/lib"
    export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:+$LD_LIBRARY_PATH:}/opt/intel/oneapi/compiler/2025.0/lib"
fi

# ============================================================================
# GOLDEN CHECKSUMS - These are the expected proof checksums
# If FRI or proof generation changes, these will fail and need to be updated
# ============================================================================
declare -A EXPECTED_CHECKSUMS
EXPECTED_CHECKSUMS["SimpleLeft_0.json"]="67f19b7e8b87ad5138edc0b61c1ab46f11dddb3cc98dce01ad5e6a62766cb62b"
EXPECTED_CHECKSUMS["SimpleRight_1.json"]="03dc94421c31af8614b3885d12a0367fe59ebe5af6da5f783b4281e5a5da0af1"
EXPECTED_CHECKSUMS["SpecifiedRanges_4.json"]="e19d09ac109eccf0d6cfc8f7668b2c7f2717cedee47def0febac4199091c9982"
EXPECTED_CHECKSUMS["U16Air_3.json"]="b1248e9304c2a27ceedeef0a05ee0d687f73f76202f76aacf70f0cc854ccbdec"
EXPECTED_CHECKSUMS["U8Air_2.json"]="d1d80ab182eaedced823bd7df17c8c24cce65c6337ae912f99cd00e48518f815"

EXPECTED_GLOBAL_CHALLENGE="[1461052753056858962, 17277128619110652023, 18440847142611318128]"
# ============================================================================

echo "=== FRI PCS Pinning Test ==="
echo ""
echo "This test verifies that proof output matches expected golden checksums."
echo "If this fails, the FRI implementation has changed in a way that affects proof output."
echo ""

# Build
echo "Building..."
"$ROOT_DIR/build.sh" > /dev/null 2>&1

# Rebuild simple with debug feature for deterministic witness
echo "Rebuilding simple with debug feature (deterministic seed)..."
cargo build --manifest-path "$ROOT_DIR/pil2-components/test/simple/rs/Cargo.toml" --features debug 2>/dev/null

# Clean and create test output directory
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"

# Run proof generation
echo "Generating proofs..."
set +e  # Temporarily disable exit on error to capture failures
OUTPUT=$(cargo run --manifest-path "$ROOT_DIR/Cargo.toml" --bin proofman-cli prove \
    --witness-lib "$ROOT_DIR/target/debug/libsimple.so" \
    --proving-key "$BUILD_DIR/provingKey" \
    --output-dir "$TEST_DIR" \
    --save-proofs \
    --verify-proofs 2>&1)
PROVE_EXIT_CODE=$?
set -e  # Re-enable exit on error

# Check if proof generation/verification failed
if [ $PROVE_EXIT_CODE -ne 0 ]; then
    echo ""
    echo "=== PINNING TEST FAILED ==="
    echo ""
    echo "Proof generation or verification failed."
    echo "This means the FRI implementation is producing INVALID proofs (not just different ones)."
    echo ""
    echo "Error details:"
    echo "$OUTPUT" | grep -E "(ERROR|FAILED|error|failed)" | head -20
    echo ""
    exit 1
fi

# Check global challenge
ACTUAL_CHALLENGE=$(echo "$OUTPUT" | grep "Global challenge:" | sed 's/.*Global challenge: //')
echo ""
echo "Expected global challenge: $EXPECTED_GLOBAL_CHALLENGE"
echo "Actual global challenge:   $ACTUAL_CHALLENGE"

if [ "$ACTUAL_CHALLENGE" != "$EXPECTED_GLOBAL_CHALLENGE" ]; then
    echo ""
    echo "FAILED: Global challenge mismatch!"
    exit 1
fi
echo "Global challenge: OK"

# Check each proof file checksum
echo ""
echo "Checking proof checksums..."
FAILED=0

for PROOF_FILE in "${!EXPECTED_CHECKSUMS[@]}"; do
    EXPECTED="${EXPECTED_CHECKSUMS[$PROOF_FILE]}"
    ACTUAL=$(sha256sum "$TEST_DIR/proofs/$PROOF_FILE" 2>/dev/null | awk '{print $1}')

    if [ "$ACTUAL" = "$EXPECTED" ]; then
        echo "  $PROOF_FILE: OK"
    else
        echo "  $PROOF_FILE: FAILED"
        echo "    Expected: $EXPECTED"
        echo "    Actual:   $ACTUAL"
        FAILED=1
    fi
done

echo ""
if [ $FAILED -eq 0 ]; then
    echo "=== PINNING TEST PASSED ==="
    echo "All proof checksums match expected golden values."
    rm -rf "$TEST_DIR"
    exit 0
else
    echo "=== PINNING TEST FAILED ==="
    echo ""
    echo "Proof checksums do not match expected golden values."
    echo "This means the FRI implementation has changed in a way that produces DIFFERENT (but possibly valid) proofs."
    echo ""
    echo "If this change is intentional, update EXPECTED_CHECKSUMS in this script."
    echo "Proof output preserved in: $TEST_DIR"
    exit 1
fi
