#!/bin/bash
set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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

# Simple test checksums
declare -A SIMPLE_CHECKSUMS
SIMPLE_CHECKSUMS["SimpleLeft_0.json"]="67f19b7e8b87ad5138edc0b61c1ab46f11dddb3cc98dce01ad5e6a62766cb62b"
SIMPLE_CHECKSUMS["SimpleRight_1.json"]="03dc94421c31af8614b3885d12a0367fe59ebe5af6da5f783b4281e5a5da0af1"
SIMPLE_CHECKSUMS["SpecifiedRanges_4.json"]="e19d09ac109eccf0d6cfc8f7668b2c7f2717cedee47def0febac4199091c9982"
SIMPLE_CHECKSUMS["U16Air_3.json"]="b1248e9304c2a27ceedeef0a05ee0d687f73f76202f76aacf70f0cc854ccbdec"
SIMPLE_CHECKSUMS["U8Air_2.json"]="d1d80ab182eaedced823bd7df17c8c24cce65c6337ae912f99cd00e48518f815"
SIMPLE_GLOBAL_CHALLENGE="[1461052753056858962, 17277128619110652023, 18440847142611318128]"

# Lookup test checksums (Lookup2_12 has 4096 rows - significantly more complex)
declare -A LOOKUP_CHECKSUMS
LOOKUP_CHECKSUMS["Lookup0_0.json"]="91a23330035cc576bac2b203a2140fa799633947afc81c39abfce4c410e168a6"
LOOKUP_CHECKSUMS["Lookup1_1.json"]="239719361db9ff50a22726dc7c01d654296cb0e3f31d7049ec6d980096ec6e56"
LOOKUP_CHECKSUMS["Lookup2_12_2.json"]="419ac85c0c97a0deeb1534543bebd1c32e24b6ff7bad47e6fed6cc7f0738dcd0"
LOOKUP_CHECKSUMS["Lookup2_13_3.json"]="4d2e9644f17eef6dde9dc72d5c585f0c4c791434036e01253be452c1897d40f5"
LOOKUP_CHECKSUMS["Lookup2_15_4.json"]="c34fcda32546e4027031d987d484f7eb59df2441b644c6e3cf02f2e4da5875a9"
LOOKUP_CHECKSUMS["Lookup3_5.json"]="69f5ebd4dad26be9297954aa8b96949666c5f1b5a8fee5dc035221d0b595767d"
LOOKUP_GLOBAL_CHALLENGE="[8703044403523920118, 18374967019439620840, 17962188255440010291]"
# ============================================================================

# Track overall test status
OVERALL_FAILED=0

# ===========================================================================
# Run pinning test for a specific test
# ===========================================================================
run_pinning_test() {
    local TEST_NAME="$1"
    local BUILD_DIR="$2"
    local LIB_NAME="$3"
    local -n CHECKSUMS=$4
    local EXPECTED_CHALLENGE="$5"

    local TEST_DIR="$BUILD_DIR/pinning_test_output"

    echo ""
    echo "=== Testing $TEST_NAME ==="

    # Check if provingKey exists
    if [ ! -d "$BUILD_DIR/provingKey" ]; then
        echo "ERROR: provingKey not found at $BUILD_DIR/provingKey"
        echo "Run ./setup.sh first to generate proving keys."
        return 1
    fi

    # Build library with debug feature for deterministic witness
    echo "Building $LIB_NAME with debug feature..."
    cargo build --manifest-path "$ROOT_DIR/pil2-components/test/$TEST_NAME/rs/Cargo.toml" --features debug 2>/dev/null

    # Clean and create test output directory
    rm -rf "$TEST_DIR"
    mkdir -p "$TEST_DIR"

    # Run proof generation
    echo "Generating proofs..."
    set +e
    OUTPUT=$(cargo run --manifest-path "$ROOT_DIR/Cargo.toml" --bin proofman-cli prove \
        --witness-lib "$ROOT_DIR/target/debug/$LIB_NAME" \
        --proving-key "$BUILD_DIR/provingKey" \
        --output-dir "$TEST_DIR" \
        --save-proofs \
        --verify-proofs 2>&1)
    PROVE_EXIT_CODE=$?
    set -e

    # Check if proof generation/verification failed
    if [ $PROVE_EXIT_CODE -ne 0 ]; then
        echo ""
        echo "FAILED: Proof generation or verification failed for $TEST_NAME"
        echo "Error details:"
        echo "$OUTPUT" | grep -E "(ERROR|FAILED|error|failed)" | head -20
        return 1
    fi

    # Check global challenge
    ACTUAL_CHALLENGE=$(echo "$OUTPUT" | grep "Global challenge:" | sed 's/.*Global challenge: //')
    echo "Expected challenge: $EXPECTED_CHALLENGE"
    echo "Actual challenge:   $ACTUAL_CHALLENGE"

    if [ "$ACTUAL_CHALLENGE" != "$EXPECTED_CHALLENGE" ]; then
        echo "FAILED: Global challenge mismatch!"
        return 1
    fi
    echo "Global challenge: OK"

    # Check each proof file checksum
    echo "Checking proof checksums..."
    local FAILED=0

    for PROOF_FILE in "${!CHECKSUMS[@]}"; do
        EXPECTED="${CHECKSUMS[$PROOF_FILE]}"

        # Skip placeholder checksums (not yet generated)
        if [[ "$EXPECTED" == PLACEHOLDER_* ]]; then
            if [ -f "$TEST_DIR/proofs/$PROOF_FILE" ]; then
                ACTUAL=$(sha256sum "$TEST_DIR/proofs/$PROOF_FILE" | awk '{print $1}')
                echo "  $PROOF_FILE: NEEDS UPDATE (actual: $ACTUAL)"
            else
                echo "  $PROOF_FILE: NOT FOUND"
            fi
            FAILED=1
            continue
        fi

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

    if [ $FAILED -eq 0 ]; then
        echo "$TEST_NAME: PASSED"
        rm -rf "$TEST_DIR"
        return 0
    else
        echo "$TEST_NAME: FAILED"
        echo "Proof output preserved in: $TEST_DIR"
        return 1
    fi
}

# ===========================================================================
# Main
# ===========================================================================

echo "=== FRI PCS Pinning Test ==="
echo ""
echo "This test verifies that proof output matches expected golden checksums."
echo "If this fails, the FRI implementation has changed in a way that affects proof output."

# Build workspace
echo ""
echo "Building workspace..."
"$ROOT_DIR/build.sh" > /dev/null 2>&1

# Determine which tests to run
TEST_TARGETS="${1:-all}"

case "$TEST_TARGETS" in
    simple)
        run_pinning_test "simple" \
            "$ROOT_DIR/pil2-components/test/simple/build" \
            "libsimple.so" \
            SIMPLE_CHECKSUMS \
            "$SIMPLE_GLOBAL_CHALLENGE" || OVERALL_FAILED=1
        ;;
    lookup)
        run_pinning_test "lookup" \
            "$ROOT_DIR/pil2-components/test/lookup/build" \
            "liblookup.so" \
            LOOKUP_CHECKSUMS \
            "$LOOKUP_GLOBAL_CHALLENGE" || OVERALL_FAILED=1
        ;;
    all)
        run_pinning_test "simple" \
            "$ROOT_DIR/pil2-components/test/simple/build" \
            "libsimple.so" \
            SIMPLE_CHECKSUMS \
            "$SIMPLE_GLOBAL_CHALLENGE" || OVERALL_FAILED=1

        run_pinning_test "lookup" \
            "$ROOT_DIR/pil2-components/test/lookup/build" \
            "liblookup.so" \
            LOOKUP_CHECKSUMS \
            "$LOOKUP_GLOBAL_CHALLENGE" || OVERALL_FAILED=1
        ;;
    *)
        echo "Usage: $0 [simple|lookup|all]"
        exit 1
        ;;
esac

echo ""
if [ $OVERALL_FAILED -eq 0 ]; then
    echo "=== ALL PINNING TESTS PASSED ==="
    exit 0
else
    echo "=== SOME PINNING TESTS FAILED ==="
    echo ""
    echo "If checksums changed intentionally, update the EXPECTED values in this script."
    exit 1
fi
