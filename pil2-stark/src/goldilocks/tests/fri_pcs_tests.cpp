#include <gtest/gtest.h>
#include <iostream>
#include <cstring>

#include "../src/goldilocks_base_field.hpp"
#include "../src/goldilocks_cubic_extension.hpp"
#include "../src/ntt_goldilocks.hpp"
#include "../../starkpil/fri/fri.hpp"
#include "../../starkpil/fri/fri_pcs.hpp"
#include "fri_test_vectors.hpp"

/**
 * FRI PCS Unit Tests
 *
 * These tests verify the FRI folding operations in isolation,
 * independent of the full STARK proving flow.
 */

// ===========================================================================
// Test: FRI::fold basic operation
// ===========================================================================

TEST(FRI_PCS_TEST, fold_basic_8_to_4) {
    // Test folding an 8-element polynomial (nBits=3) to 4 elements (nBits=2)

    // Create a simple polynomial with known values
    // 8 cubic extension elements = 24 Goldilocks elements
    const uint64_t n_elements = 8;
    const uint64_t n_values = n_elements * FIELD_EXTENSION;
    Goldilocks::Element poly[n_values];

    // Initialize with simple sequence
    for (uint64_t i = 0; i < n_values; i++) {
        poly[i] = Goldilocks::fromU64(i + 1);
    }

    // Challenge (cubic extension element)
    Goldilocks::Element challenge[FIELD_EXTENSION];
    challenge[0] = Goldilocks::fromU64(0x123456789ABCDEF0ULL);
    challenge[1] = Goldilocks::fromU64(0xFEDCBA9876543210ULL);
    challenge[2] = Goldilocks::fromU64(0x1111111111111111ULL);

    // Save input for comparison
    uint64_t input_values[n_values];
    for (uint64_t i = 0; i < n_values; i++) {
        input_values[i] = Goldilocks::toU64(poly[i]);
    }

    // Perform fold: step=0 (first step uses special handling),
    // nBitsExt=3, prevBits=3, currentBits=2
    // Note: When step=0, the fold function doesn't actually fold, it just sets up.
    // For step > 0, it performs the actual folding.

    // For step > 0, we need to actually fold
    // Let's test with step=1 to trigger actual folding
    FRI<Goldilocks::Element>::fold(1, poly, challenge, 3, 3, 2);

    // After folding, we should have 4 cubic extension elements = 12 Goldilocks elements
    // The polynomial is modified in place, with the folded result in the first 12 elements

    // Verify the output is different from input (folding occurred)
    bool changed = false;
    for (uint64_t i = 0; i < 12; i++) {
        if (Goldilocks::toU64(poly[i]) != input_values[i]) {
            changed = true;
            break;
        }
    }
    EXPECT_TRUE(changed) << "Fold should modify the polynomial";

    // The output should not be all zeros
    bool has_nonzero = false;
    for (uint64_t i = 0; i < 12; i++) {
        if (Goldilocks::toU64(poly[i]) != 0) {
            has_nonzero = true;
            break;
        }
    }
    EXPECT_TRUE(has_nonzero) << "Folded polynomial should have non-zero values";
}

// ===========================================================================
// Test: Fold determinism
// ===========================================================================

TEST(FRI_PCS_TEST, fold_deterministic) {
    // Verify that folding the same polynomial with the same challenge
    // always produces the same result

    const uint64_t n_elements = 8;
    const uint64_t n_values = n_elements * FIELD_EXTENSION;

    // Run fold twice with identical inputs
    Goldilocks::Element poly1[n_values];
    Goldilocks::Element poly2[n_values];

    for (uint64_t i = 0; i < n_values; i++) {
        poly1[i] = Goldilocks::fromU64(i + 100);
        poly2[i] = Goldilocks::fromU64(i + 100);
    }

    Goldilocks::Element challenge[FIELD_EXTENSION];
    challenge[0] = Goldilocks::fromU64(0xAAAAAAAAAAAAAAAAULL);
    challenge[1] = Goldilocks::fromU64(0x5555555555555555ULL);
    challenge[2] = Goldilocks::fromU64(0x1234567890ABCDEFULL);

    FRI<Goldilocks::Element>::fold(1, poly1, challenge, 3, 3, 2);
    FRI<Goldilocks::Element>::fold(1, poly2, challenge, 3, 3, 2);

    // Results should be identical
    for (uint64_t i = 0; i < 12; i++) {
        EXPECT_EQ(Goldilocks::toU64(poly1[i]), Goldilocks::toU64(poly2[i]))
            << "Mismatch at index " << i;
    }
}

// ===========================================================================
// Test: Fold with different challenges produces different results
// ===========================================================================

TEST(FRI_PCS_TEST, fold_challenge_sensitivity) {
    // Different challenges should produce different folded polynomials

    const uint64_t n_elements = 8;
    const uint64_t n_values = n_elements * FIELD_EXTENSION;

    Goldilocks::Element poly1[n_values];
    Goldilocks::Element poly2[n_values];

    for (uint64_t i = 0; i < n_values; i++) {
        poly1[i] = Goldilocks::fromU64(i + 1);
        poly2[i] = Goldilocks::fromU64(i + 1);
    }

    Goldilocks::Element challenge1[FIELD_EXTENSION] = {
        Goldilocks::fromU64(0x1111111111111111ULL),
        Goldilocks::fromU64(0x2222222222222222ULL),
        Goldilocks::fromU64(0x3333333333333333ULL)
    };

    Goldilocks::Element challenge2[FIELD_EXTENSION] = {
        Goldilocks::fromU64(0x4444444444444444ULL),
        Goldilocks::fromU64(0x5555555555555555ULL),
        Goldilocks::fromU64(0x6666666666666666ULL)
    };

    FRI<Goldilocks::Element>::fold(1, poly1, challenge1, 3, 3, 2);
    FRI<Goldilocks::Element>::fold(1, poly2, challenge2, 3, 3, 2);

    // Results should be different
    bool different = false;
    for (uint64_t i = 0; i < 12; i++) {
        if (Goldilocks::toU64(poly1[i]) != Goldilocks::toU64(poly2[i])) {
            different = true;
            break;
        }
    }
    EXPECT_TRUE(different) << "Different challenges should produce different results";
}

// ===========================================================================
// Test: Multi-step folding (64 -> 16 -> 4)
// ===========================================================================

TEST(FRI_PCS_TEST, multi_step_folding) {
    // Test a sequence of folding steps

    const uint64_t initial_elements = 64;  // 2^6
    const uint64_t n_values = initial_elements * FIELD_EXTENSION;

    Goldilocks::Element* poly = new Goldilocks::Element[n_values];

    // Initialize with deterministic values
    for (uint64_t i = 0; i < n_values; i++) {
        uint64_t val = ((i + 1) * 0x9E3779B97F4A7C15ULL) % Goldilocks::GOLDILOCKS_PRIME;
        poly[i] = Goldilocks::fromU64(val);
    }

    // Step 0: 64 elements (nBits=6)
    // Note: step=0 doesn't actually fold in the current implementation

    // Step 1: 64 -> 16 (nBits=6 -> nBits=4)
    Goldilocks::Element challenge1[FIELD_EXTENSION] = {
        Goldilocks::fromU64(0xAAAAAAAAAAAAAAAAULL),
        Goldilocks::fromU64(0x5555555555555555ULL),
        Goldilocks::fromU64(0x1234567890ABCDEFULL)
    };
    FRI<Goldilocks::Element>::fold(1, poly, challenge1, 6, 6, 4);

    // Verify we now have 16 cubic extension elements
    bool has_nonzero_step1 = false;
    for (uint64_t i = 0; i < 16 * FIELD_EXTENSION; i++) {
        if (Goldilocks::toU64(poly[i]) != 0) {
            has_nonzero_step1 = true;
            break;
        }
    }
    EXPECT_TRUE(has_nonzero_step1) << "Step 1 should produce non-zero values";

    // Step 2: 16 -> 4 (nBits=4 -> nBits=2)
    Goldilocks::Element challenge2[FIELD_EXTENSION] = {
        Goldilocks::fromU64(0xBBBBBBBBBBBBBBBBULL),
        Goldilocks::fromU64(0x6666666666666666ULL),
        Goldilocks::fromU64(0x2345678901234567ULL)
    };
    FRI<Goldilocks::Element>::fold(2, poly, challenge2, 6, 4, 2);

    // Verify we now have 4 cubic extension elements
    bool has_nonzero_step2 = false;
    for (uint64_t i = 0; i < 4 * FIELD_EXTENSION; i++) {
        if (Goldilocks::toU64(poly[i]) != 0) {
            has_nonzero_step2 = true;
            break;
        }
    }
    EXPECT_TRUE(has_nonzero_step2) << "Step 2 should produce non-zero values";

    delete[] poly;
}

// ===========================================================================
// Test: FriPcsConfig validation
// ===========================================================================

TEST(FRI_PCS_TEST, config_validation) {
    FriPcsConfig config;

    // Empty config should be invalid
    EXPECT_FALSE(config.is_valid());

    // Valid config
    config.n_bits_ext = 6;
    config.fri_steps = {6, 4, 2};
    config.n_queries = 10;
    config.merkle_arity = 2;
    EXPECT_TRUE(config.is_valid());

    // Invalid: fri_steps not decreasing
    FriPcsConfig bad_config;
    bad_config.n_bits_ext = 6;
    bad_config.fri_steps = {2, 4, 6};  // Increasing, not decreasing
    bad_config.n_queries = 10;
    bad_config.merkle_arity = 2;
    EXPECT_FALSE(bad_config.is_valid());
}

// ===========================================================================
// Test: FriPcsProof initialization
// ===========================================================================

TEST(FRI_PCS_TEST, proof_initialization) {
    FriPcsConfig config;
    config.n_bits_ext = 6;
    config.fri_steps = {6, 4, 2};
    config.n_queries = 10;
    config.merkle_arity = 2;
    config.last_level_verification = 0;

    FriPcsProof proof;
    proof.initialize(config);

    // Should have 2 step trees (for steps 0 and 1, not the last)
    EXPECT_EQ(proof.num_step_trees(), 2u);

    // Should have 10 query proofs
    EXPECT_EQ(proof.num_queries(), 10u);

    // Final polynomial should be 4 * 3 = 12 elements (4 cubic extension elements)
    EXPECT_EQ(proof.final_polynomial.size(), 4u * FIELD_EXTENSION);

    // Nonce should be initialized to 0
    EXPECT_EQ(proof.nonce, 0u);
}

// ===========================================================================
// Test: FriPcs static helper - calculateHash
// ===========================================================================

TEST(FRI_PCS_TEST, calculateHash_deterministic) {
    // Verify that calculateHash produces consistent results

    const uint64_t n_elements = 8;
    Goldilocks::Element buffer[n_elements];
    for (uint64_t i = 0; i < n_elements; i++) {
        buffer[i] = Goldilocks::fromU64(i + 1);
    }

    Goldilocks::Element hash1[HASH_SIZE];
    Goldilocks::Element hash2[HASH_SIZE];

    // Hash twice with same input
    FriPcs<MerkleTreeGL>::calculateHash(hash1, buffer, n_elements, 2, false);
    FriPcs<MerkleTreeGL>::calculateHash(hash2, buffer, n_elements, 2, false);

    // Results should be identical
    for (uint64_t i = 0; i < HASH_SIZE; i++) {
        EXPECT_EQ(Goldilocks::toU64(hash1[i]), Goldilocks::toU64(hash2[i]))
            << "Hash mismatch at index " << i;
    }

    // Hash should be non-zero
    bool has_nonzero = false;
    for (uint64_t i = 0; i < HASH_SIZE; i++) {
        if (Goldilocks::toU64(hash1[i]) != 0) {
            has_nonzero = true;
            break;
        }
    }
    EXPECT_TRUE(has_nonzero) << "Hash should have non-zero values";
}

// ===========================================================================
// Test: FriPcs static helper - derive_query_indices
// ===========================================================================

TEST(FRI_PCS_TEST, derive_query_indices_deterministic) {
    // Verify that derive_query_indices produces consistent results

    Goldilocks::Element challenge[FIELD_EXTENSION] = {
        Goldilocks::fromU64(0x123456789ABCDEF0ULL),
        Goldilocks::fromU64(0xFEDCBA9876543210ULL),
        Goldilocks::fromU64(0x1111111111111111ULL)
    };

    const uint64_t n_queries = 10;
    const uint64_t domain_bits = 6;
    uint64_t nonce = 12345;

    uint64_t queries1[n_queries];
    uint64_t queries2[n_queries];

    // Derive indices twice with same input
    FriPcs<MerkleTreeGL>::derive_query_indices(
        challenge, nonce, n_queries, domain_bits, 2, false, queries1);
    FriPcs<MerkleTreeGL>::derive_query_indices(
        challenge, nonce, n_queries, domain_bits, 2, false, queries2);

    // Results should be identical
    for (uint64_t i = 0; i < n_queries; i++) {
        EXPECT_EQ(queries1[i], queries2[i])
            << "Query index mismatch at " << i;
    }

    // Indices should be within domain size
    uint64_t domain_size = 1ULL << domain_bits;
    for (uint64_t i = 0; i < n_queries; i++) {
        EXPECT_LT(queries1[i], domain_size)
            << "Query index " << i << " out of range: " << queries1[i] << " >= " << domain_size;
    }
}

// ===========================================================================
// Test: FriPcs static helper - compute_grinding_nonce with zero bits
// ===========================================================================

TEST(FRI_PCS_TEST, compute_grinding_nonce_zero_bits) {
    // With pow_bits=0, should return 0 immediately

    Goldilocks::Element challenge[FIELD_EXTENSION] = {
        Goldilocks::fromU64(0xAAAAAAAAAAAAAAAAULL),
        Goldilocks::fromU64(0x5555555555555555ULL),
        Goldilocks::fromU64(0x1234567890ABCDEFULL)
    };

    uint64_t nonce = FriPcs<MerkleTreeGL>::compute_grinding_nonce(challenge, 0);
    EXPECT_EQ(nonce, 0ULL) << "With pow_bits=0, nonce should be 0";
}

// ===========================================================================
// Test: FriPcs construction and tree initialization
// ===========================================================================

TEST(FRI_PCS_TEST, friPcs_construction) {
    // Test FriPcs construction with a valid config

    FriPcsConfig config;
    config.n_bits_ext = 6;
    config.fri_steps = {6, 4, 2};
    config.n_queries = 10;
    config.pow_bits = 0;
    config.merkle_arity = 2;
    config.last_level_verification = 0;
    config.merkle_tree_custom = false;
    config.transcript_arity = 2;
    config.hash_commits = false;

    EXPECT_TRUE(config.is_valid()) << "Config should be valid";

    // Construction should succeed without throwing
    FriPcs<MerkleTreeGL> friPcs(config);

    // Should not be using external trees
    EXPECT_FALSE(friPcs.using_external_trees());

    // Should have 2 FRI trees (steps.size() - 1)
    EXPECT_NE(friPcs.get_fri_tree(0), nullptr);
    EXPECT_NE(friPcs.get_fri_tree(1), nullptr);
    EXPECT_EQ(friPcs.get_fri_tree(2), nullptr);  // Out of range

    // Config should be accessible
    EXPECT_EQ(friPcs.config().num_steps(), 3u);
}

// ===========================================================================
// Test Vector Capture Utility (for generating pinning values)
// Run this test to capture expected values for the pinning test
// ===========================================================================

TEST(FRI_PCS_TEST, DISABLED_capture_fold_vectors) {
    // This test is disabled by default. Enable it to capture test vectors.
    // Run with: ./test --gtest_also_run_disabled_tests --gtest_filter=FRI_PCS_TEST.DISABLED_capture_fold_vectors

    const uint64_t n_elements = 8;
    const uint64_t n_values = n_elements * FIELD_EXTENSION;

    Goldilocks::Element poly[n_values];

    // Use the pinning test input values
    for (uint64_t i = 0; i < n_values; i++) {
        poly[i] = Goldilocks::fromU64(FriTestVectors::Pinning::INPUT_POLY_24[i]);
    }

    Goldilocks::Element challenge[FIELD_EXTENSION];
    for (int i = 0; i < FIELD_EXTENSION; i++) {
        challenge[i] = Goldilocks::fromU64(FriTestVectors::Pinning::CHALLENGE_3[i]);
    }

    std::cout << "=== Capturing FRI fold test vectors ===" << std::endl;
    std::cout << "Input polynomial (24 elements):" << std::endl;
    for (uint64_t i = 0; i < n_values; i++) {
        std::cout << "  [" << i << "] = 0x" << std::hex << Goldilocks::toU64(poly[i]) << std::dec << std::endl;
    }

    std::cout << "Challenge (3 elements):" << std::endl;
    for (int i = 0; i < FIELD_EXTENSION; i++) {
        std::cout << "  [" << i << "] = 0x" << std::hex << Goldilocks::toU64(challenge[i]) << std::dec << std::endl;
    }

    // Perform fold
    FRI<Goldilocks::Element>::fold(1, poly, challenge, 3, 3, 2);

    std::cout << "Expected folded output (12 elements):" << std::endl;
    std::cout << "constexpr std::array<uint64_t, 12> EXPECTED_FOLDED_12 = {" << std::endl;
    for (uint64_t i = 0; i < 12; i++) {
        std::cout << "    0x" << std::hex << Goldilocks::toU64(poly[i]) << "ULL";
        if (i < 11) std::cout << ",";
        std::cout << std::endl;
    }
    std::cout << "};" << std::dec << std::endl;
}

// ===========================================================================
// Main entry point
// ===========================================================================

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
