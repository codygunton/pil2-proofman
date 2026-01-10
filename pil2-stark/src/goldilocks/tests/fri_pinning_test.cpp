/**
 * FRI Output Pinning Tests
 *
 * Validates that the FRI portion of STARK proofs matches expected golden values.
 * This serves as a regression test - if FRI output changes unexpectedly,
 * these tests will fail and show exactly which values differ.
 *
 * Prerequisites:
 *   Run test-pinning.sh first to generate proof files in:
 *   pil2-components/test/simple/build/pinning_test_output/proofs/
 *
 * Build:
 *   cd pil2-stark/src/goldilocks && make fri_pinning_test
 *
 * Run:
 *   ./fri_pinning_test [--proof-path=<path>]
 */

#include <gtest/gtest.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstdlib>
#include <memory>

#include "../src/goldilocks_base_field.hpp"
#include "../src/poseidon2_goldilocks.hpp"
#include <nlohmann/json.hpp>
#include "fri_pinning_vectors.hpp"

using json = nlohmann::json;
using Poseidon2 = Poseidon2Goldilocks<16>;  // SPONGE_WIDTH=16, outputs CAPACITY=4 elements

namespace {

// Default path to proof file (relative to pil2-proofman root)
constexpr const char* const kDefaultProofPath =
    "pil2-components/test/simple/build/pinning_test_output/proofs/SimpleLeft_0.json";

// Alternative relative path when running from goldilocks directory
constexpr const char* const kAlternativeProofPath =
    "../../../pil2-components/test/simple/build/pinning_test_output/proofs/SimpleLeft_0.json";

// Global proof path (can be overridden via command line)
std::string g_proof_path;

/**
 * Resolve the proof file path, trying multiple locations.
 * @return Valid path to proof file, or empty string if not found.
 */
std::string resolveProofPath() {
    // Use explicit path if provided
    if (!g_proof_path.empty()) {
        std::ifstream test(g_proof_path);
        if (test.is_open()) {
            return g_proof_path;
        }
        return "";
    }

    // Try default path
    std::ifstream test1(kDefaultProofPath);
    if (test1.is_open()) {
        return kDefaultProofPath;
    }

    // Try alternative relative path
    std::ifstream test2(kAlternativeProofPath);
    if (test2.is_open()) {
        return kAlternativeProofPath;
    }

    return "";
}

}  // namespace

/**
 * Test fixture for FRI output validation.
 *
 * Handles loading and parsing the proof JSON file once per test suite,
 * providing const access to proof data for individual tests.
 */
class FriOutputValidationTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        s_proof_path = resolveProofPath();
        if (s_proof_path.empty()) {
            s_load_error = "Proof file not found. Run test-pinning.sh first.\n"
                          "Tried: " + std::string(kDefaultProofPath) + "\n"
                          "  and: " + std::string(kAlternativeProofPath);
            return;
        }

        std::ifstream file(s_proof_path);
        if (!file.is_open()) {
            s_load_error = "Cannot open proof file: " + s_proof_path;
            return;
        }

        try {
            s_proof = std::make_unique<json>();
            file >> *s_proof;
        } catch (const json::parse_error& e) {
            s_load_error = "JSON parse error: " + std::string(e.what());
            s_proof.reset();
        }
    }

    static void TearDownTestSuite() {
        s_proof.reset();
        s_proof_path.clear();
        s_load_error.clear();
    }

    void SetUp() override {
        if (!s_load_error.empty()) {
            FAIL() << s_load_error;
        }
        ASSERT_NE(s_proof, nullptr) << "Proof not loaded";
    }

    // Const accessors for proof data
    static const json& proof() {
        return *s_proof;
    }

    static const std::string& proofPath() {
        return s_proof_path;
    }

private:
    static std::unique_ptr<json> s_proof;
    static std::string s_proof_path;
    static std::string s_load_error;
};

// Static member definitions
std::unique_ptr<json> FriOutputValidationTest::s_proof;
std::string FriOutputValidationTest::s_proof_path;
std::string FriOutputValidationTest::s_load_error;

/**
 * Test: Validate all finalPol values match expected golden values.
 *
 * finalPol contains the final polynomial after all FRI folding steps.
 * For SimpleLeft: 16 cubic extension elements = 48 Goldilocks field elements.
 */
TEST_F(FriOutputValidationTest, FinalPolynomialValues) {
    using namespace FriPinningVectors::SimpleLeft;

    ASSERT_TRUE(proof().contains("finalPol")) << "Proof missing 'finalPol' field";

    const auto& final_pol = proof()["finalPol"];
    constexpr size_t kExpectedCubicElements = 16;
    constexpr size_t kFieldExtension = 3;

    ASSERT_EQ(final_pol.size(), kExpectedCubicElements)
        << "Expected " << kExpectedCubicElements << " cubic elements in finalPol";

    std::cout << "Validating finalPol (" << final_pol.size() << " cubic elements, "
              << final_pol.size() * kFieldExtension << " Goldilocks values)...\n";

    size_t mismatch_count = 0;

    for (size_t i = 0; i < final_pol.size(); ++i) {
        const auto& elem = final_pol[i];
        ASSERT_EQ(elem.size(), kFieldExtension)
            << "Element " << i << " should have " << kFieldExtension << " components";

        for (size_t j = 0; j < kFieldExtension; ++j) {
            const uint64_t actual = std::stoull(elem[j].get<std::string>());
            const uint64_t expected = EXPECTED_FINAL_POL[i * kFieldExtension + j];

            if (actual != expected) {
                ++mismatch_count;
                std::cerr << "  MISMATCH at finalPol[" << i << "][" << j << "]: "
                          << "expected " << expected << ", got " << actual << "\n";
            }
        }
    }

    if (mismatch_count == 0) {
        std::cout << "  All " << final_pol.size() * kFieldExtension
                  << " values match expected.\n";
    }

    EXPECT_EQ(mismatch_count, 0u)
        << "Found " << mismatch_count << " mismatched values in finalPol";
}

/**
 * Test: Validate grinding nonce matches expected value.
 *
 * The nonce is computed via proof-of-work grinding to satisfy
 * the security parameter (powBits). For SimpleLeft: expected nonce = 56.
 */
TEST_F(FriOutputValidationTest, GrindingNonce) {
    using namespace FriPinningVectors::SimpleLeft;

    ASSERT_TRUE(proof().contains("nonce")) << "Proof missing 'nonce' field";

    const uint64_t actual_nonce = std::stoull(proof()["nonce"].get<std::string>());

    std::cout << "Validating nonce...\n"
              << "  Expected: " << EXPECTED_NONCE << "\n"
              << "  Actual:   " << actual_nonce << "\n";

    EXPECT_EQ(actual_nonce, EXPECTED_NONCE) << "Nonce mismatch";
}

/**
 * Test: Validate proof structure contains all required FRI fields.
 *
 * Checks for presence of:
 * - finalPol: final polynomial after FRI folding
 * - nonce: grinding proof-of-work nonce
 * - roots: Merkle tree roots for each stage
 * - s0_* fields: FRI query proofs (values, siblings, last levels)
 */
TEST_F(FriOutputValidationTest, ProofStructure) {
    std::cout << "Validating proof structure...\n";

    // Required top-level fields
    const std::vector<std::string> required_fields = {
        "airgroupvalues", "evals", "finalPol", "nonce",
        "root1", "root2", "root3"
    };

    for (const auto& field : required_fields) {
        EXPECT_TRUE(proof().contains(field)) << "Missing required field: " << field;
    }

    // Validate finalPol structure
    if (proof().contains("finalPol")) {
        const auto& final_pol = proof()["finalPol"];
        constexpr size_t kExpectedCubicElements = 16;
        constexpr size_t kFieldExtension = 3;

        EXPECT_EQ(final_pol.size(), kExpectedCubicElements)
            << "finalPol should have " << kExpectedCubicElements << " cubic elements";

        if (!final_pol.empty()) {
            EXPECT_EQ(final_pol[0].size(), kFieldExtension)
                << "Each finalPol element should have " << kFieldExtension << " components";
        }
    }

    // Validate Merkle roots have correct size (4 elements for arity 4)
    constexpr size_t kMerkleHashSize = 4;
    for (const auto& root_name : {"root1", "root2", "root3"}) {
        if (proof().contains(root_name)) {
            EXPECT_EQ(proof()[root_name].size(), kMerkleHashSize)
                << root_name << " should have " << kMerkleHashSize << " elements";
        }
    }

    // Check for FRI query proof fields (s0_* prefix)
    const std::vector<std::string> fri_query_fields = {
        "s0_vals1", "s0_vals2", "s0_vals3", "s0_valsC",
        "s0_siblings1", "s0_siblings2", "s0_siblings3", "s0_siblingsC",
        "s0_last_levels1", "s0_last_levels2", "s0_last_levels3", "s0_last_levelsC"
    };

    for (const auto& field : fri_query_fields) {
        EXPECT_TRUE(proof().contains(field))
            << "Missing FRI query field: " << field;
    }

    std::cout << "  Structure validation passed.\n";
}

/**
 * Test: Validate finalPol Poseidon2 hash matches expected value.
 *
 * Computes a Poseidon2 hash over all finalPol field elements and compares
 * against the expected hash stored in the test vectors.
 */
TEST_F(FriOutputValidationTest, FinalPolPoseidon2Hash) {
    using namespace FriPinningVectors::SimpleLeft;

    ASSERT_TRUE(proof().contains("finalPol")) << "Proof missing 'finalPol' field";

    const auto& final_pol = proof()["finalPol"];
    constexpr size_t kNumElements = 48;  // 16 cubic * 3 components

    // Convert JSON values to Goldilocks elements
    std::vector<Goldilocks::Element> elements(kNumElements);
    size_t idx = 0;
    for (const auto& elem : final_pol) {
        for (const auto& val : elem) {
            elements[idx++] = Goldilocks::fromU64(std::stoull(val.get<std::string>()));
        }
    }
    ASSERT_EQ(idx, kNumElements) << "Unexpected number of elements";

    // Compute Poseidon2 hash
    Goldilocks::Element hash_output[HASH_SIZE];
    Poseidon2::linear_hash_seq(hash_output, elements.data(), kNumElements);

    std::cout << "Validating finalPol Poseidon2 hash...\n"
              << "  Computed hash: ["
              << Goldilocks::toU64(hash_output[0]) << ", "
              << Goldilocks::toU64(hash_output[1]) << ", "
              << Goldilocks::toU64(hash_output[2]) << ", "
              << Goldilocks::toU64(hash_output[3]) << "]\n"
              << "  Expected hash: ["
              << EXPECTED_FINAL_POL_HASH[0] << ", "
              << EXPECTED_FINAL_POL_HASH[1] << ", "
              << EXPECTED_FINAL_POL_HASH[2] << ", "
              << EXPECTED_FINAL_POL_HASH[3] << "]\n";

    // Compare hash elements
    bool hash_matches = true;
    for (size_t i = 0; i < HASH_SIZE; ++i) {
        if (Goldilocks::toU64(hash_output[i]) != EXPECTED_FINAL_POL_HASH[i]) {
            hash_matches = false;
            std::cerr << "  MISMATCH at hash[" << i << "]: expected "
                      << EXPECTED_FINAL_POL_HASH[i] << ", got "
                      << Goldilocks::toU64(hash_output[i]) << "\n";
        }
    }

    EXPECT_TRUE(hash_matches) << "Poseidon2 hash mismatch";
}

/**
 * Test: Print FRI output summary for debugging.
 *
 * Outputs key FRI values and computed hashes to aid debugging
 * when tests fail or when updating golden values.
 */
TEST_F(FriOutputValidationTest, OutputSummary) {
    std::cout << "\n=== FRI Output Summary ===\n"
              << "Proof file: " << proofPath() << "\n";

    if (proof().contains("finalPol")) {
        const auto& final_pol = proof()["finalPol"];

        // Convert to Goldilocks elements and compute Poseidon2 hash
        std::vector<Goldilocks::Element> elements;
        for (const auto& elem : final_pol) {
            for (const auto& val : elem) {
                elements.push_back(Goldilocks::fromU64(std::stoull(val.get<std::string>())));
            }
        }

        Goldilocks::Element hash_output[HASH_SIZE];
        Poseidon2::linear_hash_seq(hash_output, elements.data(), elements.size());

        std::cout << "finalPol: " << final_pol.size() << " cubic elements ("
                  << elements.size() << " Goldilocks values)\n"
                  << "Poseidon2 hash: ["
                  << Goldilocks::toU64(hash_output[0]) << ", "
                  << Goldilocks::toU64(hash_output[1]) << ", "
                  << Goldilocks::toU64(hash_output[2]) << ", "
                  << Goldilocks::toU64(hash_output[3]) << "]\n"
                  << "First element: ["
                  << final_pol[0][0].get<std::string>() << ", "
                  << final_pol[0][1].get<std::string>() << ", "
                  << final_pol[0][2].get<std::string>() << "]\n";
    }

    if (proof().contains("nonce")) {
        std::cout << "nonce: " << proof()["nonce"].get<std::string>() << "\n";
    }

    std::cout << "==========================\n";
}

/**
 * Main entry point.
 * Supports --proof-path=<path> argument to override default proof location.
 */
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);

    // Parse custom arguments
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        const std::string prefix = "--proof-path=";
        if (arg.find(prefix) == 0) {
            g_proof_path = arg.substr(prefix.length());
            std::cout << "Using proof path: " << g_proof_path << "\n";
        }
    }

    return RUN_ALL_TESTS();
}
