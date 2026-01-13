/**
 * FRI Output Pinning Tests
 *
 * Validates that the FRI portion of STARK proofs matches expected golden values.
 * This serves as a regression test - if FRI output changes unexpectedly,
 * these tests will fail and show exactly which values differ.
 *
 * Supports multiple AIRs:
 *   - SimpleLeft (8 rows) - basic test
 *   - Lookup2_12 (4096 rows) - more complex lookup operations
 *
 * Prerequisites:
 *   Run test-pinning.sh first to generate proof files, or
 *   run generate-fri-vectors.sh to generate vectors for new AIRs.
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
#include <regex>

#include "../src/goldilocks_base_field.hpp"
#include "../src/poseidon2_goldilocks.hpp"
#include <nlohmann/json.hpp>
#include "fri_pinning_vectors.hpp"

using json = nlohmann::json;
using Poseidon2 = Poseidon2Goldilocks<16>;  // SPONGE_WIDTH=16, outputs CAPACITY=4 elements

namespace {

// Supported AIR types
enum class AirType {
    SimpleLeft,
    Lookup2_12,
    Unknown
};

// Global proof path (can be overridden via command line)
std::string g_proof_path;

// Detected AIR type based on proof file name
AirType g_air_type = AirType::Unknown;

/**
 * Detect AIR type from proof file path.
 */
AirType detectAirType(const std::string& path) {
    if (path.find("SimpleLeft") != std::string::npos) {
        return AirType::SimpleLeft;
    }
    if (path.find("Lookup2_12") != std::string::npos) {
        return AirType::Lookup2_12;
    }
    return AirType::Unknown;
}

/**
 * Get AIR type name for display.
 */
const char* airTypeName(AirType type) {
    switch (type) {
        case AirType::SimpleLeft: return "SimpleLeft";
        case AirType::Lookup2_12: return "Lookup2_12";
        default: return "Unknown";
    }
}

// Default paths to try for different AIRs
struct ProofPaths {
    const char* root_relative;
    const char* goldilocks_relative;
};

const ProofPaths kSimpleLeftPaths = {
    "pil2-components/test/simple/build/pinning_test_output/proofs/SimpleLeft_0.json",
    "../../../pil2-components/test/simple/build/pinning_test_output/proofs/SimpleLeft_0.json"
};

const ProofPaths kLookup2_12Paths = {
    "pil2-components/test/lookup/build/pinning_test_output/proofs/Lookup2_12_2.json",
    "../../../pil2-components/test/lookup/build/pinning_test_output/proofs/Lookup2_12_2.json"
};

/**
 * Resolve the proof file path, trying multiple locations.
 * @return Valid path to proof file, or empty string if not found.
 */
std::string resolveProofPath() {
    // Use explicit path if provided
    if (!g_proof_path.empty()) {
        std::ifstream test(g_proof_path);
        if (test.is_open()) {
            g_air_type = detectAirType(g_proof_path);
            return g_proof_path;
        }
        return "";
    }

    // Try SimpleLeft paths first (default for backward compatibility)
    std::ifstream test1(kSimpleLeftPaths.root_relative);
    if (test1.is_open()) {
        g_air_type = AirType::SimpleLeft;
        return kSimpleLeftPaths.root_relative;
    }

    std::ifstream test2(kSimpleLeftPaths.goldilocks_relative);
    if (test2.is_open()) {
        g_air_type = AirType::SimpleLeft;
        return kSimpleLeftPaths.goldilocks_relative;
    }

    // Try Lookup2_12 paths
    std::ifstream test3(kLookup2_12Paths.root_relative);
    if (test3.is_open()) {
        g_air_type = AirType::Lookup2_12;
        return kLookup2_12Paths.root_relative;
    }

    std::ifstream test4(kLookup2_12Paths.goldilocks_relative);
    if (test4.is_open()) {
        g_air_type = AirType::Lookup2_12;
        return kLookup2_12Paths.goldilocks_relative;
    }

    return "";
}

}  // namespace

/**
 * Test fixture for FRI output validation.
 *
 * Handles loading and parsing the proof JSON file once per test suite,
 * providing const access to proof data for individual tests.
 * Detects AIR type from proof file name to use correct expected values.
 */
class FriOutputValidationTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        s_proof_path = resolveProofPath();
        if (s_proof_path.empty()) {
            s_load_error = "Proof file not found. Run test-pinning.sh first.\n"
                          "Tried SimpleLeft and Lookup2_12 paths.";
            return;
        }

        std::cout << "Testing AIR: " << airTypeName(g_air_type) << "\n";

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

    static AirType airType() {
        return g_air_type;
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
 * The size depends on the AIR and FRI configuration.
 */
TEST_F(FriOutputValidationTest, FinalPolynomialValues) {
    ASSERT_TRUE(proof().contains("finalPol")) << "Proof missing 'finalPol' field";

    const auto& final_pol = proof()["finalPol"];
    constexpr size_t kFieldExtension = 3;

    std::cout << "Validating finalPol for " << airTypeName(airType()) << " ("
              << final_pol.size() << " cubic elements, "
              << final_pol.size() * kFieldExtension << " Goldilocks values)...\n";

    // Get expected values based on AIR type
    const uint64_t* expected_pol = nullptr;
    size_t expected_size = 0;

    switch (airType()) {
        case AirType::SimpleLeft:
            expected_pol = FriPinningVectors::SimpleLeft::EXPECTED_FINAL_POL.data();
            expected_size = FriPinningVectors::SimpleLeft::EXPECTED_FINAL_POL.size();
            break;
        case AirType::Lookup2_12:
            expected_pol = FriPinningVectors::Lookup2_12::EXPECTED_FINAL_POL.data();
            expected_size = FriPinningVectors::Lookup2_12::EXPECTED_FINAL_POL.size();
            break;
        default:
            FAIL() << "Unknown AIR type - cannot validate";
    }

    ASSERT_EQ(final_pol.size() * kFieldExtension, expected_size)
        << "Unexpected finalPol size";

    size_t mismatch_count = 0;

    for (size_t i = 0; i < final_pol.size(); ++i) {
        const auto& elem = final_pol[i];
        ASSERT_EQ(elem.size(), kFieldExtension)
            << "Element " << i << " should have " << kFieldExtension << " components";

        for (size_t j = 0; j < kFieldExtension; ++j) {
            const uint64_t actual = std::stoull(elem[j].get<std::string>());
            const uint64_t expected = expected_pol[i * kFieldExtension + j];

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
 * the security parameter (powBits).
 */
TEST_F(FriOutputValidationTest, GrindingNonce) {
    ASSERT_TRUE(proof().contains("nonce")) << "Proof missing 'nonce' field";

    const uint64_t actual_nonce = std::stoull(proof()["nonce"].get<std::string>());

    uint64_t expected_nonce = 0;
    switch (airType()) {
        case AirType::SimpleLeft:
            expected_nonce = FriPinningVectors::SimpleLeft::EXPECTED_NONCE;
            break;
        case AirType::Lookup2_12:
            expected_nonce = FriPinningVectors::Lookup2_12::EXPECTED_NONCE;
            break;
        default:
            FAIL() << "Unknown AIR type - cannot validate";
    }

    std::cout << "Validating nonce for " << airTypeName(airType()) << "...\n"
              << "  Expected: " << expected_nonce << "\n"
              << "  Actual:   " << actual_nonce << "\n";

    EXPECT_EQ(actual_nonce, expected_nonce) << "Nonce mismatch";
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
    std::cout << "Validating proof structure for " << airTypeName(airType()) << "...\n";

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
        constexpr size_t kFieldExtension = 3;

        // finalPol size varies by AIR - just verify it's non-empty and has correct structure
        EXPECT_GT(final_pol.size(), 0u) << "finalPol should not be empty";

        if (!final_pol.empty()) {
            EXPECT_EQ(final_pol[0].size(), kFieldExtension)
                << "Each finalPol element should have " << kFieldExtension << " components";
        }

        std::cout << "  finalPol: " << final_pol.size() << " cubic elements\n";
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
    ASSERT_TRUE(proof().contains("finalPol")) << "Proof missing 'finalPol' field";

    const auto& final_pol = proof()["finalPol"];

    // Convert JSON values to Goldilocks elements
    std::vector<Goldilocks::Element> elements;
    for (const auto& elem : final_pol) {
        for (const auto& val : elem) {
            elements.push_back(Goldilocks::fromU64(std::stoull(val.get<std::string>())));
        }
    }

    // Compute Poseidon2 hash
    Goldilocks::Element hash_output[HASH_SIZE];
    Poseidon2::linear_hash_seq(hash_output, elements.data(), elements.size());

    // Get expected hash based on AIR type
    const uint64_t* expected_hash = nullptr;
    switch (airType()) {
        case AirType::SimpleLeft:
            expected_hash = FriPinningVectors::SimpleLeft::EXPECTED_FINAL_POL_HASH.data();
            break;
        case AirType::Lookup2_12:
            expected_hash = FriPinningVectors::Lookup2_12::EXPECTED_FINAL_POL_HASH.data();
            break;
        default:
            FAIL() << "Unknown AIR type - cannot validate";
    }

    std::cout << "Validating finalPol Poseidon2 hash for " << airTypeName(airType()) << "...\n"
              << "  Computed hash: ["
              << Goldilocks::toU64(hash_output[0]) << ", "
              << Goldilocks::toU64(hash_output[1]) << ", "
              << Goldilocks::toU64(hash_output[2]) << ", "
              << Goldilocks::toU64(hash_output[3]) << "]\n"
              << "  Expected hash: ["
              << expected_hash[0] << ", "
              << expected_hash[1] << ", "
              << expected_hash[2] << ", "
              << expected_hash[3] << "]\n";

    // Compare hash elements
    bool hash_matches = true;
    for (size_t i = 0; i < HASH_SIZE; ++i) {
        if (Goldilocks::toU64(hash_output[i]) != expected_hash[i]) {
            hash_matches = false;
            std::cerr << "  MISMATCH at hash[" << i << "]: expected "
                      << expected_hash[i] << ", got "
                      << Goldilocks::toU64(hash_output[i]) << "\n";
        }
    }

    EXPECT_TRUE(hash_matches) << "Poseidon2 hash mismatch";
}

/**
 * Test: Validate FRI input vectors are correctly captured.
 *
 * This test verifies that the input polynomial and challenges stored in
 * fri_pinning_vectors.hpp match what's expected. For SimpleLeft, the input
 * and output polynomials are identical (no FRI folding needed for small AIRs).
 */
TEST_F(FriOutputValidationTest, InputVectorsConsistency) {
    std::cout << "Validating FRI input vectors consistency for " << airTypeName(airType()) << "...\n";

    switch (airType()) {
        case AirType::SimpleLeft: {
            // For SimpleLeft, we have the full input polynomial stored
            std::vector<Goldilocks::Element> input_elements;
            for (size_t i = 0; i < FriPinningVectors::SimpleLeft::FRI_INPUT_POLYNOMIAL.size(); ++i) {
                input_elements.push_back(Goldilocks::fromU64(
                    FriPinningVectors::SimpleLeft::FRI_INPUT_POLYNOMIAL[i]));
            }

            Goldilocks::Element computed_hash[HASH_SIZE];
            Poseidon2::linear_hash_seq(computed_hash, input_elements.data(), input_elements.size());

            std::cout << "  Input polynomial size: " << input_elements.size() << " elements\n";
            std::cout << "  Computed input hash: ["
                      << Goldilocks::toU64(computed_hash[0]) << ", "
                      << Goldilocks::toU64(computed_hash[1]) << ", "
                      << Goldilocks::toU64(computed_hash[2]) << ", "
                      << Goldilocks::toU64(computed_hash[3]) << "]\n";
            std::cout << "  Expected input hash: ["
                      << FriPinningVectors::SimpleLeft::FRI_INPUT_POL_HASH[0] << ", "
                      << FriPinningVectors::SimpleLeft::FRI_INPUT_POL_HASH[1] << ", "
                      << FriPinningVectors::SimpleLeft::FRI_INPUT_POL_HASH[2] << ", "
                      << FriPinningVectors::SimpleLeft::FRI_INPUT_POL_HASH[3] << "]\n";

            // Validate hash matches
            bool hash_matches = true;
            for (size_t i = 0; i < HASH_SIZE; ++i) {
                if (Goldilocks::toU64(computed_hash[i]) != FriPinningVectors::SimpleLeft::FRI_INPUT_POL_HASH[i]) {
                    hash_matches = false;
                }
            }
            EXPECT_TRUE(hash_matches) << "Input polynomial hash mismatch - vectors may be corrupted";

            // For SimpleLeft, verify input equals output (no folding occurs)
            bool input_equals_output = (FriPinningVectors::SimpleLeft::FRI_INPUT_POLYNOMIAL.size() ==
                                        FriPinningVectors::SimpleLeft::EXPECTED_FINAL_POL.size());
            if (input_equals_output) {
                for (size_t i = 0; i < FriPinningVectors::SimpleLeft::FRI_INPUT_POLYNOMIAL.size(); ++i) {
                    if (FriPinningVectors::SimpleLeft::FRI_INPUT_POLYNOMIAL[i] !=
                        FriPinningVectors::SimpleLeft::EXPECTED_FINAL_POL[i]) {
                        input_equals_output = false;
                        break;
                    }
                }
            }

            std::cout << "  Input equals output: " << (input_equals_output ? "yes" : "no")
                      << " (expected for small AIRs with no FRI folding)\n";
            EXPECT_TRUE(input_equals_output)
                << "For SimpleLeft, input should equal output (no FRI folding occurs)";

            // Validate challenge count matches FRI step count
            EXPECT_EQ(FriPinningVectors::SimpleLeft::FRI_CHALLENGES.size(),
                      FriPinningVectors::SimpleLeft::NUM_FRI_STEPS)
                << "Challenge count should match number of FRI steps";

            std::cout << "  FRI challenges: " << FriPinningVectors::SimpleLeft::FRI_CHALLENGES.size()
                      << " (matching " << FriPinningVectors::SimpleLeft::NUM_FRI_STEPS << " FRI steps)\n";
            break;
        }
        case AirType::Lookup2_12: {
            // For Lookup2_12, input polynomial is 6144 elements - too large to store in header.
            // We only store the hash, which was computed during vector generation.
            std::cout << "  Input polynomial: 6144 elements (hash only stored)\n";
            std::cout << "  Expected input hash: ["
                      << FriPinningVectors::Lookup2_12::FRI_INPUT_POL_HASH[0] << ", "
                      << FriPinningVectors::Lookup2_12::FRI_INPUT_POL_HASH[1] << ", "
                      << FriPinningVectors::Lookup2_12::FRI_INPUT_POL_HASH[2] << ", "
                      << FriPinningVectors::Lookup2_12::FRI_INPUT_POL_HASH[3] << "]\n";
            std::cout << "  Note: Hash validated during generate-fri-vectors.sh\n";

            // Validate challenge count matches FRI step count
            EXPECT_EQ(FriPinningVectors::Lookup2_12::FRI_CHALLENGES.size(),
                      FriPinningVectors::Lookup2_12::NUM_FRI_STEPS)
                << "Challenge count should match number of FRI steps";

            std::cout << "  FRI challenges: " << FriPinningVectors::Lookup2_12::FRI_CHALLENGES.size()
                      << " (matching " << FriPinningVectors::Lookup2_12::NUM_FRI_STEPS << " FRI steps)\n";
            break;
        }
        default:
            FAIL() << "Unknown AIR type - cannot validate input vectors";
    }
}

/**
 * Test: Print FRI output summary for debugging.
 *
 * Outputs key FRI values and computed hashes to aid debugging
 * when tests fail or when updating golden values.
 */
TEST_F(FriOutputValidationTest, OutputSummary) {
    std::cout << "\n=== FRI Output Summary ===\n"
              << "AIR type: " << airTypeName(airType()) << "\n"
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
