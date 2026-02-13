#ifndef FRI_PCS_HPP
#define FRI_PCS_HPP

#include "fri_pcs_types.hpp"
#include "fri.hpp"
#include "merkleTree/merkleTreeGL.hpp"
#include "transcript/transcriptGL.hpp"
#include "ntt_goldilocks.hpp"
#include "poseidon2_goldilocks.hpp"
#include <memory>
#include <vector>
#include <cstring>
#include <stdexcept>

/**
 * FriPcs - FRI Polynomial Commitment Scheme
 *
 * This class encapsulates the FRI proving logic, allowing it to be
 * tested independently of the full STARK proving flow.
 *
 * Template parameter MerkleTreeType allows injection of different
 * Merkle tree implementations for testing.
 *
 * Supports two modes:
 * 1. Standalone mode: FriPcs owns its Merkle trees (for testing)
 * 2. Integrated mode: Uses externally-owned trees from Starks (for production)
 */
template <typename MerkleTreeType = MerkleTreeGL>
class FriPcs {
public:
    /**
     * Constructor with configuration
     * @param config FRI PCS configuration parameters
     */
    explicit FriPcs(const FriPcsConfig& config);

    /**
     * Destructor
     */
    ~FriPcs();

    /**
     * Use externally-owned Merkle trees instead of creating new ones.
     * This allows integration with Starks which owns the trees.
     * Must be called before prove() if using external trees.
     *
     * @param external_trees Array of tree pointers (owned by caller, NOT freed by FriPcs)
     * @param num_trees Number of trees (must match config.num_steps() - 1)
     */
    void setExternalTrees(MerkleTreeType** external_trees, uint64_t num_trees);

    /**
     * Main prove method - generates a complete FRI proof
     * Matches gen_proof.hpp FRI section (lines 214-260) exactly.
     *
     * @param polynomial Pointer to polynomial in evaluation form (cubic extension)
     *                   Size must be 3 * 2^config.n_bits_ext elements
     *                   NOTE: This buffer is modified in-place during folding!
     * @param proof FRIProof structure to populate
     * @param transcript Main proof transcript (modified during proving)
     * @param nTrees Number of stage trees for proveQueries (for stage polynomial queries)
     * @param stageTrees Stage Merkle trees for proveQueries (may be nullptr if nTrees=0)
     * @return Grinding nonce (caller should set on proof)
     */
    uint64_t prove(
        Goldilocks::Element* polynomial,
        FRIProof<Goldilocks::Element>& proof,
        TranscriptGL& transcript,
        uint64_t nTrees,
        MerkleTreeType** stageTrees
    );

    /**
     * Static helper: Perform single fold step
     * Exposed for unit testing
     *
     * @param step Current FRI step index
     * @param poly Polynomial buffer (modified in-place)
     * @param challenge Folding challenge (3 elements for cubic extension)
     * @param n_bits_ext Extended domain size in bits
     * @param prev_bits Previous step bits (or n_bits_ext for step 0)
     * @param current_bits Current step bits
     */
    static void fold_step(
        uint64_t step,
        Goldilocks::Element* poly,
        Goldilocks::Element* challenge,
        uint64_t n_bits_ext,
        uint64_t prev_bits,
        uint64_t current_bits
    );

    /**
     * Static helper: Compute grinding nonce
     * Exposed for unit testing
     *
     * @param challenge Final FRI challenge (3 elements)
     * @param pow_bits Proof-of-work bits required
     * @return Grinding nonce that satisfies the PoW requirement
     */
    static uint64_t compute_grinding_nonce(
        Goldilocks::Element* challenge,
        uint64_t pow_bits
    );

    /**
     * Static helper: Calculate hash of data using temporary transcript
     * Matches Starks::calculateHash() exactly.
     *
     * @param hash Output buffer (HASH_SIZE elements)
     * @param buffer Input data to hash
     * @param n_elements Number of elements to hash
     * @param transcript_arity Transcript arity (from config)
     * @param merkle_tree_custom Custom merkle tree flag (from config)
     */
    static void calculateHash(
        Goldilocks::Element* hash,
        Goldilocks::Element* buffer,
        uint64_t n_elements,
        uint64_t transcript_arity,
        bool merkle_tree_custom
    );

    /**
     * Static helper: Derive query indices from challenge and nonce
     * Exposed for unit testing
     *
     * @param challenge Final challenge (3 elements)
     * @param nonce Grinding nonce
     * @param n_queries Number of queries to derive
     * @param domain_bits Domain size in bits for permutation
     * @param transcript_arity Transcript arity
     * @param merkle_tree_custom Custom merkle tree flag
     * @param out_queries Output array for query indices (must be pre-allocated)
     */
    static void derive_query_indices(
        Goldilocks::Element* challenge,
        uint64_t nonce,
        uint64_t n_queries,
        uint64_t domain_bits,
        uint64_t transcript_arity,
        bool merkle_tree_custom,
        uint64_t* out_queries
    );

    /**
     * Get the configuration
     */
    const FriPcsConfig& config() const { return config_; }

    /**
     * Get access to FRI trees (for integration with existing proof structure)
     * @param step FRI step index (0 to num_steps - 2)
     * @return Pointer to the Merkle tree for that step
     */
    MerkleTreeType* get_fri_tree(uint64_t step) {
        if (trees_fri_raw_ == nullptr) return nullptr;
        uint64_t num_trees = config_.num_steps() > 0 ? config_.num_steps() - 1 : 0;
        if (step >= num_trees) return nullptr;
        return trees_fri_raw_[step];
    }

    /**
     * Get the raw FRI tree array (for compatibility with existing FRI methods)
     */
    MerkleTreeType** get_fri_trees_array() {
        return trees_fri_raw_;
    }

    /**
     * Check if using external trees
     */
    bool using_external_trees() const { return use_external_trees_; }

private:
    FriPcsConfig config_;
    std::vector<std::unique_ptr<MerkleTreeType>> trees_fri_;  // Owned trees (standalone mode)
    MerkleTreeType** trees_fri_raw_;  // Raw pointer array (either owned or external)
    bool use_external_trees_;         // If true, trees_fri_raw_ points to external trees

    /**
     * Initialize Merkle trees for FRI steps (standalone mode)
     */
    void initialize_trees();

    /**
     * Clean up allocated resources
     */
    void cleanup();
};

// =============================================================================
// Implementation
// =============================================================================

template <typename MerkleTreeType>
FriPcs<MerkleTreeType>::FriPcs(const FriPcsConfig& config)
    : config_(config)
    , trees_fri_raw_(nullptr)
    , use_external_trees_(false)
{
    initialize_trees();
}

template <typename MerkleTreeType>
FriPcs<MerkleTreeType>::~FriPcs() {
    cleanup();
}

template <typename MerkleTreeType>
void FriPcs<MerkleTreeType>::setExternalTrees(MerkleTreeType** external_trees, uint64_t num_trees) {
    uint64_t expected_trees = config_.num_steps() > 0 ? config_.num_steps() - 1 : 0;
    if (num_trees != expected_trees) {
        throw std::runtime_error("FriPcs::setExternalTrees: tree count mismatch - expected " +
                                 std::to_string(expected_trees) + ", got " + std::to_string(num_trees));
    }

    // Clean up any owned trees
    trees_fri_.clear();
    if (trees_fri_raw_ && !use_external_trees_) {
        delete[] trees_fri_raw_;
    }

    // Use external trees
    use_external_trees_ = true;
    trees_fri_raw_ = external_trees;
}

template <typename MerkleTreeType>
void FriPcs<MerkleTreeType>::initialize_trees() {
    // Create Merkle trees for each FRI step (except the last)
    // The last step stores the final polynomial directly

    uint64_t num_fri_trees = config_.num_steps() > 0 ? config_.num_steps() - 1 : 0;
    trees_fri_.reserve(num_fri_trees);

    for (uint64_t step = 0; step + 1 < config_.num_steps(); step++) {
        uint64_t current_bits = config_.fri_steps[step];
        uint64_t next_bits = config_.fri_steps[step + 1];

        // Tree height is the number of elements at this level
        // Each element in the tree is (current_bits - next_bits) cubic extension values
        uint64_t height = 1ULL << next_bits;
        uint64_t width = (1ULL << (current_bits - next_bits)) * FIELD_EXTENSION;

        auto tree = std::make_unique<MerkleTreeType>(
            config_.merkle_arity,
            config_.last_level_verification,
            config_.merkle_tree_custom,
            height,
            width,
            true,   // allocateSource
            true    // allocateNodes
        );

        trees_fri_.push_back(std::move(tree));
    }

    // Create raw pointer array for compatibility with existing FRI methods
    if (num_fri_trees > 0) {
        trees_fri_raw_ = new MerkleTreeType*[num_fri_trees];
        for (uint64_t i = 0; i < num_fri_trees; i++) {
            trees_fri_raw_[i] = trees_fri_[i].get();
        }
    }
}

template <typename MerkleTreeType>
void FriPcs<MerkleTreeType>::cleanup() {
    // Only delete the raw pointer array if we own it (not using external trees)
    if (trees_fri_raw_ && !use_external_trees_) {
        delete[] trees_fri_raw_;
    }
    trees_fri_raw_ = nullptr;
    trees_fri_.clear();
    use_external_trees_ = false;
}

template <typename MerkleTreeType>
void FriPcs<MerkleTreeType>::fold_step(
    uint64_t step,
    Goldilocks::Element* poly,
    Goldilocks::Element* challenge,
    uint64_t n_bits_ext,
    uint64_t prev_bits,
    uint64_t current_bits)
{
    // Delegate to existing FRI::fold implementation
    FRI<Goldilocks::Element>::fold(step, poly, challenge, n_bits_ext, prev_bits, current_bits);
}

template <typename MerkleTreeType>
uint64_t FriPcs<MerkleTreeType>::compute_grinding_nonce(
    Goldilocks::Element* challenge,
    uint64_t pow_bits)
{
    if (pow_bits == 0) {
        return 0;
    }

    uint64_t nonce;
    // Poseidon2GoldilocksGrinding is Poseidon2Goldilocks<4>
    using Poseidon2GoldilocksGrinding = Poseidon2Goldilocks<4>;
    Poseidon2GoldilocksGrinding::grinding(nonce, (uint64_t*)challenge, pow_bits);
    return nonce;
}

template <typename MerkleTreeType>
void FriPcs<MerkleTreeType>::calculateHash(
    Goldilocks::Element* hash,
    Goldilocks::Element* buffer,
    uint64_t n_elements,
    uint64_t transcript_arity,
    bool merkle_tree_custom)
{
    // Create a fresh, temporary transcript - matches Starks::calculateHash() exactly
    TranscriptGL transcriptHash(transcript_arity, merkle_tree_custom);
    transcriptHash.put(buffer, n_elements);
    transcriptHash.getState(hash);
}

template <typename MerkleTreeType>
void FriPcs<MerkleTreeType>::derive_query_indices(
    Goldilocks::Element* challenge,
    uint64_t nonce,
    uint64_t n_queries,
    uint64_t domain_bits,
    uint64_t transcript_arity,
    bool merkle_tree_custom,
    uint64_t* out_queries)
{
    // Matches gen_proof.hpp lines 247-250 exactly
    TranscriptGL transcriptPermutation(transcript_arity, merkle_tree_custom);
    transcriptPermutation.put(challenge, FIELD_EXTENSION);
    transcriptPermutation.put((Goldilocks::Element*)&nonce, 1);
    transcriptPermutation.getPermutations(out_queries, n_queries, domain_bits);
}

template <typename MerkleTreeType>
uint64_t FriPcs<MerkleTreeType>::prove(
    Goldilocks::Element* polynomial,
    FRIProof<Goldilocks::Element>& proof,
    TranscriptGL& transcript,
    uint64_t nTrees,
    MerkleTreeType** stageTrees)
{
    // This implementation matches gen_proof.hpp lines 214-260 exactly

    Goldilocks::Element challenge[FIELD_EXTENSION];
    Goldilocks::Element* friPol = polynomial;

#ifdef CAPTURE_TEST_VECTORS
    std::vector<std::array<uint64_t, FIELD_EXTENSION>> captured_challenges;
    std::vector<std::array<uint64_t, HASH_SIZE>> captured_merkle_roots;
    std::vector<std::array<uint64_t, HASH_SIZE>> captured_poly_hashes;

    // Capture transcript state before FRI starts
    // This allows Python to initialize transcript and verify challenge generation
    std::array<uint64_t, 16> captured_transcript_state;
    std::array<uint64_t, 16> captured_transcript_out;
    uint32_t captured_out_cursor = transcript.out_cursor;
    uint32_t captured_pending_cursor = transcript.pending_cursor;
    for (int i = 0; i < 16; i++) {
        captured_transcript_state[i] = Goldilocks::toU64(transcript.state[i]);
        captured_transcript_out[i] = Goldilocks::toU64(transcript.out[i]);
    }
#endif

    // FRI Folding loop - matches gen_proof.hpp lines 216-238
    uint64_t nBitsExt = config_.fri_steps[0];
    for (uint64_t step = 0; step < config_.num_steps(); step++) {
        uint64_t currentBits = config_.fri_steps[step];
        uint64_t prevBits = step == 0 ? currentBits : config_.fri_steps[step - 1];

        // Perform folding - matches line 220
        FRI<Goldilocks::Element>::fold(step, friPol, challenge, nBitsExt, prevBits, currentBits);

        if (step < config_.num_steps() - 1) {
            // Merkelize - matches lines 223-224
            uint64_t nextBits = config_.fri_steps[step + 1];
            FRI<Goldilocks::Element>::merkelize(step, proof, friPol, trees_fri_raw_[step], currentBits, nextBits);

#ifdef CAPTURE_TEST_VECTORS
            // Capture Merkle root
            captured_merkle_roots.push_back({
                Goldilocks::toU64(proof.proof.fri.treesFRI[step].root[0]),
                Goldilocks::toU64(proof.proof.fri.treesFRI[step].root[1]),
                Goldilocks::toU64(proof.proof.fri.treesFRI[step].root[2]),
                Goldilocks::toU64(proof.proof.fri.treesFRI[step].root[3])
            });
            // Capture polynomial hash after fold
            uint64_t polySize = (1ULL << currentBits) * FIELD_EXTENSION;
            Goldilocks::Element polyHash[HASH_SIZE];
            calculateHash(polyHash, friPol, polySize, config_.transcript_arity, config_.merkle_tree_custom);
            captured_poly_hashes.push_back({
                Goldilocks::toU64(polyHash[0]),
                Goldilocks::toU64(polyHash[1]),
                Goldilocks::toU64(polyHash[2]),
                Goldilocks::toU64(polyHash[3])
            });
#endif

            // Add root to transcript - matches line 224: starks.addTranscript(transcript, &proof.proof.fri.treesFRI[step].root[0], HASH_SIZE)
            transcript.put(&proof.proof.fri.treesFRI[step].root[0], HASH_SIZE);
        } else {
            // Last step - add final polynomial to transcript - matches lines 228-235
            uint64_t finalPolySize = (1ULL << currentBits) * FIELD_EXTENSION;
            if (!config_.hash_commits) {
                // matches line 229: starks.addTranscriptGL(transcript, friPol, ...)
                transcript.put(friPol, finalPolySize);
            } else {
                // matches lines 231-233: starks.calculateHash + starks.addTranscript
                Goldilocks::Element hash[HASH_SIZE];
                calculateHash(hash, friPol, finalPolySize, config_.transcript_arity, config_.merkle_tree_custom);
                transcript.put(hash, HASH_SIZE);
            }
        }

        // Get challenge for next step - matches line 237: starks.getChallenge(transcript, *challenge)
        transcript.getField((uint64_t*)challenge);

#ifdef CAPTURE_TEST_VECTORS
        captured_challenges.push_back({
            Goldilocks::toU64(challenge[0]),
            Goldilocks::toU64(challenge[1]),
            Goldilocks::toU64(challenge[2])
        });
#endif
    }

#ifdef CAPTURE_TEST_VECTORS
    // Output captured data in JSON format
    std::cerr << "=== FRI_PCS_JSON_START ===" << std::endl;
    std::cerr << "{" << std::endl;

    // Transcript state at FRI start
    std::cerr << "  \"transcript_state\": [";
    for (int i = 0; i < 16; i++) {
        if (i > 0) std::cerr << ", ";
        std::cerr << captured_transcript_state[i];
    }
    std::cerr << "]," << std::endl;

    std::cerr << "  \"transcript_out\": [";
    for (int i = 0; i < 16; i++) {
        if (i > 0) std::cerr << ", ";
        std::cerr << captured_transcript_out[i];
    }
    std::cerr << "]," << std::endl;

    std::cerr << "  \"transcript_out_cursor\": " << captured_out_cursor << "," << std::endl;
    std::cerr << "  \"transcript_pending_cursor\": " << captured_pending_cursor << "," << std::endl;

    // FRI challenges
    std::cerr << "  \"fri_challenges\": [";
    for (size_t i = 0; i < captured_challenges.size(); i++) {
        if (i > 0) std::cerr << ", ";
        std::cerr << "[" << captured_challenges[i][0] << ", "
                  << captured_challenges[i][1] << ", "
                  << captured_challenges[i][2] << "]";
    }
    std::cerr << "]," << std::endl;

    // Grinding challenge
    std::cerr << "  \"grinding_challenge\": ["
              << Goldilocks::toU64(challenge[0]) << ", "
              << Goldilocks::toU64(challenge[1]) << ", "
              << Goldilocks::toU64(challenge[2]) << "]," << std::endl;

    // Merkle roots
    std::cerr << "  \"merkle_roots\": [";
    for (size_t i = 0; i < captured_merkle_roots.size(); i++) {
        if (i > 0) std::cerr << ", ";
        std::cerr << "[" << captured_merkle_roots[i][0] << ", "
                  << captured_merkle_roots[i][1] << ", "
                  << captured_merkle_roots[i][2] << ", "
                  << captured_merkle_roots[i][3] << "]";
    }
    std::cerr << "]," << std::endl;

    // Polynomial hashes after fold
    std::cerr << "  \"poly_hashes_after_fold\": [";
    for (size_t i = 0; i < captured_poly_hashes.size(); i++) {
        if (i > 0) std::cerr << ", ";
        std::cerr << "[" << captured_poly_hashes[i][0] << ", "
                  << captured_poly_hashes[i][1] << ", "
                  << captured_poly_hashes[i][2] << ", "
                  << captured_poly_hashes[i][3] << "]";
    }
    std::cerr << "]" << std::endl;

    std::cerr << "}" << std::endl;
    std::cerr << "=== FRI_PCS_JSON_END ===" << std::endl;
#endif

    // Grinding - matches gen_proof.hpp lines 244-245
    uint64_t nonce;
    using Poseidon2GoldilocksGrinding = Poseidon2Goldilocks<4>;
    Poseidon2GoldilocksGrinding::grinding(nonce, (uint64_t*)challenge, config_.pow_bits);

    // Query index derivation - matches gen_proof.hpp lines 247-250
    uint64_t friQueries[config_.n_queries];
    TranscriptGL transcriptPermutation(config_.transcript_arity, config_.merkle_tree_custom);
    transcriptPermutation.put(challenge, FIELD_EXTENSION);
    transcriptPermutation.put((Goldilocks::Element*)&nonce, 1);
    transcriptPermutation.getPermutations(friQueries, config_.n_queries, config_.fri_steps[0]);

#ifdef CAPTURE_TEST_VECTORS
    // Output FRI queries in JSON format
    std::cerr << "=== FRI_QUERIES_JSON_START ===" << std::endl;
    std::cerr << "{" << std::endl;
    std::cerr << "  \"fri_queries\": [";
    for (uint64_t i = 0; i < config_.n_queries; i++) {
        if (i > 0) std::cerr << ", ";
        std::cerr << friQueries[i];
    }
    std::cerr << "]";

    // Capture first query proof siblings for step 0 tree (for Python verification)
    if (config_.num_steps() > 1) {
        uint64_t proof_idx = friQueries[0] % (1 << config_.fri_steps[1]);
        uint64_t tree_width = trees_fri_raw_[0]->getMerkleTreeWidth();
        uint64_t proof_size = trees_fri_raw_[0]->getMerkleProofSize();
        Goldilocks::Element* buff = new Goldilocks::Element[tree_width + proof_size];
        trees_fri_raw_[0]->getGroupProof(buff, proof_idx);

        std::cerr << "," << std::endl;
        std::cerr << "  \"query_proof_idx\": " << proof_idx << "," << std::endl;
        std::cerr << "  \"query_proof_siblings\": [";
        for (uint64_t i = 0; i < proof_size; i++) {
            if (i > 0) std::cerr << ", ";
            std::cerr << Goldilocks::toU64(buff[tree_width + i]);
        }
        std::cerr << "]" << std::endl;
        delete[] buff;
    } else {
        std::cerr << std::endl;
    }

    std::cerr << "}" << std::endl;
    std::cerr << "=== FRI_QUERIES_JSON_END ===" << std::endl;
#endif

    // Stage tree queries - matches gen_proof.hpp lines 252-253
    if (nTrees > 0 && stageTrees != nullptr) {
        FRI<Goldilocks::Element>::proveQueries(friQueries, config_.n_queries, proof, stageTrees, nTrees);
    }

    // FRI tree queries - matches gen_proof.hpp lines 255-258
    for (uint64_t step = 1; step < config_.num_steps(); ++step) {
        FRI<Goldilocks::Element>::proveFRIQueries(
            friQueries, config_.n_queries, step,
            config_.fri_steps[step], proof, trees_fri_raw_[step - 1]
        );
    }

    // Final polynomial - matches gen_proof.hpp line 260
    FRI<Goldilocks::Element>::setFinalPol(proof, friPol, config_.fri_steps[config_.num_steps() - 1]);

    // Return nonce for caller to set on proof
    return nonce;
}

#endif // FRI_PCS_HPP
