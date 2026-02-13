#ifndef FRI_PCS_TYPES_HPP
#define FRI_PCS_TYPES_HPP

#include "goldilocks_base_field.hpp"
#include <vector>
#include <array>
#include <cstdint>

// Field extension size (Goldilocks cubic extension)
#ifndef FIELD_EXTENSION
#define FIELD_EXTENSION 3
#endif

// Hash size for Goldilocks
#ifndef HASH_SIZE
#define HASH_SIZE 4
#endif

/**
 * Configuration for FRI PCS (extracted from StarkStruct)
 * This struct contains all parameters needed for FRI proving without
 * depending on the full StarkInfo structure.
 */
struct FriPcsConfig {
    uint64_t n_bits_ext = 0;              // Extended domain size bits (initial poly size = 2^n_bits_ext)
    std::vector<uint64_t> fri_steps;      // nBits for each FRI step (decreasing)
    uint64_t n_queries = 0;               // Number of FRI queries
    uint64_t merkle_arity = 2;            // Merkle tree branching factor (2, 4, 8, or 16)
    uint64_t pow_bits = 0;                // Grinding/proof-of-work bits
    uint64_t last_level_verification = 0; // Last level verification depth
    bool hash_commits = false;            // Whether to hash commits in transcript
    uint64_t transcript_arity = 16;       // Transcript arity for permutation
    bool merkle_tree_custom = false;      // Custom merkle tree flag

    /**
     * Get the number of FRI folding steps
     */
    uint64_t num_steps() const {
        return fri_steps.size();
    }

    /**
     * Get the final polynomial size (number of cubic extension elements)
     */
    uint64_t final_poly_size() const {
        if (fri_steps.empty()) return 0;
        return 1ULL << fri_steps.back();
    }

    /**
     * Validate the configuration
     * Returns true if valid, false otherwise
     */
    bool is_valid() const {
        if (fri_steps.empty()) return false;
        if (n_bits_ext == 0) return false;
        if (n_queries == 0) return false;
        if (merkle_arity == 0) return false;

        // fri_steps should be decreasing
        for (size_t i = 1; i < fri_steps.size(); i++) {
            if (fri_steps[i] >= fri_steps[i-1]) return false;
        }

        return true;
    }
};

/**
 * Merkle proof for a single query at a single FRI step
 */
struct FriMerkleProof {
    std::vector<Goldilocks::Element> values;                          // Values at the query point
    std::vector<std::vector<Goldilocks::Element>> siblings;           // Merkle siblings per level

    FriMerkleProof() = default;

    FriMerkleProof(uint64_t n_values, uint64_t n_levels, uint64_t siblings_per_level)
        : values(n_values)
        , siblings(n_levels, std::vector<Goldilocks::Element>(siblings_per_level))
    {}
};

/**
 * Query proof for a single FRI query across all FRI steps
 */
struct FriQueryProof {
    uint64_t query_idx;                          // Original query index
    std::vector<FriMerkleProof> step_proofs;     // Merkle proofs for each FRI step

    FriQueryProof() : query_idx(0) {}

    explicit FriQueryProof(uint64_t idx) : query_idx(idx) {}
};

/**
 * FRI step tree data (root and last levels)
 */
struct FriStepTree {
    std::array<Goldilocks::Element, HASH_SIZE> root;      // Merkle root
    std::vector<Goldilocks::Element> last_levels;         // Last level nodes for verification

    FriStepTree() {
        root.fill(Goldilocks::zero());
    }

    explicit FriStepTree(uint64_t last_level_size)
        : last_levels(last_level_size, Goldilocks::zero())
    {
        root.fill(Goldilocks::zero());
    }
};

/**
 * Complete FRI proof output
 * This is a standalone proof structure that doesn't depend on StarkInfo
 */
struct FriPcsProof {
    std::vector<FriStepTree> step_trees;                   // Trees for each FRI step (except last)
    std::vector<FriQueryProof> query_proofs;               // Proofs for each query
    std::vector<Goldilocks::Element> final_polynomial;     // Final polynomial coefficients
    uint64_t nonce;                                        // Grinding nonce

    FriPcsProof() : nonce(0) {}

    /**
     * Initialize proof structure with given configuration
     */
    void initialize(const FriPcsConfig& config) {
        // Step trees for all steps except the last
        step_trees.clear();
        step_trees.reserve(config.num_steps() > 0 ? config.num_steps() - 1 : 0);

        uint64_t last_level_size = 0;
        if (config.last_level_verification > 0) {
            last_level_size = HASH_SIZE;
            for (uint64_t i = 0; i < config.last_level_verification; i++) {
                last_level_size *= config.merkle_arity;
            }
        }

        for (uint64_t i = 0; i + 1 < config.num_steps(); i++) {
            step_trees.emplace_back(last_level_size);
        }

        // Query proofs
        query_proofs.clear();
        query_proofs.reserve(config.n_queries);
        for (uint64_t i = 0; i < config.n_queries; i++) {
            query_proofs.emplace_back(i);
        }

        // Final polynomial (cubic extension elements)
        final_polynomial.resize(config.final_poly_size() * FIELD_EXTENSION, Goldilocks::zero());

        nonce = 0;
    }

    /**
     * Get the number of step trees
     */
    uint64_t num_step_trees() const {
        return step_trees.size();
    }

    /**
     * Get the number of query proofs
     */
    uint64_t num_queries() const {
        return query_proofs.size();
    }
};

#endif // FRI_PCS_TYPES_HPP
