# FRI Polynomial Commitment Scheme Modularization Plan

## Executive Summary

### Problem Statement
The FRI (Fast Reed-Solomon Interactive Oracle Proof) polynomial commitment scheme is currently deeply embedded within the STARK prover flow in `gen_proof.hpp`. This tight coupling makes it impossible to:
- Unit test the FRI protocol in isolation
- Verify FRI correctness independently of the full STARK system
- Reuse the FRI implementation in other contexts

### Proposed Solution
Extract the FRI computation into a standalone, minimal-interface module (`FriPcs`) that:
- Takes raw polynomial coefficients (in Goldilocks cubic extension field) and challenges as input
- Performs FRI folding and Merkle tree commitment
- Outputs a self-contained FRI proof
- Can be tested independently with synthetic test vectors

### Technical Approach
1. **Establish pinning tests** to capture golden proof output BEFORE any changes
2. Define minimal input/output types that don't depend on `StarkInfo` or `expressionsCtx`
3. Create a `FriPcs` class with a clean interface
4. Extract the "Compute FRI" logic (lines 203-268 of `gen_proof.hpp`) into this class
5. Modify `gen_proof.hpp` to use the new interface (thin adapter)
6. Create comprehensive gtest suite for the isolated FRI module
7. **Verify pinning tests pass** after every change to ensure identical output

### Data Flow
```
Input: FriPcsInput
├── polynomial: Goldilocks::Element* (cubic extension coefficients)
├── poly_size: uint64_t (2^n_bits_ext elements)
├── fri_steps: vector<uint64_t> (folding step sizes)
├── n_queries: uint64_t
├── merkle_arity: uint64_t
└── challenges: vector<Goldilocks3::Element> (one per FRI step)

Processing:
┌─────────────────────────────────────────────────────────┐
│ FriPcs::prove()                                         │
├─────────────────────────────────────────────────────────┤
│ 1. For each FRI step s:                                 │
│    a. fold(challenge[s]) → reduce polynomial degree     │
│    b. merkelize() → commit to folded polynomial         │
│    c. store root in proof                               │
│ 2. Compute grinding nonce (proof of work)               │
│ 3. Derive query indices from final challenge + nonce    │
│ 4. For each query:                                      │
│    a. Generate Merkle proofs for stage 0 polynomial     │
│    b. Generate Merkle proofs for each FRI step          │
│ 5. Store final polynomial coefficients                  │
└─────────────────────────────────────────────────────────┘

Output: FriPcsProof
├── roots: vector<array<Goldilocks::Element, 4>> (FRI step roots)
├── query_proofs: vector<QueryProof> (Merkle proofs per query)
├── final_polynomial: vector<Goldilocks::Element> (final poly coeffs)
└── nonce: uint64_t (grinding nonce)
```

### Expected Outcomes
- The FRI PCS can be instantiated and tested without any STARK context
- Unit tests can verify FRI folding correctness with known test vectors
- The existing `gen_proof.hpp` continues to work unchanged (uses adapter)
- Future FRI improvements can be tested in isolation before integration

## Goals & Objectives

### Primary Goals
- Create `FriPcs` class with minimal interface that takes polynomial + challenges → proof
- Achieve 100% test coverage for FRI folding operations
- Maintain backward compatibility with existing `gen_proof.hpp` flow

### Secondary Objectives
- Document the FRI protocol implementation for future maintainers
- Enable property-based testing (random polynomials, random challenges)
- Lay groundwork for potential Rust port of FRI prover

## Solution Overview

### Approach
Extract FRI into a self-contained module with dependency injection for Merkle tree operations. The key insight is that FRI only needs:
1. A polynomial (coefficients in evaluation form)
2. Folding parameters (step sizes)
3. Challenges (one per step)
4. A Merkle tree implementation (injectable)

Everything else (`StarkInfo`, `Transcript`, `expressionsCtx`) is either derivable from these inputs or only needed by the outer STARK layer.

### Key Components

1. **`FriPcsConfig`**: Configuration struct holding FRI parameters (replaces parts of `StarkStruct`)
2. **`FriPcsInput`**: Input struct with polynomial and challenges
3. **`FriPcsProof`**: Output struct with complete FRI proof
4. **`FriPcs<MerkleTree>`**: Main class template, parameterized by Merkle tree type
5. **Test harness**: gtest-based tests with known vectors

### Architecture Diagram
```
┌─────────────────────────────────────────────────────────────────┐
│                        gen_proof.hpp                            │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  starks.calculateFRIPolynomial() → friPol                 │  │
│  │  transcript.getChallenge() → challenges                   │  │
│  │                         │                                 │  │
│  │                         ▼                                 │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │                    FriPcs                           │  │  │
│  │  │  ┌───────────────┐  ┌───────────────────────────┐   │  │  │
│  │  │  │ FriPcsInput   │  │ FriPcsConfig              │   │  │  │
│  │  │  │ - polynomial  │  │ - n_bits_ext              │   │  │  │
│  │  │  │ - challenges  │  │ - fri_steps               │   │  │  │
│  │  │  └───────────────┘  │ - n_queries               │   │  │  │
│  │  │         │           │ - merkle_arity            │   │  │  │
│  │  │         ▼           │ - pow_bits                │   │  │  │
│  │  │  ┌─────────────┐    └───────────────────────────┘   │  │  │
│  │  │  │ prove()     │─────────────────────────────────┐  │  │  │
│  │  │  └─────────────┘                                 │  │  │  │
│  │  │         │                                        │  │  │  │
│  │  │         ▼                                        ▼  │  │  │
│  │  │  ┌─────────────────────┐    ┌────────────────────┐  │  │  │
│  │  │  │ FRI::fold()         │    │ MerkleTreeGL       │  │  │  │
│  │  │  │ FRI::merkelize()    │───▶│ (injected)         │  │  │  │
│  │  │  │ FRI::proveQueries() │    └────────────────────┘  │  │  │
│  │  │  └─────────────────────┘                            │  │  │
│  │  │         │                                           │  │  │
│  │  │         ▼                                           │  │  │
│  │  │  ┌───────────────────┐                              │  │  │
│  │  │  │ FriPcsProof       │                              │  │  │
│  │  │  │ - roots           │                              │  │  │
│  │  │  │ - query_proofs    │                              │  │  │
│  │  │  │ - final_poly      │                              │  │  │
│  │  │  └───────────────────┘                              │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  │                         │                                 │  │
│  │                         ▼                                 │  │
│  │  Copy proof data to FRIProof<ElementType>                 │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Implementation Tasks

### CRITICAL IMPLEMENTATION RULES
1. **NO PLACEHOLDER CODE**: Every implementation must be production-ready
2. **BACKWARD COMPATIBILITY**: `gen_proof.hpp` must continue to work unchanged after refactoring
3. **MINIMAL DEPENDENCIES**: `FriPcs` should only depend on Goldilocks, NTT, and Merkle tree
4. **TEST-FIRST**: Write test vectors before implementing, verify against known-good outputs
5. **PINNING TEST FIRST**: Establish golden reference proofs BEFORE any refactoring

### Visual Dependency Tree

```
pil2-stark/src/
├── starkpil/
│   ├── fri/
│   │   ├── fri.hpp                    (existing - keep for low-level operations)
│   │   ├── fri_pcs.hpp                (Task #1: New PCS interface header)
│   │   ├── fri_pcs_types.hpp          (Task #0: Input/output type definitions)
│   │   └── fri_pcs.cpp                (Task #2: Implementation - optional, can be header-only)
│   │
│   ├── gen_proof.hpp                  (Task #4: Refactor to use FriPcs)
│   └── ...
│
├── goldilocks/
│   └── tests/
│       ├── tests.cpp                  (existing)
│       └── fri_pcs_tests.cpp          (Task #3: New FRI PCS tests)
│
└── ...
```

### Execution Plan

#### Group 0: Pinning Test (COMPLETE)

This group establishes a "golden reference" proof that we can compare against after refactoring to ensure bit-for-bit identical output.

- [x] **Task #P1**: Create pinning test with hardcoded expected checksums
  - **Status**: COMPLETE
  - **File**: `test_pinning.sh` (repository root)
  - **Run with**: `./test_pinning.sh`
  - **Key discovery**: The `simple` test uses random seeding by default. Must build with `--features debug` to get deterministic proofs (seed=0).
  - **Golden values hardcoded in script**:
    - Global challenge: `[1461052753056858962, 17277128619110652023, 18440847142611318128]`
    - `SimpleLeft_0.json`: `67f19b7e8b87ad5138edc0b61c1ab46f11dddb3cc98dce01ad5e6a62766cb62b`
    - `SimpleRight_1.json`: `03dc94421c31af8614b3885d12a0367fe59ebe5af6da5f783b4281e5a5da0af1`
    - `SpecifiedRanges_4.json`: `e19d09ac109eccf0d6cfc8f7668b2c7f2717cedee47def0febac4199091c9982`
    - `U16Air_3.json`: `b1248e9304c2a27ceedeef0a05ee0d687f73f76202f76aacf70f0cc854ccbdec`
    - `U8Air_2.json`: `d1d80ab182eaedced823bd7df17c8c24cce65c6337ae912f99cd00e48518f815`
  - **Test behavior**:
    - Builds workspace, then rebuilds `simple` with `--features debug`
    - Generates proofs with `--save-proofs`
    - Verifies global challenge matches expected
    - Verifies each proof file's SHA256 matches expected
    - Exits 0 on success, 1 on failure
  - **Usage**: Run after any FRI/proof generation changes to verify no regression

~~Tasks #P2, #P3, #P4 are superseded by the comprehensive #P1 implementation above.~~

---

#### Group A: Foundation Types (Execute in parallel, AFTER Group 0)

- [ ] **Task #P-CPP** (Optional): Create C++ FRI-specific pinning test
  - Folder: `pil2-stark/src/goldilocks/tests/`
  - File: `fri_pinning_test.cpp`
  - Purpose: Lower-level pinning test for `FRI::fold()` specifically
  - Note: The shell-based pinning test (#P1) covers the full proof pipeline. This C++ test would provide more granular coverage of FRI internals if needed.
  - Implements:
    ```cpp
    #include <gtest/gtest.h>
    #include "../../starkpil/fri/fri.hpp"
    #include "../src/goldilocks_base_field.hpp"
    #include "../src/ntt_goldilocks.hpp"
    #include <cstring>

    // Golden test vectors - these values are captured from the current implementation
    // and MUST NOT CHANGE after refactoring

    namespace FriPinningVectors {
        // Fixed input polynomial (8 cubic extension elements = 24 Goldilocks elements)
        constexpr uint64_t INPUT_POLY[24] = {
            // These values will be populated by running the capture utility
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24
        };

        // Fixed challenge (3 Goldilocks elements for cubic extension)
        constexpr uint64_t CHALLENGE[3] = {
            0x123456789ABCDEF0ULL,
            0xFEDCBA9876543210ULL,
            0x1111111111111111ULL
        };

        // Expected output after single fold step (4 cubic extension elements = 12 Goldilocks elements)
        // TO BE FILLED IN by running capture utility
        constexpr uint64_t EXPECTED_FOLDED[12] = {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  // Placeholder - will be filled
        };
    }

    TEST(FRI_PINNING_TEST, single_fold_step_deterministic) {
        // Create polynomial from fixed input
        Goldilocks::Element poly[24];
        for (int i = 0; i < 24; i++) {
            poly[i] = Goldilocks::fromU64(FriPinningVectors::INPUT_POLY[i]);
        }

        // Create challenge from fixed input
        Goldilocks::Element challenge[3];
        for (int i = 0; i < 3; i++) {
            challenge[i] = Goldilocks::fromU64(FriPinningVectors::CHALLENGE[i]);
        }

        // Perform fold: 8 elements (nBits=3) -> 4 elements (nBits=2)
        // step=1, nBitsExt=3, prevBits=3, currentBits=2
        FRI<Goldilocks::Element>::fold(1, poly, challenge, 3, 3, 2);

        // Verify output matches expected
        for (int i = 0; i < 12; i++) {
            ASSERT_EQ(Goldilocks::toU64(poly[i]), FriPinningVectors::EXPECTED_FOLDED[i])
                << "Mismatch at index " << i;
        }
    }
    ```
  - Status: Optional - the shell-based test provides sufficient coverage

---

- [x] **Task #0a**: Create FRI PCS type definitions header
  - Folder: `pil2-stark/src/starkpil/fri/`
  - File: `fri_pcs_types.hpp`
  - Implements:
    ```cpp
    #ifndef FRI_PCS_TYPES_HPP
    #define FRI_PCS_TYPES_HPP

    #include "goldilocks_base_field.hpp"
    #include <vector>
    #include <array>

    // Configuration for FRI PCS (subset of StarkStruct)
    struct FriPcsConfig {
        uint64_t n_bits_ext;              // Extended domain size bits (initial poly size = 2^n_bits_ext)
        std::vector<uint64_t> fri_steps;  // nBits for each FRI step (decreasing)
        uint64_t n_queries;               // Number of FRI queries
        uint64_t merkle_arity;            // Merkle tree branching factor (2, 4, 8, or 16)
        uint64_t pow_bits;                // Grinding/proof-of-work bits
        uint64_t last_level_verification; // Last level verification depth
        bool hash_commits;                // Whether to hash commits in transcript
    };

    // Query proof for a single FRI query
    struct FriQueryProof {
        uint64_t query_idx;                                    // Query index
        std::vector<std::vector<Goldilocks::Element>> values;  // Values at query point per FRI step
        std::vector<std::vector<std::vector<Goldilocks::Element>>> siblings; // Merkle siblings per step
    };

    // Complete FRI proof output
    struct FriPcsProof {
        std::vector<std::array<Goldilocks::Element, 4>> roots;  // Merkle roots for each FRI step
        std::vector<FriQueryProof> query_proofs;                // Proofs for each query
        std::vector<Goldilocks::Element> final_polynomial;      // Final polynomial (3 * 2^last_step_bits elements)
        uint64_t nonce;                                         // Grinding nonce
        std::vector<Goldilocks::Element> last_levels;           // Last level nodes for verification
    };

    #endif // FRI_PCS_TYPES_HPP
    ```
  - Exports: `FriPcsConfig`, `FriQueryProof`, `FriPcsProof`
  - Context: These are standalone types with no dependencies beyond Goldilocks

- [x] **Task #0b**: Create FRI PCS test vectors header
  - Folder: `pil2-stark/src/goldilocks/tests/`
  - File: `fri_test_vectors.hpp`
  - Implements:
    ```cpp
    #ifndef FRI_TEST_VECTORS_HPP
    #define FRI_TEST_VECTORS_HPP

    #include "goldilocks_base_field.hpp"
    #include <vector>

    namespace FriTestVectors {
        // Small polynomial (degree 8) for basic fold test
        struct SmallPolyTest {
            static constexpr uint64_t n_bits_ext = 3;  // 8 elements
            static std::vector<Goldilocks::Element> get_polynomial();
            static Goldilocks::Element get_challenge();
            static std::vector<Goldilocks::Element> expected_folded();  // 4 elements
        };

        // Medium polynomial (degree 64) for multi-step FRI
        struct MediumPolyTest {
            static constexpr uint64_t n_bits_ext = 6;  // 64 elements
            static constexpr std::array<uint64_t, 3> fri_steps = {6, 4, 2};
            static std::vector<Goldilocks::Element> get_polynomial();
            static std::vector<Goldilocks::Element> get_challenges();
            static std::vector<Goldilocks::Element> expected_final_poly();
        };
    }

    #endif
    ```
  - Exports: Test vector data for FRI operations
  - Context: These vectors will be computed by running the existing FRI code once and capturing outputs

---

#### Group B: Core Implementation (Execute after Group A)

- [x] **Task #1**: Create FRI PCS main interface header
  - Folder: `pil2-stark/src/starkpil/fri/`
  - File: `fri_pcs.hpp`
  - Imports:
    ```cpp
    #include "fri_pcs_types.hpp"
    #include "fri.hpp"
    #include "merkleTreeGL.hpp"
    #include "ntt_goldilocks.hpp"
    #include "poseidon2_goldilocks.hpp"
    #include <memory>
    ```
  - Implements:
    ```cpp
    template <typename MerkleTreeType = MerkleTreeGL>
    class FriPcs {
    public:
        // Constructor with configuration
        explicit FriPcs(const FriPcsConfig& config);

        // Main prove method
        // polynomial: Pointer to polynomial in evaluation form (cubic extension)
        //             Size must be 3 * 2^config.n_bits_ext elements
        // challenges: FRI folding challenges (one per FRI step)
        //             Size must equal config.fri_steps.size()
        // Returns: Complete FRI proof
        FriPcsProof prove(
            Goldilocks::Element* polynomial,
            const std::vector<Goldilocks::Element>& challenges  // Each challenge is 3 elements (cubic ext)
        );

        // Verify method (for testing)
        // Returns true if proof is valid for given commitment and final poly
        bool verify(
            const FriPcsProof& proof,
            const std::array<Goldilocks::Element, 4>& initial_root,
            const std::vector<Goldilocks::Element>& challenges
        );

        // Helper: Perform single fold step (exposed for unit testing)
        static void fold_step(
            Goldilocks::Element* poly,
            uint64_t n_bits_ext,
            uint64_t prev_bits,
            uint64_t current_bits,
            const Goldilocks::Element* challenge  // 3 elements
        );

        // Helper: Compute grinding nonce
        static uint64_t compute_grinding_nonce(
            const Goldilocks::Element* challenge,  // 3 elements
            uint64_t pow_bits
        );

        // Helper: Derive query indices from challenge and nonce
        static std::vector<uint64_t> derive_query_indices(
            const Goldilocks::Element* challenge,
            uint64_t nonce,
            uint64_t n_queries,
            uint64_t domain_bits,
            uint64_t transcript_arity,
            bool merkle_tree_custom
        );

    private:
        FriPcsConfig config_;
        std::vector<std::unique_ptr<MerkleTreeType>> trees_fri_;

        void initialize_trees();
    };
    ```
  - Exports: `FriPcs` template class
  - Context: This is the main interface that `gen_proof.hpp` will eventually use

- [x] **Task #2**: Implement FRI PCS methods
  - Folder: `pil2-stark/src/starkpil/fri/`
  - File: `fri_pcs.hpp` (continuation, template implementation in header)
  - Implements:
    - `FriPcs::prove()` - Main proof generation (extracted from gen_proof.hpp lines 207-260)
    - `FriPcs::verify()` - Basic verification for testing
    - `FriPcs::fold_step()` - Delegates to `FRI<>::fold()` with proper parameters
    - `FriPcs::compute_grinding_nonce()` - Delegates to `Poseidon2GoldilocksGrinding::grinding()`
    - `FriPcs::derive_query_indices()` - Extracted transcript permutation logic
  - Implementation mapping from gen_proof.hpp:
    ```cpp
    // gen_proof.hpp line 208 → FriPcs::prove() step 1
    // starks.calculateFRIPolynomial(params, expressionsCtx);
    // NOTE: This stays in gen_proof.hpp, FriPcs receives the result

    // gen_proof.hpp lines 214-238 → FriPcs::prove() main loop
    for (uint64_t step = 0; step < config_.fri_steps.size(); step++) {
        uint64_t current_bits = config_.fri_steps[step];
        uint64_t prev_bits = step == 0 ? current_bits : config_.fri_steps[step - 1];

        FRI<Goldilocks::Element>::fold(step, poly, &challenges[step * 3],
                                        config_.n_bits_ext, prev_bits, current_bits);

        if (step < config_.fri_steps.size() - 1) {
            // Merkelize and store root
            FRI<Goldilocks::Element>::merkelize(step, ...);
        } else {
            // Store final polynomial
        }
    }

    // gen_proof.hpp lines 244-250 → FriPcs::prove() grinding + queries
    uint64_t nonce = compute_grinding_nonce(&challenges[last_idx * 3], config_.pow_bits);
    auto query_indices = derive_query_indices(...);

    // gen_proof.hpp lines 252-258 → FriPcs::prove() query proofs
    for (uint64_t i = 0; i < config_.n_queries; i++) {
        // Generate Merkle proofs
    }
    ```
  - Integration: Uses existing `FRI<>` static methods internally
  - Note: Most logic is extracted/adapted from `gen_proof.hpp`, not new code

---

#### Group C: Testing (Execute after Group B)

- [x] **Task #3**: Create FRI PCS unit tests
  - Folder: `pil2-stark/src/goldilocks/tests/`
  - File: `fri_pcs_tests.cpp`
  - Imports:
    ```cpp
    #include <gtest/gtest.h>
    #include "../../starkpil/fri/fri_pcs.hpp"
    #include "fri_test_vectors.hpp"
    ```
  - Implements test cases:
    ```cpp
    // Test 1: Single fold step correctness
    TEST(FRI_PCS_TEST, fold_step_basic) {
        // Use SmallPolyTest vector
        auto poly = FriTestVectors::SmallPolyTest::get_polynomial();
        auto challenge = FriTestVectors::SmallPolyTest::get_challenge();
        auto expected = FriTestVectors::SmallPolyTest::expected_folded();

        FriPcs<>::fold_step(poly.data(), 3, 3, 2, &challenge);

        // Verify folded polynomial matches expected
        for (size_t i = 0; i < expected.size(); i++) {
            ASSERT_EQ(Goldilocks::toU64(poly[i]), Goldilocks::toU64(expected[i]));
        }
    }

    // Test 2: Multi-step FRI folding
    TEST(FRI_PCS_TEST, multi_step_folding) {
        // Use MediumPolyTest vector
        // Verify final polynomial after all folding steps
    }

    // Test 3: Complete prove/verify round-trip
    TEST(FRI_PCS_TEST, prove_verify_roundtrip) {
        FriPcsConfig config{
            .n_bits_ext = 6,
            .fri_steps = {6, 4, 2},
            .n_queries = 4,
            .merkle_arity = 2,
            .pow_bits = 0,  // No grinding for test speed
            .last_level_verification = 0,
            .hash_commits = false
        };

        FriPcs<> pcs(config);

        // Generate random polynomial
        std::vector<Goldilocks::Element> poly(3 * 64);  // 64 cubic extension elements
        for (auto& e : poly) {
            e = Goldilocks::fromU64(rand() % GOLDILOCKS_PRIME);
        }

        // Random challenges
        std::vector<Goldilocks::Element> challenges(3 * 3);  // 3 steps, 3 elements each
        for (auto& e : challenges) {
            e = Goldilocks::fromU64(rand() % GOLDILOCKS_PRIME);
        }

        auto proof = pcs.prove(poly.data(), challenges);

        // Verify should pass
        // Note: Need to compute initial root for verification
    }

    // Test 4: Grinding nonce computation
    TEST(FRI_PCS_TEST, grinding_nonce) {
        // Verify grinding produces valid nonce for given pow_bits
    }

    // Test 5: Query index derivation
    TEST(FRI_PCS_TEST, query_indices) {
        // Verify query indices are uniformly distributed
    }
    ```
  - Context: These tests exercise FriPcs in isolation without any STARK context

- [x] **Task #3b**: Generate test vectors from existing implementation
  - Folder: `pil2-stark/src/goldilocks/tests/`
  - File: `generate_fri_vectors.cpp` (one-time utility)
  - Purpose: Run existing FRI code with known inputs, capture outputs as test vectors
  - Implements:
    ```cpp
    // Run once to generate vectors for fri_test_vectors.hpp
    void generate_small_poly_vector() {
        // Create 8-element polynomial
        // Run single fold step
        // Print expected output
    }
    ```
  - Note: This is a development utility, not a permanent test

---

#### Group D: Integration (Execute after Group C tests pass)

**STATUS: DEFERRED** - The foundation work (Groups A-C) is complete. Integration with gen_proof.hpp
is deferred due to the following technical considerations:

1. **Transcript Method Mismatch**: gen_proof.hpp uses `starks.addTranscript()` and `starks.addTranscriptGL()`
   while FriPcs uses `transcript.put()` directly. These may have different hashing behaviors.

2. **Merkle Tree Ownership**: gen_proof.hpp uses `starks.treesFRI` which are owned by the Starks class.
   FriPcs creates its own trees, which would require careful synchronization.

3. **Challenge Derivation**: gen_proof.hpp uses `starks.getChallenge()` which may have additional
   transcript state management that differs from direct `transcript.getState()` calls.

**Recommended Approach for Future Integration**:
- First, add a wrapper method to Starks that uses FriPcs internally
- Ensure transcript operations are identical by comparing byte-for-byte output
- Add integration tests that verify proof output matches before/after

- [ ] **Task #4**: Refactor gen_proof.hpp to use FriPcs (DEFERRED)
  - Folder: `pil2-stark/src/starkpil/`
  - File: `gen_proof.hpp`
  - Changes:
    1. Add include: `#include "fri/fri_pcs.hpp"`
    2. Replace lines 203-268 with FriPcs usage:
    ```cpp
    //--------------------------------
    // 6. Compute FRI
    //--------------------------------
    TimerStart(STARK_STEP_FRI);

    TimerStart(COMPUTE_FRI_POLYNOMIAL);
    starks.calculateFRIPolynomial(params, expressionsCtx);
    TimerStopAndLog(COMPUTE_FRI_POLYNOMIAL);

    // Build FriPcsConfig from StarkStruct
    FriPcsConfig fri_config;
    fri_config.n_bits_ext = setupCtx.starkInfo.starkStruct.steps[0].nBits;
    for (const auto& step : setupCtx.starkInfo.starkStruct.steps) {
        fri_config.fri_steps.push_back(step.nBits);
    }
    fri_config.n_queries = setupCtx.starkInfo.starkStruct.nQueries;
    fri_config.merkle_arity = setupCtx.starkInfo.starkStruct.merkleTreeArity;
    fri_config.pow_bits = setupCtx.starkInfo.starkStruct.powBits;
    fri_config.last_level_verification = setupCtx.starkInfo.starkStruct.lastLevelVerification;
    fri_config.hash_commits = setupCtx.starkInfo.starkStruct.hashCommits;

    // Collect challenges for FRI
    std::vector<Goldilocks::Element> fri_challenges;
    // ... extract from transcript

    // Run FRI PCS
    FriPcs<MerkleTreeGL> fri_pcs(fri_config);
    Goldilocks::Element* friPol = &params.aux_trace[setupCtx.starkInfo.mapOffsets[std::make_pair("f", true)]];
    auto fri_proof = fri_pcs.prove(friPol, fri_challenges);

    // Copy results to existing proof structure
    // ... (adapter code to maintain compatibility)

    TimerStopAndLog(STARK_STEP_FRI);
    ```
  - Constraint: MUST maintain identical proof output - verify with existing tests
  - Integration test: Run `./run-proofman.sh` before and after, compare proof outputs

- [x] **Task #5**: Update Makefile for new test files (OPTIONAL)
  - Folder: `pil2-stark/src/goldilocks/`
  - File: `Makefile`
  - Status: The header files are standalone and don't require build changes.
           The test file (fri_pcs_tests.cpp) can be compiled separately:
           ```bash
           cd pil2-stark/src/goldilocks
           g++ -std=c++17 -O3 -I./src -I../starkpil -fopenmp -mavx2 \
               tests/fri_pcs_tests.cpp src/*.cpp \
               -lgtest -lgmp -lpthread -o fri_pcs_tests
           ```
  - Note: For full integration, add a new target to Makefile similar to `testscpu`
  - Context: New header files are header-only and don't affect existing build

---

## Implementation Workflow

This plan file serves as the authoritative checklist for implementation. When implementing:

### Required Process
1. **Load Plan**: Read this entire plan file before starting
2. **Sync Tasks**: Create TodoWrite tasks matching the checkboxes below
3. **Execute & Update**: For each task:
   - Mark TodoWrite as `in_progress` when starting
   - Update checkbox `[ ]` to `[x]` when completing
   - Mark TodoWrite as `completed` when done
4. **Maintain Sync**: Keep this file and TodoWrite synchronized throughout

### Critical Rules
- This plan file is the source of truth for progress
- Update checkboxes in real-time as work progresses
- Never lose synchronization between plan file and TodoWrite
- Mark tasks complete only when fully implemented (no placeholders)
- Tasks in Groups A-C should be run in parallel using subtasks to avoid context bloat
- Group D (integration) must wait for Group C tests to pass

### Testing Strategy

**CRITICAL: Pinning tests must be established BEFORE any refactoring begins.**

1. **First (Group 0)**:
   - Run `pinning_test.sh` to capture golden proof hashes
   - Run the C++ capture test to get golden FRI::fold() values
   - Commit these golden values to the repository

2. **Before implementing Task #2**: Generate test vectors using Task #3b

3. **Before implementing Task #4**: All Task #3 tests must pass

4. **After EVERY change**:
   - Run `verify_pinning.sh` to ensure proof hashes match golden reference
   - Run C++ pinning test to ensure FRI::fold() output is unchanged

5. **After Task #4 (integration)**:
   - Run `./run-proofman.sh` with `--save-proofs`
   - Verify checksums match golden reference EXACTLY
   - Any difference indicates a regression

### Pinning Test Checkpoints

**Run `./test_pinning.sh` at these mandatory checkpoints:**

| Checkpoint | When to Run | Purpose |
|------------|-------------|---------|
| **CP-0** | Before starting ANY implementation | Verify baseline passes |
| **CP-A** | After Group A (types headers created) | Ensure no accidental changes |
| **CP-B1** | After Task #1 (FriPcs interface) | Verify interface doesn't break existing code |
| **CP-B2** | After Task #2 (FriPcs implementation) | Verify implementation is isolated |
| **CP-C** | After Task #3 (unit tests passing) | Confirm tests don't affect production |
| **CP-D** | After Task #4 (gen_proof.hpp refactored) | **CRITICAL**: Must produce identical proofs |
| **CP-FINAL** | After Task #5 (CMake updated) | Final verification before merge |

**If any checkpoint fails:**
1. STOP immediately
2. `git diff` to identify the breaking change
3. Revert or fix before proceeding
4. Re-run pinning test until it passes

### Progress Tracking
The checkboxes above represent the authoritative status of each task. Keep them updated as you work.

## Appendix: Current Code References

### gen_proof.hpp FRI Section (lines 203-268)
```cpp
//--------------------------------
// 6. Compute FRI
//--------------------------------
TimerStart(STARK_STEP_FRI);

TimerStart(COMPUTE_FRI_POLYNOMIAL);
starks.calculateFRIPolynomial(params, expressionsCtx);
TimerStopAndLog(COMPUTE_FRI_POLYNOMIAL);

Goldilocks::Element challenge[FIELD_EXTENSION];
Goldilocks::Element *friPol = &params.aux_trace[setupCtx.starkInfo.mapOffsets[std::make_pair("f", true)]];

TimerStart(STARK_FRI_FOLDING);
uint64_t nBitsExt =  setupCtx.starkInfo.starkStruct.steps[0].nBits;
for (uint64_t step = 0; step < setupCtx.starkInfo.starkStruct.steps.size(); step++)
{
    uint64_t currentBits = setupCtx.starkInfo.starkStruct.steps[step].nBits;
    uint64_t prevBits = step == 0 ? currentBits : setupCtx.starkInfo.starkStruct.steps[step - 1].nBits;
    FRI<Goldilocks::Element>::fold(step, friPol, challenge, nBitsExt, prevBits, currentBits);
    // ... merkelize, transcript, etc.
}
// ... grinding, queries, final polynomial
```

### fri.hpp Key Methods
- `FRI<>::fold()` - Core folding operation
- `FRI<>::merkelize()` - Merkle tree commitment
- `FRI<>::proveQueries()` - Query proof generation
- `FRI<>::proveFRIQueries()` - FRI-specific query proofs
- `FRI<>::setFinalPol()` - Final polynomial storage
