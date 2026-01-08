# FRI PCS Integration Implementation Plan

## Executive Summary

### Problem Statement
The FRI PCS modularization (Phase 1) created standalone types and interfaces (`fri_pcs_types.hpp`, `fri_pcs.hpp`) but deferred integration with `gen_proof.hpp` due to perceived complexity around transcript methods and Merkle tree ownership.

### Key Findings from Research
The research revealed that integration is **simpler than expected**:

1. **Transcript methods are thin wrappers**:
   - `starks.addTranscript()` = `transcript.put()` (direct delegation)
   - `starks.addTranscriptGL()` = `transcript.put()` (direct delegation)
   - `starks.getChallenge()` = `transcript.getField()` (direct delegation)
   - `starks.calculateHash()` = creates temporary transcript, calls `put()` then `getState()`

2. **Merkle trees can be owned independently**:
   - FriPcs already demonstrates independent tree ownership
   - FRI methods are static and take tree pointers (no coupling to Starks)
   - Both approaches work: FriPcs owns trees OR uses Starks' trees

3. **The real requirement**: Byte-for-byte identical proof output, verified by pinning test

### Proposed Solution
Refactor the existing `FriPcs::prove()` method to match `gen_proof.hpp` transcript operations exactly, then replace the FRI section in `gen_proof.hpp` with a single `FriPcs::prove()` call.

### Technical Approach
1. **Update `FriPcs::prove()`** to match gen_proof.hpp transcript flow exactly
2. **Add dual-mode operation**: Use external trees (integration) or internal trees (standalone)
3. **Add `calculateHash()` helper** matching Starks implementation
4. **Replace FRI section in gen_proof.hpp** with FriPcs call
5. **Verify with pinning test** after every change

### Data Flow

```
BEFORE (gen_proof.hpp lines 203-268):
┌─────────────────────────────────────────────────────────────────────────┐
│ gen_proof.hpp                                                           │
│ ┌─────────────────────────────────────────────────────────────────────┐ │
│ │ starks.calculateFRIPolynomial()                                     │ │
│ │ for each step:                                                      │ │
│ │   FRI::fold()                                                       │ │
│ │   FRI::merkelize() → starks.addTranscript() → starks.getChallenge() │ │
│ │ Poseidon2GoldilocksGrinding::grinding()                             │ │
│ │ TranscriptGL permutation → FRI::proveQueries() → FRI::setFinalPol() │ │
│ └─────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘

AFTER:
┌─────────────────────────────────────────────────────────────────────────┐
│ gen_proof.hpp                                                           │
│ ┌─────────────────────────────────────────────────────────────────────┐ │
│ │ starks.calculateFRIPolynomial()                                     │ │
│ │ FriPcs friPcs(config, starks.treesFRI);  // Use Starks' trees       │ │
│ │ friPcs.prove(friPol, proof, transcript); // All FRI logic inside    │ │
│ └─────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

### Expected Outcomes
- FRI PCS is fully modular and testable in isolation
- `gen_proof.hpp` FRI section reduced from 60+ lines to ~10 lines
- Pinning test passes with identical proof output
- Future FRI improvements can be tested without full STARK context

## Goals & Objectives

### Primary Goals
- Integrate `FriPcs` into `gen_proof.hpp` with **zero proof output changes**
- Reduce FRI section in gen_proof.hpp from 65 lines to <15 lines
- Pass all pinning test checkpoints

### Secondary Objectives
- Enable standalone FRI testing without Starks context
- Document transcript flow for future maintainers
- Lay groundwork for potential Rust port

## Solution Overview

### Approach
Conservative, incremental refactoring with pinning test verification at each step:

1. **Phase 1**: Update FriPcs to match gen_proof.hpp exactly (internal changes only)
2. **Phase 2**: Add external tree injection to FriPcs
3. **Phase 3**: Replace gen_proof.hpp FRI section with FriPcs call
4. **Phase 4**: Cleanup and documentation

### Key Components

1. **`FriPcs::prove()` update**: Match transcript operations exactly
2. **`FriPcs::setExternalTrees()`**: Accept Starks' trees instead of creating new ones
3. **`FriPcs::calculateHash()`**: Static helper matching Starks implementation
4. **`gen_proof.hpp` refactor**: Replace inline FRI logic with FriPcs call

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              gen_proof.hpp                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│  Stages 1-5: Setup, commitments, quotient polynomial                        │
│                                    │                                        │
│                                    ▼                                        │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                           Stage 6: FRI                                │  │
│  │  ┌────────────────────────────────────────────────────────────────┐  │  │
│  │  │ starks.calculateFRIPolynomial(params, expressionsCtx)          │  │  │
│  │  │                         │                                      │  │  │
│  │  │                         ▼                                      │  │  │
│  │  │ FriPcsConfig config = buildConfig(setupCtx.starkInfo)          │  │  │
│  │  │ FriPcs<MerkleTreeGL> friPcs(config)                            │  │  │
│  │  │ friPcs.setExternalTrees(starks.treesFRI)  // Use existing      │  │  │
│  │  │                         │                                      │  │  │
│  │  │                         ▼                                      │  │  │
│  │  │ friPcs.prove(friPol, proof, transcript)                        │  │  │
│  │  │                         │                                      │  │  │
│  │  │      ┌──────────────────┼──────────────────┐                   │  │  │
│  │  │      ▼                  ▼                  ▼                   │  │  │
│  │  │  FRI::fold()     FRI::merkelize()   FRI::proveQueries()        │  │  │
│  │  │      │                  │                  │                   │  │  │
│  │  │      └──────────────────┼──────────────────┘                   │  │  │
│  │  │                         ▼                                      │  │  │
│  │  │           proof populated, nonce set                           │  │  │
│  │  └────────────────────────────────────────────────────────────────┘  │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                    │                                        │
│                                    ▼                                        │
│  Stage 7: Finalize proof, serialize                                         │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Implementation Tasks

### CRITICAL IMPLEMENTATION RULES
1. **PINNING TEST AFTER EVERY CHANGE**: Run `./test_pinning.sh` after each task
2. **NO PROOF OUTPUT CHANGES**: Any pinning test failure = immediate rollback
3. **TRANSCRIPT OPERATIONS MUST BE IDENTICAL**: Byte-for-byte same as gen_proof.hpp
4. **PRESERVE EXISTING BEHAVIOR**: This is refactoring, not new features

### Visual Dependency Tree

```
pil2-stark/src/
├── starkpil/
│   ├── fri/
│   │   ├── fri_pcs_types.hpp    (existing - no changes needed)
│   │   ├── fri_pcs.hpp          (Task #1, #2, #3: Update prove(), add helpers)
│   │   └── fri.hpp              (existing - no changes needed)
│   │
│   ├── gen_proof.hpp            (Task #4: Replace FRI section with FriPcs)
│   └── starks.hpp               (reference only - no changes)
│
└── goldilocks/
    └── tests/
        └── fri_pcs_tests.cpp    (Task #5: Add integration test)
```

### Execution Plan

#### Group A: FriPcs Updates (Execute sequentially - each builds on previous)

- [x] **Task #1**: Add `calculateHash()` static method to FriPcs
  - **File**: `pil2-stark/src/starkpil/fri/fri_pcs.hpp`
  - **Location**: Add after `derive_query_indices()` method (around line 110)
  - **Implements**:
    ```cpp
    /**
     * Static helper: Calculate hash of data using temporary transcript
     * Matches Starks::calculateHash() exactly
     *
     * @param hash Output buffer (HASH_SIZE elements)
     * @param buffer Input data
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
    ) {
        TranscriptGL transcriptHash(transcript_arity, merkle_tree_custom);
        transcriptHash.put(buffer, n_elements);
        transcriptHash.getState(hash);
    }
    ```
  - **Why**: Matches `starks.calculateHash()` for `hashCommits` mode
  - **Pinning Test**: Run after - should pass (no integration yet)

- [x] **Task #2**: Add `setExternalTrees()` method to FriPcs
  - **File**: `pil2-stark/src/starkpil/fri/fri_pcs.hpp`
  - **Changes**:
    1. Add private member: `bool use_external_trees_ = false;`
    2. Add public method after constructor:
    ```cpp
    /**
     * Use externally-owned Merkle trees instead of creating new ones
     * This allows integration with Starks which owns the trees
     *
     * @param external_trees Array of tree pointers (owned by caller)
     * @param num_trees Number of trees (must match config.num_steps() - 1)
     */
    void setExternalTrees(MerkleTreeType** external_trees, uint64_t num_trees) {
        if (num_trees != config_.num_steps() - 1) {
            throw std::runtime_error("FriPcs: external tree count mismatch");
        }
        use_external_trees_ = true;
        // Clear owned trees
        trees_fri_.clear();
        if (trees_fri_raw_) {
            delete[] trees_fri_raw_;
        }
        // Use external trees
        trees_fri_raw_ = external_trees;
    }
    ```
    3. Update `initialize_trees()` to check `use_external_trees_` flag
    4. Update destructor to NOT delete `trees_fri_raw_` if external
  - **Why**: Allows FriPcs to use Starks' existing trees, avoiding memory duplication
  - **Pinning Test**: Run after - should pass (no integration yet)

- [x] **Task #3**: Rewrite `FriPcs::prove()` to match gen_proof.hpp exactly
  - **File**: `pil2-stark/src/starkpil/fri/fri_pcs.hpp`
  - **Current signature**: `void prove(Goldilocks::Element* polynomial, Goldilocks::Element* challenges, FRIProof<Goldilocks::Element>& proof, TranscriptGL& transcript)`
  - **New signature**:
    ```cpp
    /**
     * Generate FRI proof - matches gen_proof.hpp FRI section exactly
     *
     * @param polynomial Polynomial in evaluation form (modified in-place)
     * @param proof FRIProof structure to populate
     * @param transcript Main proof transcript (modified)
     * @param nTrees Number of stage trees for proveQueries
     * @param stageTrees Stage Merkle trees for proveQueries (may be nullptr if nTrees=0)
     */
    void prove(
        Goldilocks::Element* polynomial,
        FRIProof<Goldilocks::Element>& proof,
        TranscriptGL& transcript,
        uint64_t nTrees,
        MerkleTreeType** stageTrees
    );
    ```
  - **Implementation** (must match gen_proof.hpp lines 214-260 exactly):
    ```cpp
    template <typename MerkleTreeType>
    void FriPcs<MerkleTreeType>::prove(
        Goldilocks::Element* polynomial,
        FRIProof<Goldilocks::Element>& proof,
        TranscriptGL& transcript,
        uint64_t nTrees,
        MerkleTreeType** stageTrees)
    {
        Goldilocks::Element challenge[FIELD_EXTENSION];
        Goldilocks::Element* friPol = polynomial;

        // FRI Folding loop - matches gen_proof.hpp lines 216-238
        uint64_t nBitsExt = config_.fri_steps[0];
        for (uint64_t step = 0; step < config_.num_steps(); step++) {
            uint64_t currentBits = config_.fri_steps[step];
            uint64_t prevBits = step == 0 ? currentBits : config_.fri_steps[step - 1];

            FRI<Goldilocks::Element>::fold(step, friPol, challenge, nBitsExt, prevBits, currentBits);

            if (step < config_.num_steps() - 1) {
                uint64_t nextBits = config_.fri_steps[step + 1];
                FRI<Goldilocks::Element>::merkelize(step, proof, friPol, trees_fri_raw_[step], currentBits, nextBits);
                transcript.put(&proof.proof.fri.treesFRI[step].root[0], HASH_SIZE);
            } else {
                // Last step - add final polynomial to transcript
                uint64_t finalPolySize = (1ULL << currentBits) * FIELD_EXTENSION;
                if (!config_.hash_commits) {
                    transcript.put(friPol, finalPolySize);
                } else {
                    Goldilocks::Element hash[HASH_SIZE];
                    calculateHash(hash, friPol, finalPolySize, config_.transcript_arity, config_.merkle_tree_custom);
                    transcript.put(hash, HASH_SIZE);
                }
            }
            transcript.getField((uint64_t*)challenge);
        }

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

        // Set nonce - matches gen_proof.hpp line 268
        proof.proof.setNonce(nonce);
    }
    ```
  - **Critical**: Every transcript operation must be identical to gen_proof.hpp
  - **Pinning Test**: Run after - should pass (no integration yet)

---

#### Group B: Integration (Execute after Group A passes pinning test)

- [x] **Task #4**: Replace FRI section in gen_proof.hpp with FriPcs
  - **File**: `pil2-stark/src/starkpil/gen_proof.hpp`
  - **Add include** at top (around line 1):
    ```cpp
    #include "fri/fri_pcs.hpp"
    ```
  - **Replace lines 203-268** with:
    ```cpp
    //--------------------------------
    // 6. Compute FRI
    //--------------------------------
    TimerStart(STARK_STEP_FRI);

    TimerStart(COMPUTE_FRI_POLYNOMIAL);
    starks.calculateFRIPolynomial(params, expressionsCtx);
    TimerStopAndLog(COMPUTE_FRI_POLYNOMIAL);

    // Build FriPcsConfig from StarkInfo
    FriPcsConfig friConfig;
    friConfig.n_bits_ext = setupCtx.starkInfo.starkStruct.steps[0].nBits;
    for (const auto& step : setupCtx.starkInfo.starkStruct.steps) {
        friConfig.fri_steps.push_back(step.nBits);
    }
    friConfig.n_queries = setupCtx.starkInfo.starkStruct.nQueries;
    friConfig.merkle_arity = setupCtx.starkInfo.starkStruct.merkleTreeArity;
    friConfig.pow_bits = setupCtx.starkInfo.starkStruct.powBits;
    friConfig.last_level_verification = setupCtx.starkInfo.starkStruct.lastLevelVerification;
    friConfig.hash_commits = setupCtx.starkInfo.starkStruct.hashCommits;
    friConfig.transcript_arity = setupCtx.starkInfo.starkStruct.transcriptArity;
    friConfig.merkle_tree_custom = setupCtx.starkInfo.starkStruct.merkleTreeCustom;

    // Create FriPcs and use Starks' existing trees
    TimerStart(STARK_FRI_FOLDING);
    FriPcs<MerkleTreeGL> friPcs(friConfig);
    friPcs.setExternalTrees(starks.treesFRI, setupCtx.starkInfo.starkStruct.steps.size() - 1);

    // Get FRI polynomial pointer
    Goldilocks::Element* friPol = &params.aux_trace[setupCtx.starkInfo.mapOffsets[std::make_pair("f", true)]];

    // Number of stage trees for query proofs
    uint64_t nTrees = setupCtx.starkInfo.nStages + setupCtx.starkInfo.customCommits.size() + 2;

    // Run FRI proving
    friPcs.prove(friPol, proof, transcript, nTrees, starks.treesGL);
    TimerStopAndLog(STARK_FRI_FOLDING);

    TimerStopAndLog(STARK_STEP_FRI);

    proof.proof.setEvals(params.evals);
    proof.proof.setAirgroupValues(params.airgroupValues);
    proof.proof.setAirValues(params.airValues);
    ```
  - **Lines removed**: 214-268 (55 lines)
  - **Lines added**: ~35 lines
  - **Net reduction**: ~20 lines, much cleaner organization
  - **Pinning Test**: Run IMMEDIATELY after - **MUST PASS**

---

#### Group C: Verification & Cleanup (Execute after Task #4 passes pinning test)

- [x] **Task #5**: Add integration test to fri_pcs_tests.cpp
  - **File**: `pil2-stark/src/goldilocks/tests/fri_pcs_tests.cpp`
  - **Add test**:
    ```cpp
    // ===========================================================================
    // Test: FriPcs configuration from StarkStruct-like parameters
    // ===========================================================================
    TEST(FRI_PCS_TEST, config_from_stark_params) {
        // Simulate StarkStruct parameters from a real proof
        FriPcsConfig config;
        config.n_bits_ext = 17;  // Typical extended domain
        config.fri_steps = {17, 14, 11, 8, 5};  // Typical FRI step sequence
        config.n_queries = 64;
        config.merkle_arity = 2;
        config.pow_bits = 20;
        config.last_level_verification = 1;
        config.hash_commits = false;
        config.transcript_arity = 16;
        config.merkle_tree_custom = false;

        EXPECT_TRUE(config.is_valid());
        EXPECT_EQ(config.num_steps(), 5u);
        EXPECT_EQ(config.final_poly_size(), 32u);  // 2^5 = 32
    }

    // ===========================================================================
    // Test: FriPcs external tree injection
    // ===========================================================================
    TEST(FRI_PCS_TEST, external_tree_injection) {
        FriPcsConfig config;
        config.n_bits_ext = 4;
        config.fri_steps = {4, 2};  // 2 steps, 1 tree
        config.n_queries = 2;
        config.merkle_arity = 2;
        config.pow_bits = 0;
        config.last_level_verification = 0;
        config.hash_commits = false;
        config.transcript_arity = 16;
        config.merkle_tree_custom = false;

        // Create a mock external tree
        MerkleTreeGL* externalTree = new MerkleTreeGL(2, 0, false, 4, 12, true, true);
        MerkleTreeGL* trees[1] = { externalTree };

        FriPcs<MerkleTreeGL> pcs(config);

        // Should not throw
        EXPECT_NO_THROW(pcs.setExternalTrees(trees, 1));

        delete externalTree;
    }
    ```
  - **Purpose**: Verify FriPcs API works correctly
  - **Pinning Test**: Run after - should pass

- [x] **Task #6**: Update plan file checkboxes and add completion notes
  - **File**: `ai_plans/fri-pcs-modularization.md`
  - **Changes**:
    - Mark Task #4 as `[x]` (no longer deferred)
    - Update "STATUS: DEFERRED" section to "STATUS: COMPLETE"
    - Add completion timestamp and verification notes
  - **Pinning Test**: Final run to confirm everything works

---

## Implementation Workflow

This plan file serves as the authoritative checklist for implementation. When implementing:

### Required Process
1. **Load Plan**: Read this entire plan file before starting
2. **Sync Tasks**: Create TodoWrite tasks matching the checkboxes above
3. **Execute & Update**: For each task:
   - Mark TodoWrite as `in_progress` when starting
   - Run `./test_pinning.sh` after completing
   - Update checkbox `[ ]` to `[x]` when pinning test passes
   - Mark TodoWrite as `completed` when done
4. **Maintain Sync**: Keep this file and TodoWrite synchronized throughout

### Critical Rules
- **PINNING TEST IS MANDATORY** after every task
- If pinning test fails, **STOP AND ROLLBACK** before proceeding
- Task #4 is the highest-risk change - verify carefully
- Never mark Task #4 complete until pinning test passes
- Tasks #1-3 can be done in parallel (independent changes)
- Task #4 depends on Tasks #1-3 completing
- Tasks #5-6 depend on Task #4 completing

### Pinning Test Checkpoints

| Checkpoint | After Task | Purpose |
|------------|------------|---------|
| **CP-A1** | Task #1 | Verify calculateHash() doesn't break anything |
| **CP-A2** | Task #2 | Verify setExternalTrees() doesn't break anything |
| **CP-A3** | Task #3 | Verify prove() rewrite doesn't break anything |
| **CP-B** | Task #4 | **CRITICAL**: Verify integration produces identical proofs |
| **CP-C** | Task #5 | Verify new tests don't affect build |
| **CP-FINAL** | Task #6 | Final verification |

### Progress Tracking
The checkboxes above represent the authoritative status of each task. Keep them updated as you work.

## Appendix: Transcript Operation Mapping

| gen_proof.hpp | FriPcs equivalent | Notes |
|---------------|-------------------|-------|
| `starks.addTranscript(transcript, data, size)` | `transcript.put(data, size)` | Direct replacement |
| `starks.addTranscriptGL(transcript, data, size)` | `transcript.put(data, size)` | Direct replacement |
| `starks.getChallenge(transcript, challenge)` | `transcript.getField((uint64_t*)&challenge)` | Direct replacement |
| `starks.calculateHash(hash, data, size)` | `FriPcs::calculateHash(hash, data, size, arity, custom)` | New static method |

## Appendix: Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Transcript state differs after changes | Low | Critical | Pinning test catches immediately |
| Memory leak from tree ownership | Medium | Low | RAII with unique_ptr, clear ownership |
| Performance regression | Low | Medium | Timer macros preserved, can compare |
| Build breaks from include cycles | Low | Low | fri_pcs.hpp is standalone |

---

## Implementation Complete

### Completion Date: 2026-01-08

### Summary
All tasks completed successfully. The FRI PCS modularization is now fully integrated into `gen_proof.hpp`.

### Verification Results
- **CP-A (Group A)**: PASSED - FriPcs updates don't affect proof output
- **CP-B (Integration)**: PASSED - gen_proof.hpp integration produces identical proofs
- **CP-FINAL**: PASSED - All changes verified with pinning test

### Key Outcomes
1. **FRI section reduced**: gen_proof.hpp FRI section reduced from ~55 lines to ~25 lines
2. **Modular design**: FriPcs can now be tested independently of full STARK context
3. **External tree injection**: FriPcs supports both standalone and integrated modes
4. **Zero regression**: Pinning test confirms byte-for-byte identical proof output

### Files Changed
- `pil2-stark/src/starkpil/fri/fri_pcs.hpp` - Updated with prove(), calculateHash(), setExternalTrees()
- `pil2-stark/src/starkpil/gen_proof.hpp` - Replaced FRI section with FriPcs call
- `pil2-stark/src/goldilocks/tests/fri_pcs_tests.cpp` - Added integration tests
- `pil2-stark/src/rapidsnark/binfile_utils.hpp` - Fixed missing `#include <cstdint>` (pre-existing bug)
- `pil2-stark/src/rapidsnark/binfile_writer.hpp` - Fixed missing `#include <cstdint>` (pre-existing bug)

### Notes
- The rapidsnark header fixes were for a pre-existing bug unrelated to FRI PCS changes
- Timer markers STARK_FRI_FOLDING and STARK_FRI_QUERIES were consolidated into STARK_STEP_FRI
- The integration uses external trees from Starks to avoid memory duplication
