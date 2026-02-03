# Verifier E2E Test Implementation Plan

## Executive Summary

### Problem Statement
The Python verifier implementation (`executable-spec/protocol/verifier.py`) has four placeholder Merkle verification functions that simply return `True` without performing actual verification:
- `_verify_stage_merkle_tree()`
- `_verify_constant_merkle_tree()`
- `_verify_custom_commit_merkle_tree()`
- `_verify_fri_folding_merkle_tree()`

Additionally, there is no test that exercises the `stark_verify()` function against real proofs.

### Proposed Solution
1. Implement all four Merkle verification functions following the C++ reference
2. Add a `verify_merkle_root()` static method to the MerkleTree class
3. Create an E2E test that generates a proof with the Python prover and verifies it with `stark_verify()`

### Technical Approach
- The MerkleTree class already has `verify_group_proof()` - we add root verification from last-level nodes
- All four placeholder functions follow the same pattern: parse proof data, verify root from last level, verify each query's Merkle path
- The test uses Python-generated proofs (already validated to match C++ byte-for-byte)

### Expected Outcomes
- Complete Merkle verification in Python verifier
- E2E test proving Python can verify proofs it generates
- Foundation for future cross-verification (Python verifying C++ proofs directly)

## Goals & Objectives

### Primary Goals
- Remove all placeholder implementations from verifier.py
- Create a passing E2E test for `stark_verify()`

### Secondary Objectives
- Maintain consistency with C++ implementation patterns
- Enable future testing of C++ proof binary verification

## Solution Overview

### Approach
Implement the missing Merkle verification by:
1. Adding infrastructure to MerkleTree class
2. Implementing each verification function following C++ patterns
3. Creating a test that exercises the complete verification flow

### Key Components

1. **MerkleTree.verify_merkle_root()**: Static method to verify root from last-level nodes
2. **_verify_stage_merkle_tree()**: Verify committed polynomial Merkle trees (stages 1..nStages+1)
3. **_verify_constant_merkle_tree()**: Verify constant polynomial Merkle tree
4. **_verify_custom_commit_merkle_tree()**: Verify custom commitment Merkle trees
5. **_verify_fri_folding_merkle_tree()**: Verify FRI layer Merkle trees

### Data Flow
```
stark_verify(jproof, setup_ctx, verkey, publics)
    │
    ├─→ Parse proof data (roots, evals, airvalues, etc.)
    ├─→ Reconstruct Fiat-Shamir transcript
    ├─→ Derive challenges
    ├─→ Verify proof-of-work
    ├─→ Derive FRI query indices
    │
    ├─→ _verify_evaluations()           ✓ Already implemented
    ├─→ _verify_fri_consistency()       ✓ Already implemented
    │
    ├─→ _verify_stage_merkle_tree()     ← IMPLEMENT
    ├─→ _verify_constant_merkle_tree()  ← IMPLEMENT
    ├─→ _verify_custom_commit_merkle_tree() ← IMPLEMENT
    ├─→ _verify_fri_folding_merkle_tree()   ← IMPLEMENT
    │
    ├─→ _verify_fri_folding()           ✓ Already implemented
    └─→ _verify_final_polynomial()      ✓ Already implemented
```

## Implementation Tasks

### CRITICAL IMPLEMENTATION RULES
1. **NO PLACEHOLDER CODE**: Every implementation must be production-ready
2. **FOLLOW C++ PATTERNS**: Match stark_verify.hpp logic exactly
3. **HANDLE LAST LEVEL VERIFICATION**: Support the `lastLevelVerification` optimization
4. **PARSE PROOF FORMAT CORRECTLY**: Match exact JSON key names from C++

### Visual Dependency Tree

```
executable-spec/
├── primitives/
│   └── merkle_tree.py
│       └── (Task #0: Add verify_merkle_root static method)
│
├── protocol/
│   └── verifier.py
│       ├── (Task #1: Implement _verify_stage_merkle_tree)
│       ├── (Task #1: Implement _verify_constant_merkle_tree)
│       ├── (Task #1: Implement _verify_custom_commit_merkle_tree)
│       └── (Task #1: Implement _verify_fri_folding_merkle_tree)
│
└── tests/
    └── test_verifier_e2e.py
        └── (Task #2: Create E2E verifier test)
```

### Execution Plan

#### Group A: Foundation (Execute in parallel)

- [ ] **Task #0**: Add `verify_merkle_root` static method to MerkleTree
  - Folder: `executable-spec/primitives/`
  - File: `merkle_tree.py`
  - Imports needed: `from poseidon2_ffi import hash_seq` (already imported)
  - Implements:
    ```python
    @staticmethod
    def verify_merkle_root(
        root: List[int],           # Expected root (4 elements)
        level: List[int],          # Last level nodes (num_nodes * 4 elements)
        height: int,               # Tree height (number of leaves)
        last_level_verification: int,  # Levels to skip
        arity: int,                # Tree arity (2, 3, or 4)
        sponge_width: int          # Hash sponge width
    ) -> bool:
        """Verify Merkle root from last-level nodes.

        C++ reference: merkleTreeGL.hpp lines 70-99

        Computes the root by hashing up from the last level and compares
        against the expected root.
        """
    ```
  - Logic:
    1. Calculate `num_nodes = arity ** last_level_verification`
    2. Build tree from level nodes up to root using `hash_seq`
    3. Compare computed root to expected root
  - Exports: Method on MerkleTree class
  - Context: Used by all `_verify_*_merkle_tree` functions when `lastLevelVerification > 0`

#### Group B: Merkle Verification Functions (Execute all in parallel after Group A)

- [ ] **Task #1**: Implement `_verify_stage_merkle_tree`
  - Folder: `executable-spec/protocol/`
  - File: `verifier.py`
  - C++ Reference: stark_verify.hpp lines 373-437
  - Replace placeholder at lines 717-745 with full implementation
  - Implements:
    ```python
    def _verify_stage_merkle_tree(
        jproof: Dict,
        stark_info,
        verkey: List[int],
        stage: int,              # 0-indexed (stage 1 = index 0)
        fri_queries: List[int]
    ) -> bool:
    ```
  - Logic:
    1. Get tree parameters: `arity`, `last_level_verification`, `custom`, `n_bits_ext`
    2. Get section info: `n_cols = stark_info.mapSectionsN[f"cm{stage+1}"]`
    3. Parse root from `jproof[f"root{stage+1}"]` (4 elements)
    4. Parse last level from `jproof[f"s0_last_levels{stage+1}"]` if applicable
    5. Verify root from last level using `MerkleTree.verify_merkle_root()`
    6. Calculate siblings structure:
       - `n_siblings = ceil(n_bits_ext / log2(arity)) - last_level_verification`
       - `n_siblings_per_level = (arity - 1) * HASH_SIZE`
    7. For each query q in fri_queries:
       - Parse values from `jproof[f"s0_vals{stage+1}"][q]`
       - Parse siblings from `jproof[f"s0_siblings{stage+1}"][q]`
       - Call `tree.verify_group_proof(root, siblings, fri_queries[q], values)`
  - Context: Called for each stage (0 to nStages)

- [ ] **Task #1**: Implement `_verify_constant_merkle_tree`
  - Folder: `executable-spec/protocol/`
  - File: `verifier.py`
  - C++ Reference: stark_verify.hpp lines 439-494
  - Replace placeholder at lines 748-769 with full implementation
  - Implements:
    ```python
    def _verify_constant_merkle_tree(
        jproof: Dict,
        stark_info,
        verkey: List[int],       # Root of constant tree
        fri_queries: List[int]
    ) -> bool:
    ```
  - Logic:
    1. Same tree parameters as stage verification
    2. `n_cols = stark_info.nConstants`
    3. Root is `verkey` (passed in, not from jproof)
    4. Parse last level from `jproof["s0_last_levelsC"]`
    5. Verify root from last level
    6. For each query q:
       - Parse values from `jproof["s0_valsC"][q]`
       - Parse siblings from `jproof["s0_siblingsC"][q]`
       - Verify Merkle proof
  - Context: Always called once per verification

- [ ] **Task #1**: Implement `_verify_custom_commit_merkle_tree`
  - Folder: `executable-spec/protocol/`
  - File: `verifier.py`
  - C++ Reference: stark_verify.hpp lines 496-557
  - Replace placeholder at lines 772-795 with full implementation
  - Implements:
    ```python
    def _verify_custom_commit_merkle_tree(
        jproof: Dict,
        stark_info,
        publics: np.ndarray,     # Public inputs contain custom commit roots
        commit_idx: int,         # Which custom commit
        fri_queries: List[int]
    ) -> bool:
    ```
  - Logic:
    1. Get custom commit info: `cc = stark_info.customCommits[commit_idx]`
    2. Extract root from publics: `root = [publics[cc.publicValues[j]] for j in range(4)]`
    3. Get section: `name = cc.name`, `n_cols = stark_info.mapSectionsN[f"{name}0"]`
    4. Parse last level from `jproof[f"s0_last_levels_{name}_0"]`
    5. Verify root from last level
    6. For each query q:
       - Parse values from `jproof[f"s0_vals_{name}_0"][q]`
       - Parse siblings from `jproof[f"s0_siblings_{name}_0"][q]`
       - Verify Merkle proof
  - Context: Called for each custom commit (may be 0)

- [ ] **Task #1**: Implement `_verify_fri_folding_merkle_tree`
  - Folder: `executable-spec/protocol/`
  - File: `verifier.py`
  - C++ Reference: stark_verify.hpp lines 560-623
  - Replace placeholder at lines 798-819 with full implementation
  - Implements:
    ```python
    def _verify_fri_folding_merkle_tree(
        jproof: Dict,
        stark_info,
        step: int,               # FRI step (1 to len(steps)-1)
        fri_queries: List[int]
    ) -> bool:
    ```
  - Logic:
    1. Calculate FRI dimensions:
       - `n_groups = 1 << stark_info.starkStruct.steps[step].nBits`
       - `group_size = (1 << stark_info.starkStruct.steps[step-1].nBits) // n_groups`
       - `n_cols = group_size * FIELD_EXTENSION`
    2. Parse root from `jproof[f"s{step}_root"]`
    3. Parse last level from `jproof[f"s{step}_last_levels"]`
    4. Verify root from last level
    5. Calculate adjusted siblings count for smaller tree
    6. For each query q:
       - Compute query index: `idx = fri_queries[q] % (1 << steps[step].nBits)`
       - Parse values from `jproof[f"s{step}_vals"][q]`
       - Parse siblings from `jproof[f"s{step}_siblings"][q]`
       - Verify Merkle proof with adjusted index
  - Context: Called for FRI steps 1 to len(steps)-1 (step 0 has no tree)

#### Group C: E2E Test (Execute after Group B)

- [ ] **Task #2**: Create E2E verifier test
  - Folder: `executable-spec/tests/`
  - File: `test_verifier_e2e.py` (new file)
  - Imports:
    ```python
    import pytest
    import numpy as np
    from pathlib import Path
    from protocol.verifier import stark_verify
    from protocol.setup_ctx import SetupCtx
    from protocol.prover import gen_proof
    from tests.fri_vectors import get_config
    ```
  - Implements:
    ```python
    AIR_CONFIGS = {
        "simple": {...},      # paths to setup files
        "lookup": {...},
        "permutation": {...},
    }

    @pytest.fixture
    def setup_ctx(air_name):
        """Load SetupCtx for the given AIR."""
        ...

    @pytest.fixture
    def proof_and_inputs(air_name, setup_ctx):
        """Generate proof using Python prover and return (jproof, verkey, publics)."""
        # Use existing test infrastructure to generate proof
        # Return the proof dict, verkey, and public inputs
        ...

    @pytest.mark.parametrize("air_name", ["simple", "lookup", "permutation"])
    class TestVerifierE2E:
        def test_verify_valid_proof(self, air_name, setup_ctx, proof_and_inputs):
            """Test that stark_verify returns True for valid Python-generated proofs."""
            jproof, verkey, publics = proof_and_inputs

            result = stark_verify(
                jproof=jproof,
                setup_ctx=setup_ctx,
                verkey=verkey,
                publics=publics
            )

            assert result is True, "Valid proof should verify"

        def test_verify_corrupted_proof_fails(self, air_name, setup_ctx, proof_and_inputs):
            """Test that stark_verify returns False for corrupted proofs."""
            jproof, verkey, publics = proof_and_inputs

            # Corrupt a Merkle root
            jproof_corrupted = jproof.copy()
            jproof_corrupted["root1"] = [0, 0, 0, 0]  # Invalid root

            result = stark_verify(
                jproof=jproof_corrupted,
                setup_ctx=setup_ctx,
                verkey=verkey,
                publics=publics
            )

            assert result is False, "Corrupted proof should fail verification"
    ```
  - Test data: Uses existing test vector infrastructure from `tests/fri_vectors.py`
  - Context: This is the main deliverable - proves the verifier works end-to-end

---

## Implementation Workflow

This plan file serves as the authoritative checklist for implementation. When implementing:

### Required Process
1. **Load Plan**: Read this entire plan file before starting
2. **Sync Tasks**: Create TodoWrite tasks matching the checkboxes above
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
- Run tests after completing Group B to catch issues early

### Progress Tracking
The checkboxes above represent the authoritative status of each task. Keep them updated as you work.

## Risk Assessment

### Low Risk
- **MerkleTree.verify_group_proof** already works - just need to add root verification
- **Proof format is known** - C++ implementation documents exact JSON keys

### Medium Risk
- **Last level verification complexity** - need to handle `lastLevelVerification > 0` correctly
- **Siblings parsing** - 2D array structure must match C++ exactly

### Mitigation
- Follow C++ implementation line-by-line
- Add debug logging during development
- Test each Merkle function in isolation before E2E test
