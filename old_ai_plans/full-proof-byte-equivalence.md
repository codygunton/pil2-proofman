# Full Proof Byte Equivalence Implementation Plan

## Executive Summary

### Problem Statement
The Python executable spec currently generates only ~15-20% of a complete STARK proof. It produces the header (airgroupValues, airValues, roots, evals) and footer (finalPol, nonce), but is missing the middle sections: query proofs (Merkle authentication paths) for committed polynomials and FRI folding steps.

This prevents true byte-for-byte validation against C++ proofs. The current "partial" comparison could miss bugs in query proof generation or serialization order.

### Proposed Solution
Complete the Python proof generation by implementing:
1. Merkle tree construction during polynomial commitment stages
2. Query proof generation (values + Merkle paths) for all committed trees
3. FRI query value capture at each folding step
4. Complete proof serialization matching C++ `proof2pointer()` exactly

### Technical Approach
```
Current Python Flow:
  [Stage 1 Polynomials] → [Stage 2] → [Stage Q] → [FRI Folding] → [Partial Proof]
                                                                        ↓
                                                            Header + Footer only

Target Python Flow:
  [Stage 1 Polynomials] → Merkle Tree → Root + Tree Reference
  [Stage 2 Polynomials] → Merkle Tree → Root + Tree Reference
  [Stage Q Polynomials] → Merkle Tree → Root + Tree Reference
  [FRI Folding]         → Merkle Trees per step → Roots + Tree References
  [Query Derivation]    → Query proofs from ALL trees
  [Serialization]       → Complete binary proof matching C++
```

### Data Flow: Proof Binary Layout
```
C++ proof2pointer() binary layout (sections 1-13):

┌─────────────────────────────────────────────────────────────────┐
│ HEADER (Python generates this)                                  │
├─────────────────────────────────────────────────────────────────┤
│ 1. airgroupValues    [n_airgroup × 3 elements]                  │
│ 2. airValues         [n_air × 3 elements]                       │
│ 3. roots             [(nStages+1) × 4 elements]                 │
│ 4. evals             [n_evals × 3 elements]                     │
├─────────────────────────────────────────────────────────────────┤
│ QUERY PROOFS (Python missing this - THE GAP)                    │
├─────────────────────────────────────────────────────────────────┤
│ 5. const tree values     [nQueries × nConstants]                │
│ 6. const tree siblings   [nQueries × nSiblings × sibling_size]  │
│ 7. const tree last_lvls  [arity^lastLvl × 4] (if applicable)    │
│ 8. custom commit proofs  [for each custom commit...]            │
│ 9. stage tree proofs     [for cm1, cm2, ..., cmQ...]            │
│ 10. FRI step roots       [(nSteps-1) × 4 elements]              │
│ 11. FRI step proofs      [for each step: values + siblings]     │
├─────────────────────────────────────────────────────────────────┤
│ FOOTER (Python generates this)                                  │
├─────────────────────────────────────────────────────────────────┤
│ 12. finalPol         [final_degree × 3 elements]                │
│ 13. nonce            [1 element]                                │
└─────────────────────────────────────────────────────────────────┘
```

### Expected Outcomes
- Python generates complete STARK proofs identical to C++
- `test_full_proof_matches` compares entire binary proof (not just header/footer)
- Any serialization or computation bug is caught by byte comparison
- Proof structure changes in C++ will immediately fail Python tests

## Goals & Objectives

### Primary Goals
- Generate complete STARK proofs in Python that are byte-for-byte identical to C++
- Replace partial proof comparison with full binary comparison
- Catch any proof structure or computation discrepancies

### Secondary Objectives
- Document the complete proof layout for future reference
- Create reusable Merkle tree query proof infrastructure
- Enable future verification implementation in Python

## Solution Overview

### Approach
Incrementally add missing components to the Python prover:
1. First, make Merkle tree construction produce stored trees (not just roots)
2. Add query proof extraction from stored trees
3. Integrate into FRI PCS for FRI step trees
4. Serialize complete proof
5. Test byte equivalence

### Key Components

1. **MerkleTree Query Proof API**: Add methods to extract query proofs (values + siblings) from constructed trees

2. **Starks Stage Commitment**: Modify to build and store Merkle trees, not just compute roots

3. **FriPcs Query Proofs**: Capture FRI polynomial values at query points and generate Merkle proofs

4. **Proof Serialization**: Implement `to_bytes_full()` matching C++ `proof2pointer()` exactly

5. **Test Infrastructure**: Full binary comparison test

### Architecture Changes
```
Before:
  Starks.commitStage() → hash polynomial → return root (tree discarded)
  FriPcs.prove() → fold polynomials → query proofs (incomplete)

After:
  Starks.commitStage() → build MerkleTree → store tree + return root
  FriPcs.prove() → fold polynomials → build step trees → complete query proofs
  gen_proof() → collect all trees → derive queries → extract all proofs → serialize
```

## Implementation Tasks

### CRITICAL IMPLEMENTATION RULES
1. **NO PLACEHOLDER CODE**: Every implementation must be production-ready
2. **MATCH C++ EXACTLY**: Binary output must be identical to C++ proof2pointer()
3. **PRESERVE EXISTING TESTS**: All current tests must continue passing
4. **INCREMENTAL VALIDATION**: Each phase should be testable independently

### Visual Dependency Tree

```
executable-spec/
├── primitives/
│   └── merkle_tree.py (Task #1: Add query proof extraction methods)
│
├── protocol/
│   ├── stark_info.py (no changes needed)
│   ├── stages.py (Task #2: Store Merkle trees during commitment)
│   ├── pcs.py (Task #3: Complete FRI query proof generation)
│   ├── prover.py (Task #4: Orchestrate query proof collection)
│   └── proof.py (Task #5: Implement to_bytes_full serialization)
│
└── tests/
    └── test_stark_e2e.py (Task #6: Full binary comparison test)
```

### Execution Plan

#### Group A: Foundation (Execute in parallel)

- [ ] **Task #1**: Add query proof extraction to MerkleTree
  - Folder: `executable-spec/primitives/`
  - File: `merkle_tree.py`
  - Implements:
    ```python
    class MerkleTree:
        def get_query_proof(self, query_idx: int) -> MerkleProof:
            """Extract leaf values and sibling path for a query index.

            Args:
                query_idx: Index into the leaf array

            Returns:
                MerkleProof with:
                - v: List of leaf values at query_idx (one per column)
                - mp: List of sibling hashes from leaf to root
            """

        def get_last_level_nodes(self) -> List[int]:
            """Extract last level verification nodes.

            Returns:
                List of arity^lastLevelVerification × HASH_SIZE elements
                Empty list if lastLevelVerification == 0
            """
    ```
  - Must match C++ MerkleTree::getGroupProof() behavior exactly
  - Sibling ordering: (arity - 1) × HASH_SIZE per level, bottom to top
  - Context: Used by stages and FRI PCS to generate query proofs

- [ ] **Task #1b**: Add MerkleProof dataclass
  - Folder: `executable-spec/primitives/`
  - File: `merkle_tree.py` (same file)
  - Implements:
    ```python
    @dataclass
    class MerkleProof:
        """Merkle authentication path for a query.

        Corresponds to C++ MerkleProof in proof_stark.hpp lines 39-69.
        """
        v: List[List[int]]   # Leaf values: [n_columns][1] for base field
        mp: List[List[int]]  # Sibling hashes: [n_levels][siblings_per_level]
    ```
  - Context: Returned by get_query_proof(), stored in proof structure

#### Group B: Stage Tree Storage (After Group A)

- [ ] **Task #2**: Store Merkle trees during stage commitment
  - Folder: `executable-spec/protocol/`
  - File: `stages.py`
  - Current behavior: `commitStage()` computes root, discards tree
  - New behavior: Build tree, store reference, return root
  - Implements:
    ```python
    class Starks:
        def __init__(self, ...):
            self.stage_trees: Dict[int, MerkleTree] = {}  # stage_num -> tree
            self.const_tree: Optional[MerkleTree] = None

        def commitStage(self, stage: int, params: StepsParams, ntt: NTT) -> List[int]:
            """Commit polynomials for a stage.

            Args:
                stage: Stage number (1, 2, ..., nStages+1 for Q)
                params: Contains polynomial data
                ntt: NTT instance for transforms

            Returns:
                Merkle root (4 field elements)

            Side effect:
                Stores tree in self.stage_trees[stage]
            """
            # ... existing polynomial extension code ...

            # Build Merkle tree from extended polynomials
            tree = MerkleTree(
                data=extended_pols,
                n_cols=n_stage_pols,
                arity=self.stark_info.starkStruct.merkleTreeArity,
                custom=self.stark_info.starkStruct.merkleTreeCustom
            )
            self.stage_trees[stage] = tree
            return tree.root
    ```
  - Must also handle constant polynomial tree (built during setup or first use)
  - Context: Trees needed later for query proof extraction

#### Group C: FRI Query Proofs (After Group A)

- [ ] **Task #3**: Complete FRI query proof generation
  - Folder: `executable-spec/protocol/`
  - File: `pcs.py`
  - Current: `FriPcs.prove()` generates FRI roots and partial query structure
  - New: Capture values at query points, generate complete Merkle proofs
  - Implements:
    ```python
    class FriPcs:
        def prove(self, fri_pol: np.ndarray, transcript: Transcript) -> FriProof:
            # ... existing folding code ...

            # Store trees for each FRI step
            self.step_trees: List[MerkleTree] = []

            for step in range(1, n_steps):
                # Fold polynomial
                folded_pol = self._fold_polynomial(current_pol, challenge)

                # Build Merkle tree for this step
                tree = MerkleTree(
                    data=folded_pol,
                    n_cols=n_fri_cols,
                    arity=self.arity,
                    custom=self.custom
                )
                self.step_trees.append(tree)

                # Add root to transcript
                transcript.put(tree.root)

            # Derive query indices
            query_indices = self._derive_query_indices(transcript)

            # Generate query proofs for each step
            fri_query_proofs = []
            for step_idx, tree in enumerate(self.step_trees):
                step_proofs = []
                for q_idx in query_indices:
                    # Adjust query index for this step's domain size
                    adjusted_idx = self._adjust_query_index(q_idx, step_idx)
                    proof = tree.get_query_proof(adjusted_idx)
                    step_proofs.append(proof)
                fri_query_proofs.append(step_proofs)

            return FriProof(
                trees_fri=[ProofTree(root=t.root, ...) for t in self.step_trees],
                pol=final_pol,
                nonce=nonce,
                query_proofs=fri_query_proofs,
                query_indices=query_indices,  # Needed for stage tree queries
            )
    ```
  - FRI values at query: `2^(prev_bits - curr_bits) × FIELD_EXTENSION` per query
  - Query index adjustment: `q_idx >> (step_bits_reduction)` per step
  - Context: Complete FRI proof structure matching C++

#### Group D: Proof Assembly (After Groups B and C)

- [ ] **Task #4**: Orchestrate complete query proof collection
  - Folder: `executable-spec/protocol/`
  - File: `prover.py`
  - Modify `gen_proof()` to collect query proofs from all trees
  - Implements:
    ```python
    def gen_proof(setup_ctx, params, transcript, captured_roots, ...):
        # ... existing stage commitment code ...

        # After FRI proves (which derives query indices):
        query_indices = fri_proof.query_indices

        # Collect stage tree query proofs
        stage_query_proofs = {}  # stage_num -> List[MerkleProof]
        for stage_num, tree in starks.stage_trees.items():
            stage_proofs = []
            for q_idx in query_indices:
                proof = tree.get_query_proof(q_idx)
                stage_proofs.append(proof)
            stage_query_proofs[stage_num] = stage_proofs

        # Collect constant tree query proofs
        const_query_proofs = []
        if starks.const_tree:
            for q_idx in query_indices:
                proof = starks.const_tree.get_query_proof(q_idx)
                const_query_proofs.append(proof)

        # Return complete proof
        return {
            'evals': params.evals[:n_evals],
            'airgroup_values': params.airgroupValues,
            'air_values': params.airValues,
            'nonce': fri_proof.nonce,
            'fri_proof': fri_proof,
            'roots': roots,
            'stage_query_proofs': stage_query_proofs,
            'const_query_proofs': const_query_proofs,
            'query_indices': query_indices,
        }
    ```
  - Context: Complete proof dict for serialization

- [ ] **Task #5**: Implement complete proof serialization
  - Folder: `executable-spec/protocol/`
  - File: `proof.py`
  - Implement `to_bytes_full()` matching C++ `proof2pointer()` exactly
  - Implements:
    ```python
    def to_bytes_full(proof_dict: Dict[str, Any], stark_info: Any) -> bytes:
        """Serialize complete proof to binary matching C++ proof2pointer().

        Args:
            proof_dict: Complete proof from gen_proof()
            stark_info: StarkInfo configuration

        Returns:
            bytes: Little-endian packed uint64 array identical to C++

        Raises:
            ValueError: If proof is incomplete (missing query proofs)
        """
        import struct
        values = []

        # SECTION 1: airgroupValues
        for i in range(len(stark_info.airgroupValuesMap)):
            values.extend(proof_dict['airgroup_values'][i*3:(i+1)*3])

        # SECTION 2: airValues
        for i in range(len(stark_info.airValuesMap)):
            values.extend(proof_dict['air_values'][i*3:(i+1)*3])

        # SECTION 3: roots
        for root in proof_dict['roots']:
            values.extend(root[:HASH_SIZE])

        # SECTION 4: evals
        for i in range(len(stark_info.evMap)):
            values.extend(proof_dict['evals'][i*3:(i+1)*3])

        # SECTION 5-7: constant tree query proofs
        _serialize_tree_queries(values, proof_dict['const_query_proofs'],
                                stark_info.nConstants, stark_info, ...)

        # SECTION 8: custom commits (iterate over customCommits)
        for custom in stark_info.customCommits:
            _serialize_tree_queries(values, ...)

        # SECTION 9: stage tree query proofs (cm1, cm2, ..., cmQ)
        for stage in range(1, stark_info.nStages + 2):
            stage_proofs = proof_dict['stage_query_proofs'].get(stage, [])
            _serialize_tree_queries(values, stage_proofs, ...)

        # SECTION 10: FRI step roots
        for tree in proof_dict['fri_proof'].trees_fri:
            values.extend(tree.root[:HASH_SIZE])

        # SECTION 11: FRI step query proofs
        for step_idx, step_proofs in enumerate(proof_dict['fri_proof'].query_proofs):
            _serialize_fri_step_queries(values, step_proofs, step_idx, stark_info)

        # SECTION 12: finalPol
        final_pol = proof_dict['fri_proof'].final_pol
        for i in range(0, len(final_pol), FIELD_EXTENSION):
            values.extend(final_pol[i:i+FIELD_EXTENSION])

        # SECTION 13: nonce
        values.append(proof_dict['nonce'])

        return struct.pack(f'<{len(values)}Q', *values)


    def _serialize_tree_queries(values: List[int], query_proofs: List[MerkleProof],
                                 n_cols: int, stark_info: Any, ...):
        """Serialize query proofs for a single tree type.

        Order: all query values, then all Merkle paths, then last levels
        """
        n_queries = stark_info.starkStruct.nQueries

        # First: all leaf values for all queries
        for q_idx in range(n_queries):
            proof = query_proofs[q_idx]
            for col in range(n_cols):
                values.append(proof.v[col][0])  # Base field value

        # Second: all Merkle siblings for all queries
        for q_idx in range(n_queries):
            proof = query_proofs[q_idx]
            for level in proof.mp:
                values.extend(level)

        # Third: last level nodes (if applicable)
        if stark_info.starkStruct.lastLevelVerification > 0:
            # Extract from first query proof or separate storage
            values.extend(...)
    ```
  - Order is critical: C++ serializes all values, then all paths, then last levels
  - Context: Final step before byte comparison

#### Group E: Testing (After Group D)

- [ ] **Task #6**: Add full binary comparison test
  - Folder: `executable-spec/tests/`
  - File: `test_stark_e2e.py`
  - Replace partial comparison with full comparison in `test_full_proof_matches`
  - Implements:
    ```python
    def test_full_proof_matches(self, air_name):
        # ... existing setup code ...

        proof = gen_proof(setup_ctx, params, transcript=transcript,
                         captured_roots=captured_roots)

        # Add root1 for complete proof
        if 'root1' in intermediates:
            proof['roots'] = [intermediates['root1']] + proof['roots']

        # ... existing field-by-field checks ...

        # FULL BINARY COMPARISON (replaces partial)
        config = AIR_CONFIGS.get(air_name)
        bin_filename = config['test_vector'].replace('.json', '.proof.bin')
        bin_path = TEST_DATA_DIR / bin_filename

        if not bin_path.exists():
            pytest.fail(f"Binary proof file not found: {bin_path}")

        with open(bin_path, 'rb') as f:
            cpp_proof_bytes = f.read()

        # Full serialization (not partial!)
        from protocol.proof import to_bytes_full
        python_proof_bytes = to_bytes_full(proof, stark_info)

        # Byte-for-byte comparison
        if python_proof_bytes != cpp_proof_bytes:
            # Find first difference for debugging
            import struct
            cpp_vals = struct.unpack(f'<{len(cpp_proof_bytes)//8}Q', cpp_proof_bytes)
            py_vals = struct.unpack(f'<{len(python_proof_bytes)//8}Q', python_proof_bytes)

            if len(cpp_vals) != len(py_vals):
                mismatches.append(
                    f"proof_bytes: length mismatch "
                    f"(cpp={len(cpp_vals)} uint64s, py={len(py_vals)} uint64s)"
                )
            else:
                first_diff = next((i for i in range(len(cpp_vals))
                                   if cpp_vals[i] != py_vals[i]), -1)
                mismatches.append(
                    f"proof_bytes: mismatch at uint64[{first_diff}] "
                    f"(cpp={cpp_vals[first_diff]}, py={py_vals[first_diff]})"
                )

        assert not mismatches, f"Proof mismatches:\n" + "\n".join(f"  - {m}" for m in mismatches)
    ```
  - Test must fail if proofs don't match exactly
  - Context: Final validation that Python matches C++

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
- Tasks in the same group can run in parallel using subtasks

### Testing Strategy
1. After Task #1: Unit test MerkleTree.get_query_proof() against known values
2. After Task #2: Verify stage roots still match C++ captured roots
3. After Task #3: Compare FRI query proof structure with C++ (may need debug output)
4. After Task #5: Compare serialized bytes section-by-section
5. After Task #6: Full byte equivalence test must pass

### Progress Tracking
The checkboxes above represent the authoritative status of each task. Keep them updated as you work.

---

## Appendix: C++ Reference

### proof2pointer() Section Boundaries (proof_stark.hpp lines 235-378)

```cpp
// Section 1-4: Header
p = 0
for airgroupValue: p += FIELD_EXTENSION
for airValue: p += FIELD_EXTENSION
for root: p += HASH_SIZE
for eval: p += FIELD_EXTENSION

// Section 5-7: Constant tree
for query: for col: p += 1 (leaf values)
for query: for level: p += (arity-1)*HASH_SIZE (siblings)
if lastLevelVerification: p += arity^llv * HASH_SIZE

// Section 8: Custom commits (same pattern as const tree)

// Section 9: Stage trees cm1..cmQ (same pattern)

// Section 10: FRI roots
for step 1..n-1: p += HASH_SIZE

// Section 11: FRI query proofs
for step 1..n-1:
  n_vals = 2^(prev_bits - curr_bits) * FIELD_EXTENSION
  for query: for val: p += 1
  for query: for level: p += (arity-1)*HASH_SIZE
  if lastLevelVerification: p += arity^llv * HASH_SIZE

// Section 12-13: Footer
for final_pol_coef: p += FIELD_EXTENSION
p += 1 (nonce)
```

### Key Constants
- FIELD_EXTENSION = 3 (Goldilocks cubic extension)
- HASH_SIZE = 4 (Poseidon2 output size)
- Arity typically = 16 (Merkle tree branching factor)
- lastLevelVerification typically = 0 or 1
