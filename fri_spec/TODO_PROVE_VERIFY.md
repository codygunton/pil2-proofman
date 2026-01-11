# FRI Prove/Verify Testing TODO

## Current State

The Python FRI implementation has been verified to produce **byte-identical output** to C++ for all core components:

| Component | Status | Test |
|-----------|--------|------|
| FRI.fold() | Verified | `test_fri_folding_step_*`, `test_exhaustive_fri_pipeline` |
| Polynomial hashes | Verified | `test_intermediate_polynomial_hashes` |
| Merkle roots | Verified | `test_merkle_roots_match_cpp` |
| Transcript challenges | Verified | `test_challenge_generation_matches_cpp` |
| Final polynomial | Verified | `test_final_polynomial_matches_expected` |
| Grinding nonce | Verified | `test_grinding_nonce_valid` |

## What Remains

### 1. FriPcs.prove() End-to-End Test

The `FriPcs.prove()` method orchestrates the full FRI proving flow but is not tested end-to-end. Need to:

1. **Capture full proof structure from C++**
   - Merkle proofs for each query
   - Query indices derived from grinding
   - Complete FRIProof structure

2. **Test Python FriPcs.prove() produces identical proof**
   ```python
   def test_fri_pcs_prove_matches_cpp():
       # Load input polynomial and transcript state
       # Initialize FriPcs with same config as C++
       # Run prove() and compare:
       #   - proof.trees (Merkle proofs)
       #   - proof.queries (query indices)
       #   - proof.final_pol
       #   - proof.nonce
   ```

3. **Required C++ captures** (add to `fri_pcs.hpp`):
   ```cpp
   #ifdef CAPTURE_FRI_VECTORS
   // Already captured:
   // - fri_input_polynomial, challenges, merkle_roots, poly_hashes
   // - transcript_state

   // Need to add:
   // - friQueries[] (query indices after grinding)
   // - Merkle proof paths for each query
   #endif
   ```

### 2. FriPcs.verify() Implementation and Test

The verifier is not yet implemented. Need to:

1. **Implement FriPcs.verify()** in `fri_pcs.py`:
   ```python
   def verify(self, proof: FriProof, transcript: Transcript) -> bool:
       # 1. Verify Merkle roots match transcript flow
       # 2. Derive query indices from grinding
       # 3. For each query:
       #    - Verify Merkle proof for each FRI step
       #    - Verify fold consistency (FRI.verify_fold)
       # 4. Verify final polynomial evaluation
       return True/False
   ```

2. **Test verify accepts valid proof**:
   ```python
   def test_fri_pcs_verify_accepts_valid_proof():
       # Load C++ generated proof
       # Run Python verify()
       # Assert returns True
   ```

3. **Test verify rejects corrupted proof**:
   ```python
   def test_fri_pcs_verify_rejects_corrupted_proof():
       # Load valid proof, corrupt one value
       # Assert verify() returns False
   ```

### 3. Query Index Derivation Test

Query indices are derived from grinding challenge + nonce via transcript permutations:

```python
def test_query_indices_match_cpp():
    # Capture friQueries[] from C++
    # Initialize transcript with grinding challenge + nonce
    # Call transcript.get_permutations(n_queries, n_bits_ext)
    # Compare to C++ friQueries[]
```

### 4. Merkle Proof Generation/Verification Test

```python
def test_merkle_proof_generation():
    # Build tree from polynomial (already tested via root comparison)
    # Generate proof for specific indices
    # Verify proof reconstructs correct root

def test_merkle_proof_matches_cpp():
    # Capture Merkle proofs from C++ for specific queries
    # Generate same proofs in Python
    # Compare byte-for-byte
```

## Implementation Order

1. **Query indices** - Quick win, just capture and compare
2. **Merkle proof generation** - Already have tree, just need proof extraction
3. **FriPcs.verify()** - Implement based on C++ `FRI::verify_fold`
4. **FriPcs.prove() end-to-end** - Full integration test

## C++ Capture Additions Needed

Add to `fri_pcs.hpp` under `#ifdef CAPTURE_FRI_VECTORS`:

```cpp
// After grinding, capture query indices
std::cerr << "constexpr std::array<uint64_t, " << config_.n_queries
          << "> FRI_QUERIES = {\n";
for (uint64_t i = 0; i < config_.n_queries; i++) {
    std::cerr << "    " << friQueries[i] << "ULL";
    if (i < config_.n_queries - 1) std::cerr << ",";
    std::cerr << "\n";
}
std::cerr << "};\n";
```

## Success Criteria

When complete, running `python -m pytest fri_spec/` should verify:
- Python can generate a proof identical to C++
- Python can verify a C++-generated proof
- Python can detect corrupted proofs
