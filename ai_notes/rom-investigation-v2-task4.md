# Task #4 Findings: Custom Commit Merkle Verification Comparison

## Executive Summary

The C++ verifier **does fully verify custom commit Merkle trees** for GL (Goldilocks)
mode. The previous hypothesis that "C++ JSON verifier masks this by skipping custom
commit Merkle verification" is **FALSE**. Both C++ and Python use `nFieldElements=4`
(= HASH_SIZE) for GL mode, and both perform full Merkle verification including
last-level verification, query proof verification, and root verification.

The two implementations are structurally identical in their Merkle verification logic
for custom commits. If the Merkle verification fails in Python, it would also fail in
C++ -- unless the proof data being fed to each verifier differs (binary vs JSON format).

## Detailed Comparison

### 1. nFieldElements / HASH_SIZE

**C++ (stark_verify.hpp line 31):**
```cpp
uint64_t nFieldElements = starkInfo.starkStruct.verificationHashType == std::string("BN128") ? 1 : HASH_SIZE;
```
Where `HASH_SIZE = 4` (defined in `fri/fri_pcs_types.hpp` line 16).

**Python (primitives/merkle_tree.py line 11):**
```python
HASH_SIZE = 4
```
Used directly wherever C++ uses `nFieldElements` in GL mode.

**Conclusion:** Both use 4. The previous hypothesis about nFieldElements=1 was wrong -- that only applies to BN128 mode, which Zisk does not use. Rom's starkinfo confirms `verificationHashType: "GL"`.

### 2. Root Loading from Publics

**C++ (stark_verify.hpp lines 501-505):**
```cpp
ElementType root[nFieldElements];
ElementType level[nFieldElements * numNodesLevel];
for(uint64_t j = 0; j < nFieldElements; ++j) {
    root[j] = fromString<ElementType>(Goldilocks::toString(publics[starkInfo.customCommits[c].publicValues[j]]));
}
```
This loads 4 elements (`nFieldElements=4` for GL) from `publics` using indices from `customCommits[c].publicValues`.

**Python (protocol/verifier.py lines 142-144):**
```python
for custom_commit in stark_info.custom_commits:
    root = [int(publics[custom_commit.public_values[j]]) for j in range(HASH_SIZE)]
```
This loads 4 elements (`HASH_SIZE=4`) from `publics` using the same indices.

**Rom's publicValues (from starkinfo JSON):**
```json
"publicValues": [{"idx": 0}, {"idx": 1}, {"idx": 2}, {"idx": 3}]
```
So both load `publics[0], publics[1], publics[2], publics[3]`.

**Python parsing (protocol/stark_info.py line 172):**
```python
c.public_values = [pv["idx"] for pv in c_data.get("publicValues", [])]
```

**C++ parsing (stark_info.cpp line 80):**
```cpp
c.publicValues.push_back(j["customCommits"][i]["publicValues"][k]["idx"]);
```

**Conclusion:** IDENTICAL. Both load 4 root elements from publics[0..3]. The `publicValues` array has exactly 4 entries for Rom, matching HASH_SIZE/nFieldElements.

### 3. Last-Level Verification

**C++ (stark_verify.hpp lines 518-524):**
```cpp
if (starkInfo.starkStruct.lastLevelVerification > 0) {
    bool isValidRoot = MerkleTreeType::verifyMerkleRoot(root, level,
        1 << starkInfo.starkStruct.nBitsExt,
        starkInfo.starkStruct.lastLevelVerification,
        starkInfo.starkStruct.merkleTreeArity, nFieldElements);
    if (!isValidRoot) { ... isValid = false; }
}
```

**Python (primitives/merkle_verifier.py lines 280-304):**
```python
def _verify_last_level_once(self) -> bool:
    ...
    height = 1 << self.config.domain_bits
    result = MerkleTree.verify_merkle_root(
        self.root, self._last_level_nodes, height,
        self.config.last_level_verification,
        self.config.arity, self.config.sponge_width,
    )
```

Both verify the root from last-level nodes using the same parameters. The only minor
difference is that C++ passes `nFieldElements` while Python passes `sponge_width` --
but the Python `verify_merkle_root` uses `sponge_width` for the hash function width,
and `HASH_SIZE` is always used implicitly when handling hash outputs.

**Rom's tree parameters:**
- `lastLevelVerification = 2`
- `merkleTreeArity = 4`
- `nBitsExt = 23`
- `numNodesLevel = 4^2 = 16`

**Conclusion:** IDENTICAL logic. Both perform last-level verification.

### 4. Query Proof Verification (verifyGroupProof)

**C++ (merkleTreeGL.cpp lines 177-215):**
```cpp
bool MerkleTreeGL::verifyGroupProof(Goldilocks::Element* root, Goldilocks::Element* level,
    std::vector<std::vector<Goldilocks::Element>> &mp, uint64_t idx,
    std::vector<Goldilocks::Element> &v) {
    Goldilocks::Element value[4];
    // linear_hash of leaf values v
    Poseidon2Goldilocks<16>::linear_hash_seq(value, v.data(), v.size());
    // walk up tree through siblings
    calculateRootFromProof(value, mp, queryIdx, 0);
    // compare against root or last-level node
    if (last_level_verification == 0) {
        // compare with root
    } else {
        // compare with level[queryIdx * nFieldElements]
    }
}
```

**Python (primitives/merkle_verifier.py lines 240-276):**
```python
def verify_query(self, query_index, leaf_values, siblings):
    # Hash leaf data
    current_hash = linear_hash(leaf_values, self.config.sponge_width)
    current_idx = query_index
    # Walk up the tree through sibling levels
    for level_siblings in siblings:
        child_position = current_idx % self.config.arity
        current_idx = current_idx // self.config.arity
        hash_input = self._build_parent_hash_input(current_hash, level_siblings, child_position)
        current_hash = hash_seq(hash_input, self.config.sponge_width)
    # Check against target (root or last-level node)
    return self._check_against_target(current_hash, current_idx)
```

The hashing logic is structurally identical:
1. Both hash the leaf values with `linear_hash` (Poseidon2)
2. Both walk up through siblings computing parent hashes with `hash_seq` (Poseidon2)
3. Both compare the final hash against either root (if lastLevelVerification=0) or the last-level node at the computed index

**Conclusion:** IDENTICAL logic.

### 5. Leaf Value Extraction for Custom Commits

**C++ (stark_verify.hpp lines 529-532):**
```cpp
for(uint64_t q = 0; q < starkInfo.starkStruct.nQueries; ++q) {
    std::vector<Goldilocks::Element> values(nCols);
    for (uint64_t i = 0; i < nCols; ++i) {
        values[i] = Goldilocks::fromString(jproof["s0_vals_" + starkInfo.customCommits[c].name + "_0"][q][i]);
    }
```

**Python (protocol/verifier.py lines 847-849):**
```python
for query_idx in range(n_queries):
    query_proof = proof.fri.trees.pol_queries[query_idx][tree_idx]
    values = [int(query_proof.v[i][0]) for i in range(n_cols)]
```

Both extract `nCols` (= 11 for Rom) values per query. The C++ code reads from JSON
directly, while the Python code reads from parsed binary proof data.

**Conclusion:** Structurally identical. The values should be the same IF the binary
proof was parsed correctly.

### 6. Sibling Extraction

**C++ (stark_verify.hpp lines 535-546):**
```cpp
uint64_t nSiblings = std::ceil(steps[0].nBits / log2(arity)) - lastLevelVerification;
uint64_t nSiblingsPerLevel = (arity - 1) * nFieldElements;

std::vector<std::vector<ElementType>> siblings(nSiblings, std::vector<ElementType>(nSiblingsPerLevel));
for (uint64_t i = 0; i < nSiblings; ++i) {
    for (uint64_t j = 0; j < nSiblingsPerLevel; ++j) {
        siblings[i][j] = fromString<ElementType>(jproof["s0_siblings_" + name + "_0"][q][i][j]);
    }
}
```

**Python (protocol/proof.py lines 253-258, binary deserialization):**
```python
for q in range(n_queries):
    for _ in range(n_siblings):
        proof.fri.trees.pol_queries[q][tree_idx].mp.append(
            list(values[idx:idx + n_siblings_per_level])
        )
        idx += n_siblings_per_level
```

Where `n_siblings_per_level = (merkle_arity - 1) * HASH_SIZE` and
`n_siblings = ceil(n_bits_ext / log2(merkle_arity)) - last_level_verification`.

For Rom: `n_siblings = ceil(23 / 2) - 2 = 12 - 2 = 10`, `n_siblings_per_level = 3 * 4 = 12`.

**Conclusion:** IDENTICAL computation of nSiblings and nSiblingsPerLevel.

### 7. Tree Construction Parameters

**C++ (stark_verify.hpp line 500):**
```cpp
MerkleTreeType tree(starkInfo.starkStruct.merkleTreeArity,
    starkInfo.starkStruct.lastLevelVerification,
    starkInfo.starkStruct.merkleTreeCustom,
    1 << starkInfo.starkStruct.nBitsExt, nCols);
```

**Python (primitives/merkle_verifier.py lines 193-197):**
```python
config = MerkleConfig(
    arity=stark_struct.merkle_tree_arity,
    domain_bits=stark_struct.fri_fold_steps[0].domain_bits,
    last_level_verification=stark_struct.last_level_verification,
)
```

C++ uses `nBitsExt` directly; Python uses `fri_fold_steps[0].domain_bits`. For Rom,
`nBitsExt=23` and `fri_fold_steps[0].domain_bits=23`, so these are identical.

**Conclusion:** IDENTICAL.

### 8. Binary vs JSON Proof: The Key Difference

The C++ verifier (`starkVerify`) reads from a JSON proof (jproof), while the Python
verifier reads from a binary proof (`from_bytes_full`). The binary proof is produced by
the C++ `proof2pointer()` method, and the JSON is produced by `pointer2json()` /
`proof2json()`.

**C++ proof2pointer (proof_stark.hpp lines 291-311):**
```cpp
for(uint64_t c = 0; c < starkInfo.customCommits.size(); ++c) {
    // values
    for (uint64_t i = 0; i < starkInfo.starkStruct.nQueries; i++) {
        for(uint64_t l = 0; l < mapSectionsN[name + "0"]; l++) {
            pointer[p++] = Goldilocks::toU64(fri.trees.polQueries[i][nStages + 2 + c].v[l][0]);
        }
    }
    // siblings
    for (uint64_t i = 0; i < starkInfo.starkStruct.nQueries; i++) {
        for(uint64_t l = 0; l < nSiblings; ++l) {
            for(uint64_t k = 0; k < nSiblingsPerLevel; ++k) {
                pointer[p++] = toU64(fri.trees.polQueries[i][nStages + 2 + c].mp[l][k]);
            }
        }
    }
    // last levels
    if (lastLevelVerification != 0) {
        for (uint64_t k = 0; k < pow(arity, lastLevelVerification) * nFieldElements; k++) {
            pointer[p++] = toU64(last_levels[nStages + 2 + c][k]);
        }
    }
}
```

**Python from_bytes_full (protocol/proof.py lines 241-267):**
```python
for c, custom_commit in enumerate(stark_info.custom_commits):
    n_custom_cols = stark_info.map_sections_n.get(custom_commit.name + "0", 0)
    tree_idx = n_stages + 2 + c
    # Values
    for q in range(n_queries):
        proof.fri.trees.pol_queries[q][tree_idx].v = [
            [values[idx + i]] for i in range(n_custom_cols)
        ]
        idx += n_custom_cols
    # Merkle paths
    for q in range(n_queries):
        for _ in range(n_siblings):
            proof.fri.trees.pol_queries[q][tree_idx].mp.append(
                list(values[idx:idx + n_siblings_per_level])
            )
            idx += n_siblings_per_level
    # Last levels
    if last_level_verification != 0:
        num_nodes = int(merkle_arity ** last_level_verification)
        custom_last_levels = []
        for _ in range(num_nodes):
            custom_last_levels.append(list(values[idx:idx + HASH_SIZE]))
            idx += HASH_SIZE
        proof.last_levels[tree_idx] = custom_last_levels
```

**Conclusion:** The binary format is the SAME in both. The serialization order is:
1. values (all queries)
2. siblings (all queries)
3. last_levels (one block)

Both C++ and Python follow this exact order. The deserialization in Python mirrors the
serialization in C++.

## Summary of Findings

| Aspect | C++ | Python | Match? |
|--------|-----|--------|--------|
| nFieldElements / HASH_SIZE | 4 (GL mode) | 4 (HASH_SIZE) | YES |
| Root from publics[idx] | `publics[customCommits[c].publicValues[j]]` for j in 0..3 | `publics[custom_commit.public_values[j]]` for j in range(4) | YES |
| publicValues parsing | `j["customCommits"][i]["publicValues"][k]["idx"]` | `[pv["idx"] for pv in ...]` | YES |
| Last-level verification | `verifyMerkleRoot(root, level, 1<<nBitsExt, llv, arity, nFE)` | `MerkleTree.verify_merkle_root(root, nodes, 1<<domain_bits, llv, arity, sponge_width)` | YES |
| Leaf hashing | `linear_hash_seq(value, v.data(), v.size())` | `linear_hash(leaf_values, sponge_width)` | YES |
| Tree walk | `calculateRootFromProof(value, mp, idx, 0)` | Loop through siblings with `hash_seq` | YES |
| Target check | `value[i] vs root[i]` or `level[idx*nFE + i]` | `computed_hash[:4] == root[:4]` or `last_level_nodes[idx*4:(idx+1)*4]` | YES |
| nCols for Rom | `mapSectionsN["rom0"]` = 11 | `map_sections_n["rom0"]` = 11 | YES |
| nSiblings | `ceil(23/log2(4)) - 2 = 10` | `ceil(23/log2(4)) - 2 = 10` | YES |
| Binary serialization order | vals, siblings, last_levels | vals, siblings, last_levels | YES |

## Key Conclusion

**The previous hypothesis is REFUTED.** The C++ verifier does NOT skip custom commit
Merkle verification. Both implementations are structurally identical.

If the custom commit Merkle verification fails in Python:

1. **Either the binary proof data is corrupted** (the C++ prover wrote bad data for
   the custom commit tree), OR

2. **The publics data passed to the Python verifier differs from what C++ uses.**
   The root comes from `publics[0..3]` -- if the publics array is wrong, the root
   would be wrong. This should be investigated.

3. **Or there is an extremely subtle difference** in the Poseidon2 FFI boundary
   (unlikely since 12 other AIRs pass through the same Poseidon2 code).

Since the C++ verifier would also fail Merkle verification if the proof data is bad,
and we know the C++ toolchain generates and verifies these proofs successfully, the
most likely explanation is that either:
- The binary proof we have was not generated by a passing verification run
- The publics array in the Python test differs from what C++ uses
- There is a binary parsing offset error specific to the custom commit section

The binary deserialization code appears correct by inspection, but a byte-level
comparison against the JSON proof (via `proof2zkinStark.cpp` / `pointer2json`) would
be the definitive way to verify this.
