# Lattice Expansion Algorithm for Global Challenge Computation

## Overview

The C++ proofman computes `global_challenge` using a multi-step lattice expansion algorithm. This document describes the algorithm and explains why it was not replicated in the Python executable spec.

## Algorithm Description

The global challenge computation in C++ (`proofman/src/challenge_accumulation.rs`) involves three main functions:

### 1. `get_contribution_air()` - Prepare Values to Hash

Location: `proofman/src/proofman.rs:3472-3540`

```rust
let size = 2 * n_field_elements + n_airvalues;  // typically 8 + n_airvalues
let mut values_hash = vec![F::ZERO; size];

// Copy verkey to positions [0..4]
values_hash[..n_field_elements].copy_from_slice(&setup.verkey[..n_field_elements]);

// Copy air_values (stage 1) to positions [8..]
for air_value in airvalues_map {
    if air_value.stage == 1 {
        values_hash[2 * n_field_elements + count] = air_values[p];
    }
}

*values_contributions[instance_id] = values_hash;
```

**Output**: `values_contributions[instance_id]` = `[verkey[0..4], zeros[4..8], air_values...]`

### 2. `calculate_internal_contributions()` - Hash and Expand

Location: `proofman/src/challenge_accumulation.rs:27-82`

```rust
// Determine contribution size from global config
let contributions_size = match pctx.global_info.curve {
    CurveType::None => pctx.global_info.lattice_size.unwrap(),  // e.g., 368
    _ => 10,  // For elliptic curve modes
};

// Clone values_contributions and insert root1
let mut values_to_hash = values_contributions[instance_id].clone();
values_to_hash[4..8].copy_from_slice(&root_contribution[..4]);  // Insert root1

// Hash [verkey, root1, air_values] through Poseidon2 transcript
let mut hash: Transcript<F, Poseidon16, 16> = Transcript::new();
hash.put(&values_to_hash);
let contribution = hash.get_state();  // 16 elements

// LATTICE EXPANSION: Expand 16 elements to lattice_size via hash chain
let mut values_row = vec![F::ZERO; contributions_size];  // 368 zeros

// Copy initial 16 elements
for (i, v) in contribution.iter().enumerate().take(16) {
    values_row[i] = *v;
}

// Chain hash to expand to full lattice_size
let n_hashes = contributions_size / 16 - 1;  // 368/16 - 1 = 22
for j in 0..n_hashes {
    let mut input: [F; 16] = [F::ZERO; 16];
    input.copy_from_slice(&values_row[(j * 16)..((j + 1) * 16)]);
    let output = poseidon2_hash::<F, Poseidon16, 16>(&input);
    values_row[((j + 1) * 16)..((j + 2) * 16)].copy_from_slice(&output[..16]);
}

// Aggregate across all workers (for distributed proving)
let partial_contribution = add_contributions(pctx, &values);
```

**Key insight**: The 16-element hash state is expanded to 368 elements through 22 sequential Poseidon2 hash operations, creating a "hash chain":

```
values_row[0..16]   = initial_hash_state
values_row[16..32]  = poseidon2(values_row[0..16])
values_row[32..48]  = poseidon2(values_row[16..32])
...
values_row[352..368] = poseidon2(values_row[336..352])
```

### 3. `calculate_global_challenge()` - Final Challenge Derivation

Location: `proofman/src/challenge_accumulation.rs:84-111`

```rust
let mut transcript: Transcript<F, Poseidon16, 16> = Transcript::new();

// Hash public inputs (if any)
transcript.put(&pctx.get_publics());

// Hash stage 1 proof values (if any)
let proof_values_stage1 = pctx.get_proof_values_by_stage(1);
if !proof_values_stage1.is_empty() {
    transcript.put(&proof_values_stage1);
}

// Aggregate all partial contributions from workers
let value = aggregate_contributions(pctx, &all_partial_contributions);

// Hash the FULL 368-element contribution
transcript.put(&value);  // All 368 elements!

// Extract 3 field elements as global_challenge
let mut global_challenge = [F::ZERO; 3];
transcript.get_field(&mut global_challenge);
```

## Why This Is Complex for Python

### 1. Configuration Dependency

The algorithm requires `lattice_size` from `globalInfo.json`:
```json
{
  "latticeSize": 368,
  "curve": "None"
}
```

The Python executable spec doesn't currently parse or use `globalInfo.json`. Adding this would require:
- New JSON parser for global info
- Propagating lattice_size through the setup context
- Different code paths for different curve types

### 2. Distributed Proving Design

The lattice expansion is designed for **distributed proving**:
- Multiple workers compute partial contributions in parallel
- `add_contributions()` sums contributions element-wise across workers
- `aggregate_contributions()` combines results from different airgroups

For a single-machine Python spec, this complexity provides no benefit.

### 3. Security Feature Not Needed for Spec

The lattice expansion serves as a cryptographic "mixing" step that:
- Expands the entropy of the initial 16-element hash
- Provides security margins for lattice-based aggregation
- Supports future post-quantum security properties

For an **executable specification** whose purpose is to document and validate the protocol, this security feature adds complexity without educational value.

### 4. Alternative Approach Works

The verifier supports a simpler "non-VADCOP" mode that seeds the transcript directly:
```python
transcript.put(verkey)           # 4 elements
transcript.put(publics_hash)     # 4 elements (if nPublics > 0)
transcript.put(root1)            # 4 elements
```

This produces different challenges than VADCOP mode, but generates valid proofs that pass verification.

## Data Flow Comparison

### C++ Proofman (VADCOP mode)
```
verkey + root1 + air_values (8+ elements)
    │
    ▼
Poseidon2 Transcript Hash
    │
    ▼
16-element state
    │
    ▼
Lattice Expansion (22 hash chain iterations)
    │
    ▼
368-element contribution
    │
    ▼
Aggregate across workers (identity for single worker)
    │
    ▼
Hash into final transcript with publics + proof_values
    │
    ▼
3-element global_challenge
```

### Python Executable Spec (current implementation)
```
Option A: VADCOP mode (global_challenge provided from test vectors)
    global_challenge (3 elements) → transcript.put()

Option B: Non-VADCOP mode (self-contained)
    verkey (4 elements) → transcript.put()
    publics_hash (4 elements) → transcript.put()
    root1 (4 elements) → transcript.put()
```

## Conclusion

The Python executable spec accepts `global_challenge` as an optional parameter:
- When provided (from C++ test vectors): Uses VADCOP mode for byte-identical proofs
- When not provided: Uses simpler non-VADCOP mode for self-contained operation

This approach maintains compatibility with C++ while keeping the spec readable and focused on protocol understanding rather than implementation-specific optimizations.

## References

- `proofman/src/challenge_accumulation.rs` - Main algorithm implementation
- `proofman/src/proofman.rs:3472-3540` - `get_contribution_air()` function
- `common/src/global_info.rs` - `lattice_size` field definition
- `pil2-components/test/simple/build/provingKey/pilout.globalInfo.json` - Example config with `latticeSize: 368`
