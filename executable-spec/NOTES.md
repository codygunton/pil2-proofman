# Executable Spec Development Notes

## Transcript Seeding Modes (VADCOP vs Non-VADCOP)

### Terminology Confusion

The C++ and Python codebases use different terminology for the same concepts:

| C++ Parameter | C++ Behavior | Python Equivalent |
|---------------|--------------|-------------------|
| `recursive=false` (default) | Seeds transcript with `globalChallenge` | `challenges_vadcop=True` |
| `recursive=true` | Seeds transcript with `verkey + publics + root1` | `challenges_vadcop=False` |

The "recursive" naming in C++ refers to recursive SNARK composition (verifying a proof inside another proof). In that context, you use the simpler `verkey+publics` seeding because the outer proof provides the binding.

### C++ Code Reference

From `pil2-stark/src/starkpil/gen_proof.hpp` lines 74-89:

```cpp
if(recursive) {
    // Recursive mode: seed with verkey + publics
    starks.addTranscript(transcript, &verkey[0], HASH_SIZE);
    if(setupCtx.starkInfo.nPublics > 0) {
        // ... add publics (hashed or direct)
    }
} else {
    // Non-recursive mode: seed with globalChallenge
    starks.addTranscript(transcript, globalChallenge, FIELD_EXTENSION);
}
```

### API Entry Points

- **`gen_proof`** (starks_api.cpp:780) → `recursive=false` → uses `globalChallenge`
- **`gen_recursive_proof`** (starks_api.cpp:862) → `recursive=true` → uses `verkey+publics`

### Test Coverage Status

Current test vectors are generated via `proofman-cli prove` which uses `gen_proof` with `recursive=false`, meaning they use `globalChallenge` seeding.

**Tested paths:**
- Python prover: `global_challenge=<value>` (Mode 1: External VADCOP)
- Python prover: `compute_global_challenge=True` (Mode 2: Internal VADCOP)
- Python verifier: `challenges_vadcop=True`

**Untested paths:**
- Python prover: `global_challenge=None, compute_global_challenge=False` (Mode 3: non-VADCOP)
- Python verifier: `challenges_vadcop=False`
- C++ equivalent: `gen_recursive_proof` with `recursive=true`

### Python Prover Modes

From `protocol/prover.py`:

```python
if global_challenge is not None:
    # Mode 1: External VADCOP - use pre-computed global_challenge
    transcript.put(global_challenge[:3])
elif compute_global_challenge:
    # Mode 2: Internal VADCOP - compute via lattice expansion
    computed_challenge = derive_global_challenge(...)
    transcript.put(computed_challenge[:3])
else:
    # Mode 3: Non-VADCOP - seed with verkey + publics + root1
    transcript.put(verkey)
    transcript.put(publics)  # or hash
    transcript.put(root1)
```

## Simplified `stark_verify` Signature

The verifier was simplified to only support the tested code path. Removed parameters:
- `challenges_vadcop` - was always `True` in tests
- Made `global_challenge` required (was optional)

New signature:
```python
def stark_verify(
    jproof: Dict,
    setup_ctx: SetupCtx,
    verkey: List[int],
    global_challenge: np.ndarray,  # Now required, moved before optional args
    publics: Optional[np.ndarray] = None,
    proof_values: Optional[np.ndarray] = None,
) -> bool:
```

The non-VADCOP transcript seeding path (verkey + publics + root1) was removed entirely.

### Remaining Untested Arguments

| Argument | Tested? | Notes |
|----------|---------|-------|
| `proof_values` | **No** | All test AIRs have empty `proofValuesMap` |

The `proof_values` parameter is used for cross-AIR communication in multi-AIR proofs. Testing it would require a test circuit that actually uses proof values.
