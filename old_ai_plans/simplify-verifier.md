# Simplify protocol/verifier.py

## Agent Review Summary

### type-enforcer findings
- **5 function return types need fixing:**
  - `_reconstruct_transcript` (line 326): `tuple` → `tuple[InterleavedFF3, InterleavedFF3]`
  - `_parse_trace_values` (line 294): `tuple` → `tuple[FFArray, FFArray, FFArray]`
  - `_compute_stage_offsets` (line 215): `tuple[dict, int]` → `tuple[dict[int, int], int]`
  - `_compute_custom_commit_offsets` (line 232): `tuple[dict, int]` → `tuple[dict[int, int], int]`
  - `_allocate_trace_buffers` (line 249): `tuple` → `tuple[FFArray, FFArray, FFArray]`
- Line 185 empty array return is correct (InterleavedFF3 = np.ndarray)

### crypto-spec-simplifier findings
- **Dead code confirmed:**
  - `_allocate_trace_buffers`: `stage_offsets`/`custom_offsets` params unused
  - `_fill_trace_from_proof`: `custom_offsets` param unused
  - `_compute_custom_commit_offsets`: returns dict that's never read (only `custom_total` used)
  - `custom_commits` buffer: allocated but never filled
- **Simplify:** `_verify_evaluations` takes `params` but only uses `params.airgroupValues`

### human-simplicity-enforcer analysis (applied guidelines)
- **File length:** 957 lines - over 300 line guideline, consider splitting
- **Long functions:**
  - `_reconstruct_transcript` (78 lines) - doing multiple things: stage challenges, evals, FRI steps
  - `stark_verify` (126 lines) - acceptable as main entry point with clear structure
- **Magic numbers needing names:**
  - `+ 2` and `+ 3` for stage numbers (e.g., `si.nStages + 2`) - could use named constants
- **Dense lines:**
  - Line 81: `grinding_challenge = challenges[grinding_idx * FIELD_EXTENSION_DEGREE:(grinding_idx + 1) * FIELD_EXTENSION_DEGREE]` - repeated pattern
- **Parameter list:** `_verify_merkle_query` has 8 parameters - at the limit

### protocol-purity-guardian analysis (applied guidelines)
- **Good:** Uses `to_coefficients()` abstraction instead of raw INTT
- **Good:** Uses `linear_hash()` and `hash_seq()` - correct abstraction level
- **Good:** FRI verification uses `FRI.verify_fold()` - proper encapsulation
- **Minor concern:** Buffer index calculations (lines 452-460, 559-560) expose interleaved layout - could use helper
- **Overall:** Protocol purity is good - no major violations

---

## Proposed Changes (Prioritized)

### 1. Remove dead code (safe, high impact)
- Remove unused `stage_offsets`/`custom_offsets` params from `_allocate_trace_buffers`
- Remove unused `custom_offsets` param from `_fill_trace_from_proof`
- Inline `_compute_custom_commit_offsets` - just compute `custom_total` directly

### 2. Fix return type annotations (5 functions)
- Add explicit tuple types as identified by type-enforcer

### 3. Simplify `_verify_evaluations` signature
- Change `params: ProofContext` to `airgroup_values: InterleavedFF3`

### 4. Extract repeated buffer indexing pattern
- Create helper `def _challenge_slice(challenges, idx) -> InterleavedFF3` for the repeated pattern

### 5. Add named constants for stage offsets
- `EVAL_STAGE_OFFSET = 2` (nStages + 2 = evaluation stage)
- `FRI_STAGE_OFFSET = 3` (nStages + 3 = FRI polynomial stage)

### Deferred (not worth the risk)
- Splitting `_reconstruct_transcript` - complex control flow, risk of bugs
- Splitting the 957-line file - would require careful interface design

---

## Test Command
```bash
cd executable-spec && ./run-tests.sh
```

## Verification
After each change:
1. Run `./run-tests.sh` (all 164 tests)
2. Run `./run-tests.sh verifier` (verifier-specific tests)
