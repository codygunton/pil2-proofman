# verifier.py Style Review

## Summary: ~40 violations found

### 1. Type Annotations - `si` parameter (15+ issues)
Throughout the file, `si` parameter lacks type annotation. Add `si: StarkInfo` to:
- `_parse_evals`, `_parse_airgroup_values`, `_parse_air_values`, `_parse_const_pols_vals`
- `_compute_stage_offsets`, `_compute_custom_commit_offsets`, `_allocate_trace_buffers`
- `_fill_trace_from_proof`, `_parse_trace_values`, `_find_xi_challenge`
- `_reconstruct_transcript`, `_compute_x_div_x_sub`, `_evaluate_constraint_at_xi`
- `_reconstruct_quotient_at_xi`, `_verify_evaluations`, `_verify_fri_consistency`
- `_verify_merkle_tree`, `_verify_stage_merkle`, `_verify_const_merkle`
- `_verify_custom_commit_merkle`, `_verify_fri_merkle_tree`, `_verify_fri_folding`

### 2. Abbreviations (major - pervasive)
- `si` → `stark_info` (used ~100+ times)
- `ss` → `stark_struct` (used ~30+ times)
- `llv` → `last_level_verification` (used ~10 times)
- `c` → `challenge_index` (line 344)
- `q` → `query_idx` (inconsistent - sometimes used, sometimes not)

### 3. Dense Comprehensions → Explicit Loops (11 issues)
- Line 136: `[int(publics[cc.publicValues[j]]) for j in range(HASH_SIZE)]`
- Line 168: Ternary with comprehension
- Line 364: Nested comprehension `[int(v) for ev in ... for v in ev]`
- Lines 498-501: Comprehension in ff3 constructor
- Line 563: Dense slice arithmetic
- Line 669: Values comprehension
- Lines 670-673: Nested siblings comprehension
- Lines 779-782: Nested siblings comprehension
- Lines 784-785: Challenge extraction comprehension
- Line 838: `any()` with generator

### 4. Magic Numbers → Module Constants (3 issues)
- Lines 651, 719: `{2: 8, 3: 12, 4: 16}[arity]` → `SPONGE_WIDTH_BY_ARITY`
- Line 368: `width=16` → `EVALS_HASH_WIDTH = 16`

### 5. Docstrings (8+ issues)
Missing Args/Returns sections:
- `_parse_root`, `_parse_evals`, `_parse_airgroup_values`
- `_verify_stage_merkle`, `_verify_const_merkle`, `_verify_custom_commit_merkle`
- `_verify_fri_merkle_tree`

### 6. Explicit Loops Over Functional (3 issues)
- Lines 482-485: `next()` with generator → explicit loop
- Lines 492-495: `next()` with generator → explicit loop
- Line 838: `any()` → explicit loop with break

### 7. Mathematical Notation Citations (2 issues)
- Lines 420-422: `omega_extended`, `omega_trace` need STARK paper citation
- Function `_compute_x_div_x_sub` needs reference to DEEP-ALI protocol

### 8. Vertical Whitespace (2 issues)
- Line 281: Add blank line before "Fill custom commit values"
- Lines 358, 370: Add blank lines to separate transcript stages

## Positive Notes
- Excellent type aliases (JProof, Challenge, QueryIdx)
- Comprehensive main docstring in stark_verify()
- Well-named helper functions
- Good logical decomposition (8 distinct verification checks)
- Explicit conditionals (`n == 0` not `not n`)
