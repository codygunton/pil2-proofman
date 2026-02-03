# prover.py Style Review

## Summary: ~20 violations found

### 1. Type Annotations (7 issues)
- Line 25: `_get_air_values_stage1(stark_info, ...)` → add `stark_info: StarkInfo`
- Line 41: `_get_proof_values_stage1(stark_info, ...)` → add `stark_info: StarkInfo`
- Line 650: `_derive_stage_challenges(..., challenges_map: list, ...)` → `challenges_map: list[dict]`
- Line 659: `_derive_eval_challenges(..., stark_info, ...)` → add `stark_info: StarkInfo`
- Line 678: `_compute_all_evals(stark_info, ...)` → add `stark_info: StarkInfo`
- Line 697: `_collect_stage_query_proofs(..., stark_info, ...)` → add `stark_info: StarkInfo`
- Line 708: `_collect_last_level_nodes(..., stark_info, ...)` → add `stark_info: StarkInfo`

### 2. Docstrings (6 issues)
- Line 650: `_derive_stage_challenges` - incomplete docstring
- Line 659: `_derive_eval_challenges` - incomplete docstring
- Line 678: `_compute_all_evals` - incomplete docstring
- Line 689: `_collect_const_query_proofs` - missing Args/Returns
- Line 697: `_collect_stage_query_proofs` - missing Args/Returns
- Line 708: `_collect_last_level_nodes` - missing Args/Returns

### 3. Magic Numbers (3 issues)
- Line 185: `[0] * 4` → use `HASH_SIZE` from imports
- Line 222: `368` → `DEFAULT_LATTICE_SIZE = 368` at module level
- Line 435: `width=16` → `POSEIDON2_LINEAR_HASH_WIDTH = 16` at module level

### 4. Dense Expressions (2 issues)
- Lines 478-484: FRI polynomial extraction - add intermediate variables
- Lines 497-533: FRI config construction - extract `fri_round_log_sizes` first

### 5. Abbreviations (1 issue)
- Line 683: `LEv` → `lagrange_evaluations`

### 6. Comprehensions (1 issue)
- Line 435: Inline comprehension in function call → extract to variable

## Positive Notes
- Excellent inline documentation explaining protocol flow
- Good use of vertical whitespace to separate logical sections
- Explicit loops used throughout (no map/filter/reduce)
- No walrus operators
- Good type aliases (MerkleRoot, StageNum)
