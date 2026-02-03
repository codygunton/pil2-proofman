# Field Type Centralization Implementation Plan

## Executive Summary

### Problem Statement
Protocol files are polluted with type conversion code that should live in `field.py`. This creates:
- **33+ scattered conversion instances** across 7 protocol files
- **Duplicate implementations** of the same patterns (e.g., `c0 + c1*p + c2*p2` appears 8 times)
- **Obscured protocol logic** where mathematical operations are buried under conversion noise
- **Maintenance burden** where changes to coefficient ordering require touching 7 files

### Proposed Solution
Centralize ALL type conversions in `primitives/field.py`. Protocol files work exclusively with `FF` and `FF3` galois types. Conversion happens only at boundaries:
- **Serialization boundary**: `proof.py` (JSON/binary output)
- **Deserialization boundary**: `verifier.py` (JSON proof parsing)
- **C++ buffer boundary**: `auxTrace` interleaved coefficient storage

### Technical Approach
1. Add 12 serialization/deserialization functions to `field.py`
2. Update each protocol file to import and use these functions
3. Remove all local conversion helpers from protocol files
4. Change API types from `List[int]` to `FF3` where appropriate

### Expected Outcomes
- Protocol files contain only mathematical operations on `FF`/`FF3`
- All coefficient encoding/decoding logic in one place (`field.py`)
- ~200 lines of duplicated conversion code eliminated
- Type signatures clearly express field element semantics

---

## Goals & Objectives

### Primary Goals
- Protocol files use `FF`/`FF3` exclusively (no `List[int]` for field elements)
- All conversion logic centralized in `primitives/field.py`
- All 142 tests continue passing

### Secondary Objectives
- Eliminate `EvalPoly = List[int]` type alias (use `FF3` directly)
- Remove `GOLDILOCKS_PRIME` imports from protocol files
- Restore `FIELD_EXTENSION` constant usage (eliminate magic number `3`)
- Change proof.py dataclasses to use `FF3` instead of `list[int]`
- Simplify hot paths in `expression_evaluator.py`

---

## Solution Overview

### Approach
Bottom-up: Add functions to `field.py`, then update consumers file-by-file.

### Key Components

1. **field.py**: Add 12 conversion functions covering all patterns
2. **fri.py**: Remove `_list_to_ff3_array`/`_ff3_array_to_list`, change API to use `FF3`
3. **verifier.py**: Remove `_parse_ff3_list`/`_ff3_to_flat_numpy`
4. **witness_generation.py**: Remove 4 `_np_*` helpers
5. **expression_evaluator.py**: Replace 7 inline conversion patterns
6. **stages.py**: Replace 10+ coefficient packing patterns
7. **proof.py**: Change dataclasses to use `FF3`, use field.py helpers
8. **All protocol files**: Restore `FIELD_EXTENSION` constant (remove magic `3`)

### Data Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PROTOCOL LAYER (FF/FF3 only)                        │
│                                                                             │
│   fri.py          stages.py        expression_evaluator.py                  │
│   (FF3 arrays)    (FF3 arithmetic) (FF/FF3 operations)                      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      FIELD.PY CONVERSION LAYER                              │
│                                                                             │
│   ff3_from_flat_list()     ff3_to_flat_list()                              │
│   ff3_from_json()          ff3_to_json()                                   │
│   ff3_from_interleaved()   ff3_to_interleaved()                            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    BOUNDARY LAYER (List[int], np.ndarray)                   │
│                                                                             │
│   proof.py (JSON/binary)    verifier.py (JSON input)    auxTrace (C++ buf) │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Implementation Tasks

### CRITICAL IMPLEMENTATION RULES
1. **NO PLACEHOLDER CODE**: Every function must be production-ready
2. **CROSS-FILE CONSISTENCY**: When adding a function to field.py, update ALL consumers in the same task
3. **PRESERVE TEST COMPATIBILITY**: All 142 tests must pass after each task
4. **COEFFICIENT ORDER**: Ascending `[c0, c1, c2]` everywhere (galois uses descending internally)

### Visual Dependency Tree

```
executable-spec/
├── primitives/
│   └── field.py (Task #0: Add 12 conversion functions)
│
├── protocol/
│   ├── fri.py (Task #1: Replace helpers, change API to FF3)
│   ├── verifier.py (Task #2: Replace helpers; Task #8: FIELD_EXTENSION)
│   ├── witness_generation.py (Task #3: Replace helpers; Task #8: FIELD_EXTENSION)
│   ├── expression_evaluator.py (Task #4: Replace inline patterns)
│   ├── stages.py (Task #5: Replace coefficient patterns; Task #8: FIELD_EXTENSION)
│   ├── setup_ctx.py (Task #6: Replace ff3 patterns; Task #8: FIELD_EXTENSION)
│   ├── proof.py (Task #7: FF3 in dataclasses + field.py helpers)
│   ├── prover.py (Task #8: FIELD_EXTENSION constant)
│   ├── steps_params.py (Task #8: FIELD_EXTENSION constant)
│   └── pcs.py (Task #1: Update to use FF3 API from fri.py)
│
└── tests/
    └── (No changes - tests validate compatibility)
```

### Execution Plan

#### Group A: Foundation (Execute first)

- [x] **Task #0**: Add conversion functions to field.py
  - File: `primitives/field.py`
  - Add these functions after the existing `ff3_array_from_base()`:

  ```python
  # --- Flat List Conversions (for serialization/transcript) ---

  def ff3_from_flat_list(coeffs: List[int]) -> FF3:
      """Convert flattened [c0,c1,c2,c0,c1,c2,...] to FF3 array.

      Used by: fri.py (EvalPoly parsing), transcript reconstruction
      """
      n = len(coeffs) // 3
      c0 = [coeffs[i * 3] for i in range(n)]
      c1 = [coeffs[i * 3 + 1] for i in range(n)]
      c2 = [coeffs[i * 3 + 2] for i in range(n)]
      return ff3_array(c0, c1, c2)


  def ff3_to_flat_list(arr: FF3) -> List[int]:
      """Convert FF3 array to flattened [c0,c1,c2,c0,c1,c2,...].

      Used by: fri.py (EvalPoly output), proof serialization
      """
      result = []
      for elem in arr:
          result.extend(ff3_coeffs(elem))
      return result


  # --- JSON Conversions (for proof parsing) ---

  def ff3_from_json(json_arr: List[List[int]]) -> FF3:
      """Parse JSON [[c0,c1,c2],...] to FF3 array.

      Used by: verifier.py (jproof parsing)
      """
      n = len(json_arr)
      c0 = [int(json_arr[i][0]) for i in range(n)]
      c1 = [int(json_arr[i][1]) for i in range(n)]
      c2 = [int(json_arr[i][2]) for i in range(n)]
      return ff3_array(c0, c1, c2)


  def ff3_to_json(arr: FF3) -> List[List[int]]:
      """Convert FF3 array to JSON [[c0,c1,c2],...] format.

      Used by: proof.py (JSON output)
      """
      return [ff3_coeffs(elem) for elem in arr]


  # --- Interleaved NumPy Buffer Conversions (for C++ compatibility) ---

  def ff3_from_interleaved_numpy(arr: np.ndarray, n: int) -> FF3:
      """Convert interleaved numpy [c0,c1,c2,c0,c1,c2,...] to FF3 array.

      Used by: witness_generation.py, expression_evaluator.py (auxTrace access)
      Args:
          arr: numpy array with interleaved coefficients
          n: number of FF3 elements to extract
      """
      c0 = arr[0::3][:n].tolist()
      c1 = arr[1::3][:n].tolist()
      c2 = arr[2::3][:n].tolist()
      return ff3_array(c0, c1, c2)


  def ff3_to_interleaved_numpy(arr: FF3) -> np.ndarray:
      """Convert FF3 array to interleaved numpy [c0,c1,c2,c0,c1,c2,...].

      Used by: witness_generation.py, expression_evaluator.py (auxTrace storage)
      """
      n = len(arr)
      result = np.zeros(n * 3, dtype=np.uint64)
      vecs = arr.vector()  # (n, 3) in descending [c2, c1, c0] order
      result[0::3] = vecs[:, 2].view(np.ndarray).astype(np.uint64)  # c0
      result[1::3] = vecs[:, 1].view(np.ndarray).astype(np.uint64)  # c1
      result[2::3] = vecs[:, 0].view(np.ndarray).astype(np.uint64)  # c2
      return result


  # --- Scalar Conversions ---

  def ff3_from_base(val: int) -> FF3:
      """Embed base field element into FF3 as (val, 0, 0).

      Used by: stages.py, setup_ctx.py (ff3([int(x), 0, 0]) patterns)
      """
      return ff3([val, 0, 0])


  def ff3_from_numpy_coeffs(arr: np.ndarray) -> FF3:
      """Convert numpy [c0, c1, c2] to FF3 scalar.

      Used by: witness_generation.py, expression_evaluator.py
      """
      return ff3([int(arr[0]), int(arr[1]), int(arr[2])])


  def ff3_to_numpy_coeffs(elem: FF3) -> np.ndarray:
      """Convert FF3 scalar to numpy [c0, c1, c2].

      Used by: witness_generation.py, stages.py
      """
      return np.array(ff3_coeffs(elem), dtype=np.uint64)


  # --- Buffer Index Access (for expression_evaluator hot path) ---

  def ff3_from_buffer_at(buffer: np.ndarray, indices: List[int]) -> FF3:
      """Extract FF3 elements from buffer at coefficient indices.

      Each index points to c0, with c1 at index+1, c2 at index+2.
      Used by: expression_evaluator.py (_load_operand for evals, xDivXSub)
      """
      n = len(indices)
      c0 = [int(buffer[i]) for i in indices]
      c1 = [int(buffer[i + 1]) for i in indices]
      c2 = [int(buffer[i + 2]) for i in indices]
      return ff3_array(c0, c1, c2)


  def ff3_store_to_buffer(arr: FF3, buffer: np.ndarray, indices: List[int]) -> None:
      """Store FF3 elements to buffer at coefficient indices.

      Each index points to c0, stores c1 at index+1, c2 at index+2.
      Used by: expression_evaluator.py (_store_result)
      """
      vecs = arr.vector()  # (n, 3) descending [c2, c1, c0]
      for j, idx in enumerate(indices):
          buffer[idx] = int(vecs[j, 2])      # c0
          buffer[idx + 1] = int(vecs[j, 1])  # c1
          buffer[idx + 2] = int(vecs[j, 0])  # c2
  ```

  - Exports: Add all 12 functions to module exports
  - Add `import numpy as np` if not present
  - Validation: Run `uv run python -c "from primitives.field import *"` to verify imports

#### Group B: Protocol Updates (Execute in parallel after Group A)

- [x] **Task #1**: Update fri.py to use FF3 API
  - File: `protocol/fri.py`
  - Remove:
    - `EvalPoly = List[int]` type alias
    - `_list_to_ff3_array()` helper
    - `_ff3_array_to_list()` helper
  - Change imports:
    ```python
    from primitives.field import (FF, FF3, ff3, ff3_coeffs, ff3_from_flat_list,
                                   ff3_to_flat_list, SHIFT, SHIFT_INV, get_omega_inv)
    ```
  - Update `FRI.fold()`:
    - Change signature: `pol: List[int]` → `pol: FF3`
    - Change return type: `-> List[int]` → `-> FF3`
    - Remove internal `_list_to_ff3_array(pol)` call (pol is already FF3)
    - Remove internal `_ff3_array_to_list()` call (return FF3 directly)
  - Update `FRI.merkelize()`:
    - If it takes `EvalPoly`, change to `FF3`
    - Convert to flat list only at Merkle boundary using `ff3_to_flat_list()`
  - Update callers in `protocol/pcs.py`:
    - `pcs.py` calls `fri.fold()` - update to pass/receive FF3
  - Validation: `uv run python -m pytest tests/test_fri.py -v`

- [x] **Task #2**: Update verifier.py to use field.py helpers
  - File: `protocol/verifier.py`
  - Remove:
    - `_parse_ff3_list()` helper (lines 26-32)
    - `_ff3_to_flat_numpy()` helper (lines 35-43)
  - Change imports:
    ```python
    from primitives.field import (FF, FF3, ff3, ff3_coeffs, ff3_from_json,
                                   ff3_to_interleaved_numpy, get_omega, SHIFT)
    ```
  - Update usages:
    - `_parse_ff3_list(json_arr)` → `ff3_from_json(json_arr)`
    - `_ff3_to_flat_numpy(arr)` → `ff3_to_interleaved_numpy(arr)`
  - Validation: `uv run python -m pytest tests/test_verifier_e2e.py -v`

- [x] **Task #3**: Update witness_generation.py to use field.py helpers
  - File: `protocol/witness_generation.py`
  - Remove:
    - `_np_to_ff3()` helper
    - `_ff3_to_np()` helper
    - `_np_column_to_ff3_array()` helper
    - `_ff3_array_to_np()` helper
  - Change imports:
    ```python
    from primitives.field import (FF, FF3, ff3, ff3_coeffs, ff3_from_numpy_coeffs,
                                   ff3_to_numpy_coeffs, ff3_from_interleaved_numpy,
                                   ff3_to_interleaved_numpy, batch_inverse, GOLDILOCKS_PRIME)
    ```
  - Update usages:
    - `_np_to_ff3(arr)` → `ff3_from_numpy_coeffs(arr)`
    - `_ff3_to_np(elem)` → `ff3_to_numpy_coeffs(elem)`
    - `_np_column_to_ff3_array(arr, N)` → `ff3_from_interleaved_numpy(arr, N)`
    - `_ff3_array_to_np(arr, N)` → `ff3_to_interleaved_numpy(arr)` (note: N implicit)
  - Note: Keep `GOLDILOCKS_PRIME` import if used elsewhere, but remove from conversion logic
  - Validation: `uv run python -m pytest tests/test_stark_e2e.py -v`

- [x] **Task #4**: Update expression_evaluator.py to use field.py helpers
  - File: `protocol/expression_evaluator.py`
  - Remove: `from primitives.field import GOLDILOCKS_PRIME` (only needed for p, p2 encoding)
  - Change imports:
    ```python
    from primitives.field import (FF, FF3, ff3, ff3_coeffs, ff3_array,
                                   ff3_from_numpy_coeffs, ff3_from_buffer_at,
                                   ff3_store_to_buffer)
    ```
  - Update `_load_direct_poly()` (lines 382-397):
    - Replace manual `c0 + c1*p + c2*p2` encoding with `ff3_array(c0, c1, c2)`
  - Update `_load_operand()` for evals access (lines 422-430):
    - Replace manual coefficient extraction with `ff3_from_buffer_at(params.evals, [base])`
  - Update `_load_operand()` for auxTrace access (lines 486-502):
    - Replace manual encoding with `ff3_from_buffer_at(params.auxTrace, indices)`
  - Update `_load_operand()` for xDivXSub access (lines 533-540):
    - Replace manual encoding with `ff3_from_buffer_at(params.xDivXSub, indices)`
  - Update `_store_result()` (lines 639-654):
    - Replace manual coefficient storage with `ff3_store_to_buffer(result, dest.dest, indices)`
  - Validation: `uv run python -m pytest tests/test_stark_e2e.py -v`

- [x] **Task #5**: Update stages.py to use field.py helpers
  - File: `protocol/stages.py`
  - Change imports:
    ```python
    from primitives.field import (FF, FF3, ff3, ff3_coeffs, ff3_array,
                                   ff3_from_base, ff3_from_numpy_coeffs,
                                   ff3_to_numpy_coeffs, SHIFT_INV)
    ```
  - Update patterns:
    - `ff3([int(x), 0, 0])` → `ff3_from_base(int(x))`
    - `ff3([int(a[0]), int(a[1]), int(a[2])])` → `ff3_from_numpy_coeffs(a)` or `ff3(list(a))`
    - `coeffs = ff3_coeffs(val); buf[i:i+3] = coeffs` → `ff3_to_numpy_coeffs(val)` or direct assignment
  - Key locations:
    - Line 166: `shift_p = ff3([int(S[p]), 0, 0])` → `ff3_from_base(int(S[p]))`
    - Line 244, 282: `xiFF3 = ff3([...])` → `ff3_from_numpy_coeffs(xiChallenge)`
    - Lines 256-258, 290-305: coefficient packing → use helpers
    - Lines 338-343: LEv array construction → use `ff3_array(c0, c1, c2)`
    - Lines 355-356: `params.evals[idx:idx+3] = ff3_coeffs(val)` → use helper
  - Validation: `uv run python -m pytest tests/test_stark_e2e.py -v`

- [x] **Task #6**: Update setup_ctx.py to use field.py helpers
  - File: `protocol/setup_ctx.py`
  - Change imports:
    ```python
    from primitives.field import (FF, FF3, ff3, ff3_coeffs, ff3_from_base,
                                   ff3_to_numpy_coeffs, batch_inverse, SHIFT, get_omega)
    ```
  - Update patterns:
    - `ff3([int(z[0]), int(z[1]), int(z[2])])` → `ff3([int(z[0]), int(z[1]), int(z[2])])` (keep, or use helper if z is numpy)
    - `ff3([1, 0, 0])` → `ff3_from_base(1)`
    - `ff3([int(w ** k), 0, 0])` → `ff3_from_base(int(w ** k))`
    - `helpers.zi[i*3:(i+1)*3] = ff3_coeffs(val)` → `helpers.zi[i*3:(i+1)*3] = ff3_to_numpy_coeffs(val)`
  - Validation: `uv run python -m pytest tests/test_verifier_e2e.py -v`

- [x] **Task #7**: Update proof.py to use FF3 in dataclasses and field.py helpers
  - File: `protocol/proof.py`
  - Change type aliases:
    ```python
    # REMOVE these:
    # Fe = int
    # Fe3 = list[int]

    # KEEP only:
    Hash = list[int]  # Poseidon hash output stays as list[int]
    ```
  - Change imports:
    ```python
    from primitives.field import FF, FF3, ff3_coeffs, ff3_to_flat_list, ff3_to_json
    ```
  - Update dataclasses to use FF3:
    - `FriProof.pol: list[Fe3]` → `pol: FF3`
    - `STARKProof.evals: list[Fe3]` → `evals: FF3`
    - `STARKProof.airgroup_values: list[Fe3]` → `airgroup_values: FF3`
    - `STARKProof.air_values: list[Fe3]` → `air_values: FF3`
  - Update `_to_list()` function:
    - For FF3 scalar: use `ff3_coeffs(arr)`
    - For FF3 array: use `ff3_to_flat_list(arr)` instead of manual `.vector()` loop
  - Update serialization functions to handle FF3 dataclass fields:
    - `proof_to_json()`: convert FF3 fields using `ff3_to_json()`
    - `to_bytes_full_from_dict()`: convert FF3 fields using `ff3_to_flat_list()`
  - The `_is_galois_array()` and `_is_extension_field()` helpers can stay (they detect types)
  - Validation: `uv run python -m pytest tests/test_proof.py -v`

#### Group C: Constants Cleanup (Execute after Group B)

- [ ] **Task #8**: Restore FIELD_EXTENSION constant usage (remove magic number 3)
  - Files: All protocol files
  - Problem: Magic number `3` is used throughout instead of `FIELD_EXTENSION` constant
  - Import `FIELD_EXTENSION` from `protocol.stark_info` in each file that needs it
  - Replace ALL instances of magic `3` representing FF3 coefficient count:

  **prover.py**:
    - Line 102: `n_evals = len(stark_info.evMap) * 3` → `* FIELD_EXTENSION`
    - Line 118: `fri_pol_size = ... * 3` → `* FIELD_EXTENSION`

  **steps_params.py**:
    - Line 72, 77: `base = index * 3` → `* FIELD_EXTENSION`

  **witness_generation.py**:
    - Line 44: `np.zeros(N * 3, ...)` → `* FIELD_EXTENSION`

  **verifier.py** (many instances):
    - Line 41: `np.zeros(len(arr) * 3, ...)` → `* FIELD_EXTENSION`
    - Line 44-46: `i * 3`, `i * 3 + 1`, `i * 3 + 2` → use FIELD_EXTENSION
    - Line 77: `grinding_idx * 3` → `* FIELD_EXTENSION`
    - Line 298: `i * 3:(i + 1) * 3` → `* FIELD_EXTENSION`
    - Line 318: `(n_challenges + n_steps + 1) * 3` → `* FIELD_EXTENSION`
    - Lines 351, 367, 382, 390, 410: `c * 3:(c + 1) * 3` → `* FIELD_EXTENSION`
    - Line 422: `n_queries * n_opening_points * 3` → `* FIELD_EXTENSION`
    - Line 444-445: `* 3`, `idx + 3` → `* FIELD_EXTENSION`
    - Line 485: `ev_id * 3` → `* FIELD_EXTENSION`
    - Lines 530-531, 538: `group_idx * 3`, `q * 3` → `* FIELD_EXTENSION`
    - Line 649: `group_size * 3` → `* FIELD_EXTENSION`
    - Lines 698, 704, 721: `i * 3`, `challenge_idx * 3`, `sibling_pos * 3` → `* FIELD_EXTENSION`

  **fri.py**:
    - Line 26: `pol[i * 3]` etc. → `* FIELD_EXTENSION` (if not removed by Task #1)

  **stages.py**:
    - All `* 3` patterns for FF3 indexing → `* FIELD_EXTENSION`

  **setup_ctx.py**:
    - All `* 3` patterns → `* FIELD_EXTENSION`

  - Note: Keep literal `3` only where it genuinely means "three" (e.g., loop unrolling), not FF3 dimension
  - Validation: `uv run python -m pytest -v`

#### Group D: Final Validation (Execute after Group C)

- [ ] **Task #9**: Final validation and cleanup
  - Run full test suite: `uv run python -m pytest -v`
  - Verify all 142 tests pass
  - Check no `GOLDILOCKS_PRIME` imports remain in protocol files (except where truly needed)
  - Check no manual `c0 + c1*p + c2*p2` patterns remain
  - Verify `EvalPoly` type alias is removed
  - Verify no magic `3` for FIELD_EXTENSION remains (grep for `\* 3` patterns)
  - Update `protocol/__init__.py` exports if needed

---

## Implementation Workflow

This plan file serves as the authoritative checklist for implementation. When implementing:

### Required Process
1. **Load Plan**: Read this entire plan file before starting
2. **Sync Tasks**: Create TodoWrite tasks matching the checkboxes above
3. **Execute & Update**: For each task:
   - Mark TodoWrite as `in_progress` when starting
   - Use `crypto-spec-simplifier` agent for implementation
   - Update checkbox `[ ]` to `[x]` when completing
   - Mark TodoWrite as `completed` when done
4. **Maintain Sync**: Keep this file and TodoWrite synchronized throughout

### Critical Rules
- This plan file is the source of truth for progress
- Update checkboxes in real-time as work progresses
- Task #0 must complete before Group B tasks start
- Group B tasks (1-7) can run in parallel
- Task #8 (FIELD_EXTENSION cleanup) runs after Group B completes
- Task #9 (final validation) runs after Task #8
- Mark tasks complete only when tests pass

### Progress Tracking
The checkboxes above represent the authoritative status of each task. Keep them updated as you work.
