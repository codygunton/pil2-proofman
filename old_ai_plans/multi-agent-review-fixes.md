# Multi-Agent Review Fixes Implementation Plan

## Executive Summary

Four review agents audited the Python executable spec codebase. The paranoid-skeptic confirmed zero regressions (all 320+ tests pass). The remaining three agents identified style, readability, and architectural issues across 5 files. None are correctness bugs — all are readability and maintainability improvements.

**Problem**: The codebase has:
1. **Protocol purity violation** — `stages.py` directly imports and calls NTT, leaking implementation details into the protocol layer
2. **Dense FF3 constructions** — Repeated `FF3.Vector([int(x[2]), int(x[1]), int(x[0])])` patterns across verifier.py, bytecode_adapter.py, and polynomial.py
3. **Long functions** — `_load_operand` (220 lines), `_parse_polynomial_values` (110 lines), `_build_verifier_data` (114 lines)
4. **Minor style issues** — inline ternaries, dense numpy chains, abbreviation (`zh`)

**Approach**: Extract a shared `ff3_from_descending_interleaved` helper, replace NTT calls with existing polynomial abstractions, split long functions into named phases, and fix minor style issues. All changes are mechanical refactors — no behavioral change, tests must remain byte-identical.

**Expected outcomes**: All 320+ tests continue to pass. Protocol layer uses only abstract polynomial operations. No function exceeds ~60 lines. FF3 constructions are readable.

## Goals & Objectives

### Primary Goals
- Remove all direct NTT usage from `protocol/stages.py` (7 violations → 0)
- Reduce max function length to ~60 lines (from 220)
- Extract repeated FF3 construction pattern into shared helper

### Secondary Objectives
- Improve code readability for cryptographer audience
- Establish pattern for future FF3 construction sites
- All changes verified by byte-identical test results

## Solution Overview

### Approach
Pure refactoring — extract helpers, rename, split functions. Zero behavioral changes.

### Key Components
1. **FF3 helper** (`primitives/field.py`): New `ff3_from_interleaved_ints()` eliminates repeated descending-order construction
2. **stages.py NTT removal**: Replace 6 direct NTT/INTT calls with existing `polynomial.py` abstractions
3. **Function splitting**: Break 3 oversized functions into named phases
4. **Style fixes**: Inline ternaries → if/else, `zh` → `vanishing_polynomial`, dense chains → named intermediates

### Expected Outcomes
- `protocol/stages.py` has zero NTT imports or direct NTT calls
- No function in the codebase exceeds ~60 lines
- All 320+ tests pass with byte-identical results
- All FF3.Vector constructions use the shared helper or named intermediates

## Implementation Tasks

### CRITICAL IMPLEMENTATION RULES
1. **ZERO BEHAVIORAL CHANGE**: Every refactor must be semantics-preserving. Tests must remain byte-identical.
2. **RUN TESTS AFTER EACH TASK**: `cd executable-spec && uv run pytest tests/ -x -q` after each task.
3. **RUN LINTER**: `cd executable-spec && uv run ruff check .` after each task.

### Visual Dependency Tree

```
executable-spec/
├── primitives/
│   ├── field.py              (Task #1: Add ff3_from_interleaved_ints helper)
│   ├── polynomial.py         (NO CHANGES — abstractions already exist)
│   └── expression_bytecode/
│       └── expression_evaluator.py  (Task #5: Split _load_operand, fix inline ternary)
│
├── constraints/
│   └── bytecode_adapter.py   (Task #2: Use ff3 helper, rename zh, fix dense exprs)
│
├── protocol/
│   ├── verifier.py           (Task #3: Use ff3 helper, split long functions, fix dense exprs)
│   └── stages.py             (Task #4: Replace NTT with polynomial abstractions)
│
└── tests/                    (NO CHANGES — test file already "Beautiful")
```

### Execution Plan

#### Group A: Foundation (Execute first — other tasks depend on this)

- [ ] **Task #1**: Add FF3 construction helper to `primitives/field.py`
  - **File**: `primitives/field.py`
  - **What**: Add a helper function that constructs an FF3 element from 3 interleaved int-like values in ascending order (c0, c1, c2), handling the descending-order conversion galois requires internally.
  - **Implements**:
    ```python
    def ff3_from_interleaved_ints(c0: int, c1: int, c2: int) -> FF3:
        """Construct a single FF3 element from base-field coefficients.

        Args:
            c0: Coefficient of x^0 (constant term)
            c1: Coefficient of x^1
            c2: Coefficient of x^2

        Returns:
            FF3 element c0 + c1*x + c2*x^2
        """
        return FF3.Vector([int(c2), int(c1), int(c0)])
    ```
  - **Also add** an array variant for the numpy-buffer pattern:
    ```python
    def ff3_from_interleaved_buffer(buf: np.ndarray, offset: int = 0) -> FF3:
        """Construct FF3 from interleaved numpy buffer at given offset.

        Reads 3 consecutive uint64 values from buf[offset:offset+3],
        interpreting them as (c0, c1, c2) in ascending coefficient order.
        """
        c0 = int(buf[offset])
        c1 = int(buf[offset + 1])
        c2 = int(buf[offset + 2])
        return FF3.Vector([c2, c1, c0])
    ```
  - **Exports**: Both functions added to module scope
  - **Verification**: `uv run pytest tests/ -x -q` (no tests should change — these are new unused functions)
  - **Rationale**: This pattern appears 10+ times across verifier.py, bytecode_adapter.py, polynomial.py. The descending-order reversal (`[c2, c1, c0]`) is a galois implementation detail that should be hidden.

#### Group B: Apply helpers and fix style (Execute all in parallel after Group A)

- [ ] **Task #2**: Clean up `constraints/bytecode_adapter.py`
  - **File**: `constraints/bytecode_adapter.py`
  - **Changes**:
    1. **Import** `ff3_from_interleaved_ints` and `ff3_from_interleaved_buffer` from `primitives.field`
    2. **Line ~363**: Replace `xi = FF3.Vector([int(z[2]), int(z[1]), int(z[0])])` with `xi = ff3_from_interleaved_buffer(z)`
    3. **Line ~503**: Replace `q_xi = ff3([int(dest_buffer[0]), int(dest_buffer[1]), int(dest_buffer[2])])` with `q_xi = ff3_from_interleaved_buffer(dest_buffer)`
    4. **Rename `zh_xi`**: This is already well-named (it's `Z_H(xi)` at a point). Keep as-is. The `zh` that the style agent flagged may be in the prover path — check `_recover_constraint_from_quotient_prover` and rename any bare `zh` to `vanishing_polynomial` there.
    5. **Dense numpy chain** (if any `np.asarray(...).tolist()` patterns exist): Break into named intermediates.
  - **Verification**: `uv run pytest tests/ -x -q && uv run ruff check .`

- [ ] **Task #3**: Clean up `protocol/verifier.py` — FF3 helpers + split long functions
  - **File**: `protocol/verifier.py`
  - **Part A — FF3 helper usage** (6 sites):
    1. Import `ff3_from_interleaved_ints`, `ff3_from_interleaved_buffer` from `primitives.field`
    2. **Lines 523-527** (`_build_verifier_data` evals): Replace with `eval_val = ff3_from_interleaved_buffer(evals, eval_base)`
    3. **Lines 535-539** (`_build_verifier_data` challenges): Replace with `ch_val = ff3_from_interleaved_buffer(challenges, ch_base)`
    4. **Lines 547-551** (`_build_verifier_data` airgroup values): Replace with `ff3_from_interleaved_buffer(airgroup_values, idx)`
    5. **Line 624** (`_compute_x_div_x_sub`): Replace with `xi = ff3_from_interleaved_buffer(xi_challenge)` — but NOTE: xi_challenge might not be a flat numpy buffer. Check the actual data type. If it's a list/array with [c0,c1,c2] semantics, use `ff3_from_interleaved_ints(int(xi_challenge[0]), int(xi_challenge[1]), int(xi_challenge[2]))`.
    6. **Lines 686-690** (`_reconstruct_quotient_at_xi`): Replace with `q_piece_eval = ff3_from_interleaved_buffer(evals, eval_map_idx * FIELD_EXTENSION_DEGREE)`
    7. **Line 713** and **Line 719**: Same pattern — use helper.
  - **Part B — Dense expressions**:
    1. **Line 175** (`_parse_evals`): Break into named intermediates:
       ```python
       evals_slice = proof.evals[:len(stark_info.ev_map)]
       evals_ff3 = ff3_from_json(evals_slice)
       return ff3_to_interleaved_numpy(evals_ff3)
       ```
    2. **Line 182** (`_parse_airgroup_values`): Same pattern.
  - **Part C — Split `_parse_polynomial_values`** (110 lines → ~3 functions of ~35 lines):
    - Extract `_parse_committed_polynomial_values(proof, stark_info, n_queries)` — handles cm polynomials
    - Extract `_parse_custom_commit_polynomial_values(proof, stark_info, n_queries)` — handles custom commits
    - Keep `_parse_polynomial_values` as the orchestrator that calls both and merges results
  - **Part D — Split `_build_verifier_data`** (114 lines → ~3 functions of ~35 lines):
    - Extract `_map_evaluations(stark_info, evals)` — maps eval indices to named PolynomialId values
    - Extract `_map_challenges(stark_info, challenges)` — maps challenge indices
    - Keep `_build_verifier_data` as orchestrator
  - **Part E — Inline conditionals** (lines ~284-298):
    - If these are simple ternaries, expand to if/else blocks
  - **Verification**: `uv run pytest tests/ -x -q && uv run ruff check .`

- [ ] **Task #4**: Replace NTT with polynomial abstractions in `protocol/stages.py`
  - **File**: `protocol/stages.py`
  - **Changes**:
    1. **Remove import**: Delete `from primitives.ntt import NTT` (line 28)
    2. **Add import**: `from primitives.polynomial import to_coefficients, to_evaluations, extend_to_domain`
    3. **Remove NTT instances**: Delete lines 389-396 (the `_ntt` and `_ntt_extended` instance variables and their comments)
    4. **Line 445** (`extend_pol`): Replace:
       ```python
       # Before:
       pBuffExtended_result = self._ntt.extend_pol(pBuff_2d, NExtended, N, nCols)
       # After:
       pBuffExtended_result = extend_to_domain(pBuff_2d, N, NExtended, nCols)
       ```
    5. **Line 529** (`intt` in `computeFriPol`): Replace:
       ```python
       # Before:
       qCoeffs = self._ntt_extended.intt(qPolReshaped, n_cols=qDim)
       # After:
       qCoeffs = to_coefficients(qPolReshaped, domain_size=NExtended, n_cols=qDim)
       ```
    6. **Line 561** (`ntt` in `computeFriPol`): Replace:
       ```python
       # Before:
       cmQEvaluations = self._ntt_extended.ntt(cmQReshaped, n_cols=nCols)
       # After:
       cmQEvaluations = to_evaluations(cmQReshaped, domain_size=NExtended, n_cols=nCols)
       ```
    7. **Line 716** (`intt` in `computeLEv`): Replace:
       ```python
       # Before:
       LEvCoeffs = self._ntt.intt(LEvReshaped, n_cols=nOpeningPoints * FIELD_EXTENSION_DEGREE)
       # After:
       LEvCoeffs = to_coefficients(LEvReshaped, domain_size=N, n_cols=nOpeningPoints * FIELD_EXTENSION_DEGREE)
       ```
    8. **Update comments**: Change "INTT" and "NTT" references in comments to "convert to coefficient form" / "convert to evaluation form" / "extend to larger domain"
  - **Performance note**: `polynomial.py` currently creates a new `NTT(domain_size)` object per call. This is fine for now — the NTT constructor precomputes twiddle factors but this is fast. If it becomes a bottleneck, add caching to `polynomial.py` (NOT to stages.py).
  - **Verification**: `uv run pytest tests/ -x -q && uv run ruff check .` — tests MUST produce byte-identical results.

- [ ] **Task #5**: Split `_load_operand` and fix style in `expression_evaluator.py`
  - **File**: `primitives/expression_bytecode/expression_evaluator.py`
  - **Part A — Fix inline ternary** (lines 406-412):
    Replace:
    ```python
    return [int(x) for x in v] if hasattr(v, '__len__') else int(v)
    ```
    With:
    ```python
    if hasattr(v, '__len__'):
        return [int(x) for x in v]
    return int(v)
    ```
  - **Part B — Split `_load_operand`** (220 lines → ~5 functions of ~40 lines):
    The function is a giant switch on operand type. Split into per-type handlers:
    - `_load_committed_polynomial(...)` — handles committed polynomial loads
    - `_load_constant_polynomial(...)` — handles constant polynomial loads
    - `_load_challenge(...)` — handles challenge loads
    - `_load_public_input(...)` — handles public input loads
    - `_load_custom_commit(...)` — handles custom commit loads
    - Keep `_load_operand` as the dispatcher that calls the appropriate handler based on operand type
    - Each handler receives the same parameters `_load_operand` currently uses
  - **Part C — Dense expression** (lines 650-652):
    Break `FF3(np.asarray(x_vals, dtype=np.uint64).tolist())` into:
    ```python
    x_array = np.asarray(x_vals, dtype=np.uint64)
    x_ff3 = FF3(x_array.tolist())
    ```
  - **Verification**: `uv run pytest tests/ -x -q && uv run ruff check .`

#### Group C: Fix polynomial.py FF3 pattern (Execute after Group A)

- [ ] **Task #6**: Clean up `to_coefficients_cubic` in `primitives/polynomial.py`
  - **File**: `primitives/polynomial.py`
  - **Changes**:
    1. Import `ff3_from_interleaved_ints` from `primitives.field`
    2. **Line 121**: Replace the dense list comprehension:
       ```python
       # Before:
       return [FF3.Vector([int(results[2][i]), int(results[1][i]), int(results[0][i])]) for i in range(n)]
       # After:
       return [ff3_from_interleaved_ints(int(results[0][i]), int(results[1][i]), int(results[2][i])) for i in range(n)]
       ```
  - **Verification**: `uv run pytest tests/ -x -q && uv run ruff check .`

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
- Tasks in Group B can be run in parallel via subtasks
- Run tests after EVERY task: `cd executable-spec && uv run pytest tests/ -x -q`
- Run linter after EVERY task: `cd executable-spec && uv run ruff check .`

### Post-Implementation
After all tasks complete, run the full multi-agent review again:
- **paranoid-skeptic** — verify no regressions
- **protocol-purity-guardian** — verify stages.py is clean
- **zksnark-python-style** — verify style compliance
- **human-simplicity-enforcer** — verify readability

### Progress Tracking
The checkboxes above represent the authoritative status of each task. Keep them updated as you work.
