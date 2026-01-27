# Native Galois FieldArray Migration Plan

## Executive Summary

### Problem Statement
The executable-spec codebase is a faithful C++ translation that uses flat `np.ndarray[uint64]` buffers with manual field arithmetic. This obscures the mathematical protocol with engineering noise:
- Manual `int(FF(int(x)) * FF(int(y)))` conversions everywhere
- `dim` parameter threaded through 85+ locations to distinguish FF vs FF3
- Helper functions (`_ff3_mul`, `_mul_columns`, etc.) that galois handles natively
- AoS buffer layouts requiring manual offset calculations

### Proposed Solution
Migrate to native galois `FF` and `FF3` FieldArrays throughout. The galois library (a numpy subclass) supports:
- Vectorized arithmetic: `a * b`, `a + b`, `a ** -1` on arrays
- Arbitrary shapes: `FF.Zeros((N, n_cols))`, broadcasting, slicing
- Direct NTT: `galois.ntt(ff_array, omega=omega)`

### Technical Approach
1. Replace buffer types from `np.ndarray[uint64]` to `FF` or `FF3` arrays
2. Treat FF3 as **opaque field elements** - never extract coefficients in protocol code
3. Eliminate `dim` parameter - let Python's type system distinguish FF vs FF3
4. Remove manual arithmetic helpers - use galois operators directly
5. Convert to integers only at serialization boundaries (proof output, Poseidon2 FFI, transcript)

### Expected Outcomes
- Protocol code reads like mathematical specification
- ~50% code reduction in protocol/ modules
- Elimination of 85+ `dim` parameter usages
- Removal of all `_ff3_*` and `_mul_columns` helper functions
- All E2E tests continue passing (byte-identical proofs)

---

## Goals & Objectives

### Primary Goals
- Protocol code uses native galois arithmetic: `poly_a * poly_b` instead of manual loops
- Type safety: FF vs FF3 distinguished by Python types, not runtime `dim` checks
- Maintain byte-identical proof output (E2E tests pass)

### Secondary Objectives
- Simplify NTT wrapper (galois handles most complexity)
- Improve performance through vectorized galois operations
- Enable future optimizations (galois has SIMD backends)

---

## Solution Overview

### Approach
Bottom-up migration: primitives → data structures → protocol modules → serialization boundaries.

### Key Components

1. **primitives/field.py**: No changes needed - galois provides everything
2. **primitives/ntt.py**: Simplify to thin wrapper over galois.ntt/intt
3. **protocol/steps_params.py**: Change buffer types to FF/FF3 arrays
4. **protocol/witness_generation.py**: Remove all helper functions, use galois operators
5. **protocol/expression_evaluator.py**: Eliminate dim branching, use typed operations
6. **protocol/stages.py**: Use FF3 arrays directly for polynomial operations
7. **protocol/verifier.py**: Typed parsing, eliminate FIELD_EXTENSION constants
8. **protocol/proof.py**: Add boundary conversion (galois ↔ int) at serialization

### Data Flow
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         INTERNAL (Native Galois)                            │
│                                                                             │
│   FF.Zeros((N,))  ───►  poly * challenge  ───►  FF3 array                  │
│   FF3 array       ───►  galois.ntt()      ───►  FF3 array                  │
│   challenges: FF3 ───►  a + b * xi        ───►  evaluations: FF3           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    SERIALIZATION BOUNDARIES (Convert to int)                │
│                                                                             │
│   Merkle leaf hashing:    [int(x) for x in row]  →  linear_hash()          │
│   Transcript.put():       [int(x) for x in vals] →  absorb                 │
│   Proof binary output:    struct.pack('<Q', int(x))                        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Implementation Tasks

### CRITICAL IMPLEMENTATION RULES
1. **USE crypto-spec-simplifier AGENT**: Each task uses the specialized simplification agent
2. **TEST AFTER EACH GROUP**: Run full test suite after completing each task group
3. **FF3 IS OPAQUE**: Protocol code NEVER extracts coefficients from FF3. Treat it as a single field element.
4. **SERIALIZE AT BOUNDARIES**: Only convert to int at proof.py, merkle_tree.py, transcript.py
5. **NO dim PARAMETER**: Use `isinstance(x, FF3)` if type dispatch truly needed (rare)

### Visual Dependency Tree

```
executable-spec/
├── primitives/
│   ├── field.py (No changes - galois provides FF, FF3, ff3(), ff3_coeffs())
│   ├── ntt.py (Task #1: Simplify to use native galois arrays)
│   ├── batch_inverse.py (Task #2: Already uses galois, minor cleanup)
│   ├── merkle_tree.py (Task #3: Add int conversion at leaf hashing)
│   └── transcript.py (Task #4: Add int conversion at put())
│
├── protocol/
│   ├── steps_params.py (Task #5: Change buffer types to FF/FF3)
│   ├── setup_ctx.py (Task #6: Use FF arrays for x, zi buffers)
│   ├── stark_info.py (Task #7: Store FieldType enum instead of dim int)
│   │
│   ├── witness_generation.py (Task #8: Remove helpers, use galois ops)
│   ├── expression_evaluator.py (Task #9: Eliminate dim branching)
│   ├── stages.py (Task #10: Use FF3 arrays for polynomials)
│   ├── fri.py (Task #11: Use FF3 arrays throughout)
│   ├── pcs.py (Task #12: Simplify with native galois)
│   │
│   ├── prover.py (Task #13: Use typed challenges/evals)
│   ├── verifier.py (Task #14: Typed parsing, eliminate FIELD_EXTENSION)
│   └── proof.py (Task #15: Boundary conversion at serialization)
│
└── tests/
    ├── test_stark_e2e.py (Task #16: Update buffer allocation)
    ├── test_verifier_e2e.py (Task #16: Verify still passes)
    └── conftest.py (Task #16: Update fixtures if needed)
```

### Execution Plan

#### Group A: Primitives Foundation (Execute in parallel)

- [x] **Task #1**: Simplify NTT to use native galois arrays
  - File: `primitives/ntt.py`
  - Agent: `crypto-spec-simplifier`
  - Changes:
    - Input/output types: `FF` arrays (already the case internally)
    - Remove unnecessary reshaping when input is already 2D FF array
    - Keep coset shift logic (r_ multiplication) - this is protocol-specific
    - Keep extend_pol() - orchestrates the extension pipeline
  - Simplify:
    - Remove manual column loops where galois broadcasting works
    - Use `FF.Zeros()` instead of `np.zeros(..., dtype=np.uint64)`
  - Validation: `pytest tests/test_ntt.py -v`

- [x] **Task #2**: Cleanup batch_inverse.py
  - File: `primitives/batch_inverse.py`
  - Agent: `crypto-spec-simplifier`
  - This file already uses galois well
  - Minor: Remove any redundant type conversions
  - Validation: `pytest tests/test_batch_inverse.py -v`

- [x] **Task #3**: Add int conversion at Merkle leaf hashing
  - File: `primitives/merkle_tree.py`
  - Agent: `crypto-spec-simplifier`
  - Changes:
    - `merkelize()`: Accept FF/FF3 arrays, convert to int at FFI boundary
    - `get_query_proof()`: Return values can stay as int (serialization format)
    - Add helper: `_to_int_row(row_data)` for FFI boundary
  - Critical: `linear_hash()` and `hash_seq()` FFI calls MUST receive `List[int]`
  - Validation: `pytest tests/test_fri.py -v`

- [x] **Task #4**: Add int conversion at Transcript.put()
  - File: `primitives/transcript.py`
  - Agent: `crypto-spec-simplifier`
  - Changes:
    - `put()`: Accept `List[int | FF | FF3]`, convert to int internally
    - Add: `def _to_int(v): return int(v) if hasattr(v, '__int__') else v`
  - Keep: Internal state as plain integers (Poseidon2 FFI requirement)
  - Validation: `pytest tests/test_fri.py -v`

#### Group B: Data Structures (Execute after Group A)

- [x] **Task #5**: Change StepsParams buffer types to FF/FF3
  - File: `protocol/steps_params.py`
  - Agent: `crypto-spec-simplifier`
  - Changes:
    ```python
    @dataclass
    class StepsParams:
        # Stage 1 witness (base field)
        trace: FF  # shape (N, n_cols) or (N * n_cols,)

        # Working buffer for stages 2+ (mixed FF and FF3 sections)
        # Keep as uint64 for now - complex multi-section layout
        auxTrace: np.ndarray  # TODO: May need phased migration

        # These are all FF3 (cubic extension challenges/evals)
        challenges: FF3  # shape (n_challenges,)
        evals: FF3  # shape (n_evals,)
        airgroupValues: FF3
        airValues: FF3  # Note: stage 1 values are FF, others FF3 - needs care

        # Constant polynomials (base field)
        constPols: FF  # shape (N, n_constants)
        constPolsExtended: FF  # shape (N_ext, n_constants)
    ```
  - Note: `auxTrace` is complex (multi-section with mixed dims) - may need phased approach
  - Validation: Tests will fail until consumers updated

- [x] **Task #6**: Use FF arrays for ProverHelpers buffers
  - File: `protocol/setup_ctx.py`
  - Agent: `crypto-spec-simplifier`
  - Changes:
    ```python
    class ProverHelpers:
        x: FF  # shape (N_ext,) - coset points
        x_n: FF  # shape (N,) - PIL1 compatibility
        zi: FF  # shape (n_boundaries * N_ext,) - zerofier inverses
    ```
  - Simplify: `compute_x()` using galois cumulative product
  - Remove: FIELD_EXTENSION constant (not needed here)
  - Validation: Depends on Task #5

- [x] **Task #7**: Store FieldType instead of dim int in StarkInfo
  - File: `protocol/stark_info.py`
  - Agent: `crypto-spec-simplifier`
  - Changes:
    ```python
    from enum import Enum
    from typing import Literal

    class FieldType(Enum):
        FF = 1   # Base field
        FF3 = 3  # Cubic extension

    @dataclass
    class PolInfo:
        # ... existing fields ...
        field_type: FieldType  # Replace dim: int

        @property
        def dim(self) -> int:
            """Backwards compatibility."""
            return self.field_type.value
    ```
  - Update all `dim=` assignments to use `field_type=FieldType.FF` or `FieldType.FF3`
  - Validation: `pytest tests/test_stark_info.py -v`

#### Group C: Protocol Core (Execute sequentially - heavy dependencies)

- [x] **Task #8**: Remove helpers from witness_generation.py, use galois ops
  - File: `protocol/witness_generation.py`
  - Agent: `crypto-spec-simplifier`
  - Remove entirely:
    - `_ff3_add()`, `_ff3_mul()`, `_ff3_inv()` - use galois operators
    - `_mul_scalar()` - use galois `*` operator
    - `_mul_columns()` - use galois `*` on arrays
    - `_inv_column()` - use galois `** -1` or batch_inverse
    - `_ff_inv()` - use galois `** -1`
  - Replace patterns:
    ```python
    # Before
    result = _mul_columns(a, b, N, dim)

    # After (dim=1)
    result = a * b  # FF arrays

    # After (dim=3)
    result = a * b  # FF3 arrays - galois handles it
    ```
  - Eliminate: All `if dim == 1: ... else: ...` branches
  - Use: `isinstance(arr, FF3)` if type dispatch truly needed
  - Validation: `pytest tests/test_stark_e2e.py -v` (will fail until more updated)

- [x] **Task #9**: Eliminate dim branching in expression_evaluator.py
  - File: `protocol/expression_evaluator.py`
  - Agent: `crypto-spec-simplifier`
  - Changes:
    - `_load_operand()`: Return `FF | FF3` based on source type, no dim param
    - `_store_result()`: Accept `FF | FF3`, determine storage from type
    - `_multiply_results()`: Use galois `*` directly (handles FF*FF, FF3*FF3, FF*FF3)
    - Remove: `OP_ADD`, `OP_SUB`, `OP_MUL` operation dispatch - use operators
  - Key insight: galois FF3 * FF works via broadcasting (scalar extension)
  - Validation: `pytest tests/test_stark_e2e.py -v`

- [x] **Task #10**: Use FF3 arrays for polynomials in stages.py
  - File: `protocol/stages.py`
  - Agent: `crypto-spec-simplifier`
  - Changes:
    - `computeFriPol()`: Use FF3 arrays for quotient polynomial
    - `computeLEv()`: Use FF3 arrays for Lagrange evaluations
    - `evmap()`: Return FF3 arrays directly
    - `_load_evmap_poly()`: Return FF3 array, no manual encoding
  - Remove: Manual `c0 + c1*p + c2*p²` encoding - use native FF3 arrays
  - Validation: `pytest tests/test_stark_e2e.py -v`

- [x] **Task #11**: Use FF3 arrays throughout fri.py
  - File: `protocol/fri.py`
  - Agent: `crypto-spec-simplifier`
  - Changes:
    - `fold()`: Input/output as FF3 arrays
    - `verify_fold()`: Use FF3 arithmetic directly
    - `_intt_cubic()`: Simplify using native galois operations
  - Remove: `FIELD_EXTENSION` constant - use FF3 type
  - Validation: `pytest tests/test_fri.py -v`

- [x] **Task #12**: Simplify pcs.py with native galois
  - File: `protocol/pcs.py`
  - Agent: `crypto-spec-simplifier`
  - Changes:
    - `prove()`: Work with FF3 polynomial arrays
    - Remove: `FIELD_EXTENSION` constant
    - Merkle calls: Convert to int at boundary
  - Validation: `pytest tests/test_fri.py -v`

#### Group D: Prover/Verifier (Execute after Group C)

- [x] **Task #13**: Use typed challenges/evals in prover.py
  - File: `protocol/prover.py`
  - Agent: `crypto-spec-simplifier`
  - Changes:
    - `gen_proof()`: Work with FF3 challenge/eval arrays
    - Challenge extraction: `challenges[i]` returns FF3 element (not slice)
    - Remove: `* FIELD_EXTENSION` indexing patterns
    - Serialization boundary: Convert at proof dict construction
  - Validation: `pytest tests/test_stark_e2e.py -v`

- [x] **Task #14**: Typed parsing in verifier.py, eliminate FIELD_EXTENSION
  - File: `protocol/verifier.py`
  - Agent: `crypto-spec-simplifier`
  - Changes:
    - `_parse_evals()`: Return FF3 array
    - `_parse_airgroup_values()`: Return FF3 array
    - `_reconstruct_transcript()`: Use FF3 for challenges
    - Remove: All `* FIELD_EXTENSION` and `for j in range(FIELD_EXTENSION)` patterns
    - Remove: `FIELD_EXTENSION` constant
  - Key: This is the largest file - be thorough
  - Validation: `pytest tests/test_verifier_e2e.py -v`

- [x] **Task #15**: Boundary conversion in proof.py serialization
  - File: `protocol/proof.py`
  - Agent: `crypto-spec-simplifier`
  - Changes:
    - `to_bytes_full_from_dict()`: Handle FF/FF3 arrays in proof dict
    - For FF3: Use `.vector()` to get coefficients, flatten with correct ordering
    - `from_bytes_full_to_jproof()`: Can return int (verifier converts later)
  - Keep: JSON serialization as strings (existing format)
  - Validation: `pytest tests/test_proof.py -v && pytest tests/test_stark_e2e.py::TestFullBinaryComparison -v`

#### Group E: Tests (Execute after Group D)

- [x] **Task #16**: Update test buffer allocation
  - Files: `tests/test_stark_e2e.py`, `tests/conftest.py`
  - Agent: `crypto-spec-simplifier`
  - Changes:
    - StepsParams construction: Use `FF.Zeros()`, `FF3.Zeros()` instead of `np.zeros(..., uint64)`
    - Test vector loading: Convert loaded data to FF/FF3 arrays
    - Assertions: May need `np.array_equal()` adjustments for galois arrays
  - Validation: Full test suite `pytest -v`

#### Group F: Final Validation

- [x] **Task #17**: Final E2E validation
  - Run: `cd executable-spec && uv run python -m pytest -v`
  - Verify:
    - [ ] test_verifier_e2e.py passes (Python verifies C++ proofs)
    - [ ] test_stark_e2e.py::TestFullBinaryComparison passes (byte-identical)
    - [ ] All 142 tests pass
  - If failures: Debug and fix specific conversion issues

---

## Implementation Workflow

This plan file serves as the authoritative checklist for implementation. When implementing:

### Required Process
1. **Load Plan**: Read this entire plan file before starting
2. **Sync Tasks**: Create TodoWrite tasks matching the checkboxes above
3. **Execute & Update**: For each task:
   - Mark TodoWrite as `in_progress` when starting
   - Use `crypto-spec-simplifier` agent with task-specific prompt
   - Update checkbox `[ ]` to `[x]` when completing
   - Mark TodoWrite as `completed` when done
4. **Maintain Sync**: Keep this file and TodoWrite synchronized throughout

### Critical Rules
- This plan file is the source of truth for progress
- Update checkboxes in real-time as work progresses
- **Group A tasks can run in parallel**
- **Group B depends on Group A completion**
- **Group C tasks should run sequentially** (heavy interdependencies)
- **Group D depends on Group C**
- Mark tasks complete only when tests pass

### Serialization Boundary Checklist
These 17 locations MUST convert galois types to int:
1. `merkle_tree.py:merkelize()` - leaf hashing
2. `merkle_tree.py:_hash_internal_nodes()` - internal hashing
3. `merkle_tree.py:get_query_proof()` - value extraction
4. `transcript.py:put()` - sponge absorption
5. `transcript.py:_apply_permutation()` - Poseidon2 input
6. `proof.py:to_bytes_full_from_dict()` - binary serialization
7. `proof.py:proof_to_json()` - JSON serialization
8. `prover.py:gen_proof()` - evals_hash computation
9. `prover.py:gen_proof()` - root commitments to transcript
10. `verifier.py:_reconstruct_transcript()` - transcript rebuild
11. `verifier.py:_verify_evaluations()` - constraint checking
12. `pcs.py:prove()` - final_pol hash
13. `pcs.py:prove()` - FRI root commitments
14. `fri.py:merkelize()` - FRI polynomial hashing
15. `stages.py:extendAndMerkelize()` - stage commitment hashing
16. `create-test-vectors.py:compute_final_pol_hash()` - test vector generation
17. `fri_vectors.py` - test vector loading

---

## Risk Mitigation

### If a task breaks tests:
1. Check serialization boundaries - likely missing int conversion
2. Verify galois array shapes match expected layout
3. Check FF3 coefficient ordering (galois uses descending, we use ascending)
4. Temporarily add `print(type(x), x.shape)` debugging

### Common pitfalls:
- **FF3 coefficient order at serialization**: galois `.vector()` returns `[c2, c1, c0]` (descending), C++ expects `[c0, c1, c2]` (ascending). Handle this ONLY in `proof.py` serialization - protocol code treats FF3 as opaque.
- **Broadcasting**: FF3 * FF works, but may need explicit conversion in some cases
- **Shape preservation**: galois operations preserve shapes; verify with `.shape`
- **Integer overflow**: galois handles modular arithmetic, but `int()` conversion must happen before `struct.pack`

### Rollback strategy:
- Each task modifies 1-2 files
- Git commit after each successful task
- If stuck, revert task and try smaller changes
