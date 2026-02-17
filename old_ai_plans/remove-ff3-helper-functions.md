# Remove ff3_scalar and ff3_from_ff Helper Functions

## Executive Summary

The `ff3_scalar()` and `ff3_from_ff()` functions in `primitives/field.py` are unnecessary wrapper functions around the `FF3()` constructor. They add indirection without adding clarity. This plan removes them and replaces all usages with direct constructor calls.

**Problem:** Created wrapper functions instead of using constructors directly.

**Solution:** Delete the functions, use `FF3()` constructor directly everywhere.

**Scope:** 96 usages across 7 files.

## Goals & Objectives

### Primary Goals
- Remove `ff3_scalar()` and `ff3_from_ff()` from `primitives/field.py`
- Replace all 96 usages with direct `FF3()` constructor calls
- All 164 tests must continue to pass

### Secondary Objectives
- Code is more explicit about what it's doing
- No unnecessary abstraction layers

## Solution Overview

### Replacement Patterns

**Pattern 1: `ff3_scalar(value)` (scalar) →**
```python
ff3([value % GOLDILOCKS_PRIME, 0, 0])
```

**Pattern 2: `ff3_scalar(value, n)` (array) →**
```python
FF3(np.full(n, value % GOLDILOCKS_PRIME, dtype=np.uint64))
```

**Pattern 3: `ff3_from_ff(arr)` (type conversion) →**
```python
arr if type(arr) == FF3 else FF3(np.asarray(arr, dtype=np.uint64))
```

### Expected Outcomes
- `ff3_scalar` and `ff3_from_ff` no longer exist
- All code uses `FF3()` constructor directly
- Tests pass unchanged

## Implementation Tasks

### Visual Dependency Tree

```
executable-spec/
├── primitives/
│   └── field.py (Task #1: Delete ff3_scalar and ff3_from_ff definitions)
│
├── constraints/
│   ├── base.py (Task #2: Update compress_2col to use FF3 directly)
│   ├── simple_left.py (Task #3: Replace all ff3_scalar/ff3_from_ff calls)
│   ├── lookup2_12.py (Task #3: Replace all ff3_scalar/ff3_from_ff calls)
│   └── permutation1_6.py (Task #3: Replace all ff3_scalar/ff3_from_ff calls)
│
└── witness/
    ├── simple_left.py (Task #4: Replace all ff3_scalar calls)
    ├── lookup2_12.py (Task #4: Replace all ff3_scalar calls)
    └── permutation1_6.py (Task #4: Replace all ff3_scalar calls)
```

### Execution Plan

#### Group A: Delete Definitions

- [x] **Task #1**: Delete `ff3_scalar` and `ff3_from_ff` from `primitives/field.py`
  - File: `executable-spec/primitives/field.py`
  - Delete lines 86-113 (both function definitions)
  - Keep all other functions unchanged

#### Group B: Update Constraints (Execute in parallel)

- [x] **Task #2**: Update `constraints/base.py`
  - File: `executable-spec/constraints/base.py`
  - Remove `ff3_scalar` from import on line 25
  - Add `import numpy as np` and `GOLDILOCKS_PRIME` to imports
  - Update `compress_2col` function (line 35):
    ```python
    # Before:
    return (col2 * alpha + col1) * alpha + ff3_scalar(busid, n) + gamma

    # After:
    busid_arr = FF3(np.full(n, busid % GOLDILOCKS_PRIME, dtype=np.uint64)) if n else ff3([busid % GOLDILOCKS_PRIME, 0, 0])
    return (col2 * alpha + col1) * alpha + busid_arr + gamma
    ```

- [x] **Task #3a**: Update `constraints/simple_left.py`
  - File: `executable-spec/constraints/simple_left.py`
  - Update import: remove `ff3_scalar, ff3_from_ff`, add `ff3, GOLDILOCKS_PRIME`, add `import numpy as np`
  - Replace `_compress_1col` helper:
    ```python
    def _compress_1col(busid: int, col, alpha, gamma):
        busid_scalar = ff3([busid % GOLDILOCKS_PRIME, 0, 0])
        return col * alpha + busid_scalar + gamma
    ```
  - Replace all `ff3_from_ff(x)` with inline conversion:
    ```python
    # Before:
    a = ff3_from_ff(ctx.col('a'))

    # After:
    a_raw = ctx.col('a')
    a = a_raw if type(a_raw) == FF3 else FF3(np.asarray(a_raw, dtype=np.uint64))
    ```
  - Replace all `ff3_scalar(value, n)` with:
    ```python
    FF3(np.full(n, value % GOLDILOCKS_PRIME, dtype=np.uint64))
    ```

- [x] **Task #3b**: Update `constraints/lookup2_12.py`
  - Same pattern as Task #3a
  - 17 `ff3_from_ff` calls to replace
  - 7 `ff3_scalar` calls to replace

- [x] **Task #3c**: Update `constraints/permutation1_6.py`
  - Same pattern as Task #3a
  - 17 `ff3_from_ff` calls to replace
  - 8 `ff3_scalar` calls to replace

#### Group C: Update Witnesses (Execute in parallel after Group B)

- [x] **Task #4a**: Update `witness/simple_left.py`
  - File: `executable-spec/witness/simple_left.py`
  - Update import: remove `ff3_scalar`, add `ff3, GOLDILOCKS_PRIME`, keep `import numpy as np` (already has it via batch_inverse)
  - Replace scalar usages (`ff3_scalar(value)` without n):
    ```python
    # Before:
    k[2] - ff3_scalar(1)

    # After:
    k[2] - ff3([1, 0, 0])
    ```
  - Replace array usages (`ff3_scalar(value, n)`):
    ```python
    # Before:
    neg_one = ff3_scalar(-1, n)

    # After:
    neg_one = FF3(np.full(n, (-1) % GOLDILOCKS_PRIME, dtype=np.uint64))
    ```

- [x] **Task #4b**: Update `witness/lookup2_12.py`
  - Same pattern as Task #4a
  - 4 `ff3_scalar` calls to replace

- [x] **Task #4c**: Update `witness/permutation1_6.py`
  - Same pattern as Task #4a
  - 5 `ff3_scalar` calls to replace

#### Group D: Verify

- [x] **Task #5**: Run full test suite
  - Run: `./run-tests.sh`
  - Verify: All 164 tests pass

---

## Implementation Workflow

### Required Process
1. **Load Plan**: Read this entire plan file before starting
2. **Execute sequentially**: Task #1 first (delete definitions), then Groups B/C in parallel, then Task #5
3. **Update checkboxes**: Mark `[x]` when each task completes

### Critical Rules
- Do NOT create new helper functions
- Use `FF3()` constructor directly
- Keep the type check inline for `ff3_from_ff` replacements (needed for verifier context)
- Run tests after each group to catch issues early
