# Consolidate Constraints and Witnesses Boilerplate

## Executive Summary

The constraints and witnesses modules contain significant code duplication across three AIR-specific implementations (SimpleLeft, Lookup2_12, Permutation1_6). Analysis identified:

- **~170-200 lines of duplicate helper functions** (identical code in 3 files)
- **Repeated algorithmic patterns** (cumulative sums, constraint combination, mode detection)
- **Wrapper functions instead of proper constructors** (e.g., `_ff_to_ff3()` wrapping `FF3()`)

**Solution**: Add proper constructors to `field.py` for FF3 conversions, then call them directly from constraint/witness code. Add concrete helper methods to base classes for algorithmic patterns. No wrapper functions - direct constructor calls for clarity.

**Cost Assessment**: Zero runtime cost. Adding constructors to `field.py` is equivalent to the current wrapper functions. Base class methods have identical cost to inline code.

## Goals & Objectives

### Primary Goals
- Eliminate ~150-170 lines of duplicated code across 6 files
- Add proper constructors to `field.py` for FF3 conversions (clarity over wrappers)
- Add concrete helper methods to base classes for reusable algorithmic patterns

### Secondary Objectives
- Improve maintainability (fix a bug once, not 3 times)
- Make AIR-specific implementations more focused on their unique logic
- Preserve all existing behavior (tests must pass unchanged)

## Solution Overview

### Approach

1. **Add constructors to `field.py`** - Instead of wrapper functions like `_ff_to_ff3()`, add proper constructors `ff3_scalar()` and `ff3_from_ff()` to `field.py`. Call these directly - no intermediary functions.

2. **Add concrete methods to base classes** - The `ConstraintModule` and `WitnessModule` base classes are purely abstract. Add concrete helper methods that subclasses can call: `_combine_constraints()`, `_compute_cumulative_sum()`, etc.

3. **Remove all duplicate helper functions** - Delete the local `_ff3_scalar`, `_ff_to_ff3`, `_compress_exprs`, `_compute_logup_term` from each AIR implementation.

### Key Components

1. **`primitives/field.py`**: Add `ff3_scalar(value, n=None)` and `ff3_from_ff(arr)` constructors.

2. **`constraints/base.py`**: Add `_combine_constraints()` as concrete method. Add `compress_2col()` as module function.

3. **`witness/base.py`**: Add `compress_exprs()`, `compute_logup_term()` as module functions. Add `_compute_cumulative_sum()`, `_compute_cumulative_product()` as concrete methods.

4. **AIR implementations**: Remove duplicated functions, import constructors from `field.py`, use inherited helper methods.

### Expected Outcomes
- `constraints/simple_left.py`: ~200 → ~160 lines (-40 lines)
- `constraints/lookup2_12.py`: ~180 → ~140 lines (-40 lines)
- `constraints/permutation1_6.py`: ~190 → ~150 lines (-40 lines)
- `witness/simple_left.py`: ~250 → ~200 lines (-50 lines)
- `witness/lookup2_12.py`: ~205 → ~165 lines (-40 lines)
- `witness/permutation1_6.py`: ~210 → ~170 lines (-40 lines)

## Implementation Tasks

### CRITICAL IMPLEMENTATION RULES
1. **NO PLACEHOLDER CODE**: Every implementation must be production-ready.
2. **TESTS MUST PASS**: All 164 tests must pass after each task. Run `./run-tests.sh` after each change.
3. **PRESERVE BEHAVIOR**: This is a pure refactor - no behavioral changes.
4. **NO WRAPPER FUNCTIONS**: Use constructors directly, not functions that call constructors.

### Visual Dependency Tree

```
executable-spec/
├── primitives/
│   └── field.py (Task #1: Add ff3_scalar and ff3_from_ff constructors)
│
├── constraints/
│   ├── base.py (Task #2: Add compress_2col function and _combine_constraints method)
│   ├── simple_left.py (Task #3: Remove duplicates, use constructors directly)
│   ├── lookup2_12.py (Task #3: Remove duplicates, use constructors directly)
│   └── permutation1_6.py (Task #3: Remove duplicates, use constructors directly)
│
├── witness/
│   ├── base.py (Task #4: Add compress_exprs, compute_logup_term, cumulative methods)
│   ├── simple_left.py (Task #5: Remove duplicates, use constructors directly)
│   ├── lookup2_12.py (Task #5: Remove duplicates, use constructors directly)
│   └── permutation1_6.py (Task #5: Remove duplicates, use constructors directly)
│
└── tests/
    └── (run full suite after each task to verify no regressions)
```

### Execution Plan

#### Group A: Add Constructors to field.py (Foundation)

- [x] **Task #1**: Add FF3 constructors to `primitives/field.py`
  - Folder: `executable-spec/primitives/`
  - File: `field.py`
  - Add after line 83 (`ff3_array_from_base`):
    ```python
    def ff3_scalar(value: int, n: int = None) -> FF3:
        """Create FF3 scalar or constant array.

        Args:
            value: Integer value (handles negatives via modular reduction)
            n: If None, return scalar. If int, return array of length n.

        Returns:
            FF3 scalar (n=None) or FF3 array filled with value (n>0)
        """
        val = value % GOLDILOCKS_PRIME
        if n is None:
            return ff3([val, 0, 0])
        return FF3(np.full(n, val, dtype=np.uint64))


    def ff3_from_ff(arr) -> FF3:
        """Convert FF array to FF3 array (embed base field in extension).

        If arr is already FF3, returns it unchanged (no copy).
        Otherwise, embeds base field values as (val, 0, 0) in FF3.
        """
        if type(arr) == FF3:
            return arr
        return FF3(np.asarray(arr, dtype=np.uint64))
    ```
  - Update exports in module docstring if needed
  - Run tests: `./run-tests.sh unit` (quick sanity check)

#### Group B: Constraints Module Consolidation

- [x] **Task #2**: Add helper function and concrete method to `constraints/base.py`
  - Folder: `executable-spec/constraints/`
  - File: `base.py`
  - Add import: `from primitives.field import ff3_scalar`
  - Add module-level function:
    ```python
    def compress_2col(busid: int, col1, col2, alpha, gamma, n: int = None):
        """Compress 2-column expression: ((col2*α + col1)*α + busid) + γ."""
        return (col2 * alpha + col1) * alpha + ff3_scalar(busid, n) + gamma
    ```
  - Add concrete method to `ConstraintModule` class:
    ```python
    def _combine_constraints(self, constraints, vc):
        """Combine constraint list using standard accumulation pattern.

        Computes: ((constraints[0] * vc + constraints[1]) * vc + ...) + constraints[-1]
        """
        acc = constraints[0] * vc
        for i in range(1, len(constraints) - 1):
            acc = (acc + constraints[i]) * vc
        acc = acc + constraints[-1]
        return acc
    ```
  - Keep `constraint_polynomial` as abstract method
  - Exports: `compress_2col` (module function), `ConstraintModule` (class)

- [x] **Task #3**: Update constraint implementations to use constructors directly
  - Folder: `executable-spec/constraints/`
  - Files: `simple_left.py`, `lookup2_12.py`, `permutation1_6.py`
  - For each file:
    1. Update imports:
       ```python
       from primitives.field import ff3_scalar, ff3_from_ff
       from .base import compress_2col, ConstraintModule
       ```
    2. Delete local `_ff3_scalar` function (~13 lines)
    3. Delete local `_ff_to_ff3` function (~10 lines)
    4. Delete local `_compress_2col` function (~4 lines)
    5. Replace all calls:
       - `_ff3_scalar(x, n)` → `ff3_scalar(x, n)`
       - `_ff_to_ff3(col)` → `ff3_from_ff(col)`
       - `_compress_2col(...)` → `compress_2col(...)`
    6. Replace constraint combination at end of `constraint_polynomial()`:
       ```python
       # BEFORE:
       acc = constraints[0] * vc
       for i in range(1, len(constraints) - 1):
           acc = (acc + constraints[i]) * vc
       acc = acc + constraints[-1]
       return acc

       # AFTER:
       return self._combine_constraints(constraints, vc)
       ```
  - Run tests: `./run-tests.sh constraints`
  - Expected: ~27 lines removed from each file

#### Group C: Witness Module Consolidation

- [x] **Task #4**: Add helper functions and concrete methods to `witness/base.py`
  - Folder: `executable-spec/witness/`
  - File: `base.py`
  - Add imports:
    ```python
    from primitives.field import FF3, ff3_scalar, GOLDILOCKS_PRIME
    from primitives.field import batch_inverse
    import numpy as np
    ```
  - Add module-level functions:
    ```python
    def compress_exprs(busid: int, cols, alpha, gamma):
        """Compute denominator: busid + col1*α + col2*α² + ... + γ."""
        n = len(cols[0])
        result = ff3_scalar(busid, n)
        alpha_power = alpha
        for col in cols:
            result = result + col * alpha_power
            alpha_power = alpha_power * alpha
        return result + gamma


    def compute_logup_term(busid: int, cols, selector, alpha, gamma):
        """Compute a single logup term: selector / (compressed_exprs + γ)."""
        denominator = compress_exprs(busid, cols, alpha, gamma)
        n = len(cols[0])

        if isinstance(selector, int):
            numerator = ff3_scalar(selector, n)
        else:
            numerator = selector

        return numerator * batch_inverse(denominator)
    ```
  - Add concrete methods to `WitnessModule` class:
    ```python
    def _compute_cumulative_sum(self, row_values):
        """Compute cumulative sum: result[i] = sum(row_values[0:i+1])."""
        result = row_values.copy()
        for i in range(1, len(row_values)):
            result[i] = result[i - 1] + row_values[i]
        return result

    def _compute_cumulative_product(self, row_values):
        """Compute cumulative product: result[i] = prod(row_values[0:i+1])."""
        result = row_values.copy()
        for i in range(1, len(row_values)):
            result[i] = result[i - 1] * row_values[i]
        return result
    ```
  - Keep `compute_intermediates` and `compute_grand_sums` as abstract methods

- [x] **Task #5**: Update witness implementations to use constructors directly
  - Folder: `executable-spec/witness/`
  - Files: `simple_left.py`, `lookup2_12.py`, `permutation1_6.py`
  - For each file:
    1. Update imports:
       ```python
       from primitives.field import ff3_scalar
       from .base import compress_exprs, compute_logup_term, WitnessModule
       ```
    2. Delete local `_compress_exprs` function (~10 lines)
    3. Delete local `_compute_logup_term` function (~12 lines)
    4. Replace `FF3(np.full(n, value, dtype=np.uint64))` → `ff3_scalar(value, n)`
    5. Replace cumulative sum loops:
       ```python
       # BEFORE:
       gsum = row_sum.copy()
       for i in range(1, n):
           gsum[i] = gsum[i - 1] + row_sum[i]

       # AFTER:
       gsum = self._compute_cumulative_sum(row_sum)
       ```
    6. For `permutation1_6.py`, also replace cumulative product loop:
       ```python
       # BEFORE:
       gprod = inv_denom.copy()
       for i in range(1, n):
           gprod[i] = gprod[i - 1] * inv_denom[i]

       # AFTER:
       gprod = self._compute_cumulative_product(inv_denom)
       ```
  - Run tests: `./run-tests.sh witness`
  - Expected: ~22 lines removed from each file

#### Group D: Final Verification

- [x] **Task #6**: Run full test suite and verify no regressions
  - Run: `./run-tests.sh` (all 164 tests)
  - Verify: All tests pass
  - Check: No behavioral changes (proofs should be byte-identical to before)

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
- Run tests after each task to catch regressions early

### Progress Tracking
The checkboxes above represent the authoritative status of each task. Keep them updated as you work.

---

## Appendix: Detailed Code Analysis

### Constraints Module - Duplicate Helper Functions

| Function | SimpleLeft | Lookup2_12 | Permutation1_6 | Lines Each |
|----------|------------|------------|----------------|------------|
| `_ff3_scalar` | lines 23-35 | lines 30-40 | lines 29-41 | ~13 |
| `_ff_to_ff3` | lines 38-47 | lines 43-52 | lines 44-53 | ~10 |
| `_compress_2col` | lines 55-57 | lines 55-57 | lines 56-58 | ~4 |
| Constraint combo | lines 178-182 | lines 171-175 | lines 167-171 | ~5 |

### Witness Module - Duplicate Helper Functions

| Function | SimpleLeft | Lookup2_12 | Permutation1_6 | Lines Each |
|----------|------------|------------|----------------|------------|
| `_compress_exprs` | lines 38-47 | lines 28-37 | lines 29-38 | ~10 |
| `_compute_logup_term` | lines 50-60 | lines 40-58 | lines 41-59 | ~12 |
| Cumulative sum | lines 243-247 | lines 200-204 | lines 194-197 | ~5 |

### Why Constructors in field.py

Adding `ff3_scalar()` and `ff3_from_ff()` to `field.py` is the right approach because:

1. **Clarity**: `ff3_scalar(5, n)` clearly constructs an FF3 value. No indirection through wrapper functions.

2. **Single source of truth**: `field.py` already has `ff3()`, `ff3_array()`, `ff3_from_base()`, etc. These new constructors belong with them.

3. **Zero runtime cost**: Calling `ff3_scalar(5, n)` has identical cost to calling a local `_ff3_scalar(5, n)` that does the same thing. Python function call overhead is the same either way.

4. **Proper layering**: Primitive constructors live in `primitives/field.py`. Protocol-specific logic lives in `constraints/` and `witness/`. This keeps the dependency direction clean.
