# Expression Evaluator Performance Optimization Plan

## Executive Summary

The Python executable spec's expression evaluator takes **~350 seconds** for the lookup test (4096 rows), compared to seconds in C++. Profiling reveals two root causes:

1. **Scalar FF3 inversions using Fermat's little theorem**: 3.5ms per inversion (150s total)
2. **Per-row ff3 object creation overhead**: 56% of ops time spent creating objects, not doing math

### Proposed Solution

1. **Batch Montgomery Inversion**: Replace N scalar inversions with 3N-3 multiplications + 1 inversion (47× speedup demonstrated)
2. **Vectorized Field Operations**: Process all N rows per operation using galois arrays instead of row-by-row loops (4× speedup demonstrated)

### Expected Outcome

| Component | Current | Optimized | Speedup |
|-----------|---------|-----------|---------|
| FF3 inversions | ~150s | ~5s | 30× |
| Field ops (creation + arithmetic) | ~70s | ~35s | 2× |
| Other (loads, NTT, etc.) | ~130s | ~100s | 1.3× |
| **Total** | **350s** | **~140s** | **~2.5×** |

Note: Using native FF3 arrays prioritizes code clarity over maximum performance. The coefficient-array approach would be ~4× faster on ops but less readable.

## Goals & Objectives

### Primary Goals
- Reduce lookup test runtime from 350s to <150s (>2× improvement)
- Maintain byte-for-byte proof equivalence with C++ implementation
- Keep code readable as an executable specification

### Secondary Objectives
- Establish patterns for future vectorization work
- Document the Montgomery batch inversion algorithm for educational value
- Minimize code churn - surgical changes to hot paths only

## Solution Overview

### Approach

The optimization targets two specific hot paths in `protocol/expression_evaluator.py`:

1. **`_get_inverse_polynomial`**: Currently does N scalar `ff3 ** -1` operations. Replace with Montgomery batch inversion that does 3N-3 multiplications + 1 inversion.

2. **`_goldilocks3_op_pack` / `_goldilocks3_op_31_pack`**: Currently create 2 ff3 objects per row. Replace with vectorized operations on coefficient arrays using galois FF arrays.

### Key Components

1. **`primitives/batch_inverse.py`** (NEW): Montgomery batch inversion for FF and FF3
2. **`protocol/expression_evaluator.py`** (MODIFY): Vectorized operation methods
3. **`protocol/witness_generation.py`** (MODIFY): Use batch inversion for column operations

### Data Flow

Current (per-row):
```
for each row:
    a = ff3([...])      # Create object - SLOW
    b = ff3([...])      # Create object - SLOW
    result = a * b      # Fast
    extract coeffs      # SLOW
```

Optimized (vectorized):
```
a0, a1, a2 = FF(col0), FF(col1), FF(col2)  # Create arrays once
b0, b1, b2 = FF(col0), FF(col1), FF(col2)  # Create arrays once
c0, c1, c2 = ff3_mul_vectorized(a, b)       # Single vectorized op
```

### Architecture: SoA Layout Compatibility

The current code uses Structure-of-Arrays (SoA) layout which is ideal for vectorization:
```
values buffer: [e0_row0..e0_rowN, e1_row0..e1_rowN, e2_row0..e2_rowN]
```

This means coefficient arrays are already contiguous in memory.

## Implementation Tasks

### CRITICAL IMPLEMENTATION RULES
1. **NO PLACEHOLDER CODE**: Every implementation must be production-ready
2. **MAINTAIN PROOF EQUIVALENCE**: All tests must pass after each task
3. **SURGICAL CHANGES**: Only modify the specific hot paths identified

### Visual Dependency Tree

```
primitives/
├── batch_inverse.py (Task #1: Montgomery batch inversion for FF and FF3)
├── field.py (unchanged - already has FF, FF3, ff3, ff3_coeffs)
│
protocol/
├── expression_evaluator.py
│   ├── _get_inverse_polynomial (Task #2: Use batch inversion)
│   ├── _goldilocks_op_pack (Task #3: Vectorize base field ops)
│   ├── _goldilocks3_op_pack (Task #4: Vectorize FF3 ops via coefficient arrays)
│   └── _goldilocks3_op_31_pack (Task #4: Vectorize FF3×FF ops)
│
├── witness_generation.py
│   └── _field_inverse_column (Task #5: Use batch inversion)
│
tests/
└── test_batch_inverse.py (Task #1: Unit tests for batch inversion)
```

### Execution Plan

#### Group A: Foundation (Execute in parallel)

- [ ] **Task #1a**: Create batch inversion module with unit tests
  - Folder: `primitives/`
  - File: `batch_inverse.py`
  - Implements:
    ```python
    def batch_inverse_ff(values: List[FF]) -> List[FF]:
        """Montgomery batch inversion for base field.

        Inverts N elements using 3N-3 multiplications + 1 inversion.

        Algorithm:
        1. Forward pass: cumprods[i] = values[0] * ... * values[i]
        2. Single inversion: inv_total = cumprods[-1] ** -1
        3. Backward pass: results[i] = inv_total * cumprods[i-1]

        Args:
            values: List of FF elements to invert (must be non-zero)

        Returns:
            List of FF elements where result[i] = values[i]^(-1)
        """

    def batch_inverse_ff3(values: List[FF3]) -> List[FF3]:
        """Montgomery batch inversion for cubic extension field.

        Same algorithm as batch_inverse_ff but for FF3 elements.
        """
    ```
  - Exports: `batch_inverse_ff`, `batch_inverse_ff3`
  - Test file: `tests/test_batch_inverse.py`
    - Test correctness: `batch_inverse(values)[i] * values[i] == 1`
    - Test edge cases: single element, two elements
    - Test performance: 4096 elements should complete in <1s
  - Context: Core primitive used by expression evaluator and witness generation

#### Group B: Expression Evaluator Optimization (Execute sequentially)

- [ ] **Task #2**: Integrate batch inversion into `_get_inverse_polynomial`
  - Folder: `protocol/`
  - File: `expression_evaluator.py`
  - Method: `_get_inverse_polynomial` (lines 817-854)
  - Current signature:
    ```python
    def _get_inverse_polynomial(self, nrows_pack: int, dest_vals: np.ndarray,
                                buff_helper: np.ndarray, batch: bool, dim: int):
    ```
  - Changes:
    - Import `batch_inverse_ff`, `batch_inverse_ff3` from `primitives.batch_inverse`
    - When `nrows_pack > 1`, use batch inversion instead of loop
    - For `dim == 1`:
      ```python
      ff_vals = [FF(int(dest_vals[i])) for i in range(nrows_pack)]
      ff_invs = batch_inverse_ff(ff_vals)
      for i in range(nrows_pack):
          dest_vals[i] = int(ff_invs[i])
      ```
    - For `dim == 3`:
      ```python
      # Convert SoA to list of ff3
      ff3_vals = [ff3([int(dest_vals[i + d*nrows_pack]) for d in range(3)])
                  for i in range(nrows_pack)]
      ff3_invs = batch_inverse_ff3(ff3_vals)
      # Convert back to SoA
      for i in range(nrows_pack):
          coeffs = ff3_coeffs(ff3_invs[i])
          for d in range(3):
              dest_vals[i + d*nrows_pack] = coeffs[d]
      ```
  - Verification: Run `pytest tests/test_stark_e2e.py -k simple -v` - must pass
  - Expected impact: ~47× speedup on inversions (150s → 3s)

- [ ] **Task #3**: Vectorize base field operations in `_goldilocks_op_pack`
  - Folder: `protocol/`
  - File: `expression_evaluator.py`
  - Method: `_goldilocks_op_pack` (lines 935-963)
  - Current implementation (loop-based):
    ```python
    for i in range(nrows_pack):
        a_val = FF(int(a[0]) if is_constant_a else int(a[i]))
        b_val = FF(int(b[0]) if is_constant_b else int(b[i]))
        if op == 0:  dest[i] = int(a_val + b_val)
        # ...
    ```
  - New implementation (vectorized):
    ```python
    # Handle constant vs array operands
    if is_constant_a:
        ff_a = FF(int(a[0]))
    else:
        ff_a = FF(np.asarray(a[:nrows_pack], dtype=np.uint64))

    if is_constant_b:
        ff_b = FF(int(b[0]))
    else:
        ff_b = FF(np.asarray(b[:nrows_pack], dtype=np.uint64))

    # Single vectorized operation
    if op == 0:    ff_result = ff_a + ff_b
    elif op == 1:  ff_result = ff_a - ff_b
    elif op == 2:  ff_result = ff_a * ff_b
    elif op == 3:  ff_result = ff_b - ff_a

    # Store result
    dest[:nrows_pack] = np.asarray(ff_result, dtype=np.uint64)
    ```
  - Verification: Run `pytest tests/test_stark_e2e.py -k simple -v` - must pass
  - Expected impact: Minor (base field ops are already fast)

- [ ] **Task #4**: Vectorize cubic extension operations using native FF3 arrays
  - Folder: `protocol/`
  - File: `expression_evaluator.py`
  - Methods: `_goldilocks3_op_pack` (lines 966-1007), `_goldilocks3_op_31_pack` (lines 1010-1049)
  - Approach: Use native galois FF3 arrays for clarity, even at some performance cost
  - Helper functions needed in `primitives/field.py`:
    ```python
    def soa_to_ff3_array(soa: np.ndarray, nrows: int) -> FF3:
        """Convert SoA layout to FF3 array.

        Args:
            soa: Array in SoA layout [c0_0..c0_n, c1_0..c1_n, c2_0..c2_n]
            nrows: Number of rows

        Returns:
            FF3 array of length nrows
        """
        p = GOLDILOCKS_PRIME
        # Galois uses descending order internally, but we can construct via integer encoding
        ints = [int(soa[i]) + int(soa[i + nrows]) * p + int(soa[i + 2*nrows]) * p**2
                for i in range(nrows)]
        return FF3(ints)

    def ff3_array_to_soa(arr: FF3, dest: np.ndarray, nrows: int) -> None:
        """Convert FF3 array back to SoA layout in dest buffer.

        Args:
            arr: FF3 array of length nrows
            dest: Destination buffer (must have space for 3*nrows elements)
            nrows: Number of rows
        """
        vecs = arr.vector()  # Shape (nrows, 3) in descending order [c2, c1, c0]
        for i in range(nrows):
            dest[i] = int(vecs[i, 2])              # c0
            dest[i + nrows] = int(vecs[i, 1])      # c1
            dest[i + 2*nrows] = int(vecs[i, 0])    # c2
    ```
  - New implementation for `_goldilocks3_op_pack`:
    ```python
    def _goldilocks3_op_pack(self, nrows_pack, op, dest, a, is_constant_a, b, is_constant_b):
        from primitives.field import soa_to_ff3_array, ff3_array_to_soa, FF3, ff3

        # Convert SoA to FF3 arrays
        if is_constant_a:
            # Single element, broadcast
            ff3_a = ff3([int(a[0]), int(a[nrows_pack]), int(a[2*nrows_pack])])
        else:
            ff3_a = soa_to_ff3_array(a, nrows_pack)

        if is_constant_b:
            ff3_b = ff3([int(b[0]), int(b[nrows_pack]), int(b[2*nrows_pack])])
        else:
            ff3_b = soa_to_ff3_array(b, nrows_pack)

        # Single vectorized operation
        if op == 0:    ff3_result = ff3_a + ff3_b
        elif op == 1:  ff3_result = ff3_a - ff3_b
        elif op == 2:  ff3_result = ff3_a * ff3_b
        elif op == 3:  ff3_result = ff3_b - ff3_a
        else:
            raise ValueError(f"Invalid operation: {op}")

        # Convert back to SoA layout
        if is_constant_a and is_constant_b:
            # Result is scalar, extract coefficients
            coeffs = ff3_coeffs(ff3_result)
            dest[0] = coeffs[0]
            dest[nrows_pack] = coeffs[1]
            dest[2*nrows_pack] = coeffs[2]
        else:
            ff3_array_to_soa(ff3_result, dest, nrows_pack)
    ```
  - New implementation for `_goldilocks3_op_31_pack` (FF3 × FF → FF3):
    ```python
    def _goldilocks3_op_31_pack(self, nrows_pack, op, dest, a, is_constant_a, b, is_constant_b):
        from primitives.field import soa_to_ff3_array, ff3_array_to_soa, FF3, FF, ff3

        # Convert a (FF3) from SoA
        if is_constant_a:
            ff3_a = ff3([int(a[0]), int(a[nrows_pack]), int(a[2*nrows_pack])])
        else:
            ff3_a = soa_to_ff3_array(a, nrows_pack)

        # Convert b (FF scalar) - embed in FF3 as (b, 0, 0)
        if is_constant_b:
            ff3_b = ff3([int(b[0]), 0, 0])
        else:
            # Create FF3 array with b values in coefficient 0, zeros elsewhere
            p = GOLDILOCKS_PRIME
            ints = [int(b[i]) for i in range(nrows_pack)]  # Just c0, c1=c2=0
            ff3_b = FF3(ints)

        # Single vectorized operation
        if op == 0:    ff3_result = ff3_a + ff3_b
        elif op == 1:  ff3_result = ff3_a - ff3_b
        elif op == 2:  ff3_result = ff3_a * ff3_b
        elif op == 3:  ff3_result = ff3_b - ff3_a
        else:
            raise ValueError(f"Invalid operation: {op}")

        # Convert back to SoA layout
        if is_constant_a and is_constant_b:
            coeffs = ff3_coeffs(ff3_result)
            dest[0] = coeffs[0]
            dest[nrows_pack] = coeffs[1]
            dest[2*nrows_pack] = coeffs[2]
        else:
            ff3_array_to_soa(ff3_result, dest, nrows_pack)
    ```
  - Verification: Run `pytest tests/test_stark_e2e.py -v` - ALL tests must pass
  - Expected impact: ~2× speedup on FF3 ops (eliminates per-row object creation overhead)

#### Group C: Witness Generation Optimization (After Group B)

- [ ] **Task #5**: Use batch inversion in witness generation
  - Folder: `protocol/`
  - File: `witness_generation.py`
  - Function: `_field_inverse_column` (lines 171-193)
  - Current implementation:
    ```python
    def _field_inverse_column(a: np.ndarray, N: int, dim: int) -> np.ndarray:
        result = np.zeros(N * dim, dtype=np.uint64)
        if dim == 1:
            for i in range(N):
                result[i] = _goldilocks_inv(int(a[i]))
        else:
            for i in range(N):
                result[i * dim:(i + 1) * dim] = _goldilocks3_inv(a[i * dim:(i + 1) * dim])
        return result
    ```
  - New implementation:
    ```python
    from primitives.batch_inverse import batch_inverse_ff, batch_inverse_ff3

    def _field_inverse_column(a: np.ndarray, N: int, dim: int) -> np.ndarray:
        result = np.zeros(N * dim, dtype=np.uint64)
        if dim == 1:
            ff_vals = [FF(int(a[i])) for i in range(N)]
            ff_invs = batch_inverse_ff(ff_vals)
            for i in range(N):
                result[i] = int(ff_invs[i])
        else:
            ff3_vals = [ff3([int(a[i*dim + d]) for d in range(dim)]) for i in range(N)]
            ff3_invs = batch_inverse_ff3(ff3_vals)
            for i in range(N):
                coeffs = ff3_coeffs(ff3_invs[i])
                for d in range(dim):
                    result[i * dim + d] = coeffs[d]
        return result
    ```
  - Verification: Run `pytest tests/test_stark_e2e.py -v` - ALL tests must pass

#### Group D: Cleanup (After Group C)

- [ ] **Task #6**: Remove timing instrumentation
  - Files to modify:
    - `protocol/prover.py`: Remove `[TIMING]` print statements
    - `protocol/stages.py`: Remove timing code from `extendAndMerkelize`
    - `protocol/pcs.py`: Remove timing from `prove`
    - `protocol/fri.py`: Remove timing from `fold` and `merkelize`
    - `protocol/expression_evaluator.py`: Remove timing from `calculate_expressions`
    - `protocol/witness_generation.py`: Remove timing from `calculate_witness_std`
    - `primitives/merkle_tree.py`: Remove timing from `merkelize`
    - `primitives/ntt.py`: Remove timing from `extend_pol`
  - Keep the code structure clean for the executable spec
  - Verification: Run full test suite, grep for `[TIMING]` - should find nothing

---

## Implementation Workflow

This plan file serves as the authoritative checklist for implementation. When implementing:

### Required Process
1. **Load Plan**: Read this entire plan file before starting
2. **Sync Tasks**: Create TodoWrite tasks matching the checkboxes below
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
- Run tests after EACH task to ensure no regressions

### Progress Tracking
The checkboxes above represent the authoritative status of each task. Keep them updated as you work.

---

## Appendix: Montgomery Batch Inversion Algorithm

For elements `a[0], a[1], ..., a[N-1]`:

```
1. Forward pass - Compute prefix products:
   tmp[0] = a[0]
   tmp[i] = tmp[i-1] * a[i]  for i = 1..N-1

2. Single inversion:
   z = tmp[N-1]^(-1)

3. Backward pass - Extract individual inverses:
   for i = N-1 down to 1:
       z2 = z * a[i]
       result[i] = z * tmp[i-1]
       z = z2
   result[0] = z
```

**Complexity**: 3N-3 multiplications + 1 inversion (vs N inversions)

## Appendix: FF3 Array Conversion (SoA ↔ Galois)

The expression evaluator uses SoA (Structure of Arrays) layout:
```
[c0_row0, c0_row1, ..., c0_rowN,   <- coefficient 0 for all rows
 c1_row0, c1_row1, ..., c1_rowN,   <- coefficient 1 for all rows
 c2_row0, c2_row1, ..., c2_rowN]   <- coefficient 2 for all rows
```

Galois FF3 uses integer encoding internally: `value = c0 + c1*p + c2*p^2`

**SoA → FF3 array:**
```python
ints = [soa[i] + soa[i+N]*p + soa[i+2*N]*p**2 for i in range(N)]
ff3_arr = FF3(ints)
```

**FF3 array → SoA:**
```python
vecs = ff3_arr.vector()  # Shape (N, 3), descending order [c2, c1, c0]
for i in range(N):
    dest[i] = vecs[i, 2]        # c0
    dest[i + N] = vecs[i, 1]    # c1
    dest[i + 2*N] = vecs[i, 0]  # c2
```

Note: Galois `.vector()` returns coefficients in **descending** order `[c2, c1, c0]`, opposite of our ascending convention.
