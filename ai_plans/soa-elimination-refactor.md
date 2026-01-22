# SoA Elimination Refactor - Implementation Plan

## Executive Summary

### Problem Statement
The Python executable spec's expression evaluator uses a Structure-of-Arrays (SoA) layout for FF3 (cubic extension field) values, mirroring the C++ implementation's memory layout for SIMD optimization. This layout:
- Adds complexity through constant `soa_to_ff3_array` / `ff3_array_to_soa` conversions
- Obscures the mathematical operations with low-level memory management
- Provides no performance benefit in Python (no SIMD)
- Makes the code harder to understand as an executable specification

### Proposed Solution
Refactor the expression evaluator to use native galois FF3 arrays throughout, eliminating the SoA layout entirely. The galois library already provides efficient vectorized operations on FF3 arrays - we just need to use them directly instead of converting back and forth.

### Technical Approach
1. **Change internal buffer representation**: Replace SoA uint64 buffers with native galois FF3 arrays
2. **Simplify field operations**: Use galois vectorized ops directly without conversion overhead
3. **Maintain I/O compatibility**: Convert at boundaries only (reading from/writing to auxTrace)
4. **Preserve test compatibility**: All existing tests must pass (they validate outputs, not internal layout)

### Data Flow (Current vs Proposed)

**Current Flow:**
```
auxTrace (row-major) → load component-by-component → SoA buffer
                                                        ↓
                                              soa_to_ff3_array()
                                                        ↓
                                              galois FF3 operation
                                                        ↓
                                              ff3_array_to_soa()
                                                        ↓
                                                   SoA buffer
                                                        ↓
                              store component-by-component → auxTrace (row-major)
```

**Proposed Flow:**
```
auxTrace (row-major) → load_ff3_from_row_major() → FF3 array
                                                       ↓
                                             galois FF3 operation (direct)
                                                       ↓
                                                   FF3 array
                                                       ↓
                              store_ff3_to_row_major() → auxTrace (row-major)
```

### Expected Outcomes
- Cleaner, more readable expression evaluator code
- Elimination of 7 SoA conversion call sites
- Reduced memory allocation (no intermediate SoA buffers)
- Potential performance improvement from fewer conversions
- Better alignment with the spec's purpose: clarity over C++ fidelity

## Goals & Objectives

### Primary Goals
- Eliminate all SoA layout usage from expression_evaluator.py
- Remove `soa_to_ff3_array` and `ff3_array_to_soa` functions from field.py
- All existing tests (test_fri.py, test_stark_e2e.py) must pass unchanged

### Secondary Objectives
- Measure performance impact (before/after benchmarks)
- Simplify the `_goldilocks3_op_pack` and `_goldilocks3_op_31_pack` methods
- Reduce cognitive load for spec readers

## Solution Overview

### Approach
Replace the three-buffer system (`values`, `tmp1`, `tmp3`) with typed arrays:
- `values`: Change from `np.ndarray[uint64]` with SoA layout to `List[FF3 | FF]`
- `tmp1`: Keep as `np.ndarray[uint64]` (base field only, no SoA needed)
- `tmp3`: Change from SoA `np.ndarray[uint64]` to `List[FF3]` indexed by slot

### Key Components

1. **field.py**: Remove SoA conversion functions, add row-major ↔ FF3 converters
2. **expression_evaluator.py**: Refactor buffer management and field operations
3. **batch_inverse.py**: Already works with native FF3 arrays (no changes needed)

### Architecture Diagram
```
┌─────────────────────────────────────────────────────────────────┐
│                    expression_evaluator.py                       │
├─────────────────────────────────────────────────────────────────┤
│  calculate_expressions()                                         │
│    ├── _load() → returns FF or FF3 array (native galois)        │
│    ├── _goldilocks_op_pack() → FF array operations              │
│    ├── _goldilocks3_op_pack() → FF3 array operations (direct)   │
│    ├── _goldilocks3_op_31_pack() → FF3 × FF operations (direct) │
│    ├── _get_inverse_polynomial() → batch_inverse (already FF3)  │
│    └── _store_polynomial() → writes to auxTrace (row-major)     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                         field.py                                 │
├─────────────────────────────────────────────────────────────────┤
│  FF, FF3 (galois field types)                                    │
│  ff3(), ff3_coeffs() (single element helpers)                    │
│  load_ff3_from_row_major() (NEW: auxTrace → FF3 array)          │
│  store_ff3_to_row_major() (NEW: FF3 array → auxTrace)           │
│  [REMOVED: soa_to_ff3_array, ff3_array_to_soa]                  │
└─────────────────────────────────────────────────────────────────┘
```

## Implementation Tasks

### CRITICAL IMPLEMENTATION RULES
1. **NO PLACEHOLDER CODE**: Every implementation must be production-ready
2. **MAINTAIN TEST COMPATIBILITY**: All test_fri.py and test_stark_e2e.py tests must pass
3. **INCREMENTAL REFACTORING**: Each task should leave the code in a working state
4. **BENCHMARK BEFORE/AFTER**: Measure performance impact of the refactoring

### Visual Dependency Tree

```
executable-spec/
├── primitives/
│   └── field.py (Task #1: Add row-major converters, Task #4: Remove SoA functions)
│
├── protocol/
│   └── expression_evaluator.py
│       ├── (Task #2: Refactor _load to return native FF/FF3)
│       ├── (Task #3: Refactor _goldilocks3_op_pack to use FF3 directly)
│       ├── (Task #3: Refactor _goldilocks3_op_31_pack to use FF3 directly)
│       ├── (Task #3: Refactor _get_inverse_polynomial - simplify)
│       ├── (Task #5: Refactor buffer allocation in calculate_expressions)
│       └── (Task #6: Refactor _store_polynomial for native FF3)
│
├── profile_prover.py (Task #0: Add before/after benchmarks)
│
└── tests/
    ├── test_fri.py (Task #7: Run and verify passing)
    └── test_stark_e2e.py (Task #7: Run and verify passing)
```

### Execution Plan

#### Group A: Foundation (Execute in parallel)

- [ ] **Task #0**: Create performance benchmark baseline
  - Folder: `executable-spec/`
  - File: `profile_prover.py` (modify existing or create)
  - Implements:
    - `benchmark_expression_evaluator(air_name, iterations=10)` function
    - Times `calculate_expressions()` for each test AIR (simple, lookup, permutation)
    - Outputs mean/std timing for comparison
  - Run before any refactoring to establish baseline
  - Context: Need before/after comparison to measure impact

- [ ] **Task #1**: Add row-major ↔ FF3 conversion functions
  - Folder: `executable-spec/primitives/`
  - File: `field.py`
  - Imports: `numpy as np`, existing `FF`, `FF3`, `GOLDILOCKS_PRIME`
  - Implements:
    ```python
    def load_ff3_from_row_major(buffer: np.ndarray, offset: int, n_cols: int,
                                 col: int, nrows: int, stride: int = 1) -> FF3:
        """Load FF3 array from row-major buffer.

        Args:
            buffer: Source buffer (e.g., auxTrace)
            offset: Base offset in buffer
            n_cols: Number of columns per row
            col: Column index for first coefficient
            nrows: Number of rows to load
            stride: Row stride (for cyclic access, default 1)

        Returns:
            FF3 array of length nrows
        """
        # Extract c0, c1, c2 from consecutive columns
        p = GOLDILOCKS_PRIME
        p2 = p * p
        ints = []
        for i in range(nrows):
            row_offset = offset + i * stride * n_cols
            c0 = int(buffer[row_offset + col])
            c1 = int(buffer[row_offset + col + 1])
            c2 = int(buffer[row_offset + col + 2])
            ints.append(c0 + c1 * p + c2 * p2)
        return FF3(ints)

    def store_ff3_to_row_major(arr: FF3, buffer: np.ndarray, offset: int,
                                n_cols: int, col: int, nrows: int) -> None:
        """Store FF3 array to row-major buffer.

        Args:
            arr: FF3 array to store
            buffer: Destination buffer
            offset: Base offset in buffer
            n_cols: Number of columns per row (stride between rows)
            col: Column index for first coefficient
            nrows: Number of rows to store
        """
        vecs = arr.vector()  # Shape (nrows, 3) in descending order [c2, c1, c0]
        for i in range(nrows):
            row_offset = offset + i * n_cols
            buffer[row_offset + col] = int(vecs[i, 2])      # c0
            buffer[row_offset + col + 1] = int(vecs[i, 1])  # c1
            buffer[row_offset + col + 2] = int(vecs[i, 0])  # c2
    ```
  - Exports: `load_ff3_from_row_major`, `store_ff3_to_row_major`
  - Note: Keep existing `soa_to_ff3_array` and `ff3_array_to_soa` until Task #4
  - Context: These are the new I/O boundary functions

#### Group B: Core Refactoring (Execute sequentially - each depends on previous)

- [ ] **Task #2**: Refactor `_load` method to return native FF/FF3 arrays
  - Folder: `executable-spec/protocol/`
  - File: `expression_evaluator.py`
  - Method: `ExpressionsPack._load()` (lines 595-772)
  - Changes:
    - Change return type from `np.ndarray` slice to `FF | FF3` galois array
    - For dim=1 (base field): return `FF(values_list)`
    - For dim=3 (extension field): return `FF3(encoded_ints)` using integer encoding
    - Remove all `value_buffer[j + d * nrows_pack]` indexing patterns
    - For constant values: return scalar `FF` or `FF3` element (galois handles broadcasting)
  - Key changes by type_arg:
    - **type 0 (const pols)**: Load nrows values, return `FF(list)`
    - **type 1..nStages+1 (committed)**: Load and encode, return `FF` or `FF3`
    - **type nStages+2 (boundary)**: Return `FF` array or `FF3` array directly
    - **type nStages+3 (xi)**: Return `FF3` array
    - **tmp1/tmp3**: Return stored galois array directly (change tmp3 storage)
    - **scalars**: Return galois scalar
  - Context: This is the main input path - changing return types here cascades to operations

- [ ] **Task #3**: Refactor field operation methods to use native FF3
  - Folder: `executable-spec/protocol/`
  - File: `expression_evaluator.py`
  - Methods to change:

    **`_goldilocks_op_pack()` (lines 884-922):**
    - Already mostly correct, just ensure input/output are `FF` arrays
    - Simplify: remove `is_constant` checks for array length (galois handles this)
    ```python
    def _goldilocks_op_pack(self, op: int, a: FF, b: FF) -> FF:
        """Execute Goldilocks field operation (vectorized).

        Args:
            op: Operation (0=add, 1=sub, 2=mul, 3=sub_swap)
            a: First operand (FF scalar or array)
            b: Second operand (FF scalar or array)
        Returns:
            FF result (scalar if both inputs scalar, array otherwise)
        """
        if op == 0:   return a + b
        elif op == 1: return a - b
        elif op == 2: return a * b
        elif op == 3: return b - a
    ```

    **`_goldilocks3_op_pack()` (lines 925-975):**
    - Remove all SoA conversion calls
    - Input/output are native `FF3` arrays
    ```python
    def _goldilocks3_op_pack(self, op: int, a: FF3, b: FF3) -> FF3:
        """Execute Goldilocks3 field extension operation (vectorized).

        Args:
            op: Operation (0=add, 1=sub, 2=mul, 3=sub_swap)
            a: First operand (FF3 scalar or array)
            b: Second operand (FF3 scalar or array)
        Returns:
            FF3 result
        """
        if op == 0:   return a + b
        elif op == 1: return a - b
        elif op == 2: return a * b
        elif op == 3: return b - a
    ```

    **`_goldilocks3_op_31_pack()` (lines 978-1032):**
    - Remove SoA conversion
    - Embed FF scalar in FF3 as (b, 0, 0) using integer encoding
    ```python
    def _goldilocks3_op_31_pack(self, op: int, a: FF3, b: FF) -> FF3:
        """Execute Goldilocks3 operation: FF3 × FF → FF3.

        Args:
            op: Operation
            a: First operand (FF3)
            b: Second operand (FF, embedded as (b, 0, 0))
        Returns:
            FF3 result
        """
        # Embed FF in FF3: for Goldilocks, FF3 integer encoding is c0 + c1*p + c2*p^2
        # When c1=c2=0, the integer value equals c0, so FF value can be used directly
        if isinstance(b, FF) and b.ndim == 0:
            # Scalar FF → scalar FF3
            ff3_b = FF3(int(b))
        else:
            # Array FF → array FF3 (just use the values directly as integers)
            ff3_b = FF3(np.asarray(b, dtype=np.uint64).tolist())

        if op == 0:   return a + ff3_b
        elif op == 1: return a - ff3_b
        elif op == 2: return a * ff3_b
        elif op == 3: return ff3_b - a
    ```

    **`_get_inverse_polynomial()` (lines 775-803):**
    - Simplify - input/output are already native galois arrays
    ```python
    def _get_inverse_polynomial(self, vals: FF | FF3) -> FF | FF3:
        """Compute inverse of field values using Montgomery batch inversion.

        Args:
            vals: FF or FF3 array to invert
        Returns:
            Inverted array (same type as input)
        """
        if isinstance(vals, FF):
            return batch_inverse_ff_array(vals)
        else:
            return batch_inverse_ff3_array(vals)
    ```
  - Context: These methods become much simpler without SoA bookkeeping

- [ ] **Task #5**: Refactor buffer allocation and operation dispatch in calculate_expressions
  - Folder: `executable-spec/protocol/`
  - File: `expression_evaluator.py`
  - Method: `ExpressionsPack.calculate_expressions()` (lines 315-592)
  - Changes:
    - Replace `values = np.zeros(3 * FIELD_EXTENSION * nrows_pack, ...)` with:
      ```python
      # Operand storage - now stores galois arrays directly
      operand_a: Optional[FF | FF3] = None
      operand_b: Optional[FF | FF3] = None
      result: Optional[FF | FF3] = None
      ```
    - Replace `tmp1 = np.zeros(...)` with:
      ```python
      tmp1: Dict[int, FF] = {}  # slot_id → FF array
      ```
    - Replace `tmp3 = np.zeros(...)` with:
      ```python
      tmp3: Dict[int, FF3] = {}  # slot_id → FF3 array
      ```
    - Update operation dispatch (lines 493-567):
      ```python
      for kk in range(parser_params.n_ops):
          op_type = ops[kk]

          if op_type == 0:  # dim1 × dim1 → dim1
              a = self._load(...)  # Returns FF
              b = self._load(...)  # Returns FF
              res = self._goldilocks_op_pack(args[i_args], a, b)
              if kk == parser_params.n_ops - 1:
                  operand_result = res
              else:
                  tmp1[args[i_args + 1]] = res
              i_args += 8

          elif op_type == 1:  # dim3 × dim1 → dim3
              a = self._load(...)  # Returns FF3
              b = self._load(...)  # Returns FF
              res = self._goldilocks3_op_31_pack(args[i_args], a, b)
              if kk == parser_params.n_ops - 1:
                  operand_result = res
              else:
                  tmp3[args[i_args + 1]] = res
              i_args += 8

          elif op_type == 2:  # dim3 × dim3 → dim3
              a = self._load(...)  # Returns FF3
              b = self._load(...)  # Returns FF3
              res = self._goldilocks3_op_pack(args[i_args], a, b)
              if kk == parser_params.n_ops - 1:
                  operand_result = res
              else:
                  tmp3[args[i_args + 1]] = res
              i_args += 8
      ```
    - Update `_load` to read from `tmp1`/`tmp3` dicts instead of arrays
  - Context: Main control flow changes - buffer management simplification

- [ ] **Task #6**: Refactor `_store_polynomial` for native FF3
  - Folder: `executable-spec/protocol/`
  - File: `expression_evaluator.py`
  - Method: `ExpressionsPack._store_polynomial()` (lines 851-881)
  - Changes:
    - Input is now `FF | FF3` galois array instead of SoA buffer slice
    - For dim=1: extract values and write to dest
    - For dim=3: use `store_ff3_to_row_major` or direct coefficient extraction
    ```python
    def _store_polynomial(self, dest: Dest, result: FF | FF3, row: int,
                          nrows: int, is_constant: bool):
        """Store polynomial values to destination.

        Args:
            dest: Destination specification
            result: FF or FF3 galois array
            row: Starting row index
            nrows: Number of rows
            is_constant: If True, broadcast single value to all rows
        """
        offset = dest.offset if dest.offset != 0 else (FIELD_EXTENSION if dest.dim == 3 else 1)

        if dest.dim == 1:
            # Base field storage
            if is_constant:
                val = int(result) if result.ndim == 0 else int(result[0])
                for j in range(nrows):
                    dest.dest[(row + j) * offset] = val
            else:
                vals = np.asarray(result, dtype=np.uint64)
                for j in range(nrows):
                    dest.dest[(row + j) * offset] = vals[j]
        else:
            # Field extension storage
            if is_constant:
                coeffs = ff3_coeffs(result if result.ndim == 0 else result[0])
                for j in range(nrows):
                    base = (row + j) * offset
                    dest.dest[base] = coeffs[0]
                    dest.dest[base + 1] = coeffs[1]
                    dest.dest[base + 2] = coeffs[2]
            else:
                vecs = result.vector()  # Shape (nrows, 3), descending [c2, c1, c0]
                for j in range(nrows):
                    base = (row + j) * offset
                    dest.dest[base] = int(vecs[j, 2])      # c0
                    dest.dest[base + 1] = int(vecs[j, 1])  # c1
                    dest.dest[base + 2] = int(vecs[j, 0])  # c2
    ```
  - Context: Output boundary - converts native FF3 back to row-major

#### Group C: Cleanup and Verification (Execute sequentially)

- [ ] **Task #4**: Remove SoA functions from field.py
  - Folder: `executable-spec/primitives/`
  - File: `field.py`
  - Changes:
    - Delete `soa_to_ff3_array()` function (lines 45-63)
    - Delete `ff3_array_to_soa()` function (lines 66-78)
    - Delete `_P2` constant (line 42) if no longer needed
    - Update module docstring to remove SoA references
    - Remove SoA imports from expression_evaluator.py
  - Context: Cleanup after all usages removed

- [ ] **Task #7**: Run tests and verify correctness
  - Folder: `executable-spec/`
  - Commands:
    ```bash
    cd executable-spec
    uv run python -m pytest tests/test_fri.py -v
    uv run python -m pytest tests/test_stark_e2e.py -v
    uv run python -m pytest tests/test_batch_inverse.py -v
    ```
  - Expected: All tests pass unchanged
  - If failures: Debug and fix - tests validate outputs, not internal layout
  - Context: Final verification that refactoring is correct

- [ ] **Task #8**: Run performance benchmark and document results
  - Folder: `executable-spec/`
  - Commands:
    ```bash
    cd executable-spec
    uv run python profile_prover.py  # Run benchmark from Task #0
    ```
  - Document:
    - Before/after timing comparison
    - Memory usage if measurable
    - Any unexpected performance changes
  - Context: Verify performance goal achieved

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
- Tasks in Group B must be executed sequentially due to dependencies

### Progress Tracking
The checkboxes above represent the authoritative status of each task. Keep them updated as you work.

## Risk Assessment

### Low Risk
- **Test compatibility**: Tests validate outputs (polynomials, hashes, proofs), not internal memory layout
- **galois compatibility**: Already using galois for all field operations, just more directly

### Medium Risk
- **Performance regression**: Possible if galois array creation overhead exceeds SoA conversion overhead
- **Subtle bugs**: Different code paths for scalar vs array broadcasting

### Mitigation
- Benchmark before/after (Task #0 and #8)
- Run full test suite after each task
- Keep old implementation available (git) for comparison if issues arise
