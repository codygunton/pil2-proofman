# Expression Evaluator Vectorization Implementation Plan

## Executive Summary

The expression evaluator in `protocol/expression_evaluator.py` is the main performance bottleneck, taking ~380 seconds for the lookup test (4096 rows). Profiling and benchmarking reveal:

- **Root cause**: Row-by-row processing with `NROWS_PACK=1` creates 8000+ FF3 objects per expression
- **Benchmark validation**: Processing columns at once is **5x faster** for realistic expression chains
  - FF3 creation: 50x faster (74ms → 1.5ms for 4096 elements)
  - FF3 multiply: 4x faster (269ms → 72ms)
  - Coefficient extraction: 66x faster (161ms → 2.4ms)
- **Conversion overhead**: Keeping data in FF3 form eliminates 8% overhead per operation

**Proposed solution**: Refactor to process entire columns at once using vectorized galois operations, keeping data in FF3 array form throughout expression evaluation chains.

**Expected outcome**: 3-5x speedup on lookup test (380s → 75-125s)

**ACTUAL RESULTS (2026-01-22):**
- Lookup test: **~51 seconds** (7.4x speedup from 380s)
- All 138 tests pass with byte-identical proofs
- Full test suite: ~116 seconds total

## Goals & Objectives

### Primary Goals
- Reduce lookup test execution time from ~380s to <120s (3x+ speedup)
- Eliminate per-row FF3 object creation overhead (currently 56% of operation time)
- Process entire domain columns in single vectorized operations

### Secondary Objectives
- Maintain byte-for-byte proof compatibility with C++ implementation
- Keep code readable as an "executable specification"
- Minimize changes to overall architecture

## Solution Overview

### Approach

Transform the expression evaluator from row-by-row processing to column-wise vectorized processing:

1. **Increase batch size**: Change `NROWS_PACK` from 1 to domain size
2. **Vectorize FF3 operations**: Use galois library's array operations instead of per-element loops
3. **Vectorize data loading**: Use numpy slicing instead of per-row loops in `_load()`
4. **Keep data in FF3 form**: Convert SoA → FF3 once at operation start, FF3 → SoA once at end

### Key Components

1. **NROWS_PACK constant**: Change from 1 to large value (capped to domain_size)
2. **_goldilocks3_op_pack()**: Refactor to use `soa_to_ff3_array()` and vectorized operations
3. **_goldilocks3_op_31_pack()**: Same refactoring for dim3×dim1 operations
4. **_load()**: Vectorize non-cyclic loading paths with numpy slicing
5. **Cyclic index handling**: Pre-compute wrapped indices for cyclic regions

### Data Flow

**Current (slow):**
```
For each row i in [0, domain_size):
    For each operand:
        Load single value from buffer
        Create ff3([c0, c1, c2])           ← 74ms/4096 elements
    Perform operation on single elements
    Extract coefficients via ff3_coeffs()  ← 161ms/4096 elements
    Store single result
```

**Target (fast):**
```
For entire domain at once:
    For each operand:
        Load column via numpy slice         ← O(1) slice
        Convert to FF3 array once           ← 1.5ms/4096 elements
    Perform vectorized operation            ← 72ms/4096 multiply
    Convert back to SoA once                ← 2.8ms/4096 elements
    Store column result
```

### Expected Outcomes

- Lookup test completes in <120 seconds (vs ~380s currently)
- All E2E tests pass with byte-identical proofs
- Simple test remains fast (<2s)
- Permutation test scales proportionally

## Implementation Tasks

### CRITICAL IMPLEMENTATION RULES
1. **NO PLACEHOLDER CODE**: Every implementation must be production-ready
2. **MAINTAIN PROOF COMPATIBILITY**: All tests must pass with identical outputs
3. **INCREMENTAL VALIDATION**: Run tests after each task to catch regressions early
4. **PRESERVE SEMANTICS**: The mathematical operations must remain identical

### Visual Dependency Tree

```
protocol/
├── expression_evaluator.py
│   ├── Line 25: NROWS_PACK constant (Task #1)
│   ├── Lines 924-963: _goldilocks3_op_pack (Task #2)
│   ├── Lines 965-1004: _goldilocks3_op_31_pack (Task #2)
│   ├── Lines 637-656: _load() const loading (Task #3)
│   ├── Lines 658-690: _load() trace loading (Task #3)
│   └── Lines 349-355: Cyclic region computation (Task #4)
│
primitives/
├── field.py
│   ├── Lines 45-56: soa_to_ff3_array (Task #0 - optimize)
│   └── Lines 59-72: ff3_array_to_soa (already optimized)
│
tests/
└── test_stark_e2e.py (validation after each task)
```

### Execution Plan

#### Group A: Foundation (Execute first)

- [x] **Task #0**: Optimize soa_to_ff3_array conversion function
  - **Folder**: `primitives/`
  - **File**: `field.py`
  - **Current code** (lines 45-56):
    ```python
    def soa_to_ff3_array(soa: np.ndarray, nrows: int) -> FF3:
        p = GOLDILOCKS_PRIME
        p2 = _P2
        c0 = soa[:nrows]
        c1 = soa[nrows:2*nrows]
        c2 = soa[2*nrows:3*nrows]
        ints = [int(c0[i]) + int(c1[i]) * p + int(c2[i]) * p2 for i in range(nrows)]
        return FF3(ints)
    ```
  - **Problem**: Python list comprehension is slow for large nrows
  - **Solution**: The galois FF3 constructor can accept a list of Python ints efficiently, but we can potentially speed up the list creation using map() or a generator
  - **Implementation**:
    ```python
    def soa_to_ff3_array(soa: np.ndarray, nrows: int) -> FF3:
        """Convert SoA layout to FF3 array."""
        p = GOLDILOCKS_PRIME
        p2 = _P2
        c0 = soa[:nrows]
        c1 = soa[nrows:2*nrows]
        c2 = soa[2*nrows:3*nrows]
        # Use map for slightly faster iteration than list comprehension
        ints = list(map(lambda i: int(c0[i]) + int(c1[i]) * p + int(c2[i]) * p2, range(nrows)))
        return FF3(ints)
    ```
  - **Alternative**: If above doesn't help much, try:
    ```python
    # Pre-convert to Python lists to avoid numpy int conversion overhead
    c0_list = c0.tolist()
    c1_list = c1.tolist()
    c2_list = c2.tolist()
    ints = [c0_list[i] + c1_list[i] * p + c2_list[i] * p2 for i in range(nrows)]
    ```
  - **Validation**: Run `python bench_ff3_vectorization.py` to verify batch creation time
  - **Context**: This function is called for every operand load in vectorized mode

#### Group B: Core Vectorization (Execute after Group A)

- [x] **Task #1**: Increase NROWS_PACK to enable batch processing
  - **Folder**: `protocol/`
  - **File**: `expression_evaluator.py`
  - **Current code** (line 25):
    ```python
    NROWS_PACK = 1
    ```
  - **Change to**:
    ```python
    # Process entire domain at once for vectorization benefit
    # The min() in calculate_expressions caps this to actual domain_size
    NROWS_PACK = 1 << 16  # 65536, large enough for any test domain
    ```
  - **Why this works**: Line 341 already does `nrows_pack = min(self.nrows_pack_, domain_size)`
  - **Validation**: Run simple test - it should still pass but may be slower initially (before Task #2)
  - **Context**: This enables batch processing but requires Task #2 to get the speedup

- [x] **Task #2**: Vectorize _goldilocks3_op_pack and _goldilocks3_op_31_pack
  - **Folder**: `protocol/`
  - **File**: `expression_evaluator.py`
  - **Functions to modify**:
    - `_goldilocks3_op_pack` (lines 924-963)
    - `_goldilocks3_op_31_pack` (lines 965-1004)
  - **Add import** at top of file (around line 20):
    ```python
    from primitives.field import FF, FF3, ff3, ff3_coeffs, GOLDILOCKS_PRIME, soa_to_ff3_array, ff3_array_to_soa
    ```
  - **Replace _goldilocks3_op_pack** (lines 924-963):
    ```python
    def _goldilocks3_op_pack(self, nrows_pack: int, op: int, dest: np.ndarray,
                             a: np.ndarray, is_constant_a: bool,
                             b: np.ndarray, is_constant_b: bool):
        """Execute Goldilocks3 field extension operation (dim3 × dim3, vectorized).

        Corresponds to C++ Goldilocks3::op_pack().
        Uses galois library vectorization for batch processing.
        """
        # Convert SoA to FF3 arrays - constants broadcast automatically
        if is_constant_a:
            # Constant: extract single element's coefficients
            ff3_a = ff3([int(a[0]), int(a[1]), int(a[2])])
        else:
            ff3_a = soa_to_ff3_array(a, nrows_pack)

        if is_constant_b:
            ff3_b = ff3([int(b[0]), int(b[1]), int(b[2])])
        else:
            ff3_b = soa_to_ff3_array(b, nrows_pack)

        # Single vectorized operation - galois handles broadcasting
        if op == 0:    ff3_result = ff3_a + ff3_b
        elif op == 1:  ff3_result = ff3_a - ff3_b
        elif op == 2:  ff3_result = ff3_a * ff3_b
        elif op == 3:  ff3_result = ff3_b - ff3_a
        else:
            raise ValueError(f"Invalid operation: {op}")

        # Convert back to SoA layout
        if is_constant_a and is_constant_b:
            # Result is scalar
            coeffs = ff3_coeffs(ff3_result)
            dest[0] = coeffs[0]
            dest[1] = coeffs[1]
            dest[2] = coeffs[2]
        else:
            ff3_array_to_soa(ff3_result, dest, nrows_pack)
    ```
  - **Replace _goldilocks3_op_31_pack** (lines 965-1004):
    ```python
    def _goldilocks3_op_31_pack(self, nrows_pack: int, op: int, dest: np.ndarray,
                                a: np.ndarray, is_constant_a: bool,
                                b: np.ndarray, is_constant_b: bool):
        """Execute Goldilocks3 field extension operation (dim3 × dim1, vectorized).

        Corresponds to C++ Goldilocks3::op_31_pack().
        Operand a is FF3 (dim=3), operand b is FF (dim=1, embedded as (b,0,0)).
        """
        # Convert a (FF3) from SoA
        if is_constant_a:
            ff3_a = ff3([int(a[0]), int(a[1]), int(a[2])])
        else:
            ff3_a = soa_to_ff3_array(a, nrows_pack)

        # Convert b (FF scalar) - embed in FF3 as (b, 0, 0)
        if is_constant_b:
            ff3_b = ff3([int(b[0]), 0, 0])
        else:
            # Create FF3 array with b values in coefficient 0, zeros elsewhere
            # FF3 integer encoding: value = c0 (when c1=c2=0)
            ints = [int(b[i]) for i in range(nrows_pack)]
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
            dest[1] = coeffs[1]
            dest[2] = coeffs[2]
        else:
            ff3_array_to_soa(ff3_result, dest, nrows_pack)
    ```
  - **Critical**: The `is_constant_a` and `is_constant_b` flags indicate the array contains a single value to broadcast, NOT that it's in different memory layout. Constants are stored as `[c0, c1, c2]` (3 elements).
  - **Validation**: Run all three E2E tests - they must all pass
  - **Context**: This is the main speedup - eliminates per-row FF3 object creation

#### Group C: Load Path Optimization (Execute after Group B validates)

- [x] **Task #3**: Vectorize _load() for non-cyclic regions
  - **Folder**: `protocol/`
  - **File**: `expression_evaluator.py`
  - **Function**: `_load()` (lines 594-770)
  - **Target sections**:
    - Constant polynomial loading (lines 651-656, non-cyclic case)
    - Trace/aux_trace loading (lines 674-682, non-cyclic case)
  - **Current non-cyclic const loading** (lines 651-656):
    ```python
    else:
        offset_col = (row + o) * n_cols + stage_pos
        for j in range(nrows_pack):
            value_buffer[j] = const_pols[offset_col + j * n_cols]
    ```
  - **Replace with**:
    ```python
    else:
        # Vectorized loading for non-cyclic region
        base_offset = (row + o) * n_cols + stage_pos
        indices = base_offset + np.arange(nrows_pack) * n_cols
        value_buffer[:nrows_pack] = const_pols[indices]
    ```
  - **Current non-cyclic trace loading** (lines 674-682):
    ```python
    else:
        # Linear region
        if dim == 1:
            for j in range(nrows_pack):
                value_buffer[j] = pols[(row + j + o) * n_cols + stage_pos]
        else:
            for j in range(nrows_pack):
                for d in range(FIELD_EXTENSION):
                    value_buffer[j + d * nrows_pack] = pols[(row + j + o) * n_cols + stage_pos + d]
    ```
  - **Replace with**:
    ```python
    else:
        # Vectorized loading for linear region
        row_indices = row + np.arange(nrows_pack) + o
        if dim == 1:
            value_buffer[:nrows_pack] = pols[row_indices * n_cols + stage_pos]
        else:
            for d in range(FIELD_EXTENSION):
                value_buffer[d * nrows_pack:(d + 1) * nrows_pack] = pols[row_indices * n_cols + stage_pos + d]
    ```
  - **Note**: Keep cyclic case as-is initially (more complex to vectorize)
  - **Validation**: All E2E tests pass
  - **Context**: Reduces Python loop overhead in data loading

- [x] **Task #4**: Vectorize cyclic region loading (optional, for full optimization)
  - **Folder**: `protocol/`
  - **File**: `expression_evaluator.py`
  - **Target sections**:
    - Cyclic const loading (lines 647-650)
    - Cyclic trace loading (lines 665-672)
  - **Current cyclic const loading**:
    ```python
    if is_cyclic:
        for j in range(nrows_pack):
            l = (row + j + o) % domain_size
            value_buffer[j] = const_pols[l * n_cols + stage_pos]
    ```
  - **Replace with**:
    ```python
    if is_cyclic:
        # Vectorized cyclic loading with pre-computed wrapped indices
        row_indices = (row + np.arange(nrows_pack) + o) % domain_size
        value_buffer[:nrows_pack] = const_pols[row_indices * n_cols + stage_pos]
    ```
  - **Same pattern for trace loading**:
    ```python
    if is_cyclic:
        row_indices = (row + np.arange(nrows_pack) + o) % domain_size
        if dim == 1:
            value_buffer[:nrows_pack] = pols[row_indices * n_cols + stage_pos]
        else:
            for d in range(FIELD_EXTENSION):
                value_buffer[d * nrows_pack:(d + 1) * nrows_pack] = pols[row_indices * n_cols + stage_pos + d]
    ```
  - **Validation**: All E2E tests pass
  - **Context**: Completes vectorization of all load paths

#### Group D: Validation and Cleanup

- [x] **Task #5**: Performance validation and benchmark
  - **Run full test suite**:
    ```bash
    cd /home/cody/pil2-proofman/executable-spec
    uv run python -m pytest tests/test_stark_e2e.py::TestFullBinaryComparison -v
    ```
  - **Measure performance**:
    ```bash
    time uv run python -m pytest tests/test_stark_e2e.py::TestFullBinaryComparison::test_full_binary_proof_match -k lookup -v
    ```
  - **Expected**: Lookup test < 120 seconds (vs ~380s before)
  - **Run benchmark to confirm vectorization benefit**:
    ```bash
    uv run python bench_ff3_vectorization.py
    ```
  - **Document final performance numbers**

- [ ] **Task #6**: Clean up benchmark file (optional)
  - **File**: `bench_ff3_vectorization.py`
  - **Action**: Either delete or move to `tests/` directory
  - **Context**: Benchmark was used for validation, may not be needed long-term

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
- Run tests after EVERY task to catch regressions immediately
- Tasks #1 and #2 MUST be done together (Task #1 alone will make things slower)

### Progress Tracking
The checkboxes above represent the authoritative status of each task. Keep them updated as you work.

### Test Commands
```bash
# Quick validation (simple test only)
uv run python -m pytest tests/test_stark_e2e.py::TestFullBinaryComparison::test_full_binary_proof_match -k simple -v

# Full validation (all tests)
uv run python -m pytest tests/test_stark_e2e.py::TestFullBinaryComparison -v

# Performance measurement (lookup test)
time uv run python -m pytest tests/test_stark_e2e.py::TestFullBinaryComparison::test_full_binary_proof_match -k lookup -v
```
