# Witness Module Integration Implementation Plan

## Executive Summary

**Problem Statement:**
The expression binary machinery cannot be removed from the Python executable spec because witness generation still relies on it. Three witness modules exist (`witness/simple_left.py`, `witness/lookup2_12.py`, `witness/permutation1_6.py`) but produce different outputs than the expression binary's `calculate_witness_std` function.

**Root Cause:**
The witness modules compute logup terms from first principles using algebraic formulas, but the expression binary uses compiler-generated hints with specific:
1. **Clustering structure** - which terms are summed into which im_cluster column
2. **Accumulation order** - the order in which terms are combined
3. **Field decomposition** - how numerator/denominator fields are multiplied

Even though both approaches compute mathematically equivalent values, the intermediate columns (`im_cluster[0..5]`, `gsum`) differ, causing byte-level proof mismatches.

**Solution:**
Debug and fix witness modules to produce byte-identical output to expression binary by:
1. Adding comparison instrumentation to capture actual vs expected values
2. Identifying structural differences in clustering and accumulation
3. Fixing witness modules to match compiler-generated structure
4. Wiring fixed modules into prover.py
5. Removing expression binary usage once all tests pass

**Technical Approach:**
- Phase 1: Add debugging infrastructure to compare outputs
- Phase 2: Fix SimpleLeft witness module (simplest AIR, 8 rows)
- Phase 3: Fix Lookup2_12 and Permutation1_6 modules
- Phase 4: Wire into prover and verify tests
- Phase 5: Remove expression binary from witness generation

**Expected Outcomes:**
- All 142 E2E tests pass with witness modules instead of expression binary
- `calculate_witness_std` can be removed from the codebase
- Expression binary is no longer needed for Stage 2 witness generation

## Goals & Objectives

### Primary Goals
- Witness modules produce byte-identical im_cluster and gsum columns to expression binary
- All E2E tests pass with `calculate_witness_with_module` replacing `calculate_witness_std`

### Secondary Objectives
- Document the exact clustering and accumulation structure for each AIR
- Simplify witness module code by matching compiler structure directly
- Enable future removal of expression binary machinery

## Solution Overview

### Approach

The expression binary's `calculate_witness_std` works by:
1. Reading hints from `expressions.bin` that specify:
   - Which operands to multiply for numerator/denominator
   - Which columns to write results to (im_cluster indices)
   - Running sum/product accumulation structure
2. Using `multiply_hint_fields()` to compute `numerator/denominator` for each hint
3. Using `acc_mul_hint_fields()` to accumulate into gsum column
4. Writing results to `params.auxTrace`

The witness modules work by:
1. Computing individual logup terms: `selector / (busid + col1*α + col2*α² + ... + γ)`
2. Clustering terms into im_cluster columns (hardcoded clusters)
3. Computing running sum for gsum
4. Writing via `_write_witness_to_buffer()`

**The Fix:**
Extract the exact hint structure from expression binary and replicate it in witness modules:
- Match the exact clustering indices from hints
- Match the operand multiplication order
- Match the accumulation order

### Key Components

1. **Comparison Infrastructure**: Add debug mode to `calculate_witness_with_module` that compares its output against `calculate_witness_std` byte-by-byte

2. **Hint Structure Analysis**: Read im_col and gsum_col hints from expressions.bin to understand exact compiler structure

3. **Witness Module Fixes**: Update `compute_intermediates()` and `compute_grand_sums()` in each witness module to match hint structure

4. **Prover Integration**: Replace `calculate_witness_std` calls with `calculate_witness_with_module`

### Data Flow

```
Expression Binary Path (current):
┌──────────────────────┐     ┌──────────────────────┐
│ expressions.bin      │────▶│ calculate_witness_std │
│ (im_col, gsum_col    │     │ - multiply_hint_fields│
│  hints with fields)  │     │ - acc_mul_hint_fields │
└──────────────────────┘     └──────────────────────┘
                                       │
                                       ▼
                              ┌──────────────────────┐
                              │ params.auxTrace      │
                              │ (im_cluster, gsum)   │
                              └──────────────────────┘

Witness Module Path (target):
┌──────────────────────┐     ┌──────────────────────┐
│ WitnessModule        │────▶│calculate_witness_with│
│ (SimpleLeftWitness,  │     │_module               │
│  Lookup2_12Witness)  │     │ - compute_intermediates│
└──────────────────────┘     │ - compute_grand_sums │
                             └──────────────────────┘
                                       │
                                       ▼
                              ┌──────────────────────┐
                              │ params.auxTrace      │
                              │ (im_cluster, gsum)   │
                              │ BYTE-IDENTICAL       │
                              └──────────────────────┘
```

### Expected Outcomes
- `calculate_witness_with_module(stark_info, params)` produces same auxTrace values as `calculate_witness_std(...)` for all 3 AIRs
- Tests `TestStarkE2EComplete` pass with witness modules enabled
- Binary proof comparison tests pass with witness modules enabled

## Implementation Tasks

### CRITICAL IMPLEMENTATION RULES
1. **NO PLACEHOLDER CODE**: Every implementation must be production-ready
2. **DEBUG FIRST**: Add comparison infrastructure before fixing modules
3. **ONE AIR AT A TIME**: Fix SimpleLeft completely before moving to others
4. **VERIFY WITH TESTS**: Run E2E tests after each significant change
5. **PRESERVE FALLBACK**: Keep expression binary path until all AIRs work

### Visual Dependency Tree

```
executable-spec/
├── protocol/
│   ├── prover.py (Task #5: Wire witness modules into prover)
│   └── stages.py (Task #1: Add comparison debug mode)
│
├── witness/
│   ├── base.py (unchanged)
│   ├── simple_left.py (Task #2: Fix SimpleLeft clustering)
│   ├── lookup2_12.py (Task #3: Fix Lookup2_12 clustering)
│   └── permutation1_6.py (Task #4: Fix Permutation1_6 clustering)
│
└── tests/
    └── test_witness_comparison.py (Task #1: New comparison test)
```

### Execution Plan

#### Group A: Debugging Infrastructure (Execute first)

- [x] **Task #1**: Add witness output comparison infrastructure
  - **Files to modify:**
    - `protocol/stages.py:297-329` - Add debug comparison mode to `calculate_witness_with_module`
    - `tests/test_witness_comparison.py` - New test file for comparing outputs
  - **What to implement:**
    1. In `calculate_witness_with_module()`, add optional `debug_compare: bool = False` parameter
    2. When `debug_compare=True`:
       - Call `calculate_witness_std()` first to populate auxTrace
       - Copy im_cluster and gsum column values to `expected_values` dict
       - Clear auxTrace im_cluster/gsum columns
       - Call witness module's `compute_intermediates()` and `compute_grand_sums()`
       - Write to auxTrace via `_write_witness_to_buffer()`
       - Compare byte-by-byte with expected_values
       - Print first difference location: row index, column name, expected vs actual
    3. New test `test_witness_comparison.py`:
       ```python
       class TestWitnessComparison:
           def test_simple_left_witness_matches_expression_binary(self):
               """Compare SimpleLeft witness module output to expression binary."""
               # Load SimpleLeft test data
               # Run calculate_witness_with_module(debug_compare=True)
               # Assert no differences

           def test_lookup2_12_witness_matches_expression_binary(self):
               # Same for Lookup2_12

           def test_permutation1_6_witness_matches_expression_binary(self):
               # Same for Permutation1_6
       ```
  - **Expected output:** Test failures showing exact column/row where witness module differs from expression binary
  - **Integration:** Tests will guide fixes in Tasks #2-4

#### Group B: Fix Witness Modules (Execute sequentially, SimpleLeft first)

- [x] **Task #2**: Fix SimpleLeft witness module clustering
  - **File:** `witness/simple_left.py`
  - **Research needed first:**
    1. Run comparison test to identify which im_cluster columns differ
    2. Extract im_col hint structure from SimpleLeft's expressions.bin:
       - How many im_col hints? (currently assuming 6 for im_cluster[0..5])
       - What's in each hint's "numerator" and "denominator" fields?
       - Which cmPolsMap ids are written to?
    3. Verify gsum_col hint structure matches accumulation
  - **What to implement:**
    1. Update `_get_all_logup_terms()` if term definitions are wrong
    2. Update `clusters` list in `compute_intermediates()` to match hint structure
    3. If hints use different formula than `selector / compress`, fix the formula
    4. Verify `compute_grand_sums()` accumulation order matches acc_mul_hint_fields
  - **Verification:** Run `test_simple_left_witness_matches_expression_binary` until it passes
  - **Note:** SimpleLeft has 8 rows and no FRI folding - simplest case for debugging

- [x] **Task #3**: Fix Lookup2_12 witness module clustering
  - **File:** `witness/lookup2_12.py`
  - **Dependencies:** Task #2 must be complete (pattern established)
  - **Research needed:**
    1. Run comparison test to identify differences
    2. Extract hint structure from Lookup2_12's expressions.bin
    3. Identify clustering differences
  - **What to implement:**
    1. Apply same pattern as SimpleLeft fix
    2. Handle Lookup2_12-specific complexity (4096 rows, more terms)
  - **Verification:** Run `test_lookup2_12_witness_matches_expression_binary` until it passes

- [x] **Task #4**: Fix Permutation1_6 witness module clustering
  - **File:** `witness/permutation1_6.py`
  - **Dependencies:** Tasks #2 and #3 must be complete
  - **Research needed:**
    1. Run comparison test to identify differences
    2. Extract hint structure from Permutation1_6's expressions.bin
    3. Handle gprod (product) vs gsum (sum) distinction
  - **What to implement:**
    1. Apply pattern from Tasks #2-3
    2. Handle gprod column in addition to gsum
    3. Verify both sum and product accumulation
  - **Verification:** Run `test_permutation1_6_witness_matches_expression_binary` until it passes

#### Group C: Integration (Execute after Group B complete)

- [x] **Task #5**: Wire witness modules into prover
  - **File:** `protocol/prover.py`
  - **Dependencies:** Tasks #2, #3, #4 must all pass their tests
  - **Current code (lines 283-290):**
    ```python
    # Note: Witness modules are not yet matching expression binary output.
    # ...
    calculate_witness_std(stark_info, setup_ctx.expressions_bin, params, expressions_ctx, prod=True)
    calculate_witness_std(stark_info, setup_ctx.expressions_bin, params, expressions_ctx, prod=False)
    ```
  - **What to implement:**
    1. Add flag `use_witness_module: bool = True` (default True once tests pass)
    2. Replace with:
       ```python
       if use_witness_module:
           from protocol.stages import calculate_witness_with_module
           calculate_witness_with_module(stark_info, params)
       else:
           # Fallback for debugging
           calculate_witness_std(stark_info, setup_ctx.expressions_bin, params, expressions_ctx, prod=True)
           calculate_witness_std(stark_info, setup_ctx.expressions_bin, params, expressions_ctx, prod=False)
       ```
    3. Remove the TODO comment once working
  - **Verification:** Run full E2E test suite:
    ```bash
    cd executable-spec && uv run python -m pytest tests/test_stark_e2e.py -v
    ```
    All tests must pass with witness modules enabled

- [x] **Task #6**: Verify binary proof compatibility
  - **File:** `tests/test_stark_e2e.py`
  - **Dependencies:** Task #5 must be complete
  - **What to verify:**
    1. `TestFullBinaryComparison` tests pass
    2. Proofs generated with witness modules are byte-identical to C++ proofs
    3. Verifier accepts proofs from both paths
  - **Verification command:**
    ```bash
    cd executable-spec && uv run python -m pytest tests/test_stark_e2e.py::TestFullBinaryComparison -v
    ```

#### Group D: Cleanup (Execute after Group C verification passes)

- [x] **Task #7**: Remove expression binary from witness generation path
  - **Dependencies:** Tasks #5 and #6 must pass
  - **Files to modify:**
    - `protocol/prover.py` - Remove fallback path and import of `calculate_witness_std`
    - `protocol/stages.py` - Remove `debug_compare` parameter (keep clean interface)
  - **What to implement:**
    1. Remove the `if use_witness_module:` conditional
    2. Remove `calculate_witness_std` import from prover.py
    3. Keep `calculate_witness_std` in witness_generation.py for potential debugging
  - **Final verification:** Full test suite must pass

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
- Mark tasks complete only when fully implemented and tests pass
- Tasks in Group B MUST be sequential (SimpleLeft → Lookup2_12 → Permutation1_6)
- Do NOT proceed to Group C until ALL Group B tasks pass their comparison tests

### Testing Commands
```bash
# Run witness comparison tests (Group A/B verification)
cd executable-spec && uv run python -m pytest tests/test_witness_comparison.py -v

# Run full E2E tests (Group C verification)
cd executable-spec && uv run python -m pytest tests/test_stark_e2e.py -v

# Run binary comparison tests (Group C verification)
cd executable-spec && uv run python -m pytest tests/test_stark_e2e.py::TestFullBinaryComparison -v
```

### Progress Tracking
The checkboxes above represent the authoritative status of each task. Keep them updated as you work.
