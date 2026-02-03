# Expression Evaluator Simplification Plan

**STATUS: COMPLETED** - See `expression-evaluator-deep-refactor.md` for the next phase.

## Executive Summary

The `expression_evaluator.py` file is ~630 lines, but the actual public API is just 4 methods. The rest is C++ bytecode interpretation and buffer management that should be hidden from callers. Additionally, many function arguments are always the same value and should be removed or made constants.

**Problems**:
1. Consumers interact with `Dest`, `Params`, buffer offsets - C++ artifacts
2. Function signatures have dead arguments (`inverse`, `compilation_time`, `verify_constraints`, `debug`) that are always default
3. Protocol parameters that are constant across all AIRs are buried in StarkInfo instead of being named constants

**Solution**:
1. Make `Dest`, `Params` internal (prefix with `_`)
2. Remove dead arguments from function signatures
3. Add named constants for fixed protocol parameters
4. Add helper methods to hide remaining complexity

## Goals & Objectives

### Primary Goals
- Remove 4 dead arguments from public API
- Add named constants for protocol parameters
- Make `Dest` and `Params` internal implementation details
- All 142 tests continue to pass

### Secondary Objectives
- Improve code clarity for cryptographers reviewing the executable spec
- Document what's protocol logic vs engineering

## Named Constants

These values are constant across all three test AIRs (simple-left, lookup2-12, permutation1-6):

```python
# Protocol parameters (constant across all AIRs)
OPENING_POINTS = [-1, 0, 1]  # Polynomial opening offsets
N_STAGES = 2                  # Number of prover stages
N_QUERIES = 228               # FRI query count (security parameter)
BLOWUP_FACTOR = 2             # Domain extension factor (2^1)
```

## Dead Arguments to Remove

| Function | Argument | Always | Action |
|----------|----------|--------|--------|
| `calculate_expression` | `inverse` | `False` | Remove |
| `calculate_expression` | `compilation_time` | `False` | Remove |
| `calculate_expressions` | `compilation_time` | `False` | Remove |
| `calculate_expressions` | `verify_constraints` | `False` | Remove |
| `calculate_expressions` | `debug` | `False` | Remove |

## Solution Overview

### Before
```python
def calculate_expression(self, params: StepsParams, dest: np.ndarray,
                        expression_id: int, inverse: bool = False,
                        compilation_time: bool = False):

def calculate_expressions(self, params: StepsParams, dest: Dest,
                         domain_size: int, domain_extended: bool,
                         compilation_time: bool = False,
                         verify_constraints: bool = False, debug: bool = False):
```

### After
```python
def calculate_expression(self, params: StepsParams, dest: np.ndarray,
                        expression_id: int):

def calculate_expressions(self, params: StepsParams, dest: _Dest,
                         domain_size: int, domain_extended: bool):
```

### Data Flow

```
Caller                    Public API                  Internal
──────                    ──────────                  ────────

params ───────────────┬── calculate_expression() ──── _build_dest()
expression_id ────────┤                               _Dest, _Params
                      │                               bytecode eval
dest buffer ──────────┘                               _store_result()
```

### Expected Outcomes

- Function signatures are minimal - no dead arguments
- Protocol constants are named and documented
- Callers no longer import or construct `Dest`/`Params`
- Public API is cleaner and more obvious

## Implementation Tasks

### CRITICAL IMPLEMENTATION RULES
1. All 142 tests must pass after each task
2. No changes to bytecode interpretation logic
3. Preserve exact numerical behavior (byte-identical proofs)

### Visual Dependency Tree

```
executable-spec/protocol/
├── expression_evaluator.py (Tasks #0, #1, #2, #3)
│   ├── Add OPENING_POINTS, N_STAGES, N_QUERIES, BLOWUP_FACTOR (Task #0)
│   ├── Remove dead arguments from signatures (Task #0)
│   ├── Params → _Params, Dest → _Dest (Task #1)
│   ├── Add evaluate_combined() helper (Task #2)
│   └── Update module docstring (Task #3)
│
├── verifier.py (Task #2)
│   └── Use evaluate_combined() instead of manual Dest construction
│
├── stages.py (Task #0)
│   └── Remove dead argument passing
│
├── prover.py (no changes)
│
├── witness_generation.py (Task #0, #2)
│   └── Remove dead arguments, use new helpers
│
└── __init__.py (Task #1)
    └── Remove Dest, Params from exports, add constants
```

### Execution Plan

#### Group A: Constants and Dead Arguments (Do first)

- [x] **Task #0a**: Add named constants to expression_evaluator.py
  - File: `protocol/expression_evaluator.py`
  - Add after existing constants section (after line 20):
    ```python
    # --- Protocol Constants ---
    # These are constant across all AIRs in the test suite

    OPENING_POINTS = [-1, 0, 1]  # Polynomial opening offsets (row[i-1], row[i], row[i+1])
    N_STAGES = 2                  # Number of prover stages (stage 1 = witness, stage 2 = lookups/perms)
    N_QUERIES = 228               # FRI query count (security parameter)
    BLOWUP_FACTOR = 2             # LDE blowup factor (extended domain = N * BLOWUP_FACTOR)
    ```
  - File: `protocol/__init__.py`
    - Export the new constants
  - Test: `uv run python -m pytest tests/ -v` must pass

- [x] **Task #0b**: Remove dead arguments from calculate_expression
  - File: `protocol/expression_evaluator.py`
  - Change signature (line ~174):
    ```python
    # Before
    def calculate_expression(self, params: StepsParams, dest: np.ndarray,
                            expression_id: int, inverse: bool = False,
                            compilation_time: bool = False):

    # After
    def calculate_expression(self, params: StepsParams, dest: np.ndarray,
                            expression_id: int):
    ```
  - Update method body to use `inverse=False`, `compilation_time=False` as local constants
  - File: `protocol/stages.py`
    - Update calls to `calculate_expression()` to remove dead arguments (if any passed explicitly)
  - Test: Must pass

- [x] **Task #0c**: Remove dead arguments from calculate_expressions
  - File: `protocol/expression_evaluator.py`
  - Change signature in `ExpressionsCtx.calculate_expressions` (line ~201):
    ```python
    # Before
    def calculate_expressions(self, params: StepsParams, dest: Dest,
                             domain_size: int, domain_extended: bool,
                             compilation_time: bool = False,
                             verify_constraints: bool = False, debug: bool = False):

    # After
    def calculate_expressions(self, params: StepsParams, dest: Dest,
                             domain_size: int, domain_extended: bool):
    ```
  - Change signature in `ExpressionsPack.calculate_expressions` (line ~220):
    - Same change
    - Update method body to use constants for removed args
  - Update all callers:
    - `protocol/stages.py`: Remove trailing `False, False` arguments
    - `protocol/verifier.py`: Remove trailing arguments
    - `protocol/witness_generation.py`: Remove trailing arguments
  - Test: Must pass

#### Group B: Internalize Dest/Params (After Group A)

- [x] **Task #1**: Make Dest and Params internal
  - File: `protocol/expression_evaluator.py`
  - Changes:
    1. Rename `class Params` to `class _Params` (line 34)
    2. Rename `class Dest` to `class _Dest` (line 48)
    3. Update all internal references to use new names
  - File: `protocol/__init__.py`
    - Remove `Dest` and `Params` from `__all__` and imports
  - File: `protocol/verifier.py`
    - Update imports: `from protocol.expression_evaluator import ExpressionsPack, _Dest, _Params`
    - This is temporary until Task #2 removes the need for direct access
  - File: `protocol/witness_generation.py`
    - Update imports if needed
  - Test: Must pass

#### Group C: Add Helper Methods (After Group B)

- [x] **Task #2a**: Add evaluate_combined() for verifier use case
  - File: `protocol/expression_evaluator.py`
  - Add method to `ExpressionsPack`:
    ```python
    def evaluate_combined(self, params: StepsParams,
                          expression_specs: list[tuple[int, int, str]],
                          domain_size: int = 1) -> np.ndarray:
        """Evaluate multiple expressions and combine results.

        Used by verifier to evaluate expressions at challenge points.

        Args:
            params: Working data container
            expression_specs: List of (exp_id, dim, op_type) tuples
                - op_type: "tmp" for expression, "cm"/"const" for polynomial
            domain_size: Evaluation domain (1 for scalar, n_queries for batch)

        Returns:
            Combined evaluation result as numpy array
        """
        dest_buf = np.zeros(domain_size * FIELD_EXTENSION_DEGREE, dtype=np.uint64)
        dest = _Dest(dest=dest_buf, domain_size=domain_size, dim=FIELD_EXTENSION_DEGREE)

        for exp_id, dim, op_type in expression_specs:
            param = _Params(exp_id=exp_id, dim=dim, op=op_type)
            dest.params.append(param)

        self.calculate_expressions(params, dest, domain_size, False)
        return dest_buf
    ```
  - File: `protocol/verifier.py`
    - Refactor `_verify_evaluations()` to use `evaluate_combined()`
    - Refactor `_verify_fri_consistency()` to use `evaluate_combined()`
    - Remove direct `_Dest`/`_Params` imports
  - Test: All verifier tests must pass

- [x] **Task #2b**: Add helper for witness_generation use case
  - File: `protocol/expression_evaluator.py`
  - Add method to `ExpressionsPack`:
    ```python
    def evaluate_hint_expressions(self, params: StepsParams,
                                   expression_ids: list[int],
                                   dest_buffer: np.ndarray,
                                   domain_size: int) -> None:
        """Evaluate hint expressions into destination buffer.

        Used by witness generation to compute intermediate values.
        """
        dest = _Dest(dest=dest_buffer, domain_size=domain_size)
        for exp_id in expression_ids:
            exp_info = self.setup_ctx.expressions_bin.expressions_info[exp_id]
            param = _Params(exp_id=exp_id, dim=exp_info.dest_dim, op="tmp")
            dest.params.append(param)
            dest.dim = max(dest.dim, exp_info.dest_dim)

        self.calculate_expressions(params, dest, domain_size, False)
    ```
  - File: `protocol/witness_generation.py`
    - Refactor to use `evaluate_hint_expressions()` where possible
    - Remove direct `_Dest`/`_Params` usage
  - Test: All witness generation tests must pass

#### Group D: Documentation (Can run in parallel with Group C)

- [x] **Task #3**: Update module documentation
  - File: `protocol/expression_evaluator.py`
  - Update module docstring at top of file:
    ```python
    """Expression evaluator for STARK constraint polynomials.

    Protocol Constants:
        OPENING_POINTS: Polynomial opening offsets [-1, 0, 1]
        N_STAGES: Number of prover stages (2)
        N_QUERIES: FRI query count (228)
        BLOWUP_FACTOR: LDE extension factor (2)

    Public API:
        ExpressionsPack: Main evaluator class
        - calculate_expression(params, dest, expression_id): Evaluate single expression
        - calculate_expressions(params, dest, domain_size, domain_extended): Low-level evaluation
        - set_xi(xis): Set FRI challenge points
        - evaluate_combined(params, specs, domain_size): Evaluate and combine expressions

    Internal (prefixed with _):
        _Dest, _Params: Buffer management structures (C++ compatibility layer)
        _load_operand, _apply_op, etc.: Bytecode interpreter internals

    Architecture:
        This module separates protocol logic from engineering:
        - Protocol: expression_id, domain configuration, opening points
        - Engineering: bytecode interpretation, buffer offsets, batch processing
    """
    ```
  - File: `protocol/__init__.py`
    - Update `__all__` to export constants and `ExpressionsPack` only
    - Add comment explaining that Dest/Params are internal

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
- Run tests after each task: `uv run python -m pytest tests/ -v`

### Progress Tracking
The checkboxes above represent the authoritative status of each task. Keep them updated as you work.

## Verification

After all tasks complete:
1. `uv run python -m pytest tests/ -v` - All 142 tests pass
2. `grep -r "inverse\|compilation_time\|verify_constraints\|debug" protocol/expression_evaluator.py` - No dead arguments in signatures
3. `grep -r "from protocol.expression_evaluator import.*Dest\|Params" protocol/` - No external imports of Dest/Params (except underscore-prefixed)
4. `grep "OPENING_POINTS\|N_STAGES\|N_QUERIES\|BLOWUP_FACTOR" protocol/expression_evaluator.py` - Constants are defined
5. Verify byte-identical proofs still work
