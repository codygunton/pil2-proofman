# Expression Evaluator Comments Implementation Plan

## Executive Summary

The `expression_evaluator.py` file contains three inline comments/questions that need to be addressed:

1. **Line 67**: Question about whether `ExpressionsCtx` contains protocol logic or engineering decisions
2. **Line 213**: Request to add documentation comments to `calculate_expressions` and subsequent functions
3. **Lines 566-567**: Question about FF3 type promotion optimization

After investigation, we have clear answers for all three. This plan documents the changes to resolve these comments with proper documentation.

## Goals & Objectives

### Primary Goals
- Remove all inline TODO/question comments from `expression_evaluator.py`
- Add clear documentation distinguishing protocol logic from engineering decisions
- Document all methods in `ExpressionsPack` class with cryptographer-focused docstrings

### Secondary Objectives
- Improve code readability for cryptographers reviewing the executable spec
- Preserve the technical insights from the investigation as permanent documentation

## Solution Overview

### Approach
Replace inline question comments with permanent documentation that answers the questions. Add comprehensive docstrings to all undocumented methods.

### Key Components
1. **ExpressionsCtx class docstring**: Expand to clarify protocol vs engineering split
2. **ExpressionsPack methods**: Add docstrings explaining purpose and STARK context
3. **FF3 optimization comment**: Replace question with explanation of why current approach is correct

### Expected Outcomes
- All TODO/question comments removed
- Every method in ExpressionsPack has a clear docstring
- A cryptographer can understand what each function does without reading implementation

## Implementation Tasks

### CRITICAL IMPLEMENTATION RULES
1. All docstrings should focus on WHAT the function does, not HOW
2. Mention STARK protocol concepts where relevant (opening points, FRI, etc.)
3. Keep docstrings concise - this is an executable spec, not a tutorial

### Visual Dependency Tree

```
executable-spec/protocol/
└── expression_evaluator.py
    ├── Line 67-69: ExpressionsCtx class docstring (Task #1)
    ├── Line 213-218: calculate_expressions docstring (Task #2)
    ├── Line 354-358: _load_direct_poly docstring (Task #2)
    ├── Line 386-393: _load_operand docstring (Task #2)
    ├── Line 566-584: _apply_op - replace comment + docstring (Task #3)
    ├── Line 586-597: _multiply_results docstring (Task #3)
    └── Line 599-600: _store_result docstring (Task #2)
```

### Execution Plan

#### Group A: All tasks can execute in parallel (single file, no dependencies)

- [x] **Task #1**: Update ExpressionsCtx class documentation
  - File: `executable-spec/protocol/expression_evaluator.py`
  - Lines: 67-69
  - Changes:
    1. Remove the question comment `# Q: Does this class contain any protocol logic, or just engineering decisions?]f`
    2. Expand the class docstring to explain the split:
       - Protocol logic: opening point strides, xi values, cyclic constraint bounds, n_queries
       - Engineering: memory offsets, buffer layout, batch sizes
  - New docstring content:
    ```python
    """Memory layout and stride mappings for polynomial access.

    This class separates:
    - Protocol logic: opening point strides (next_strides), xi challenge points,
      cyclic constraint bounds (min_row/max_row), and n_queries (security parameter)
    - Engineering: buffer offsets (map_offsets), column counts (map_sections_n),
      batch sizes (nrows_pack_), and helper object references
    """
    ```

- [x] **Task #2**: Add docstrings to ExpressionsPack methods
  - File: `executable-spec/protocol/expression_evaluator.py`
  - Lines: 213-218, 354-358, 386-393, 599-600
  - Changes:
    1. Remove `# DOTHIS: comment needed on this and subsequent cuntions` (line 213)
    2. Expand `calculate_expressions` docstring to explain bytecode evaluation loop
    3. Expand `_load_direct_poly` docstring to explain cm/const buffer access
    4. Expand `_load_operand` docstring to explain bytecode operand dispatch
    5. Expand `_store_result` docstring to explain FF/FF3 storage format
  - New docstrings:
    ```python
    # calculate_expressions (line 214-218)
    """Evaluate constraint expressions via bytecode interpretation.

    Iterates over domain in batches of nrows_pack rows. For each batch:
    1. Loads operands from polynomial buffers or scalar parameters
    2. Executes arithmetic operations (add/sub/mul) per bytecode
    3. Stores results to destination buffer

    Handles cyclic constraints at domain boundaries via modular indexing.
    """

    # _load_direct_poly (line 354-358)
    """Load polynomial values directly from trace or constant buffers.

    Used for cm (committed) and const polynomial operands. Applies
    opening point offset and handles both base and extended domains.
    """

    # _load_operand (line 386-393)
    """Dispatch operand load based on bytecode type argument.

    Type codes map to data sources:
    - 0: constant polynomials
    - 1..nStages+1: committed polynomials by stage
    - nStages+2: boundary values (x_n, zerofiers zi)
    - nStages+3: FRI quotient x/(x-xi)
    - nStages+4+: custom commits
    - buffer_commits_size: base field temp registers
    - buffer_commits_size+1: extension field temp registers
    - buffer_commits_size+2..8: scalar parameters (publics, challenges, etc.)
    """

    # _store_result (line 599-600)
    """Write evaluation result to destination buffer.

    FF values store as single elements. FF3 values store as 3 consecutive
    coefficients in ascending degree order (c0, c1, c2).
    """
    ```

- [x] **Task #3**: Update FF3 type promotion documentation
  - File: `executable-spec/protocol/expression_evaluator.py`
  - Lines: 566-598
  - Changes:
    1. Remove the question comments at lines 566-567
    2. Add a clear docstring to `_apply_op` explaining the type promotion strategy
    3. The existing `_multiply_results` docstring is already good - keep it
  - **Investigation findings** (bytecode op_type distribution):
    | AIR | FF*FF (op_type=0) | FF3*FF (op_type=1) | FF3*FF3 (op_type=2) |
    |-----|-------------------|---------------------|----------------------|
    | simple-left | 16 (4.3%) | 161 (43.2%) | 196 (52.5%) |
    | lookup2-12 | 5 (2.2%) | 92 (40.9%) | 128 (56.9%) |
    | permutation1-6 | 4 (1.7%) | 100 (42.2%) | 133 (56.1%) |
  - **Answer**: Yes, FF*FF cases do occur (~2-4%). Type checking needed to preserve `FF*FF → FF`.
  - New docstring for `_apply_op`:
    ```python
    """Apply arithmetic operation with type-aware field promotion.

    Promotes FF to FF3 only when operands have mismatched types. This preserves
    FF*FF -> FF for the ~2-4% of operations that are base-field only, avoiding
    unnecessary extension. Type checking is ~54x faster than unconditional FF3
    promotion, which matters in this hot path.

    Operations: 0=add, 1=sub, 2=mul, 3=sub_swap (b-a)
    """
    ```

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

### Progress Tracking
The checkboxes above represent the authoritative status of each task. Keep them updated as you work.
