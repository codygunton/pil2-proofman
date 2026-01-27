# Expression Evaluator Deep Refactor Plan

**STATUS: COMPLETED** - All 142 tests pass. See summary below.

## Executive Summary

The current `expression_evaluator.py` exposes C++ implementation details (`_Dest`, `_Params`, buffer offsets, op type strings) that callers shouldn't need to understand. This refactor introduces a clean public API where callers think only about "evaluate expression X" while all buffer management becomes internal.

**Current State**: Callers construct `_Dest` and `_Params` objects, manage buffer offsets, and use magic strings like `"tmp"`, `"cm"`, `"const"`.

**Target State**: Callers call `evaluate(expression_id, domain_size, extended)` and get results. No buffer management, no magic strings, no C++ artifacts.

## Goals

1. **Clean public API** - Callers use 2-3 methods, not internal data structures
2. **No default arguments** - All parameters are explicit
3. **Hide buffer management** - Allocation and offsets are internal
4. **Remove magic strings** - No `"tmp"`, `"cm"`, `"const"` in public API
5. **All 142 tests pass** - No behavioral changes

## Non-Goals

- Changing the bytecode interpreter logic
- Optimizing performance
- Changing witness_generation's internal patterns (it's internal code)

## New Public API

```python
class ExpressionsPack:
    """Evaluator for STARK constraint polynomials.

    Public Methods:
        evaluate: Evaluate expression, return allocated buffer
        evaluate_into: Evaluate expression into provided buffer
        set_xi: Set FRI challenge points

    All buffer management, offset calculations, and bytecode interpretation
    are handled internally.
    """

    def evaluate(self, params: StepsParams, expression_id: int,
                 domain_size: int, extended: bool) -> np.ndarray:
        """Evaluate a single expression and return the result buffer.

        Args:
            params: Working data (trace, challenges, evals, etc.)
            expression_id: Which expression to evaluate
            domain_size: Number of evaluation points
            extended: True for extended domain (LDE), False for base domain

        Returns:
            Result buffer as numpy array (shape: domain_size * dim)
        """

    def evaluate_into(self, params: StepsParams, expression_id: int,
                      buffer: np.ndarray, offset: int, stride: int,
                      domain_size: int, extended: bool) -> None:
        """Evaluate an expression into a caller-provided buffer.

        Used when writing to a specific location in trace/auxTrace buffers.

        Args:
            params: Working data
            expression_id: Which expression to evaluate
            buffer: Destination numpy array
            offset: Starting index in buffer
            stride: Elements between consecutive results
            domain_size: Number of evaluation points
            extended: True for extended domain
        """

    def set_xi(self, xis: np.ndarray) -> None:
        """Set FRI challenge points for xi division operations."""
```

## Removed from Public API

| Item | Replacement |
|------|-------------|
| `_Dest` class | Internal only - callers use `evaluate()` or `evaluate_into()` |
| `_Params` class | Internal only - expression metadata looked up by ID |
| `calculate_expression()` | Use `evaluate()` - auto-detects domain from expression type |
| `calculate_expressions()` | Internal only - wrapped by public methods |
| `evaluate_single()` | Merged into `evaluate()` |
| Default arguments | All removed - every call is explicit |

## Internal API (for witness_generation)

Since `witness_generation.py` is internal protocol code, it can use internal methods. We'll provide a cleaner internal interface:

```python
# Internal methods (prefixed with _)
def _evaluate_operand_division(self, params: StepsParams,
                                numerator: _Operand, denominator: _Operand,
                                domain_size: int, extended: bool) -> np.ndarray:
    """Internal: evaluate numerator / denominator.

    Used by witness_generation for hint field computations.
    """

@dataclass
class _Operand:
    """Internal operand specification (replaces _Params for hint fields)."""
    kind: str  # "expr", "poly", "const", "number", "challenge", "airvalue", "airgroupvalue"
    # Fields populated based on kind:
    exp_id: int = 0
    stage: int = 0
    stage_pos: int = 0
    dim: int = 1
    row_offset_index: int = 0
    value: int = 0
    index: int = 0  # For challenge/airvalue lookups
```

## Caller Changes

### stages.py - Before

```python
# calculateImPolsExpressions
destStruct = _Dest(dest=destBuffer, domain_size=domainSize, offset=0,
                   stage_pos=polMap.stagePos, stage_cols=nCols,
                   exp_id=polMap.expId, dim=polMap.dim)
destStruct.params.append(_Params(exp_id=polMap.expId, dim=polMap.dim,
                                  batch=True, op="tmp"))
expressionsCtx.calculate_expressions(params, destStruct, domainSize, False)

# calculateQuotientPolynomial
expressionsCtx.calculate_expression(params, qPol, self.setupCtx.stark_info.cExpId)

# calculateFRIPolynomial
expressionsCtx.set_xi(xis)
expressionsCtx.calculate_expression(params, fPol, self.setupCtx.stark_info.friExpId)
```

### stages.py - After

```python
# calculateImPolsExpressions
expressionsCtx.evaluate_into(params, polMap.expId, destBuffer,
                              offset=bufferOffset, stride=nCols,
                              domain_size=domainSize, extended=False)

# calculateQuotientPolynomial
expressionsCtx.evaluate_into(params, self.setupCtx.stark_info.cExpId, qPol,
                              offset=0, stride=FIELD_EXTENSION_DEGREE,
                              domain_size=N_ext, extended=True)

# calculateFRIPolynomial
expressionsCtx.set_xi(xis)
expressionsCtx.evaluate_into(params, self.setupCtx.stark_info.friExpId, fPol,
                              offset=0, stride=FIELD_EXTENSION_DEGREE,
                              domain_size=N_ext, extended=True)
```

### verifier.py - Before

```python
buff = expressions_pack.evaluate_single(params, stark_info.cExpId, domain_size=1)
buff = expressions_pack.evaluate_single(params, stark_info.friExpId, domain_size=n_queries)
```

### verifier.py - After

```python
buff = expressions_pack.evaluate(params, stark_info.cExpId,
                                  domain_size=1, extended=False)
buff = expressions_pack.evaluate(params, stark_info.friExpId,
                                  domain_size=n_queries, extended=False)
```

### witness_generation.py - Before

```python
param1 = _build_param_from_hint_field(stark_info, hf1.values[0])
param2 = _build_param_from_hint_field(stark_info, hf2.values[0])
param2.inverse = True
dest = _Dest(dest=dest_buffer, dim=dim, domain_size=N, params=[param1, param2])
expressions_ctx.calculate_expressions(params, dest, N, False)
```

### witness_generation.py - After

```python
op1 = _build_operand_from_hint_field(stark_info, hf1.values[0])
op2 = _build_operand_from_hint_field(stark_info, hf2.values[0])
result = expressions_ctx._evaluate_operand_division(params, op1, op2,
                                                     domain_size=N, extended=False)
```

## Implementation Tasks

### CRITICAL RULES
1. All 142 tests must pass after each task
2. No changes to bytecode interpretation logic
3. Preserve exact numerical behavior (byte-identical proofs)
4. No default arguments in any function signature

### Dependency Graph

```
Task #1: Add new public methods (evaluate, evaluate_into)
    │
    ├── Task #2: Update stages.py to use new API
    │       │
    │       └── Task #3: Remove calculate_expression from stages usage
    │
    ├── Task #4: Update verifier.py to use evaluate()
    │
    └── Task #5: Create internal _Operand and _evaluate_operand_division
            │
            └── Task #6: Update witness_generation to use internal API
                    │
                    └── Task #7: Remove _Dest/_Params from all external imports
                            │
                            └── Task #8: Delete deprecated methods and classes
```

### Execution Plan

#### Task #1: Add new public methods to ExpressionsPack

**File**: `protocol/expression_evaluator.py`

Add after `set_xi()` method:

```python
def evaluate(self, params: StepsParams, expression_id: int,
             domain_size: int, extended: bool) -> np.ndarray:
    """Evaluate a single expression and return the result buffer.

    Args:
        params: Working data (trace, challenges, evals, etc.)
        expression_id: Which expression to evaluate
        domain_size: Number of evaluation points
        extended: True for extended domain (LDE), False for base domain

    Returns:
        Result buffer as numpy array (shape: domain_size * dim)
    """
    exp_info = self.setup_ctx.expressions_bin.expressions_info[expression_id]
    dim = exp_info.dest_dim
    buff = np.zeros(dim * domain_size, dtype=np.uint64)

    dest = _Dest(dest=buff, domain_size=domain_size, offset=0,
                 exp_id=expression_id, dim=dim)
    dest.params.append(_Params(exp_id=expression_id, dim=dim, batch=True, op="tmp"))

    self._calculate_expressions_internal(params, dest, domain_size, extended)
    return buff

def evaluate_into(self, params: StepsParams, expression_id: int,
                  buffer: np.ndarray, offset: int, stride: int,
                  domain_size: int, extended: bool) -> None:
    """Evaluate an expression into a caller-provided buffer.

    Args:
        params: Working data
        expression_id: Which expression to evaluate
        buffer: Destination numpy array
        offset: Starting index in buffer
        stride: Elements between consecutive results (typically dim or nCols)
        domain_size: Number of evaluation points
        extended: True for extended domain
    """
    exp_info = self.setup_ctx.expressions_bin.expressions_info[expression_id]
    dim = exp_info.dest_dim

    dest = _Dest(dest=buffer, domain_size=domain_size, offset=offset,
                 exp_id=expression_id, dim=dim, stage_cols=stride)
    dest.params.append(_Params(exp_id=expression_id, dim=dim, batch=True, op="tmp"))

    self._calculate_expressions_internal(params, dest, domain_size, extended)
```

Also rename `calculate_expressions` to `_calculate_expressions_internal` (keep old name as deprecated alias temporarily).

**Test**: `uv run python -m pytest tests/ -v`

---

#### Task #2: Update stages.py - calculateImPolsExpressions

**File**: `protocol/stages.py`

**Before** (lines ~207-224):
```python
destStruct = _Dest(dest=destBuffer, domain_size=domainSize, offset=0,
                   stage_pos=polMap.stagePos, stage_cols=nCols,
                   exp_id=polMap.expId, dim=polMap.dim)
destStruct.params.append(_Params(exp_id=polMap.expId, dim=polMap.dim,
                                  batch=True, op="tmp"))
expressionsCtx.calculate_expressions(params, destStruct, domainSize, False)
```

**After**:
```python
# Calculate buffer offset: row position * stride + column position
buffer_offset = polMap.stagePos  # Column offset within row
expressionsCtx.evaluate_into(
    params, polMap.expId, destBuffer,
    offset=buffer_offset, stride=nCols,
    domain_size=domainSize, extended=False
)
```

**Test**: Must pass

---

#### Task #3: Update stages.py - calculateQuotientPolynomial and calculateFRIPolynomial

**File**: `protocol/stages.py`

**calculateQuotientPolynomial - Before**:
```python
expressionsCtx.calculate_expression(params, qPol, self.setupCtx.stark_info.cExpId)
```

**After**:
```python
N_ext = 1 << self.setupCtx.stark_info.starkStruct.nBitsExt
expressionsCtx.evaluate_into(
    params, self.setupCtx.stark_info.cExpId, qPol,
    offset=0, stride=FIELD_EXTENSION_DEGREE,
    domain_size=N_ext, extended=True
)
```

**calculateFRIPolynomial - Before**:
```python
expressionsCtx.set_xi(xis)
expressionsCtx.calculate_expression(params, fPol, self.setupCtx.stark_info.friExpId)
```

**After**:
```python
N_ext = 1 << self.setupCtx.stark_info.starkStruct.nBitsExt
expressionsCtx.set_xi(xis)
expressionsCtx.evaluate_into(
    params, self.setupCtx.stark_info.friExpId, fPol,
    offset=0, stride=FIELD_EXTENSION_DEGREE,
    domain_size=N_ext, extended=True
)
```

Remove `_Dest` and `_Params` imports from stages.py.

**Test**: Must pass

---

#### Task #4: Update verifier.py to use evaluate()

**File**: `protocol/verifier.py`

**Before**:
```python
buff = expressions_pack.evaluate_single(params, stark_info.cExpId, domain_size=1)
buff = expressions_pack.evaluate_single(params, stark_info.friExpId, domain_size=n_queries)
```

**After**:
```python
buff = expressions_pack.evaluate(params, stark_info.cExpId,
                                  domain_size=1, extended=False)
buff = expressions_pack.evaluate(params, stark_info.friExpId,
                                  domain_size=n_queries, extended=False)
```

**Test**: Must pass

---

#### Task #5: Create internal _Operand and _evaluate_operand_division

**File**: `protocol/expression_evaluator.py`

Add new internal dataclass:

```python
@dataclass
class _Operand:
    """Internal operand specification for division operations.

    Used by witness_generation for hint field computations where
    we need to evaluate (field1 / field2) patterns.
    """
    kind: str  # "expr", "poly", "const", "number", "challenge", "airvalue", "airgroupvalue"
    exp_id: int = 0
    stage: int = 0
    stage_pos: int = 0
    dim: int = 1
    row_offset_index: int = 0
    value: int = 0
    index: int = 0
    pols_map_id: int = 0
```

Add method to ExpressionsPack:

```python
def _evaluate_operand_division(self, params: StepsParams,
                                numerator: _Operand, denominator: _Operand,
                                domain_size: int, extended: bool) -> np.ndarray:
    """Internal: evaluate numerator / denominator.

    Used by witness_generation for hint field computations.

    Args:
        params: Working data
        numerator: Numerator operand specification
        denominator: Denominator operand specification
        domain_size: Number of evaluation points
        extended: True for extended domain

    Returns:
        Result buffer (numerator / denominator at all points)
    """
    param1 = self._operand_to_params(numerator)
    param2 = self._operand_to_params(denominator)
    param2.inverse = True

    dim = max(param1.dim, param2.dim)
    buffer = np.zeros(domain_size * dim, dtype=np.uint64)

    dest = _Dest(dest=buffer, domain_size=domain_size, dim=dim,
                 params=[param1, param2])

    self._calculate_expressions_internal(params, dest, domain_size, extended)
    return buffer

def _operand_to_params(self, op: _Operand) -> _Params:
    """Convert _Operand to internal _Params."""
    if op.kind == "expr":
        return _Params(exp_id=op.exp_id, dim=op.dim,
                       row_offset_index=op.row_offset_index, batch=True, op="tmp")
    elif op.kind == "poly":
        return _Params(dim=op.dim, stage=op.stage, stage_pos=op.stage_pos,
                       pols_map_id=op.pols_map_id, row_offset_index=op.row_offset_index,
                       batch=True, op="cm")
    elif op.kind == "const":
        return _Params(dim=op.dim, stage_pos=op.stage_pos,
                       row_offset_index=op.row_offset_index, batch=True, op="const")
    elif op.kind == "number":
        return _Params(dim=1, value=op.value, batch=True, op="number")
    elif op.kind == "challenge":
        return _Params(dim=FIELD_EXTENSION_DEGREE, pols_map_id=op.index,
                       batch=True, op="challenge")
    elif op.kind == "airvalue":
        return _Params(dim=op.dim, pols_map_id=op.index, batch=True, op="airvalue")
    elif op.kind == "airgroupvalue":
        return _Params(dim=FIELD_EXTENSION_DEGREE, pols_map_id=op.index,
                       batch=True, op="airgroupvalue")
    else:
        raise ValueError(f"Unknown operand kind: {op.kind}")
```

**Test**: Must pass

---

#### Task #6: Update witness_generation to use internal API

**File**: `protocol/witness_generation.py`

Replace `_build_param_from_hint_field` with `_build_operand_from_hint_field`:

```python
from protocol.expression_evaluator import ExpressionsPack, _Operand

def _build_operand_from_hint_field(stark_info, hfv) -> _Operand:
    """Convert hint field value to internal operand."""
    if hfv.type == "exp":
        exp_info = ...  # lookup expression info
        return _Operand(kind="expr", exp_id=hfv.id, dim=exp_info.dest_dim,
                        row_offset_index=hfv.rowOffsetIndex)
    elif hfv.type == "cm":
        pol = stark_info.cmPolsMap[hfv.id]
        return _Operand(kind="poly", dim=pol.dim, stage=pol.stage,
                        stage_pos=pol.stagePos, pols_map_id=hfv.id,
                        row_offset_index=hfv.rowOffsetIndex)
    # ... etc for other types
```

Update callers to use `_evaluate_operand_division`:

```python
# Before
param1 = _build_param_from_hint_field(stark_info, hf1.values[0])
param2 = _build_param_from_hint_field(stark_info, hf2.values[0])
param2.inverse = True
dest = _Dest(dest=dest_buffer, dim=dim, domain_size=N, params=[param1, param2])
expressions_ctx.calculate_expressions(params, dest, N, False)

# After
op1 = _build_operand_from_hint_field(stark_info, hf1.values[0])
op2 = _build_operand_from_hint_field(stark_info, hf2.values[0])
result = expressions_ctx._evaluate_operand_division(params, op1, op2,
                                                     domain_size=N, extended=False)
np.copyto(dest_buffer, result)
```

Remove `_Dest` and `_Params` imports.

**Test**: Must pass

---

#### Task #7: Remove _Dest/_Params from public exports

**File**: `protocol/__init__.py`

Remove `_Dest` and `_Params` from any exports. They should not be importable from `protocol`.

**File**: `protocol/expression_evaluator.py`

Ensure `_Dest` and `_Params` are not in `__all__` (if it exists).

**Test**: Must pass

---

#### Task #8: Remove deprecated methods

**File**: `protocol/expression_evaluator.py`

1. Remove `calculate_expression()` method from `ExpressionsCtx` - replaced by `evaluate_into()`
2. Remove `evaluate_single()` method - replaced by `evaluate()`
3. Rename `calculate_expressions()` to `_calculate_expressions_internal()`
4. Remove `calculate_expressions()` from `ExpressionsCtx` base class

Update module docstring to reflect new API.

**Test**: Must pass

---

## Verification

After all tasks complete:

1. `uv run python -m pytest tests/ -v` - All 142 tests pass
2. `grep -r "from protocol.expression_evaluator import.*Dest\|Params" protocol/` - No imports of _Dest/_Params except in expression_evaluator.py itself
3. `grep "def.*=.*:" protocol/expression_evaluator.py | grep -v "self"` - No default arguments in function definitions
4. Verify byte-identical proofs: `TestFullBinaryComparison` tests pass

## Summary of Changes

| File | Changes |
|------|---------|
| `expression_evaluator.py` | +evaluate(), +evaluate_into(), +_Operand, +_evaluate_operand_division(), rename internal methods |
| `stages.py` | Use evaluate_into(), remove _Dest/_Params imports |
| `verifier.py` | Use evaluate(), already mostly clean |
| `witness_generation.py` | Use _Operand and _evaluate_operand_division(), remove _Dest/_Params |
| `__init__.py` | Remove _Dest/_Params exports |

## Implementation Workflow

1. **Load Plan**: Read this entire plan before starting
2. **Sync Tasks**: Create TodoWrite tasks matching the task list above
3. **Execute & Update**: For each task:
   - Mark TodoWrite as `in_progress` when starting
   - Update checkbox `[ ]` to `[x]` when completing
   - Run tests after each task
4. **Maintain Sync**: Keep this file and TodoWrite synchronized
