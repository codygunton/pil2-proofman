# Plan: Remove Expression Binary Machinery

## Goal
Replace bytecode-interpreted constraint expressions with direct Python code, eliminating ~1,500 lines of complexity while maintaining byte-identical proofs.

## Current State
- **~36% of protocol code** (1,880 of 5,173 lines) exists for expression binary interpretation
- 3 main files to remove/simplify:
  - `expressions_bin.py` (832 lines) - binary parser, 17 OpType variants
  - `expression_evaluator.py` (627 lines) - bytecode interpreter with 180-line `_load_operand()`
  - `witness_generation.py` (416 lines) - hint-driven witness computation

## Architecture Overview

### New Structure
```
executable-spec/
├── primitives/         # UNCHANGED
├── protocol/           # SIMPLIFIED
│   ├── prover.py       # Calls constraint modules instead of ExpressionsPack
│   ├── verifier.py     # Uses constraint modules
│   ├── stages.py       # Remove expressions_ctx parameter
│   └── setup_ctx.py    # No expressions_bin loading
│
└── constraints/        # NEW - Direct Python constraints
    ├── base.py         # WitnessAccessor + ConstraintModule interface
    ├── simple_left.py  # SimpleLeft AIR (8 constraints)
    ├── lookup2_12.py   # Lookup2_12 AIR
    └── permutation1_6.py
```

### Key Interface: ConstraintModule
```python
class ConstraintModule(ABC):
    def compute_intermediates(self, w: WitnessAccessor) -> None:
        """Stage 2: im_cluster, gsum polynomials."""

    def compute_grand_sums(self, w: WitnessAccessor) -> None:
        """Witness STD: running sums for lookup/permutation."""

    def constraint_polynomial(self, w: WitnessAccessor) -> FF3Array:
        """Quotient: C(x) / Z_H(x)."""

    def fri_polynomial(self, w: WitnessAccessor, xis: FF3Array) -> FF3Array:
        """FRI: Linear combination of committed polynomials."""
```

### Example: SimpleLeft Constraint (before vs after)

**Before (bytecode):**
```python
# 180 lines of _load_operand() to decode:
a = self._load_operand(..., OpType.cm, col_id=0, stride_table[...])
b = self._load_operand(..., OpType.cm, col_id=1, ...)
alpha = self._load_operand(..., OpType.challenge, 0, ...)
result = (a + alpha * b) * gamma_inv
```

**After (direct Python):**
```python
def compute_intermediates(self, w: WitnessAccessor):
    a, b = w.col('a'), w.col('b')
    alpha, gamma = w.challenge('std_alpha'), w.challenge('std_gamma')
    im0 = batch_inverse(a + alpha * b + gamma)
    w.set_col('im_cluster', im0, index=0)
```

---

## Implementation Phases

### Phase 1: Create constraint infrastructure
**Files to create:**
- `constraints/__init__.py` - Registry: `get_constraint_module(air_name)`
- `constraints/base.py` - `WitnessAccessor` and `ConstraintModule` ABC

**WitnessAccessor provides:**
- `col(name, row_offset=0)` - Load witness column by name
- `const(name)` - Load constant polynomial
- `challenge(name)` - Get challenge value
- `set_col(name, values)` - Write stage 2+ columns

### Phase 2: Implement SimpleLeft constraints
**File:** `constraints/simple_left.py`

SimpleLeft has 8 constraints using logup protocol:
1. 6 logup sum checks (permutation + lookup + range checks)
2. 1 grand sum accumulation
3. 1 boundary constraint

Implement all 4 `ConstraintModule` methods, test against existing test vectors.

### Phase 3: Refactor prover.py
**Current callsites to replace:**
```python
# Line ~161: ExpressionsPack initialization
expressions_ctx = ExpressionsPack(setup_ctx, prover_helpers)

# Line ~305: Stage 2 intermediates
starks.calculateImPolsExpressions(2, params, expressions_ctx)

# Line ~319-320: Witness STD
calculate_witness_std(..., expressions_ctx, prod=True/False)

# Line ~366: Quotient polynomial
starks.calculateQuotientPolynomial(params, expressions_ctx)

# Line ~483: FRI polynomial
starks.calculateFRIPolynomial(params, expressions_ctx)
```

**Replace with:**
```python
w = WitnessAccessor(stark_info, params)
constraint_module = setup_ctx.constraint_module

constraint_module.compute_intermediates(w)
constraint_module.compute_grand_sums(w)
# ... commit stage 2 ...

q_pol = constraint_module.constraint_polynomial(w)
# ... commit quotient ...

fri_pol = constraint_module.fri_polynomial(w, xis)
```

### Phase 4: Implement remaining AIRs
- `constraints/lookup2_12.py` - More complex lookup operations
- `constraints/permutation1_6.py` - Permutation constraints

### Phase 5: Delete bytecode machinery
- Delete `expressions_bin.py` entirely (832 lines)
- Gut `expression_evaluator.py` - keep only `ExpressionsCtx` for memory layout (~100 lines)
- Simplify `witness_generation.py` - remove hint parsing (~50 lines remain)
- Remove `expressions_bin` field from `SetupCtx`

### Phase 6: Update verifier
- Verifier evaluates constraints at single point (xi)
- Reuse `constraint_module.constraint_polynomial()` with domain_size=1

---

## Estimated Impact

| File | Before | After | Change |
|------|--------|-------|--------|
| expressions_bin.py | 832 | 0 | -832 |
| expression_evaluator.py | 627 | ~100 | -527 |
| witness_generation.py | 416 | ~50 | -366 |
| prover.py | 799 | ~700 | -99 |
| setup_ctx.py | 242 | ~150 | -92 |
| **New: constraints/** | 0 | ~400 | +400 |
| **Net** | ~2916 | ~1400 | **-1516 lines** |

**Conceptual complexity removed:**
- 17 OpType variants → gone
- Stride/offset table management → gone
- Bytecode instruction interpretation → gone
- Hint field parsing → gone

---

## Verification

After each phase:
1. Run `uv run python -m pytest tests/ -v`
2. Specifically verify byte-identical proofs: `TestStarkE2EComplete`, `TestFullBinaryComparison`
3. All 142 tests must pass

---

## Critical Files

| File | Role |
|------|------|
| `protocol/prover.py` | Main integration - 4 expression callsites |
| `protocol/stages.py` | `Starks` class - polynomial operations |
| `protocol/expression_evaluator.py` | Current bytecode interpreter (to delete) |
| `protocol/witness_generation.py` | Hint-driven witness (to simplify) |
| `tests/test-data/simple-left.json` | Golden test vector |

---

## Risks

1. **Byte-identical proofs** - Field operation ordering must match exactly
   - *Mitigation*: Test each phase against golden vectors

2. **Logup protocol complexity** - Grand sum/product formulas are non-trivial
   - *Mitigation*: Study existing witness_generation.py carefully

3. **Verifier changes** - Must also use constraint modules
   - *Mitigation*: Verifier is simpler (single-point evaluation)
