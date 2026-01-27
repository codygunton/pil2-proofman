# Expression Evaluator Abstraction Research

## Purpose

This document analyzes the usage patterns of `ExpressionsPack` to determine the right abstraction level for a protocol-focused API. The current API exposes engineering details (domain sizes, buffer offsets, strides) that obscure the protocol logic.

## Current API

```python
class ExpressionsPack:
    def evaluate(params, expression_id, domain_size, extended) -> np.ndarray
    def evaluate_into(params, expression_id, buffer, offset, stride, domain_size, extended)
    def set_xi(xis)
    def _evaluate_operand_pair(params, op1, op2, invert_second, domain_size)  # internal
```

## Call Site Analysis

### 1. Prover: Intermediate Polynomial Computation

**Location**: `stages.py:190-208` in `calculateImPolsExpressions()`

**What it does**: Evaluates intermediate polynomial expressions (imPol) and writes them to their designated trace columns.

**Protocol meaning**: Some committed polynomials are defined as expressions over other polynomials (e.g., `a = b * c`). These must be computed before commitment.

**Current call**:
```python
for polMap in stark_info.cmPolsMap:
    if polMap.imPol and polMap.stage == step:
        expressionsCtx.evaluate_into(
            params, polMap.expId, pAddress,
            offset=buffer_offset, stride=nCols,
            domain_size=domainSize, extended=False
        )
```

**Engineering details exposed**:
- `buffer_offset` = mapOffsets + stagePos
- `stride` = nCols (section column count)
- `domain_size` = 1 << nBits
- `extended` = False (always)

**What caller actually needs**: "Compute all intermediate polynomials for stage X"

---

### 2. Prover: Quotient Polynomial

**Location**: `stages.py:212-222` in `calculateQuotientPolynomial()`

**What it does**: Evaluates the constraint expression C(x) over the extended domain.

**Protocol meaning**: The prover must compute C(x) = sum of all constraint polynomials (weighted by challenges). This is the "main" STARK check - if constraints are satisfied, C(x) is divisible by the vanishing polynomial.

**Current call**:
```python
N_ext = 1 << stark_info.starkStruct.nBitsExt
qOffset = stark_info.mapOffsets[("q", True)]
expressionsCtx.evaluate_into(
    params, stark_info.cExpId, params.auxTrace,
    offset=qOffset, stride=FIELD_EXTENSION_DEGREE,
    domain_size=N_ext, extended=True
)
```

**Engineering details exposed**:
- `cExpId` - the constraint expression ID
- `qOffset` - buffer offset for quotient polynomial
- `stride` = 3 (FF3 element size)
- `domain_size` = N_ext
- `extended` = True (always for constraint expression)

**What caller actually needs**: "Compute the constraint polynomial over extended domain"

---

### 3. Prover: FRI Polynomial

**Location**: `stages.py:224-261` in `calculateFRIPolynomial()`

**What it does**:
1. Computes xi challenge points: `xis[i] = xi * w^openingPoint[i]`
2. Evaluates FRI polynomial: F(x) = sum of p(x)/(x - xi) terms

**Protocol meaning**: The FRI polynomial combines all committed polynomials evaluated at their respective opening points, divided by (x - xi). This is the polynomial that gets FRI-committed.

**Current call**:
```python
# Compute xis from xi challenge
xis = ...  # 20 lines of xi computation
expressionsCtx.set_xi(xis)

N_ext = 1 << stark_info.starkStruct.nBitsExt
fOffset = stark_info.mapOffsets[("f", True)]
expressionsCtx.evaluate_into(
    params, stark_info.friExpId, params.auxTrace,
    offset=fOffset, stride=FIELD_EXTENSION_DEGREE,
    domain_size=N_ext, extended=True
)
```

**Engineering details exposed**:
- `set_xi()` must be called separately before evaluation
- `friExpId` - the FRI expression ID
- `fOffset` - buffer offset for FRI polynomial
- Same stride/domain_size/extended pattern as quotient

**What caller actually needs**: "Compute the FRI polynomial given xi challenge"

---

### 4. Verifier: Constraint Evaluation Check

**Location**: `verifier.py:425-470` in `_verify_evaluations()`

**What it does**: Evaluates constraint expression at single point xi and checks Q(xi) == C(xi).

**Protocol meaning**: The verifier recomputes the constraint expression at the challenge point xi using the claimed polynomial evaluations. If the prover was honest, Q(xi) should equal C(xi).

**Current call**:
```python
buff = expressions_pack.evaluate(params, stark_info.cExpId,
                                  domain_size=1, extended=False)
```

**Engineering details exposed**:
- `cExpId` - same expression ID as prover
- `domain_size=1` - single point evaluation
- `extended=False` - verifier doesn't use extended domain

**What caller actually needs**: "Evaluate constraint expression at xi, return single FF3 value"

---

### 5. Verifier: FRI Consistency Check

**Location**: `verifier.py:473-510` in `_verify_fri_consistency()`

**What it does**: Evaluates FRI expression at all query points and checks against proof values.

**Protocol meaning**: The verifier recomputes what the FRI polynomial should be at each query point using the provided evaluations and opening values. These must match the values in the FRI proof.

**Current call**:
```python
n_queries = stark_info.starkStruct.nQueries
buff = expressions_pack.evaluate(params, stark_info.friExpId,
                                  domain_size=n_queries, extended=False)
```

**Engineering details exposed**:
- `friExpId` - same expression ID as prover
- `domain_size=n_queries` - batch evaluation at all query points
- `extended=False`

**What caller actually needs**: "Evaluate FRI expression at all query points"

---

### 6. Witness Generation: Hint Field Division

**Location**: `witness_generation.py:248-263` in `evaluate_hint_field_with_expressions()`

**What it does**: Computes field1 * field2^(-1) over entire domain using expression evaluator.

**Protocol meaning**: Lookup and permutation arguments require computing quotients of the form num/denom. These hint fields specify which polynomials/values to use.

**Current call**:
```python
param1 = _build_param_from_hint_field(stark_info, hf1.values[0])
param2 = _build_param_from_hint_field(stark_info, hf2.values[0])
return expressions_ctx._evaluate_operand_pair(
    params, param1, param2, invert_second=field2_inverse, domain_size=N
)
```

**Engineering details exposed**:
- `_Params` construction from hint fields
- `domain_size=N`
- Internal `_evaluate_operand_pair` API

**What caller actually needs**: "Evaluate hint field quotient over domain"

---

### 7. Witness Generation: Airgroup Value Update

**Location**: `witness_generation.py:322-363` in `update_airgroup_value()`

**What it does**: Evaluates field1/field2 at single point and updates airgroup accumulator.

**Protocol meaning**: Airgroup values accumulate products/sums across the constraint system for global checks.

**Current call**:
```python
result = expressions_ctx._evaluate_operand_pair(
    params, param1, param2, invert_second=True, domain_size=1
)
```

**Engineering details exposed**:
- `_Params` construction
- `domain_size=1` for single evaluation

**What caller actually needs**: "Evaluate hint field quotient at single row"

---

## Pattern Summary

| Call Site | Expression | Domain | Extended | Purpose |
|-----------|------------|--------|----------|---------|
| stages.py imPols | polMap.expId | N | False | Intermediate polynomials |
| stages.py quotient | cExpId | N_ext | True | Constraint polynomial |
| stages.py FRI | friExpId | N_ext | True | FRI polynomial |
| verifier constraint | cExpId | 1 | False | Verify Q(xi) = C(xi) |
| verifier FRI | friExpId | n_queries | False | Verify FRI at queries |
| witness_gen domain | operand pair | N | False | Hint field quotients |
| witness_gen scalar | operand pair | 1 | False | Airgroup updates |

## Key Observations

### 1. Expression IDs are Semantic
There are only a few "special" expressions:
- `cExpId` - The constraint polynomial (sum of all constraints)
- `friExpId` - The FRI polynomial (combination for opening)
- `polMap.expId` - Intermediate polynomial definitions

These could be named methods rather than IDs.

### 2. Domain Configuration is Predictable
- Prover constraint/FRI: always extended domain (N_ext)
- Verifier: never extended domain
- Intermediate polys: always base domain (N)
- The `extended` parameter could be inferred from context.

### 3. Buffer Management is Internal
The `offset`, `stride`, and buffer selection are pure engineering. The caller's intent is "compute X into its designated location" not "write to offset Y with stride Z".

### 4. set_xi() is Awkward
FRI polynomial evaluation requires calling `set_xi()` first. This is state mutation that should be encapsulated.

### 5. Witness Generation is Different
The witness generation uses a fundamentally different pattern: evaluating quotients of operand pairs rather than compiled expressions. This might warrant a separate API.

---

## Proposed Abstraction Levels

### Option A: Named Methods (Highest Abstraction)

```python
class ExpressionsPack:
    # Prover methods
    def compute_intermediate_polynomials(self, params: StepsParams, stage: int) -> None:
        """Compute all imPol expressions for a stage into their trace columns."""

    def compute_constraint_polynomial(self, params: StepsParams) -> None:
        """Compute C(x) over extended domain into quotient buffer."""

    def compute_fri_polynomial(self, params: StepsParams, xi_challenge: np.ndarray) -> None:
        """Compute F(x) over extended domain into FRI buffer."""

    # Verifier methods
    def verify_constraint_at_xi(self, params: StepsParams) -> FF3:
        """Evaluate C(xi) for verification."""

    def verify_fri_at_queries(self, params: StepsParams) -> np.ndarray:
        """Evaluate F(x) at all query points for verification."""

    # Witness generation (could be separate class)
    def evaluate_hint_quotient(self, params: StepsParams,
                                hint_id: int, field1: str, field2: str) -> np.ndarray:
        """Compute field1/field2 over domain for hint field."""
```

**Pros**:
- Callers describe what protocol step they're doing
- All engineering details hidden
- Impossible to misconfigure

**Cons**:
- Less flexible if new expression types are added
- May require changes to ExpressionsPack for new use cases
- Tight coupling to proof structure

### Option B: Context-Aware Generic Methods (Medium Abstraction)

```python
class ExpressionsPack:
    def evaluate_expression(self, params: StepsParams,
                            expression: Expression,
                            context: EvalContext) -> np.ndarray:
        """Evaluate an expression in given context."""

class Expression(Enum):
    CONSTRAINT = "constraint"      # cExpId
    FRI = "fri"                    # friExpId
    INTERMEDIATE = "intermediate"  # polMap.expId

class EvalContext(Enum):
    PROVER_EXTENDED = "prover_ext"    # N_ext, extended=True, into buffer
    PROVER_BASE = "prover_base"       # N, extended=False, into buffer
    VERIFIER_SINGLE = "verifier_1"    # 1 point, return value
    VERIFIER_QUERIES = "verifier_q"   # n_queries points, return array
```

**Pros**:
- More explicit about what's happening
- Extensible to new expressions
- Context makes configuration clear

**Cons**:
- Still requires understanding Expression and Context enums
- More verbose than Option A

### Option C: Separate Prover/Verifier Classes (Role-Based)

```python
class ProverExpressionEvaluator:
    """Expression evaluation for prover operations."""

    def compute_intermediate_polynomials(self, params, stage) -> None
    def compute_constraint_polynomial(self, params) -> None
    def compute_fri_polynomial(self, params, xi_challenge) -> None

class VerifierExpressionEvaluator:
    """Expression evaluation for verifier checks."""

    def evaluate_constraint(self, params) -> FF3
    def evaluate_fri_at_queries(self, params) -> np.ndarray

class WitnessExpressionEvaluator:
    """Expression evaluation for witness generation."""

    def evaluate_quotient(self, params, hint_id, field1, field2) -> np.ndarray
    def evaluate_quotient_scalar(self, params, hint_id, field1, field2) -> FF3
```

**Pros**:
- Clear role separation
- Each class has focused responsibility
- Natural place for role-specific state (e.g., xi for prover)

**Cons**:
- Code duplication if internals are similar
- Need to choose which class to instantiate

---

## Recommended Approach

**Start with Option A** (Named Methods) because:

1. **There are only 7 call sites** - not many patterns to support
2. **The patterns are stable** - these are fundamental STARK operations
3. **Protocol clarity is the goal** - named methods directly describe protocol steps
4. **Engineering is hidden** - callers never see offsets, strides, domain sizes

The internal implementation can still use the generic evaluate machinery, but the public API becomes:

```python
# Prover
starks.calculateQuotientPolynomial(params, expressions_ctx)
# becomes
expressions_ctx.compute_constraint_polynomial(params)

# Verifier
buff = expressions_pack.evaluate(params, stark_info.cExpId, domain_size=1, extended=False)
# becomes
result = expressions_pack.verify_constraint_at_xi(params)
```

If new expression types emerge, named methods can be added. The generic `evaluate()` could remain as an internal/escape-hatch method prefixed with `_`.

---

## Questions to Resolve

1. **Should witness generation be a separate class?** It has different patterns (operand pairs vs expressions).

2. **Where should xi computation live?** Currently in `calculateFRIPolynomial()`. Could move into `compute_fri_polynomial()`.

3. **Should buffer allocation be internal?** Prover writes to auxTrace at specific offsets. Should this be:
   - Fully internal (method knows where to write)
   - Return value (caller decides where to put it)
   - Hybrid (write to designated location AND return reference)

4. **How to handle intermediate polynomials?** They loop over polMap entries. Should this be:
   - One method that handles all stages
   - Method per polynomial
   - Iterator/callback pattern

---

## Next Steps

1. Prototype Option A with the 7 call sites
2. Validate that all engineering details can be hidden
3. Run tests to verify behavior unchanged
4. Get feedback on API clarity
5. Document the protocol meaning in method docstrings
