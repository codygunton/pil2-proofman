# Design: Remove Expression Binary Machinery

## Overview

Replace ~1,875 lines of C++ expression binary bytecode interpretation with ~400 lines of direct Python constraint code. This makes the executable spec self-contained and readable.

## Goals

- Eliminate dependency on external expression binaries compiled from C++
- Make constraint logic readable and explicit in Python
- Maintain byte-identical proofs with C++ implementation
- Simplify data structures from C++ buffer-style to clean Python

## Module Structure

```
executable-spec/
├── primitives/              # UNCHANGED
│
├── protocol/                # SIMPLIFIED
│   ├── prover.py           # Orchestrates witness + constraint modules
│   ├── verifier.py         # Uses constraint modules with VerifierData
│   ├── stages.py           # FRI polynomial (generic), NTT, commitments
│   ├── fri.py              # FRI folding (unchanged)
│   ├── pcs.py              # Polynomial commitment (unchanged)
│   └── stark_info.py       # Parses stark_info.json, builds name→index maps
│
├── constraints/             # NEW - Constraint evaluation
│   ├── base.py             # ConstraintContext, ConstraintModule ABC
│   ├── simple_left.py      # SimpleLeft constraint_polynomial()
│   ├── lookup2_12.py
│   └── permutation1_6.py
│
├── witness/                 # NEW - Witness generation (prover only)
│   ├── base.py             # WitnessModule ABC
│   ├── simple_left.py      # compute_intermediates(), compute_grand_sums()
│   ├── lookup2_12.py
│   └── permutation1_6.py
│
└── tests/                   # UNCHANGED
```

### Files Deleted

- `expressions_bin.py` (832 lines) - bytecode parser
- Most of `expression_evaluator.py` (~527 lines) - bytecode interpreter
- Most of `witness_generation.py` (~366 lines) - hint parsing

## Data Structures

Replace `ProofContext` (C++ buffer-style) with clean, semantically-named structures:

```python
@dataclass
class ProverData:
    """All polynomial data for proving."""
    columns: dict[str, FF3Poly]       # 'a' -> array of N*blowup values
    constants: dict[str, FFPoly]      # '__L1__' -> Lagrange selector
    challenges: dict[str, FF3]        # 'std_alpha' -> scalar
    public_inputs: dict[str, FF]      # named public inputs

@dataclass
class VerifierData:
    """All evaluation data for verification."""
    evals: dict[str, FF3]             # 'a@0' -> evaluation at xi*w^0
    challenges: dict[str, FF3]        # 'std_alpha' -> scalar
    public_inputs: dict[str, FF]      # named public inputs
```

### Key Properties

- **Names from stark_info** - `cmPolsMap`, `challengesMap` etc. provide name→index mapping
- **Array columns** - Indexed by name + index: `columns[('im_cluster', 3)]`
- **Galois types throughout** - No raw `np.ndarray` with manual index math
- **Prover vs verifier** - Prover operates on arrays, verifier on scalar evaluations
- **Broadcasting** - Same constraint code works on both via numpy broadcasting

### Construction

```python
ProverData.from_stark_info(stark_info, trace, constants)  # builds from raw inputs
VerifierData.from_proof(stark_info, proof)                # extracts from proof
```

## ConstraintContext Interface

Uniform interface for constraint evaluation - works for prover and verifier:

```python
class ConstraintContext(ABC):
    @abstractmethod
    def col(self, name: str, index: int = 0) -> FF3Poly | FF3:
        """Get column at current row. Returns array (prover) or scalar (verifier)."""

    @abstractmethod
    def next_col(self, name: str, index: int = 0) -> FF3Poly | FF3:
        """Get column at next row (offset +1)."""

    @abstractmethod
    def prev_col(self, name: str, index: int = 0) -> FF3Poly | FF3:
        """Get column at previous row (offset -1)."""

    @abstractmethod
    def const(self, name: str) -> FFPoly | FF:
        """Get constant polynomial."""

    @abstractmethod
    def challenge(self, name: str) -> FF3:
        """Get Fiat-Shamir challenge (always scalar)."""
```

### Prover Implementation

```python
class ProverConstraintContext(ConstraintContext):
    """Returns polynomial arrays."""

    def __init__(self, stark_info: StarkInfo, data: ProverData): ...

    def col(self, name: str, index: int = 0) -> FF3Poly:
        key = (name, index)
        return self._columns[key]

    def next_col(self, name: str, index: int = 0) -> FF3Poly:
        return np.roll(self.col(name, index), -1)
```

### Verifier Implementation

```python
class VerifierConstraintContext(ConstraintContext):
    """Returns scalar evaluations."""

    def __init__(self, stark_info: StarkInfo, data: VerifierData, xi: FF3): ...

    def col(self, name: str, index: int = 0) -> FF3:
        return self._evals[(name, index, 0)]  # eval at xi*w^0

    def next_col(self, name: str, index: int = 0) -> FF3:
        return self._evals[(name, index, 1)]  # eval at xi*w^1
```

## Module Interfaces

### ConstraintModule

Per-AIR constraint evaluation. Used by both prover and verifier.

```python
class ConstraintModule(ABC):
    @abstractmethod
    def constraint_polynomial(self, ctx: ConstraintContext) -> FF3Poly | FF3:
        """Evaluate all constraints combined into single polynomial.

        Returns:
            Prover: array of constraint evaluations at all domain points
            Verifier: single constraint evaluation at xi
        """
```

### WitnessModule

Per-AIR witness generation. Used by prover only.

```python
class WitnessModule(ABC):
    @abstractmethod
    def compute_intermediates(self, ctx: ConstraintContext) -> dict[str, dict[int, FF3Poly]]:
        """Compute im_cluster polynomials.

        Returns: {'im_cluster': {0: poly0, 1: poly1, ...}}
        """

    @abstractmethod
    def compute_grand_sums(self, ctx: ConstraintContext) -> dict[str, FF3Poly]:
        """Compute gsum/gprod running sum polynomials.

        Returns: {'gsum': gsum_poly}
        """
```

### Example: SimpleLeft Constraints

```python
class SimpleLeftConstraints(ConstraintModule):
    def constraint_polynomial(self, ctx):
        # Logup grand sum recurrence: gsum' = gsum + im_cluster_0 + ... + im_cluster_5
        gsum = ctx.col('gsum')
        gsum_next = ctx.next_col('gsum')

        im_sum = sum(ctx.col('im_cluster', i) for i in range(6))

        recurrence = gsum_next - gsum - im_sum

        # Boundary: gsum[0] = 0 (enforced by L1 selector)
        L1 = ctx.const('__L1__')
        boundary = L1 * gsum

        # Combine with random challenge
        vc = ctx.challenge('std_vc')
        return recurrence + vc * boundary
```

## Prover Integration

```python
def generate_proof(stark_info, trace, constants, ...):
    data = ProverData.from_stark_info(stark_info, trace, constants)

    constraint_module = get_constraint_module(stark_info.name)
    witness_module = get_witness_module(stark_info.name)

    # Stage 2: Compute intermediates
    ctx = ProverConstraintContext(stark_info, data)
    intermediates = witness_module.compute_intermediates(ctx)
    data.update(intermediates)

    # Stage 2: Compute grand sums
    grand_sums = witness_module.compute_grand_sums(ctx)
    data.update(grand_sums)

    # Stage 2: Commit stage 2 polynomials
    commit_stage2(data)

    # Stage 3: Compute constraint polynomial
    ctx = ProverConstraintContext(stark_info, data)
    q_poly = constraint_module.constraint_polynomial(ctx)

    # Stage 3: Commit quotient
    commit_quotient(q_poly)

    # Stage 4+: FRI (generic, driven by stark_info.evMap)
    fri_polynomial = compute_fri_polynomial(stark_info, data)
    fri_proof = fri_prove(fri_polynomial)

    return assemble_proof(...)
```

## Verifier Integration

```python
def verify_proof(stark_info, proof, public_inputs, ...):
    data = VerifierData.from_proof(stark_info, proof, public_inputs)

    constraint_module = get_constraint_module(stark_info.name)

    xi = data.challenges['std_xi']
    ctx = VerifierConstraintContext(stark_info, data, xi)

    # Evaluate constraint at challenge point
    constraint_eval = constraint_module.constraint_polynomial(ctx)

    # Constraint must equal zero at random point
    if constraint_eval != FF3.zero():
        return False

    # Verify FRI opening (generic)
    if not verify_fri(stark_info, proof, data):
        return False

    return True
```

## Design Decisions

### Separate Constraints and Witness

Constraint evaluation and witness generation are decoupled:
- **Constraints** express "what equations must hold"
- **Witness** computes "values that make equations hold"

No structural coupling between them. Verifier only uses constraints.

### Pure Functions

Module methods return dicts, no side effects:
```python
intermediates = witness_module.compute_intermediates(ctx)
# Returns {'im_cluster': {0: poly0, ...}}
# Caller handles storage
```

Easier to test and reason about.

### Galois Broadcasting

Same constraint code works for prover and verifier:
```python
def constraint(a, b, alpha):
    return a + alpha * b
# Works whether a, b are arrays (prover) or scalars (verifier)
```

### FRI Stays Generic

FRI polynomial is a linear combination defined by `stark_info.evMap`. Not AIR-specific - no per-AIR FRI modules needed.

### Names from stark_info

Column and challenge names come from stark_info mappings:
- `cmPolsMap[i].name` -> 'a', 'b', 'im_cluster', etc.
- `challengesMap[i].name` -> 'std_alpha', 'std_gamma', etc.

No hardcoded index mappings in constraint code.

## Migration Plan

```
Phase 1: Infrastructure (sequential)
├── constraints/base.py
├── witness/base.py
├── ProverData / VerifierData
└── stark_info.py name mapping helpers
    │
    ▼
┌─────────────────┬─────────────────┬─────────────────┬─────────────────┐
│ SimpleLeft      │ Lookup2_12      │ Permutation1_6  │ Verifier        │
│ - constraints/  │ - constraints/  │ - constraints/  │ - Use constraint│
│ - witness/      │ - witness/      │ - witness/      │   modules       │
│ - Wire prover   │ - Wire prover   │ - Wire prover   │ - Test with any │
│ - Test          │ - Test          │ - Test          │   completed AIR │
└─────────────────┴─────────────────┴─────────────────┘                 │
                          │                                             │
                          ▼                                             │
                  Phase 6: Cleanup ◄────────────────────────────────────┘
                  - Delete expressions_bin.py
                  - Gut expression_evaluator.py
                  - Gut witness_generation.py
                  - Remove ProofContext
```

### Parallelism

After Phase 1, four workstreams can proceed in parallel:
- SimpleLeft (constraints + witness)
- Lookup2_12 (constraints + witness)
- Permutation1_6 (constraints + witness)
- Verifier integration (once any AIR is complete)

### Verification

After each step:
1. Run `uv run python -m pytest tests/ -v`
2. Verify byte-identical proofs: `TestStarkE2EComplete`, `TestFullBinaryComparison`
3. All 142 tests must pass

## Impact

| File | Before | After | Change |
|------|--------|-------|--------|
| expressions_bin.py | 832 | 0 | -832 |
| expression_evaluator.py | 627 | ~100 | -527 |
| witness_generation.py | 416 | ~50 | -366 |
| prover.py | ~800 | ~700 | -100 |
| **New: constraints/** | 0 | ~200 | +200 |
| **New: witness/** | 0 | ~200 | +200 |
| **Net** | ~2675 | ~1250 | **~-1400 lines** |

### Complexity Removed

- 17 OpType variants
- Stride/offset table management
- Bytecode instruction interpretation
- Hint field parsing
- C++ buffer-style memory layout
