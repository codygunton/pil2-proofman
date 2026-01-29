# zkSNARK Python Style Guide

## Overview

This style guide defines the coding standards for Python code in the `executable-spec/` directory. The code serves as an **executable specification** for zkSNARK proving systems and must be maximally readable—optimized for humans reading it like a mathematical document.

**Audience:** Cryptographers and protocol engineers who need to understand STARK verification by reading the code.

**Philosophy:** Explicit is better than clever. Every line should be understandable without mental gymnastics.

## Base Requirements

### Standards
- **Google Python Style Guide** (with emphases on §2.21, §3.8, §3.16.4)
- **Type annotations** required on ALL functions (parameters and return types)
- **Docstrings** required in Google format

### Tooling
All code must pass:
```bash
uv run ruff check protocol/
uv run mypy --strict protocol/
```

## The 10 Readability-First Principles

### 1. Explicit Intermediate Variables
Break complex expressions into named steps. Each line should represent one logical operation.

```python
# GOOD: Each step is named and readable
wire_values = compute_wire_assignments(circuit, witness)
constraint_poly = build_constraint_polynomial(wire_values, selectors)
quotient = constraint_poly.divide_by_vanishing(domain)
commitment = commit_polynomial(quotient, srs)

# BAD: Dense and hard to follow
commitment = commit_polynomial(build_constraint_polynomial(compute_wire_assignments(circuit, witness), selectors).divide_by_vanishing(domain), srs)
```

### 2. Type Aliases for Domain Concepts
Use semantic type aliases at module level to make signatures self-documenting.

**Defined in `primitives/field.py`:**
| Alias | Meaning |
|-------|---------|
| `FF` | Base field GF(p) - Goldilocks prime |
| `FF3` | Cubic extension GF(p^3) |
| `FF3Poly` | Polynomial over extension field |
| `FFPoly` | Polynomial over base field |
| `FF3Array` | Array of extension field values |
| `FFArray` | Array of base field values |
| `InterleavedFF3` | Interleaved FF3 buffer `[c0,c1,c2,...]` for C++ compatibility |
| `HashOutput` | 4-element Poseidon hash output |

### 3. Functions Compute One Thing
Each function should correspond to a single mathematical operation. Name functions for what they return.

```python
# GOOD: Clear single purpose
def compute_vanishing_polynomial(domain_size: int) -> FFPoly:
    """Compute Z_H(x) = x^n - 1 for domain of size n."""
    ...

# BAD: Multiple responsibilities
def setup_and_compute_vanishing(domain_size: int, also_compute_roots: bool) -> tuple:
    ...
```

### 4. No Clever Python
Avoid these patterns:
- Walrus operator (`:=`)
- Comprehensions with more than one `for` or `if` clause
- Non-trivial inline conditionals
- Unnecessary `*args` or `**kwargs`
- Implicit boolean coercion for non-booleans

```python
# BAD: Clever but hard to read
result = [x for row in matrix for x in row if x > 0 and x % 2 == 0]

# GOOD: Explicit and clear
result = []
for row in matrix:
    for x in row:
        if x > 0 and x % 2 == 0:
            result.append(x)
```

### 5. Mathematical Notation Requires Citation
Single-letter variables MUST have a docstring or comment citing the source.

```python
def evaluate_polynomial(p: FFPoly, omega: FF) -> FF:
    """Evaluate polynomial at omega.

    Args:
        p: Polynomial coefficients
        omega: Evaluation point (primitive root of unity, see STARK paper §3.2)
    """
```

### 6. Docstrings as Specifications
Every public function needs:
- One-line description of what it computes
- Args with types and meaning
- Returns with type and meaning
- Reference to paper/section if implementing a known algorithm

```python
def compute_fri_fold(evals: FF3Array, challenge: FF3) -> FF3Array:
    """Fold polynomial evaluations using FRI folding formula.

    Implements the folding step from the FRI protocol where P'(x^2) is
    computed from P(x) and P(-x) using a random challenge.

    Args:
        evals: Evaluations [P(x_0), P(-x_0), P(x_1), P(-x_1), ...]
        challenge: Random folding challenge from verifier

    Returns:
        Folded evaluations [P'(x_0^2), P'(x_1^2), ...]

    Reference:
        DEEP-FRI paper, Section 4.2
    """
```

### 7. Vertical Whitespace for Logical Grouping
Use blank lines to separate logical steps within functions.

```python
def verify_proof(proof: Proof, vk: VerificationKey) -> bool:
    # Parse proof components
    commitments = proof.parse_commitments()
    evaluations = proof.parse_evaluations()

    # Reconstruct challenges via Fiat-Shamir
    challenges = reconstruct_challenges(commitments, evaluations)

    # Verify polynomial identities
    if not verify_quotient_identity(evaluations, challenges):
        return False

    # Verify FRI proof
    return verify_fri(proof.fri_proof, challenges)
```

### 8. Explicit Loops Over Functional Magic
Prefer explicit `for` loops over `map`, `filter`, `reduce`.

```python
# BAD: Functional style
commitments = list(map(lambda p: commit(p, srs), polynomials))

# GOOD: Explicit loop
commitments = []
for poly in polynomials:
    commitment = commit(poly, srs)
    commitments.append(commitment)
```

### 9. No Abbreviations in Names (Except Math)
Spell out words fully.

| Bad | Good |
|-----|------|
| `poly_deg` | `polynomial_degree` |
| `vk` | `verification_key` |
| `comm` | `commitment` |
| `eval` | `evaluation` |

**Exception:** Mathematical symbols with citations (`n`, `k`, `omega`, `xi`)

### 10. Constants at Module Level, Named
No magic numbers inline. All constants must have descriptive names.

```python
# BAD: Magic number
if len(coefficients) > 1024:
    ...

# GOOD: Named constant
MAX_POLYNOMIAL_DEGREE = 1024

if len(coefficients) > MAX_POLYNOMIAL_DEGREE:
    ...
```

## What We Flag

- Missing type annotations
- Missing or incomplete docstrings
- Dense one-liners that should be broken into steps
- Unnamed intermediate values in complex expressions
- Multi-clause comprehensions
- Unclear variable names (except cited math notation)
- Magic numbers
- Functions doing more than one logical thing
- Implicit behavior that could be explicit

## What We Preserve

- Single-letter math variables WITH citations (e.g., `n`, `k`, `g`, `h`, `omega`)
- Explicit verbose code (more explicit is always acceptable)
- Multiple lines where one "clever" line would work
- Existing type aliases: `FF`, `FF3`, `FF3Poly`, `FFPoly`, `FF3Array`, `FFArray`, `HashOutput`, `InterleavedFF3`

## Quick Reference Checklist

Before submitting code, verify:

- [ ] All functions have type annotations (params + return)
- [ ] All public functions have Google-format docstrings
- [ ] No dense one-liners - each line does one thing
- [ ] All single-letter variables have citations
- [ ] No magic numbers - all constants named
- [ ] No multi-clause comprehensions
- [ ] No walrus operator (`:=`)
- [ ] Blank lines separate logical steps
- [ ] `uv run ruff check` passes
- [ ] `uv run mypy --strict` passes (or documents exceptions)

## Accepted Exceptions

Document any intentional deviations here with justification.

### SIM102: Nested if statements
**Location:** verifier.py lines 676, 750
**Pattern:**
```python
if llv > 0:
    if not MerkleTree.verify_merkle_root(...):
        return False
```
**Justification:** The outer condition (`llv > 0`) is a guard check, and the inner condition is the actual verification. Keeping them separate makes the guard condition's purpose clearer. Combining with `and` would obscure the "skip if disabled" intent.

### Abbreviations: `si`, `ss`, `llv`
**Location:** Throughout verifier.py
**Justification:** These abbreviations are pervasive (100+ uses of `si`). Renaming would be a large refactor with risk of introducing bugs. The abbreviations are documented at file level:
- `si` = `stark_info` (StarkInfo)
- `ss` = `stark_struct` (StarkStruct)
- `llv` = `last_level_verification`
