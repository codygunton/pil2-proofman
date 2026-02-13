# Verifier Simplification Meta-Plan

This plan outlines a phased approach to simplifying `executable-spec/protocol/verifier.py`. Based on investigation of the 32 clarity questions in [verifier-clarity-questions.md](./verifier-clarity-questions.md).

---

## Status: D0 COMPLETE (2026-02-05)

**D0 (Architecture Decisions) has been fully implemented**, not just designed. Key outcomes:

### What was implemented:
1. **PolynomialId** (`primitives/pol_map.py`) - NamedTuple for identifying polynomials
2. **MerkleVerifier** (`primitives/merkle_verifier.py`) - Encapsulates `last_level_verification` complexity
3. **Dict-based polynomial access** - `_parse_polynomial_values()` replaces 5 buffer functions
4. **Simplified Merkle verification** - 3 functions reduced from ~30-45 lines to ~15-20 lines each

### Items resolved by D0:
| Item | Status | Reason |
|------|--------|--------|
| A #14 (rename `buff`) | **RESOLVED** | `trace`/`aux_trace` buffers eliminated from verifier |
| B #7 (`[0]` subscripts) | **SOLVED** | Handled at parsing boundary only in `_parse_polynomial_values()` |
| D #17 (eliminate verifier buffers) | **DONE** | Implemented |
| D #23 (MerkleVerifier abstraction) | **DONE** | Implemented |
| Q2 (last_level_verification) | **ADDRESSED** | Reduced from 12+ exposures to 1 (inside MerkleVerifier) |
| D #3 (hide sponge width) | **ADDRESSED** | `MerkleConfig.sponge_width` computed internally |

### Test verification:
- All 155 tests pass
- E2E tests verify byte-identical proofs against C++ implementation
- Linter checks pass

---

---

## Investigation Results (Dependency Analysis)

### Q1: Can the verifier eliminate buffers?

**Finding: YES, with moderate effort.**

The verifier uses buffers (`trace`, `aux_trace`, `const_pols`) only in `compute_fri_polynomial_verifier`. The current flow:

1. Proof parsing (`_parse_trace_values`) extracts values from `proof.fri.trees.pol_queries[query_idx][tree_idx].v[col_idx][0]` into flat buffers
2. `compute_fri_polynomial_verifier` reads from buffers using offset arithmetic

**Alternative architecture:**
- Parse proof directly into `dict[PolynomialId, FF3]` where each FF3 has shape `(n_queries,)`
- `compute_fri_polynomial_verifier` uses dict lookups instead of buffer arithmetic
- Much cleaner: `poly_vals = poly_values_at_queries[(stage, name)]`

**What this resolves:**
- B #6 (interleaved buffer abstraction) → partially resolved for verifier
- B #7 ([0] subscripts) → solved at parsing boundary, not scattered throughout
- A #14 (`buff` rename) → resolved (variable eliminated)

**What still needs buffer work:** `evals`, `challenges`, `x_div_x_sub` are still interleaved buffers, so B #6 remains useful but less critical.

### Q2: Is `last_level_verification` protocol-level?

**Finding: NO, it's purely an engineering optimization.**

From the code analysis:
- It batches Merkle proofs by sharing intermediate level nodes across queries
- Without it (`last_level_verification = 0`), each query's Merkle proof goes directly to root
- Protocol correctness is unaffected; only proof size and verification efficiency change

**The problem:** `last_level_verification` appears 70+ times in the codebase, threading through:
- `MerkleTree` construction and proof generation
- All `_verify_*_merkle` functions
- Proof parsing/serialization

**Simplification options:**
1. **Always use 0** - Simplest, but can't verify C++ proofs that use it
2. **Hide inside abstraction** - Create `MerkleVerifier` class that handles this internally, exposing clean API

Option 2 is better: maintains compatibility while hiding complexity from the auditor.

### Revised Dependency Graph

```
D: Architecture Investigation
├── Q1 (buffers) ──┬── resolves A#14
│                  ├── solves B#7 at boundary
│                  └── reduces urgency of B#6
│
└── Q2 (last_level) ── dramatically simplifies Merkle code
                       (but must maintain proof compat)

Independent of D:
├── A: #1,2,9,10,12,19,27 (type aliases, helpers, renames, errors)
├── B: #29 (FF/FF3 discipline - always needed)
└── C: #5,11,13,30,31 (documentation, naming)
```

---

## Revised Project Structure

Based on the investigation, here's the revised plan:

---

## Project D0: Architecture Decisions (DO FIRST)

**Scope:** Make key architectural decisions that affect downstream work. This is a short spike, not full implementation.

**Decisions to make:**
1. **Verifier buffer elimination:** Design the `dict[PolynomialId, FF3]` structure and confirm it works with `compute_fri_polynomial_verifier`
2. **Merkle abstraction:** Design `MerkleVerifier` class API that hides `last_level_verification`

**Deliverables:**
- Proof-of-concept for buffer-free verifier polynomial access (can be throwaway code)
- API sketch for `MerkleVerifier`
- Updated dependency analysis: which items from A/B/C become resolved

**Risk:** Low (it's just investigation + design)
**Effort:** Small (1-2 days)
**Payoff:** Avoids wasted work on items that become resolved

---

## Project A: Low-Hanging Fruit (Immediate Clarity)

**Scope:** Straightforward changes that improve readability.

**Items:**
- #1: Remove Challenge type alias
- #2: Rename QueryIdx to something clearer (e.g., FRIQueryIdx)
- #9: Use `_get_challenge` helper consistently (replace inline slicing)
- #10: Rename `prime` → `row_offset` in EvMap
- #12: Expand `cm` abbreviation (or add comment explaining it)
- #19: Fix silent failure in `_find_xi_challenge` (raise exception)
- #27: Add context to error messages (query index, step number, etc.)

**Risk:** Low
**Effort:** Small
**Payoff:** Immediate readability improvement

---

## Project B: Type System & Field Element Discipline

**Scope:** Establish and enforce consistent FF/FF3 usage.

**Items:**
- #29: Document and enforce FF/FF3 type discipline (update CLAUDE.md/style guide)
- #6: Abstract remaining interleaved buffer arithmetic (for `evals`, `challenges`, `x_div_x_sub`)

**Risk:** Medium
**Effort:** Medium
**Payoff:** High—eliminates cognitive friction on field operations

---

## Project C: Data Structure Documentation & Naming

**Scope:** Understand and document the data model.

**Items:**
- #5: Trace EVALS_HASH_WIDTH to C++ and document derivation
- #11: Investigate and clarify `airgroup_values` vs `air_values` distinction
- #13: Check `x_div_x_sub` naming in C++ (keep if matches, rename if not)
- #30: Document STARKProof structure (docstrings or diagram)
- #31: Clarify `stark_struct` vs `stark_info` distinction

**Risk:** Low
**Effort:** Medium
**Payoff:** Medium—helps auditors understand the data model

**Independent of:** D0 decisions (documentation is always useful)

---

## Project D: Architecture Implementation (Remaining Items)

**Scope:** Complete remaining architecture improvements.

**Items:**
- #4: Eliminate stage offset constants (use named stages)
- #25: Fix circular dependencies (verify scope needed)
- #26: Separate parsing phase from verification phase (partially done - poly parsing separated)

**Risk:** Low-Medium (core refactoring complete)
**Effort:** Small-Medium
**Payoff:** Incremental improvements to already-simplified verifier

---

## Recommended Execution Order

```
✅ DONE:  D0 (Architecture Decisions & Implementation) ────┐
                                                           │
Next:    A (Low-Hanging Fruit) ────────────────────────────┤ can run now
         C (Documentation) ────────────────────────────────┤ can run now
                                                           │
Later:   B (Type System - remaining buffers only) ◄────────┘
         D (remaining items: #4, #25, #26) ◄───────────────┘
```

**Updated status after D0 completion:**

**Can proceed now:**
- A (all remaining items survive: #1, #2, #9, #10, #12, #19, #27)
- C (documentation is always useful)

**Remaining from D:**
- #4: Eliminate stage offset constants (lower priority)
- #25: Fix circular dependencies (if any remain)
- #26: Separate parsing phase from verification phase (partially done with `_parse_polynomial_values()`)

**B updates:**
- B #6 now only applies to `evals`, `challenges`, `x_div_x_sub` (lower priority)
- B #7 solved by D0 implementation
- B #29 (FF/FF3 discipline) still relevant

---

## Project E: Prover Symmetry (NEW - suggested after D0)

**Scope:** Apply the same abstractions to the prover that simplified the verifier.

**Items:**
- E1: **MerkleProver abstraction** - Mirror `MerkleVerifier` for proof generation
  - The prover's `MerkleTree` class still exposes `last_level_verification` throughout
  - A `MerkleProver` class could encapsulate tree building, query proof generation, and last-level node extraction
  - Would hide `get_last_level_nodes()`, `get_query_proof()`, and related complexity

- E2: Consider dict-based polynomial storage in prover (lower priority)
  - Prover needs buffers for NTT performance, so this is less clear-cut than verifier
  - May not be worth the effort

**Risk:** Medium (prover is more complex than verifier)
**Effort:** Medium (can reuse patterns from MerkleVerifier)
**Payoff:** Medium—prover already works, this is polish

**Depends on:** Nothing (can proceed independently)

---

## Resolved Items Registry

Items that were planned but resolved by D0 implementation:

| Original Item | How Resolved | What Replaced It |
|---------------|----------|------------------|
| A #14: Rename `buff` variable | Buffer variables eliminated from verifier | `poly_values` dict in `_parse_polynomial_values()` |
| B #7: Fix `[0]` subscript confusion | Subscripts now only appear at parsing boundary | Single location in `_parse_polynomial_values()` |
| D #17: Eliminate verifier buffers | Implemented | `QueryPolynomials = dict[PolynomialId, FF3]` |
| D #23: MerkleVerifier abstraction | Implemented | `primitives/merkle_verifier.py` |
| D #3: Hide sponge width | Implemented | `MerkleConfig.sponge_width` property |

**Why track resolved items?**
- Prevents accidental re-implementation of solved problems
- Documents the rationale for anyone reviewing the plan later
- Shows the payoff of D0 (5 items eliminated by 2 abstractions)
