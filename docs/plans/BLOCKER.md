# Phase 7 Status: Witness Module Blocker RESOLVED

**Date:** 2026-02-03
**Status:** Main blocker resolved, Phase 7 can proceed with partial cleanup

## Resolution Summary

The main blocker (witness generation using expression binary) was resolved in commit `36803108`:

```
feat: replace expression binary with witness modules for witness generation

Wire per-AIR witness modules (SimpleLeft, Lookup2_12, Permutation1_6) into
the prover, replacing calculate_witness_std() with calculate_witness_with_module().
```

**All 180 tests pass with byte-identical proofs to C++ implementation.**

## Current State

### AIR-Specific Operations (FULLY MIGRATED)

| Operation | Old Path | New Path | Status |
|-----------|----------|----------|--------|
| Constraint Polynomial | `expression_evaluator` | `constraints/*.py` modules | ✅ Complete |
| Witness Generation | `calculate_witness_std` | `witness/*.py` modules | ✅ Complete |

### Protocol-Generic Operations (STILL USE EXPRESSION BINARY)

| Component | Purpose | Migration Status |
|-----------|---------|------------------|
| `calculateImPolsExpressions` | Stage 2 intermediate polynomial expressions | Not migrated - generic operation |
| `calculateFRIPolynomial` | FRI polynomial computation | Not migrated - has `use_direct_computation` flag |
| Verifier FRI consistency | FRI evaluation check | Not migrated - uses expression evaluator |

## Why Remaining Usage is Acceptable

The remaining expression binary usage is for **protocol-generic** operations:

1. **`calculateImPolsExpressions`** - Evaluates any polynomial marked `imPol=True` in stark_info. Works across all AIRs without modification.

2. **`calculateFRIPolynomial`** - Constructs FRI polynomial as linear combination per evMap. This is a standard STARK protocol operation.

3. **Verifier FRI consistency** - Checks FRI polynomial matches at query points. Standard verification step.

These don't contain AIR-specific constraint logic - they're mechanical protocol operations that evaluate whatever expressions stark_info defines.

## Phase 7 Cleanup Options

### Option A: Partial Cleanup (Recommended)

Delete files no longer needed for AIR-specific operations:
- Keep `expressions_bin.py` (needed for protocol operations)
- Keep `expression_evaluator.py` (needed for protocol operations)
- Delete `witness_generation.py` (no longer used by prover)
- Clean up `protocol/__init__.py` exports

### Option B: Full Expression Binary Removal

Would require:
1. Direct computation for `calculateImPolsExpressions`
2. Enable `use_direct_computation=True` for `calculateFRIPolynomial`
3. Rewrite verifier FRI consistency check

This is a larger effort for marginal benefit since these are generic protocol operations.

## Files Changed in Resolution

```
ai_plans/witness-module-integration.md           | 318 +++++++++++++++++++++++
executable-spec/protocol/prover.py               |  14 +-
executable-spec/protocol/stages.py               | 205 +++++++++++++++
executable-spec/tests/test_witness_comparison.py | 313 ++++++++++++++++++++++
executable-spec/witness/lookup2_12.py            | 154 ++++++-----
executable-spec/witness/permutation1_6.py        | 169 ++++++------
executable-spec/witness/simple_left.py           | 258 ++++++++++--------
```

## Next Steps

1. Proceed with Phase 7 partial cleanup (Option A)
2. Delete `witness_generation.py` and update imports
3. Update PROGRESS.md to reflect completion
4. Consider full expression binary removal as future work
