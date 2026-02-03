# Remove Expression Binaries - Progress Tracker

Last updated: 2026-02-03

## Phase 1: Infrastructure ✅

- [x] **Task 1.1**: Create ProverData and VerifierData dataclasses
- [x] **Task 1.2**: Create ConstraintContext ABC and implementations
- [x] **Task 1.3**: Create WitnessModule ABC
- [x] **Task 1.4**: Add name mapping helpers to StarkInfo

## Phase 2: SimpleLeft AIR ✅

- [x] **Task 2.1**: Implement SimpleLeft constraint module
  - Fixed vc power accumulation pattern to match expression binary
  - All tests passing
- [x] **Task 2.2**: Implement SimpleLeft witness module

## Phase 3: Lookup2_12 AIR ✅

- [x] **Task 3.1**: Implement Lookup2_12 constraint module (fe5bb1a6)
  - Fixed vc accumulation pattern
  - Added verifier context support (_ff_to_ff3, n detection)
  - All tests passing
- [x] **Task 3.2**: Implement Lookup2_12 witness module

## Phase 4: Permutation1_6 AIR ✅

- [x] **Task 4.1**: Implement Permutation1_6 constraint module (fe5bb1a6)
  - Fixed vc accumulation pattern and constraint formulas
  - Fixed cluster structure (terms 1,2 for im_cluster[0], terms 3,4,5 for im_cluster[1])
  - Fixed gsum recurrence with direct_den term
  - Added airgroup values (gsum_result, gprod_result) for boundary constraints
  - Added verifier context support
  - All tests passing
- [x] **Task 4.2**: Implement Permutation1_6 witness module

## Phase 5: Prover Integration ✅

- [x] **Task 5.1**: Wire constraint modules into prover
  - All three AIRs (SimpleLeft, Lookup2_12, Permutation1_6) use constraint modules
  - Byte-identical proofs to C++ implementation
- [x] **Task 5.2**: Wire witness modules into prover (36803108)
  - Replaced `calculate_witness_std` with `calculate_witness_with_module`
  - All 180 tests pass including byte-identical binary comparison

## Phase 6: Verifier Integration ✅

- [x] **Task 6.1**: Wire constraint modules into verifier
  - All three AIRs use constraint modules for verification
  - VerifierData builder with airgroup_values support
  - VerifierConstraintContext working
- [x] **Task 6.2**: Debug and fix verifier constraint module issues
  - Fixed `_build_verifier_data` to populate `airgroup_values`
  - Fixed `_ff_to_ff3` for verifier context (check if already FF3)
  - Fixed `n` detection for verifier mode (try/except for scalar vs array)
  - All 180 tests pass

## Phase 7: Cleanup ✅

- [x] **Task 7.1**: Partial cleanup of expression binary machinery
  - Removed `calculate_witness_std` from public exports
  - Updated `profile_prover.py` to use `calculate_witness_with_module`
  - Kept `witness_generation.py` for comparison tests (regression testing)
  - Kept `expressions_bin.py` and `expression_evaluator.py` for protocol-generic operations
  - All 180 tests pass
- [ ] **Task 7.2**: Remove ProofContext, migrate fully to ProverData/VerifierData
- [ ] **Task 7.3**: Final test verification

---

## Summary

### AIR-Specific Operations (MIGRATED TO MODULES)

| Operation | Old Path | New Path |
|-----------|----------|----------|
| Constraint Polynomial | `expression_evaluator` | `constraints/*.py` modules |
| Witness Generation | `calculate_witness_std` | `witness/*.py` modules |

### Protocol-Generic Operations (STILL USE EXPRESSION BINARY)

| Component | Purpose |
|-----------|---------|
| `calculateImPolsExpressions` | Stage 2 intermediate polynomial expressions |
| `calculateFRIPolynomial` | FRI polynomial computation |
| Verifier FRI consistency | FRI evaluation check |

These are kept because they're mechanical protocol operations that work across all AIRs without modification.

## Current State

All three supported AIRs now use:
- **Constraint modules** for constraint polynomial evaluation (prover + verifier)
- **Witness modules** for witness generation (prover)

Expression binary is only used for protocol-generic operations (FRI polynomial, intermediate expressions).

**Test counts:**
- 180 tests pass
- 3 skipped (strict comparison tests, debugging only)
- All byte-identical binary comparison tests pass

## How to Check Status

```bash
# View this file
cat docs/plans/PROGRESS.md

# Run tests
cd executable-spec && uv run pytest tests/ -v

# See uncommitted changes
git diff --stat HEAD

# See all changes since project start
git log --oneline 8f4ae953^..HEAD
```
