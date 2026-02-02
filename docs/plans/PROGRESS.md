# Remove Expression Binaries - Progress Tracker

Last updated: 2026-02-02

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
- [x] **Task 5.2**: Verify byte-identical proofs with new code path
  - All 177 tests pass including byte-identical binary comparison

## Phase 6: Verifier Integration ✅

- [x] **Task 6.1**: Wire constraint modules into verifier
  - All three AIRs use constraint modules for verification
  - VerifierData builder with airgroup_values support
  - VerifierConstraintContext working
- [x] **Task 6.2**: Debug and fix verifier constraint module issues
  - Fixed `_build_verifier_data` to populate `airgroup_values`
  - Fixed `_ff_to_ff3` for verifier context (check if already FF3)
  - Fixed `n` detection for verifier mode (try/except for scalar vs array)
  - All 177 tests pass

## Phase 7: Cleanup 🔲

- [ ] **Task 7.1**: Delete expression binary machinery
- [ ] **Task 7.2**: Remove ProofContext, migrate fully to ProverData/VerifierData
- [ ] **Task 7.3**: Final test verification

---

## Known Issues

None currently.

## Current State

All three supported AIRs now use constraint modules in both prover and verifier:
- **SimpleLeft**: 8 rows, 8 constraints
- **Lookup2_12**: 4096 rows, 5 constraints (has FRI folding)
- **Permutation1_6**: 64 rows, 6 constraints (has FRI folding)

The expression binary machinery is still present but not used for these AIRs.

## Next Steps

1. Delete expression binary machinery (Phase 7)
2. Clean up ProofContext → ProverData/VerifierData migration
3. Final verification

## How to Check Status

```bash
# View this file
cat docs/plans/PROGRESS.md

# See uncommitted changes
git diff --stat HEAD

# See all changes since project start
git log --oneline 8f4ae953^..HEAD
```
