# Remove Expression Binaries - Progress Tracker

Last updated: 2026-02-02

## Phase 1: Infrastructure ✅

- [x] **Task 1.1**: Create ProverData and VerifierData dataclasses (bc5bfe19, a7d8fc80)
- [x] **Task 1.2**: Create ConstraintContext ABC and implementations (01706adb)
- [x] **Task 1.3**: Create WitnessModule ABC (eb04ebc5)
- [x] **Task 1.4**: Add name mapping helpers to StarkInfo (c899784e)

## Phase 2: SimpleLeft AIR ✅

- [x] **Task 2.1**: Implement SimpleLeft constraint module (8f4ae953, 3d899e6f)
  - Fixed vc power accumulation pattern to match expression binary
  - Fixed airgroupValuesSize bug
  - All 171 tests passing
- [x] **Task 2.2**: Implement SimpleLeft witness module (8f4ae953)

## Phase 3: Lookup2_12 AIR 🔲

- [ ] **Task 3.1**: Implement Lookup2_12 constraint module
  - Full implementation exists (506d2b98) but uses old vc pattern
  - Needs vc accumulation fix like SimpleLeft
- [ ] **Task 3.2**: Implement Lookup2_12 witness module (81d326bb)
  - Implementation exists but doesn't match expression binary

## Phase 4: Permutation1_6 AIR 🔲

- [ ] **Task 4.1**: Implement Permutation1_6 constraint module
  - Full implementation exists (506d2b98) but uses old vc pattern
  - Needs vc accumulation fix like SimpleLeft
- [ ] **Task 4.2**: Implement Permutation1_6 witness module (81d326bb)
  - Implementation exists but doesn't match expression binary

## Phase 5: Prover Integration ✅ (SimpleLeft only)

- [x] **Task 5.1**: Wire constraint modules into prover (9872e520, 96354123)
  - Added ProverData builder for extended domain
  - Added constraint module registry (98902ffa)
  - SimpleLeft uses new path, others fall back to expression binary
- [x] **Task 5.2**: Verify byte-identical proofs with new code path
  - All 171 tests pass including byte-identical binary comparison

## Phase 6: Verifier Integration ✅ (SimpleLeft only)

- [x] **Task 6.1**: Wire constraint modules into verifier
  - VerifierData builder added with airgroup_values support
  - VerifierConstraintContext working
  - _evaluate_constraint_with_module implemented
  - SimpleLeft uses constraint module, others fall back to expression binary

- [x] **Task 6.2**: Debug and fix verifier constraint module discrepancy
  - **Root cause**: `_build_verifier_data` was not populating `airgroup_values`
  - Constraint 7 (boundary constraint) uses `gsum_result = ctx.airgroup_value(0)`
  - Without airgroup_values, it got 0 instead of the actual value from proof
  - **Fix**: Added `airgroup_values` parameter to `_build_verifier_data`
  - Unit tests added in `tests/test_constraint_verifier.py`
  - All 177 tests pass

## Phase 7: Cleanup 🔲

- [ ] **Task 7.1**: Delete expression binary machinery
- [ ] **Task 7.2**: Remove ProofContext, migrate fully to ProverData/VerifierData
- [ ] **Task 7.3**: Final test verification

---

## Known Issues

None currently.

## Pattern: Enabling Constraint Modules for New AIRs

When enabling a constraint module for a new AIR (e.g., Lookup2_12, Permutation1_6):

1. **Prover**: In `protocol/prover.py`, update the condition:
   ```python
   use_constraint_module = stark_info.name in ('SimpleLeft', 'Lookup2_12')  # add your AIR
   ```

2. **Verifier**: In `protocol/verifier.py`, update the condition in `_verify_evaluations()`:
   ```python
   use_constraint_module = si.name in ('SimpleLeft', 'Lookup2_12')  # add your AIR
   ```

3. **Constraint module**: Your constraint module just uses the `ConstraintContext` API:
   - `ctx.col('name', index)` - column at current row
   - `ctx.prev_col('name', index)` - column at row-1
   - `ctx.next_col('name', index)` - column at row+1
   - `ctx.const('name')` - constant polynomial
   - `ctx.challenge('name')` - Fiat-Shamir challenge
   - `ctx.airgroup_value(index)` - airgroup accumulated value (if needed)

The infrastructure handles prover vs verifier differences automatically. The same constraint
code works for both contexts.

## Next Steps

1. Fix Lookup2_12 constraint module vc accumulation pattern
2. Fix Permutation1_6 constraint module vc accumulation pattern
3. Enable constraint modules for all AIRs in prover and verifier
4. Delete expression binary machinery

## How to Check Status

```bash
# View this file
cat docs/plans/PROGRESS.md

# See uncommitted changes
git diff --stat HEAD

# See all changes since project start
git log --oneline 5ff75b31^..HEAD
```
