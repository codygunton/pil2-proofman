# Rom XFAIL Investigation v2 — Principled Code Comparison

## Executive Summary

The Rom AIR is the only Zisk verifier E2E test that fails (xfail). Previous
investigation attempted to debug from the Python side only — running tests,
trying fixes, and concluding "C++ prover bug" without ever reading the working
C++ verifier code. This was non-productive and left the root cause unresolved.

**This plan takes a different approach:** systematic side-by-side comparison of
the C++ verifier (known working baseline) against the Python verifier, function
by function, at the three known failure points. No test runs until the final
validation step.

**Key insight from research:** The C++ verifier compares `Q_bytecode(xi)` directly
with `Q_from_evals(xi)` — no Z_H multiplication or division. The Python verifier
adds a Z_H round-trip (adapter multiplies by Z_H, verifier divides by Z_H) that
should cancel but may not if the bytecode evaluator's verify-mode zi/x_n setup
differs between C++ and Python.

## Goals & Objectives

### Primary Goals
- Determine definitively whether the Rom proof is valid or invalid
- If invalid: document the C++ prover bug precisely and keep xfail
- If valid: find and fix the Python verifier bug so Rom passes

### Secondary Objectives
- Document any C++ vs Python differences found (even non-buggy ones)
- Update `ai_notes/rom-xfail-investigation.md` with definitive findings

## Solution Overview

### Approach
Three-phase investigation: (1) quick definitive baseline via C++ verifier,
(2) systematic code comparison at each failure point, (3) fix + validate.

### Key Comparison Points

The verification flow has these stages that could diverge:

```
                      C++ Verifier                         Python Verifier
                      ────────────                         ───────────────
1. Verify-mode        proverHelpers->x_n = xi^N            ??? (need to check)
   setup              proverHelpers->zi = 1/Z_H(xi)        ??? (need to check)

2. Bytecode eval      expressionsPack.calculateExpressions  expression_evaluator.evaluate_expression
   (cExpId)           → Q_bytecode(xi) directly             → Q_raw(xi), then adapter * Z_H → C(xi)

3. Q reconstruction   q = Σ evals[q_i] · (xi^N)^i          q = Σ evals[q_i] · (xi^N)^i
   from evals

4. Evaluation check   q == buff  (direct comparison)        q == C(xi) / Z_H(xi)  (round-trip)

5. Custom commit      load from params.pCustomCommitsFixed  _load_operand with ev_map search
   operand loading    via type >= nStages+4                 via type >= n_stages+4

6. Custom commit      root from publics[publicValues[j]]    root from publics[public_values[j]]
   Merkle verify      for j in 0..nFieldElements            for j in range(HASH_SIZE)
```

### Expected Outcomes
- Definitive answer: Python bug or C++ prover bug
- If Python bug: specific fix with passing test
- If C++ bug: documented evidence, justified xfail

## Implementation Tasks

### CRITICAL IMPLEMENTATION RULES
1. **NO TEST RUNS** until Group C. Previous investigation wasted time on 15-min test cycles.
2. **CODE COMPARISON ONLY** in Groups A-B. Read both codebases, document differences.
3. **Every finding goes to `ai_notes/rom-investigation-v2.md`** (create during Task 0).
4. **Use the C++ code as ground truth.** If Python differs from C++, Python is wrong.

### Visual Dependency Tree

```
pil2-stark/src/starkpil/                    executable-spec/
├── stark_verify.hpp ◄──────────────────┐
│   Lines 31-32:  nFieldElements        │
│   Lines 72-191: transcript rebuild    │
│   Lines 209-286: poly value loading   │   ├── protocol/verifier.py
│   Lines 305-341: evaluation check ◄───┼── │   _verify_evaluations (L704-735)
│   Lines 374-557: Merkle verify    ◄───┼── │   _verify_custom_commit_merkle (L829-856)
│                                       │   │
├── verify_constraints.hpp              │   ├── constraints/bytecode_adapter.py
│   (may not exist as separate file;    │   │   _constraint_polynomial_verifier (L462-509)
│    constraint eval is inline in       │   │   _recover_constraint_from_quotient_verifier (L345-369)
│    stark_verify.hpp via cExpId)       │   │   _build_buffers_from_verifier_data (L209-311)
│                                       │   │
├── expressions_pack.hpp ◄──────────────┼── ├── primitives/expression_bytecode/
│   load() L99-179:  verify mode        │       expression_evaluator.py
│   calculateExpressions() L312-511     │       _load_operand (L654-687): custom commits
│                                       │       evaluate_expression(): main loop
│                                       │
└── expressions_bin.hpp                 └── primitives/expression_bytecode/
    (bytecode format, shared)               expressions_bin.py
```

### Execution Plan

#### Group A: Quick Baseline (5 minutes, definitive answer)

- [ ] **Task #0**: Run C++ verifier against Rom proof
  - **Purpose**: Determine if the proof is valid. If C++ verifier passes, the bug is in Python. If it fails, the proof is bad.
  - **How**: The C++ verifier binary should already exist. Find and run it against the Rom proof fixture.
  - **Files needed**:
    - Rom proof: find the JSON proof in `tests/test-data/zisk/` or the fixture directory
    - Rom starkinfo: `$ZISK_PROVING_KEY/zisk/Zisk/airs/Rom/air/Rom.starkinfo.json`
    - Rom verkey: `$ZISK_PROVING_KEY/zisk/Zisk/airs/Rom/air/Rom.verkey.json` (or similar)
    - Publics: `tests/test-data/zisk/publics.json` or wherever publics are stored
  - **Alternative**: If no standalone verifier binary exists, check if `proofman-cli verify` works, or look for a verify mode in the Rust/C++ toolchain.
  - **Checklist**:
    - [ ] Find the C++ verifier binary or verify command
    - [ ] Locate all required inputs (proof, starkinfo, verkey, publics)
    - [ ] Run verification and record result (pass/fail + error message)
    - [ ] Record finding in `ai_notes/rom-investigation-v2.md`
  - **Outcome**: This single data point determines the entire direction of the investigation.

#### Group B: Code Comparison (Execute all in parallel — pure reading, no tests)

Each task compares a specific C++ function against its Python equivalent.
All tasks are independent and can run in parallel.

- [ ] **Task #1**: Compare evaluation check: Q_bytecode vs Q_from_evals
  - **C++ source**: `pil2-stark/src/starkpil/stark_verify.hpp` lines 305-341
  - **Python source**: `executable-spec/protocol/verifier.py` `_verify_evaluations()` (L704-735)
  - **What to compare**:
    - [ ] How xi^N is computed (loop vs pow — both are O(N) but confirm identical arithmetic)
    - [ ] How Q(xi) is reconstructed from quotient polynomial evals
    - [ ] What `qDeg` means and how quotient pieces are indexed
    - [ ] How C(xi) or Q(xi) from bytecode is obtained (direct vs Z_H round-trip)
    - [ ] The final comparison: `q == buff` (C++) vs `residual == 0` (Python)
  - **Key question**: Does the Python Z_H round-trip (Q → Q*Z_H → Q*Z_H/Z_H) introduce any error, or is the Python verifier doing the comparison differently than C++?
  - **Checklist**:
    - [ ] Read C++ evaluation check code, document exact formula
    - [ ] Read Python evaluation check code, document exact formula
    - [ ] Write side-by-side pseudocode showing both paths
    - [ ] Identify all differences (even cosmetic ones)
    - [ ] Flag any differences that could cause different results
    - [ ] Record findings in `ai_notes/rom-investigation-v2.md`

- [ ] **Task #2**: Compare bytecode evaluator verify-mode setup (x_n, zi, evals)
  - **C++ source**: `pil2-stark/src/starkpil/expressions_pack.hpp`
    - `load()` lines 99-113: x_n and zi in verify mode
    - `calculateExpressions()` lines 312-511: main eval loop
  - **Python source**: `executable-spec/primitives/expression_bytecode/expression_evaluator.py`
    - `_load_operand()`: how x_n and zi are loaded in verify mode
    - `evaluate_expression()`: main eval loop
  - **What to compare**:
    - [ ] How x_n buffer is populated in verify mode (C++ proverHelpers->x_n vs Python)
    - [ ] How zi buffer is populated in verify mode (C++ proverHelpers->zi vs Python)
    - [ ] What boundary values are available (boundary 0 = main subgroup Z_H)
    - [ ] Whether C++ uses zi internally in the bytecode (making division baked-in) while Python does NOT use zi and instead multiplies by Z_H externally
    - [ ] How evals are loaded: interleaved FF3 format, coefficient ordering (ascending vs descending)
  - **Key question**: Does the Python bytecode evaluator set up zi correctly? If zi is wrong, the bytecode computes wrong Q(xi), and the Z_H multiplication doesn't fix it.
  - **Checklist**:
    - [ ] Read C++ verify-mode x_n/zi setup in stark_verify.hpp (where proverHelpers is configured)
    - [ ] Read C++ verify-mode x_n/zi loading in expressions_pack.hpp
    - [ ] Read Python verify-mode x_n/zi setup in bytecode_adapter.py (_build_buffers_from_verifier_data)
    - [ ] Read Python verify-mode x_n/zi loading in expression_evaluator.py (_load_operand)
    - [ ] Document exact values for x_n and zi in both implementations
    - [ ] Flag any coefficient ordering differences (ascending vs descending, galois internals)
    - [ ] Record findings in `ai_notes/rom-investigation-v2.md`

- [ ] **Task #3**: Compare custom commit operand loading in bytecode
  - **C++ source**: `pil2-stark/src/starkpil/expressions_pack.hpp`
    - `load()` lines 147-171: custom commit type loading
    - Type encoding: `type >= nStages + 4`
  - **Python source**: `executable-spec/primitives/expression_bytecode/expression_evaluator.py`
    - `_load_operand()` lines 654-687: custom commit verify-mode loading
    - ev_map search logic
  - **What to compare**:
    - [ ] Type argument encoding: does C++ use same formula (nStages + 4 + commit_idx)?
    - [ ] What `args[i_args + 1]` means (stagePos) — is it the polynomial index within the commit?
    - [ ] What `args[i_args + 2]` means (opening_idx / row offset) — how does it map to ev_map?
    - [ ] In verify mode: C++ loads from `pCustomCommitsFixed` buffer, Python does ev_map linear search
    - [ ] Whether the ev_map search in Python (matching on type, id, opening_pos, commit_id) is equivalent to C++ buffer indexing
    - [ ] What happens if the ev_map search fails in Python (silent zero vs error)
  - **Key question**: Is the Python ev_map search matching the right entries for Rom's 11 custom commit polynomials? The C++ path uses direct buffer indexing — no search needed.
  - **Checklist**:
    - [ ] Read C++ custom commit loading (prover mode and verify mode paths)
    - [ ] Read Python custom commit loading (verify mode ev_map search)
    - [ ] Compare field names: id vs stage_pos, opening_pos vs row_offset, commit_id vs index
    - [ ] Verify all 18 ev_map entries for Rom are correctly matched
    - [ ] Check if args[1]/args[2] semantics match between C++ and Python
    - [ ] Record findings in `ai_notes/rom-investigation-v2.md`

- [ ] **Task #4**: Compare custom commit Merkle verification
  - **C++ source**: `pil2-stark/src/starkpil/stark_verify.hpp` lines 496-557
  - **Python source**: `executable-spec/protocol/verifier.py` `_verify_custom_commit_merkle()` (L829-856)
  - **What to compare**:
    - [ ] Root loading: C++ uses `publics[customCommits[c].publicValues[j]]` for j in `0..nFieldElements`; Python uses `publics[custom_commit.public_values[j]]` for j in `range(HASH_SIZE)`
    - [ ] Whether `nFieldElements == HASH_SIZE` (both should be 4 for Goldilocks)
    - [ ] How `publicValues` is populated — does the C++ code guarantee `publicValues.size() >= nFieldElements`?
    - [ ] Leaf value extraction: how C++ packs polynomial values vs Python
    - [ ] Sibling/path format differences
  - **Key question**: Is the nFieldElements mismatch hypothesis correct? Or is the root loading actually fine and the Merkle tree itself is corrupted in the proof?
  - **Checklist**:
    - [ ] Read C++ custom commit root loading, document exact index arithmetic
    - [ ] Read Python custom commit root loading, document exact index arithmetic
    - [ ] Compare publicValues array contents for Rom
    - [ ] Read C++ Merkle leaf hash computation for custom commits
    - [ ] Read Python Merkle leaf hash computation for custom commits
    - [ ] Identify differences in value packing/hashing
    - [ ] Record findings in `ai_notes/rom-investigation-v2.md`

- [ ] **Task #5**: Compare Q reconstruction from quotient polynomial pieces
  - **C++ source**: `pil2-stark/src/starkpil/stark_verify.hpp` lines 317-337
  - **Python source**: `executable-spec/protocol/verifier.py` `_verify_evaluations()` Q reconstruction section
  - **What to compare**:
    - [ ] How the quotient polynomial index is found (`qStage`, `qIndex` in C++)
    - [ ] How qDeg iterations work (C++ uses `starkInfo.qDeg`, Python uses `stark_info.q_deg`)
    - [ ] The accumulator formula: `q += evals[q_evId] * xAcc; xAcc *= xN`
    - [ ] Whether `xN` is `xi^N` (NOT `Z_H(xi) = xi^N - 1`) in both implementations
    - [ ] Eval index lookup: C++ searches `evMap` for matching `cm` type + `index`; Python does same?
  - **Key question**: For `qDeg=1` (Rom, unique among Zisk AIRs), the loop runs only once. Is there an off-by-one or index error that only manifests for qDeg=1?
  - **Checklist**:
    - [ ] Read C++ Q reconstruction, document formula with concrete values for qDeg=1
    - [ ] Read Python Q reconstruction, document formula with concrete values for qDeg=1
    - [ ] Verify both produce same result for qDeg=1 case
    - [ ] Check if qDeg=1 vs qDeg=2 causes different code paths
    - [ ] Record findings in `ai_notes/rom-investigation-v2.md`

#### Group C: Fix + Validate (Sequential, after Groups A+B)

- [ ] **Task #6**: Implement fixes based on findings
  - **Depends on**: All tasks in Group B
  - **If Python bug found**:
    - [ ] Implement the fix
    - [ ] Run `./run-tests.sh e2e` to verify no regressions (19 tests, ~2 min)
    - [ ] Run `./run-tests.sh zisk` to verify Rom now passes
    - [ ] Remove xfail from Rom test parameter
    - [ ] Update `ai_notes/rom-xfail-investigation.md` with resolution
  - **If C++ prover bug confirmed**:
    - [ ] Document precise C++ bug location and fix suggestion
    - [ ] Keep xfail with updated explanation citing specific C++ line numbers
    - [ ] Update `ai_notes/rom-xfail-investigation.md` with definitive evidence

---

## Comparison Reference: Known Values

From previous investigation, these concrete values can be used to verify comparison results:

```
Rom AIR: n_bits=22, qDeg=1, cExpId=73
Custom commits: 1 (name="rom", 11 polynomials)
ev_map: 18 entries (7 cm/const + 11 custom)

xi:        [8716174680162637030, 16549417886102123827, 7687471445282417950]
xi^N:      [3313400389158385524, 15738177539288021218, 3726790801791612697]
Z_H(xi):   [3313400389158385523, 15738177539288021218, 3726790801791612697]

Q_from_evals: [4216457208035997298, 12842449364465107706, 8718687622782149476]
Q_bytecode:   [8967852549743287977, 15341396557711420347, 1183051410211694445]
```

## Implementation Workflow

This plan file serves as the authoritative checklist for implementation. When implementing:

### Required Process
1. **Load Plan**: Read this entire plan file before starting
2. **Execute & Update**: For each task:
   - Mark task as `in_progress` when starting
   - Update checkbox `[ ]` to `[x]` when completing
3. **Verify each group** before proceeding to the next

### Critical Rules
- **NO TEST RUNS in Groups A-B.** Pure code reading and comparison.
- Group B tasks are fully parallel — launch them all simultaneously.
- Group C only starts after Group B findings are documented.
- All findings go to `ai_notes/rom-investigation-v2.md` (not just memory).
- Use the C++ code as the source of truth. The C++ verifier works. If Python differs, Python is wrong.

### Progress Tracking
The checkboxes above represent the authoritative status of each task. Keep them updated as you work.
