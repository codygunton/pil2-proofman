# Verifier Simplification: Complete Implementation Plan

## Status: ✅ COMPLETE (2026-02-05)

All Group 1, Group 2, and Group 3 items completed (except D #4 which was deferred).
Group 4 (MerkleProver) remains optional for future work.

## Executive Summary

**Scope:** Complete all remaining verifier simplification work from the meta-plan in a single execution pass.

**Starting point:** D0 (Architecture Decisions) is complete. The verifier now uses:
- Dict-based polynomial access via `PolynomialId` (eliminates buffer arithmetic)
- `MerkleVerifier` abstraction (encapsulates `last_level_verification`)

**Completed work:**
- Group 1: 11 quick wins (type aliases, renames, error context, docs) ✅
- Group 2: Challenge helper consistency ✅
- Group 3: B #29 FF/FF3 docs ✅, D #4 deferred (constants already well-documented)
- Group 4: E #1 MerkleProver ✅

**Approach:** Execute in parallel groups where possible, with sequential dependencies respected.

---

## Research Summary

Investigation revealed several items are already solved or lower priority than expected:

| Item | Finding |
|------|---------|
| D #25 (circular deps) | **Already solved** - no circular imports exist |
| D #26 (parse separation) | **Already solved** - `_parse_polynomial_values()` separates parsing |
| B #6 (buffer abstraction) | **Lower priority** - only `evals`, `challenges`, `x_div_x_sub` remain |

---

## Visual Dependency Tree

```
Group 1: Independent (execute in parallel)
├── A #1:  Remove Challenge type alias
├── A #2:  Rename QueryIdx → FRIQueryIndex
├── A #10: Rename prime → row_offset in EvMap
├── A #12: Expand cm abbreviation (add comment)
├── A #19: Fix silent failure in _find_xi_challenge
├── A #27: Add context to error messages
├── C #5:  Document EVALS_HASH_WIDTH derivation
├── C #11: Document airgroup_values vs air_values
├── C #13: Verify x_div_x_sub naming matches C++
├── C #30: Add STARKProof docstrings
└── C #31: Document stark_struct vs stark_info

Group 2: Depends on A #2
└── A #9:  Use _get_challenge helper consistently

Group 3: Independent (can run with Group 1)
├── D #4:  Eliminate stage offset constants
└── B #29: Document FF/FF3 type discipline

Group 4: Optional enhancement
└── E #1:  MerkleProver abstraction (mirrors MerkleVerifier)

Deferred:
└── B #6:  Abstract remaining interleaved buffers (lower priority)
```

---

## Implementation Tasks

### Group 1: Parallel Quick Wins (11 items, ~90 min total) ✅ COMPLETE

All items in this group are independent and can be executed in any order.

---

#### A #1: Remove Challenge type alias ✅

**File:** `executable-spec/protocol/verifier.py`
**Effort:** 5 min

The `Challenge` type alias adds no semantic value over `FF3`. Remove it.

**Changes:**
1. Find and remove `Challenge = FF3` type alias (if exists)
2. Replace any `Challenge` annotations with `FF3`

**Verification:** Tests pass, no type errors

---

#### A #2: Rename QueryIdx → FRIQueryIndex ✅

**Files:** `executable-spec/protocol/verifier.py`, `executable-spec/protocol/fri.py`
**Effort:** 10 min

`QueryIdx` is ambiguous. Rename to `FRIQueryIndex` for clarity.

**Changes:**
1. Search for `QueryIdx` type alias or variable naming pattern
2. Rename to `FRIQueryIndex` throughout
3. Update any docstrings referencing the old name

**Verification:** Tests pass, grep shows no remaining `QueryIdx`

---

#### A #10: Rename prime → row_offset in EvMap ✅

**File:** `executable-spec/primitives/pol_map.py`
**Effort:** 5 min

The `prime` field name is misleading (suggests primality). It's actually a row offset.

**Changes:**
1. In `EvMap` dataclass, rename `prime` field to `row_offset`
2. Update all usages in `verifier.py`, `fri_polynomial.py`
3. Keep C++ reference comment: `# C++: EvMap::prime (row offset into evaluation domain)`

**Verification:** Tests pass

---

#### A #12: Expand cm abbreviation ✅

**File:** `executable-spec/primitives/pol_map.py`
**Effort:** 5 min

`cm` means "committed" but this isn't documented.

**Changes:**
1. Add comment to `EvMap.Type.cm`: `cm = 0  # Committed polynomial`
2. Add docstring note to `PolynomialId`: `type: 'cm' (committed), 'const' (constant)`

**Verification:** N/A (documentation only)

---

#### A #19: Fix silent failure in _find_xi_challenge ✅

**File:** `executable-spec/protocol/verifier.py`
**Effort:** 10 min

`_find_xi_challenge` returns None on failure, which causes cryptic errors downstream.

**Changes:**
1. Find `_find_xi_challenge` function
2. Replace `return None` with `raise ValueError(f"Challenge 'std_xi' not found in challenges_map")`
3. Update return type annotation from `Optional[int]` to `int`
4. Remove any None checks at call sites

**Verification:** Tests pass (no AIR should be missing std_xi)

---

#### A #27: Add context to error messages ✅

**File:** `executable-spec/protocol/verifier.py`
**Effort:** 15 min

Error messages lack context (query index, step number, tree index).

**Changes:**
1. Find all `raise` statements and assertion failures
2. Add contextual information:
   - Query verification: `f"Query {query_idx}: Merkle verification failed for stage {stage}"`
   - FRI folding: `f"FRI step {step}: folded value mismatch at query {query_idx}"`
   - Constraint check: `f"Constraint verification failed at query {query_idx}"`

**Verification:** Tests pass, error messages are more informative

---

#### C #5: Document EVALS_HASH_WIDTH derivation ✅

**File:** `executable-spec/protocol/verifier.py`
**Effort:** 10 min

`EVALS_HASH_WIDTH` is a magic number that needs documentation.

**Changes:**
1. Find `EVALS_HASH_WIDTH` constant
2. Add comment explaining derivation from C++ (trace to source)
3. Format: `# EVALS_HASH_WIDTH = <formula> - see pil2-stark/src/... line N`

**Verification:** N/A (documentation only)

---

#### C #11: Document airgroup_values vs air_values ✅

**Files:** `executable-spec/protocol/verifier.py`, `executable-spec/protocol/proof.py`
**Effort:** 10 min

The distinction between `airgroup_values` and `air_values` is unclear.

**Changes:**
1. Add docstring to STARKProof explaining:
   - `airgroup_values`: Values shared across all AIRs in an airgroup
   - `air_values`: Values specific to individual AIR instances
2. Reference C++ source for authoritative definition

**Verification:** N/A (documentation only)

---

#### C #13: Verify x_div_x_sub naming matches C++ ✅

**Files:** `executable-spec/protocol/verifier.py`, `executable-spec/protocol/fri_polynomial.py`
**Effort:** 5 min

Verify `x_div_x_sub` naming matches C++ implementation.

**Changes:**
1. Search C++ codebase for equivalent variable
2. If matches: add comment `# Matches C++: xDivXSub`
3. If different: rename to match C++ and note the mapping

**Verification:** Grep confirms consistent naming

---

#### C #30: Add STARKProof docstrings ✅

**File:** `executable-spec/protocol/proof.py`
**Effort:** 15 min

STARKProof and its nested structures lack docstrings.

**Changes:**
1. Add class-level docstring to `STARKProof`
2. Add field-level comments for non-obvious fields:
   - `roots`: List of Merkle roots for each stage commitment
   - `evals`: Polynomial evaluations at challenge point xi
   - `fri`: FRI protocol data (trees, queries, final polynomial)
   - `last_levels`: Pre-verified Merkle nodes for last_level_verification optimization

**Verification:** N/A (documentation only)

---

#### C #31: Document stark_struct vs stark_info distinction ✅

**Files:** `executable-spec/protocol/stark_info.py`
**Effort:** 10 min

`stark_struct` and `stark_info` names are confusingly similar.

**Changes:**
1. Add module-level docstring explaining:
   - `StarkStruct`: Protocol parameters (FRI steps, blowup, arity) - from starkstruct.json
   - `StarkInfo`: AIR-specific metadata (polynomial maps, constraints) - from starkinfo.json
2. Add cross-reference comments in both classes

**Verification:** N/A (documentation only)

---

### Group 2: Sequential (1 item, depends on A #2) ✅ COMPLETE

#### A #9: Use _get_challenge helper consistently ✅

**File:** `executable-spec/protocol/verifier.py`
**Effort:** 15 min

Challenge extraction already uses `_get_challenge` helper consistently.
The inline patterns in tests are acceptable for test code.

**Changes:**
1. Ensure `_get_challenge(challenges, name)` helper exists
2. Find all inline challenge slicing patterns:
   ```python
   # Before:
   xi_idx = next(i for i, cm in enumerate(stark_info.challenges_map) if cm.name == 'std_xi')
   xi = challenges[xi_idx * 3:(xi_idx + 1) * 3]

   # After:
   xi = _get_challenge(challenges, 'std_xi', stark_info)
   ```
3. Replace all inline patterns with helper calls

**Verification:** Tests pass, grep shows no inline challenge slicing

---

### Group 3: Independent Medium Items (2 items, ~2 hours) - PARTIAL

#### D #4: Eliminate stage offset constants - DEFERRED

**Files:** `executable-spec/protocol/verifier.py`, `executable-spec/protocol/stages.py`
**Effort:** 1-2 hours

The existing named constants (QUOTIENT_STAGE_OFFSET, EVAL_STAGE_OFFSET, FRI_STAGE_OFFSET)
actually improve readability by documenting what `n_stages + 1`, etc. mean.
Kept as-is since they serve as semantic documentation.

**Changes:**
1. Identify all stage offset constants
2. Replace with semantic stage names or computed offsets
3. Use `StarkInfo.get_stage_offset(stage)` method if needed
4. Example transformation:
   ```python
   # Before:
   offset = STAGE_1_OFFSET + row * n_cols

   # After:
   offset = stark_info.get_stage_offset(1) + row * n_cols
   ```

**Verification:** Tests pass

---

#### B #29: Document FF/FF3 type discipline ✅

**File:** `executable-spec/primitives/field.py` (and CLAUDE.md update)
**Effort:** 30 min

The codebase lacks documented conventions for when to use FF vs FF3.

**Changes:**
1. Add docstring to `field.py` explaining:
   - `FF`: Base field - use for single evaluations, challenges, domain elements
   - `FF3`: Extension field - use for polynomial evaluations, batched operations
   - Interleaved format: `[c0_0, c1_0, c2_0, c0_1, c1_1, c2_1, ...]` for C++ compatibility
2. Update CLAUDE.md "Type System" section with these conventions

**Verification:** N/A (documentation only)

---

### Group 4: Optional Enhancement (1 item) ✅ COMPLETE

#### E #1: MerkleProver abstraction ✅

**File:** `executable-spec/primitives/merkle_prover.py` (NEW)
**Effort:** 30 min (simpler than estimated)

Created `MerkleProver` class mirroring `MerkleVerifier` pattern.
Updated stages.py to use factory methods instead of raw MerkleTree construction.
FriPcs kept unchanged (has its own clean config via FriPcsConfig).

**Changes:**
1. Created `MerkleProver` with `for_stage()`, `for_const()`, `for_fri_step()` factory methods
2. Updated stages.py: 3 `MerkleTree(arity=4, ...)` sites replaced with `MerkleProver.for_*()`
3. `tree` property provides backward compatibility for existing MerkleTree consumers

**Verification:** All 155 tests pass, byte-identical proofs

---

### Deferred Items

#### B #6: Abstract remaining interleaved buffers

**Status:** Deferred (lower priority after D0)

The remaining interleaved buffers (`evals`, `challenges`, `x_div_x_sub`) are:
- Less frequently accessed than polynomial buffers (which are now dict-based)
- Already working correctly
- Lower cognitive load than buffer-based polynomial access was

This can be addressed in a future pass if needed.

---

## Execution Workflow

### Phase 1: Quick Wins (Groups 1-2)
1. Execute all Group 1 items in parallel
2. Run `./run-tests.sh` to verify no regressions
3. Execute Group 2 (A #9) after A #2 completes
4. Run `./run-tests.sh` again
5. Commit: "refactor(verifier): simplify types, improve errors and docs"

### Phase 2: Medium Items (Group 3)
1. Execute D #4 (stage constants)
2. Run `./run-tests.sh`
3. Execute B #29 (FF/FF3 docs)
4. Commit: "refactor(verifier): eliminate stage constants, document type discipline"

### Phase 3: Optional (Group 4)
1. If time permits, implement E #1 (MerkleProver)
2. Run `./run-tests.sh`
3. Commit: "feat(prover): add MerkleProver abstraction"

### Final Verification
- All 155 tests pass
- E2E tests verify byte-identical proofs
- Linter passes (`ruff check executable-spec/`)

---

## Items Resolved by This Plan

After execution, the meta-plan will have no remaining items:

| Project | Items | Status After |
|---------|-------|--------------|
| A | 7 items | All complete |
| B | 2 items | #29 complete, #6 deferred |
| C | 5 items | All complete |
| D | 3 items | #4 complete, #25/#26 already solved |
| E | 1 item | Complete (if executed) or deferred |

---

## File Change Summary

| File | Changes |
|------|---------|
| `primitives/pol_map.py` | Rename `prime` → `row_offset`, add cm comment |
| `primitives/field.py` | Add FF/FF3 discipline docstring |
| `primitives/merkle_prover.py` | NEW (optional) |
| `protocol/verifier.py` | Remove Challenge alias, rename QueryIdx, fix errors, add context |
| `protocol/fri_polynomial.py` | Update for any verifier changes |
| `protocol/proof.py` | Add STARKProof docstrings |
| `protocol/stark_info.py` | Add stark_struct/stark_info docs |
| `CLAUDE.md` | Update Type System section |
