# Simplify gen_proof() API: Remove recursive and transcript Parameters

## Executive Summary

The `gen_proof()` function currently accepts two optional parameters—`recursive` and `transcript`—that complicate its API and introduce architectural inconsistencies:

1. **`recursive` parameter** (never explicitly tested): Controls whether public inputs and root1 are fed into the Fiat-Shamir transcript. When `False` (default, always used), causes prover/verifier transcript divergence. Partially attempts to workaround a deeper architectural mismatch that can't be fixed at this layer.

2. **`transcript` parameter** (always passed by callers): Every caller creates a transcript externally and passes it in, even though `gen_proof()` can create one internally. This adds boilerplate and obscures the fact that transcript initialization is essential to the proof, not optional.

**Proposed solution**: Remove both parameters. Let `gen_proof()` always create its own fresh transcript internally. This:
- Eliminates the untested `recursive=True` code path and associated confusion
- Removes external transcript passing boilerplate from all 8 call sites
- Simplifies function signature and clarifies that Fiat-Shamir is internal to proof generation
- Unblocks removal of unused `recursive`/`recursive_final` fields from `StarkInfo`
- Exposes the underlying architectural issue (prover/verifier transcript mismatch) clearly in docs without pretending it's solvable via optional parameters

**Trade-off**: Tests lose the ability to pre-inject `global_challenge` into the transcript before proof generation. This is a testing concern, not a protocol concern—can be handled via a separate test helper or params modification.

## Goals & Objectives

### Primary Goals
- Remove unused `recursive` parameter entirely (reducing API surface and confusion)
- Remove optional `transcript` parameter (eliminating unnecessary parameter passing)
- Simplify `gen_proof()` function signature to `gen_proof(setup_ctx, params, skip_challenge_derivation=False)`
- Update all 8 callers (7 in test_stark_e2e.py, 1 in profile_prover.py) to use new signature

### Secondary Objectives
- Remove dead `recursive` and `recursive_final` fields from `StarkInfo` class
- Clean up extensive documentation that explains transcript mismatch workarounds
- Clarify in remaining docs that prover/verifier have inherent transcript initialization differences that require external handling
- Remove unnecessary test helper `create_fresh_transcript()` or repurpose for new testing needs

## Solution Overview

### Approach

**Phase 1: Remove optional parameters from gen_proof()**
- Delete `recursive: bool = False` parameter
- Delete `transcript: Optional[Transcript] = None` parameter
- Remove all conditional logic that gates initialization on `recursive`
- Always create fresh `Transcript` internally
- Update function docstring

**Phase 2: Update all callers**
- Remove `transcript=transcript` keyword argument from 7 calls in `test_stark_e2e.py`
- Remove `transcript=transcript` keyword argument from 1 call in `profile_prover.py`
- Remove `create_fresh_transcript()` helper function from `test_stark_e2e.py` (no longer needed)

**Phase 3: Clean up supporting infrastructure**
- Remove unused `recursive` and `recursive_final` fields from `StarkInfo` class in `protocol/stark_info.py`
- Remove extensive comments explaining transcript mismatch workarounds
- Update remaining documentation to clarify architecture

### Key Components

1. **`protocol/prover.py` gen_proof()**: Simplify function signature, remove conditional logic, always create internal transcript
2. **`tests/test_stark_e2e.py`**: Update 7 test calls, remove `create_fresh_transcript()` helper
3. **`profile_prover.py`**: Update 1 test call
4. **`protocol/stark_info.py`**: Remove unused fields

### Data Flow

**Before (Current)**:
```
Test caller creates transcript → passes to gen_proof()
                                       ↓
                         gen_proof checks if recursive
                          ├─ False: ignore transcript for publics/root1
                          └─ True: feed publics/root1 into transcript
                                       ↓
                         gen_proof derives challenges from transcript
                                       ↓
                         Returns proof
```

**After (Simplified)**:
```
Test caller passes setup_ctx, params
                      ↓
    gen_proof creates fresh transcript internally
                      ↓
    Always feed (publics, root1) into transcript consistently
    (or always exclude them—see Architecture Note below)
                      ↓
    gen_proof derives challenges from transcript
                      ↓
    Returns proof
```

### Expected Outcomes

- `gen_proof()` has clearer semantics: it always creates its own transcript, always derives challenges the same way
- Removed 8 callers' transcript boilerplate
- Removed unused `recursive` parameter that was never tested
- Codebase is more maintainable (fewer conditional paths, fewer optional parameters)
- **Architecture issue remains but is now explicit**: Prover's transcript initialization doesn't match verifier's, and this needs to be addressed at a higher level (not inside gen_proof)

## Implementation Tasks

### CRITICAL ARCHITECTURAL NOTE

**Important caveat**: The prover/verifier transcript initialization mismatch documented in gen_proof's comments (lines 28-60, 96-120) is NOT fixed by this change. Currently:
- Verifier ALWAYS initializes: `verkey` → `publics (conditionally hashed)` → `root1`
- Prover (if recursive=False) initializes: nothing
- Prover (if recursive=True) initializes: `publics (raw)` → `root1`

Removing the `recursive` flag means the prover will always use one initialization strategy. The plan below assumes we choose: **Always exclude publics and root1 from prover's transcript, matching the recursive=False behavior**. This is the status quo for non-recursive proofs (which are the only ones tested).

If this assumption is wrong (i.e., publics/root1 MUST be in the transcript for correctness), the scope expands to include fixing the verifier/prover mismatch.

### Visual Dependency Tree

```
protocol/
├── prover.py (Task #1: Remove recursive and transcript parameters from gen_proof)
│
├── stark_info.py (Task #3: Remove unused recursive and recursive_final fields)
│
tests/
├── test_stark_e2e.py (Task #2: Update 7 gen_proof calls, remove create_fresh_transcript helper)
│
profile_prover.py (Task #2: Update 1 gen_proof call)
```

**Dependency order**:
- Task #1 (gen_proof changes) must be done first
- Tasks #2 and #3 can run in parallel (they both depend on Task #1)

### Execution Plan

#### Task #1: Simplify gen_proof() Function Signature and Implementation
**Folder**: `protocol/`
**File**: `prover.py`
**Dependencies**: None (this is the foundation)

**Current signature (lines 24-29)**:
```python
def gen_proof(
    setup_ctx: SetupCtx,
    params: ProofContext,
    recursive: bool = False,
    transcript: Optional[Transcript] = None,
    skip_challenge_derivation: bool = False
) -> dict:
```

**New signature**:
```python
def gen_proof(
    setup_ctx: SetupCtx,
    params: ProofContext,
    skip_challenge_derivation: bool = False
) -> dict:
```

**Exact changes required**:

1. **Remove parameters** (lines 27-28):
   - Delete: `recursive: bool = False,`
   - Delete: `transcript: Optional[Transcript] = None,`
   - Keep: `skip_challenge_derivation: bool = False`

2. **Remove docstring comments** about recursive and transcript (lines 28-74):
   - Lines 28-60: ANSWER section about recursive (DELETE)
   - Lines 62-74: ANSWER section about transcript (DELETE)
   - Lines 75-119: Extensive docstring explaining transcript mismatch (DELETE or REPLACE with simpler explanation)
   - Keep the basic docstring: "Generate complete STARK proof."
   - Add note: "Fiat-Shamir transcript is created internally. For testing purposes that require pre-set randomness, use the params object or testing helpers."

3. **Remove conditional transcript initialization** (lines 208-214):
   - Current code:
     ```python
     if transcript is None:
         transcript = Transcript(
             arity=stark_info.starkStruct.transcriptArity,
             custom=stark_info.starkStruct.merkleTreeCustom
         )
     ```
   - Replace with unconditional creation:
     ```python
     transcript = Transcript(
         arity=stark_info.starkStruct.transcriptArity,
         custom=stark_info.starkStruct.merkleTreeCustom
     )
     ```

4. **Remove recursive conditional blocks** (lines 232-239 and 278-279):
   - Lines 232-239 (Stage 0 public inputs):
     ```python
     if recursive:
         if stark_info.nPublics > 0:
             transcript.put(params.publicInputs[:stark_info.nPublics])
     ```
     DELETE this entire block (don't feed public inputs to transcript)

   - Lines 278-279 (Stage 1 root feeding):
     ```python
     if recursive:
         transcript.put(root1)
     ```
     DELETE this entire block (don't feed root1 to transcript)

5. **Remove or replace Stage 0 comments** (extensive explanatory comments about transcript mismatch):
   - Lines 216-230: Comments explaining recursive vs non-recursive differences
   - Lines 269-277: Comments about root1 timing mismatch
   - DELETE all these comments or replace with single line: `# Stage 0: Initialize Fiat-Shamir transcript (no public data)`

6. **Update the extended Stage 0 comment section** (lines 220-230):
   - Current: Explains when to feed publics/root1 based on recursive flag
   - New: Single line explaining transcript is always fresh

**Verification**: After changes, gen_proof should:
- Accept exactly 3 parameters: setup_ctx, params, skip_challenge_derivation
- Always create transcript fresh internally (no external injection)
- Not feed public inputs into transcript
- Not feed root1 into transcript
- Derive challenges identically every time (deterministic from commitments only)

---

#### Task #2: Update All Callers of gen_proof() (Test and Profile Files)
**Files to modify**:
- `tests/test_stark_e2e.py` (7 calls)
- `profile_prover.py` (1 call)

**Dependencies**: Task #1 (gen_proof signature change)

**Changes for `tests/test_stark_e2e.py`**:

1. **Remove `create_fresh_transcript()` helper function** (lines 73-91):
   - This function is no longer needed since gen_proof creates its own transcript
   - DELETE entire function

2. **Update test method: `test_challenges_match()`** (line 217):
   - Current: `proof = gen_proof(setup_ctx, params, transcript=transcript)`
   - New: `proof = gen_proof(setup_ctx, params)`
   - Remove lines 212-215 that create the transcript:
     ```python
     # Create fresh transcript with global_challenge
     transcript = create_fresh_transcript(stark_info, vectors)
     params = create_params_from_vectors(stark_info, vectors)
     ```
     Replace with:
     ```python
     params = create_params_from_vectors(stark_info, vectors)
     ```

3. **Update test method: `test_evals_match()`** (line 266):
   - Current: `proof = gen_proof(setup_ctx, params, transcript=transcript)`
   - New: `proof = gen_proof(setup_ctx, params)`
   - Remove transcript creation (same pattern as above)

4. **Update test method: `test_fri_output_matches()`** (line 305):
   - Current: `proof = gen_proof(setup_ctx, params, transcript=transcript)`
   - New: `proof = gen_proof(setup_ctx, params)`
   - Remove transcript creation

5. **Update test method: `test_fri_query_indices()`** (line 354-355):
   - Current: `proof = gen_proof(setup_ctx, params, transcript=transcript, skip_challenge_derivation=True)`
   - New: `proof = gen_proof(setup_ctx, params, skip_challenge_derivation=True)`
   - Remove transcript creation

6. **Update test method: `test_fri_folding_values()`** (line 411-412):
   - Current: `proof = gen_proof(setup_ctx, params, transcript=transcript, skip_challenge_derivation=True)`
   - New: `proof = gen_proof(setup_ctx, params, skip_challenge_derivation=True)`
   - Remove transcript creation

7. **Update test method: `test_consistency_of_roots()`** (line 476):
   - Current: `proof = gen_proof(setup_ctx, params, transcript=transcript)`
   - New: `proof = gen_proof(setup_ctx, params)`
   - Remove transcript creation

8. **Update test method: `test_fri_root_consistency()`** (line 615):
   - Current: `proof = gen_proof(setup_ctx, params, transcript=transcript)`
   - New: `proof = gen_proof(setup_ctx, params)`
   - Remove transcript creation

**Changes for `profile_prover.py`**:

1. **Update prover call** (line 228):
   - Current: `proof = gen_proof(setup_ctx, params, transcript=transcript)`
   - New: `proof = gen_proof(setup_ctx, params)`
   - Remove lines 222-227 that create the transcript:
     ```python
     transcript = create_fresh_transcript(setup_ctx.stark_info, vectors)
     ```
   - Delete this line (keep params creation)

**Imports to check**:
- In both files, verify `Transcript` is no longer imported (or remove import if present)
- In `test_stark_e2e.py`, after removing `create_fresh_transcript()`, check if any helper imports are unused

---

#### Task #3: Remove Unused Fields from StarkInfo
**Folder**: `protocol/`
**File**: `stark_info.py`
**Dependencies**: Task #1 (after gen_proof no longer uses recursive)

**Current state** (lines 104, 125):
- `self.recursive = False` (initialized in __init__)
- `self.recursive_final = False` (initialized in __init__)
- In `from_json()` classmethod (line 125): `info.recursive = recursive`

**These fields are**:
- Set but never read
- Not used anywhere in the codebase
- Only exist for compatibility with C++ or future use

**Exact changes**:

1. **Find the `__init__` method** of `StarkInfo` class
   - Locate: `self.recursive = False` line
   - Locate: `self.recursive_final = False` line
   - DELETE both lines

2. **Find the `from_json()` classmethod**
   - Locate: `recursive = json_data.get('recursive', False)` (if present)
   - Locate: `info.recursive = recursive` assignment
   - DELETE both lines (or just the assignment if the local var is needed elsewhere)

3. **Verify no other references**:
   - Grep the entire codebase for `stark_info.recursive` - should find nothing
   - Grep for `.recursive_final` - should find nothing
   - If any references exist, this task is incomplete

**Result**: StarkInfo no longer has recursive-related fields; they become pure data cleanup without behavior change.

---

## Implementation Workflow

This plan file serves as the authoritative checklist for implementation. When implementing:

### Required Process
1. **Load Plan**: Read this entire plan file before starting any task
2. **Execute in order**:
   - Task #1 first (changes gen_proof signature)
   - Tasks #2 and #3 in parallel (both depend on Task #1)
3. **For each task**:
   - Mark checkbox `[ ]` to `[x]` when task is complete
   - Verify all changes compile and tests pass
   - Don't move to next task until current task is fully done

### Critical Rules
- Update checkboxes in real-time as work progresses
- Task #1 must be done before Tasks #2 and #3
- Tasks #2 and #3 have no inter-dependencies and can run in parallel
- Mark tasks complete only when fully implemented (no placeholders, all callers updated)

### Progress Tracking

**Group A: Foundation**
- [ ] **Task #1**: Simplify gen_proof() - Remove recursive and transcript parameters
  - [ ] Remove `recursive: bool = False` parameter
  - [ ] Remove `transcript: Optional[Transcript] = None` parameter
  - [ ] Remove recursive-conditional initialization comments (lines 28-74)
  - [ ] Remove conditional `if transcript is None` block - always create fresh Transcript
  - [ ] Remove lines 232-239 (public inputs conditional feed)
  - [ ] Remove lines 278-279 (root1 conditional feed)
  - [ ] Remove/replace extensive Stage 0 comments
  - [ ] Verify function signature now: `gen_proof(setup_ctx, params, skip_challenge_derivation=False)`

**Group B: Update Callers (can run parallel after Task #1)**
- [ ] **Task #2**: Update test and profile callers
  - [ ] Remove `create_fresh_transcript()` helper from test_stark_e2e.py (lines 73-91)
  - [ ] Update `test_challenges_match()` - remove transcript param and creation
  - [ ] Update `test_evals_match()` - remove transcript param and creation
  - [ ] Update `test_fri_output_matches()` - remove transcript param and creation
  - [ ] Update `test_fri_query_indices()` - remove transcript param and creation
  - [ ] Update `test_fri_folding_values()` - remove transcript param and creation
  - [ ] Update `test_consistency_of_roots()` - remove transcript param and creation
  - [ ] Update `test_fri_root_consistency()` - remove transcript param and creation
  - [ ] Update profile_prover.py - remove transcript param and creation
  - [ ] Verify all 8 calls now use: `gen_proof(setup_ctx, params)` or `gen_proof(setup_ctx, params, skip_challenge_derivation=True)`

- [ ] **Task #3**: Clean up StarkInfo infrastructure
  - [ ] Remove `self.recursive = False` from StarkInfo.__init__
  - [ ] Remove `self.recursive_final = False` from StarkInfo.__init__
  - [ ] Remove recursive assignment from StarkInfo.from_json() classmethod
  - [ ] Grep codebase: verify no remaining references to `.recursive` or `.recursive_final`

---

## Rollout & Validation

### Testing Strategy
After implementing all tasks, run:
```bash
cd executable-spec
uv run python -m pytest tests/test_stark_e2e.py -v
```

**Expected result**: All 7 test methods pass (no functional changes, just API changes)

### Verification Checklist
- [ ] All 8 gen_proof() calls updated successfully
- [ ] No remaining references to `.recursive` or `.recursive_final` in codebase
- [ ] No remaining imports of `Transcript` in test files (or they're unused)
- [ ] `test_stark_e2e.py::test_*` test suite passes entirely
- [ ] `profile_prover.py` runs without errors
- [ ] gen_proof() always creates fresh transcript (inspect code to confirm)
- [ ] No `if recursive:` or `if transcript is None:` conditionals remain in gen_proof

### Known Limitations / Future Work
1. **Tests can no longer pre-inject global_challenge**: The `create_fresh_transcript()` helper allowed tests to inject `global_challenge` before proof generation. After this change, tests must handle randomness differently (either via params modification or separate testing infrastructure). This is out of scope for current plan.

2. **Prover/verifier transcript mismatch persists**: The underlying architectural issue (prover and verifier have different transcript initialization) is NOT fixed by this change. It's now explicit rather than hidden behind the `recursive` flag. Fixing this requires coordination between prover and verifier layers (out of scope).

3. **Public inputs handling**: Currently prover never feeds public inputs to its transcript. Verifier expects them. This discrepancy remains and may require protocol-level changes to address (out of scope).

---

## Summary

This plan removes two optional parameters (`recursive` and `transcript`) from `gen_proof()`, simplifying its API, eliminating untested code paths, and removing boilerplate from 8 call sites. The changes expose (rather than hide) underlying architectural issues around transcript initialization that will need to be addressed separately. Total implementation effort: ~2 hours across 3 tasks (1 foundation + 2 parallel).
