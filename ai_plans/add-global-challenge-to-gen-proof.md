# Add global_challenge Parameter to gen_proof() Implementation Plan

## Executive Summary

The STARK prover and verifier have a critical transcript initialization pattern that was broken during recent refactoring. The verifier receives a `global_challenge` value computed by the outer Rust layer (`proofman/src/challenge_accumulation.rs`) and uses it to seed the Fiat-Shamir transcript at Stage 0. The prover should mirror this pattern by accepting `global_challenge` as a parameter and seeding its transcript identically.

**The Broken Pattern:**
- Rust layer computes `global_challenge` from: publics + proof values + aggregated partial contributions
- This value should be passed to `gen_proof()` to initialize the transcript
- Without it, the prover's transcript state diverges from the verifier's, causing all derived challenges to be wrong
- Tests fail on challenge verification because challenges don't match

**The Fix:**
- Add `global_challenge: Optional[np.ndarray] = None` parameter to `gen_proof()`
- When provided, seed transcript with `global_challenge[:3].tolist()` at Stage 0 (matching verifier at verifier.py:318)
- When not provided, derive challenges normally (for backwards compatibility)
- Update test infrastructure to extract and pass `global_challenge` from test vectors when available

**Why This Matters:**
This restores the proper data flow where external transcript state (computed from witness data) is injected into the prover at the beginning, ensuring prover/verifier transcript synchronization. Without this pattern, the system cannot work in VADCOP mode (verification-only with external challenge provision).

## Goals & Objectives

### Primary Goals
- Restore the pattern where `global_challenge` seeds the transcript at Stage 0
- Ensure prover and verifier produce identical challenge sequences
- Enable tests to verify correct challenge derivation (currently broken)
- Maintain backwards compatibility with callers that don't provide global_challenge

### Secondary Objectives
- Ensure the parameter signature matches the C++ interface pattern
- Document the VADCOP verification mode clearly
- Provide clear test infrastructure for seeding challenges deterministically

## Solution Overview

### Approach

The fix involves two complementary changes:

1. **Prover Side (gen_proof):**
   - Accept optional `global_challenge` parameter matching verifier signature
   - At Stage 0 transcript initialization, check if `global_challenge` is provided
   - If provided: seed transcript with `global_challenge[:3].tolist()` (VADCOP mode)
   - If not provided: initialize transcript normally and derive all challenges (compatibility mode)

2. **Test Side (test_stark_e2e.py):**
   - Extract `global_challenge` from test vectors (if available)
   - Pass it to `gen_proof()` when calling with test data
   - This enables deterministic replay and challenge verification

### Key Components

1. **gen_proof signature update**: Add `global_challenge: Optional[np.ndarray] = None` parameter
2. **Transcript initialization logic**: Conditional seeding at Stage 0
3. **Test vector integration**: Extract and pass global_challenge from intermediates
4. **Documentation**: Clear explanation of VADCOP mode vs normal mode

### Data Flow

```
Rust: calculate_global_challenge()
    ↓
Computes: hash(publics + proof_values + partial_contributions)
    ↓
Returns: 3-element field array (global_challenge)
    ↓
Passes to: gen_proof(setup_ctx, params, global_challenge=...)
    ↓
Python: Prover receives global_challenge
    ↓
Seeds: transcript.put(global_challenge[:3].tolist()) at Stage 0
    ↓
Derives: All subsequent challenges from seeded transcript
    ↓
Matches: Verifier's challenge sequence
```

### Expected Outcomes

- All 142 tests pass with correct challenge verification
- Prover and verifier produce identical challenge sequences
- Clear separation between VADCOP mode (external challenge) and normal mode
- Backwards compatible API - existing callers continue to work
- Test infrastructure can deterministically validate proof correctness

## Implementation Tasks

### Visual Dependency Tree

```
protocol/
├── prover.py (Task #1: Add global_challenge parameter and Stage 0 seeding logic)
│
tests/
└── test_stark_e2e.py (Task #2: Extract and pass global_challenge from test vectors)

primitives/
└── transcript.py (Task #0: No changes needed - already supports put() with field arrays)

protocol/
└── verifier.py (Task #0: Already has pattern at line 318 - reference only)
```

### Execution Plan

#### Task #0: Review Reference Implementation (No Changes)
- **Location**: `protocol/verifier.py:315-318`
- **Reference Pattern**:
  ```python
  if global_challenge is None:
      raise ValueError("Global challenge required in VADCOP mode")
  transcript.put(global_challenge[:3].tolist())
  ```
- **Context**: This shows exactly how verifier seeds transcript with global_challenge in VADCOP mode
- **Purpose**: Understand the pattern to mirror in gen_proof

#### Task #1: Add global_challenge Parameter to gen_proof (CRITICAL)

**File**: `protocol/prover.py`

**Changes Required**:
1. **Import section** (no changes needed - numpy and Transcript already imported)

2. **Function signature** (line 22-26):
   ```python
   # BEFORE:
   def gen_proof(
       setup_ctx: SetupCtx,
       params: ProofContext,
       skip_challenge_derivation: bool = False
   ) -> dict:

   # AFTER:
   def gen_proof(
       setup_ctx: SetupCtx,
       params: ProofContext,
       skip_challenge_derivation: bool = False,
       global_challenge: Optional[np.ndarray] = None
   ) -> dict:
   ```
   - Add import: `from typing import Optional`
   - Add parameter after skip_challenge_derivation
   - Default to None for backwards compatibility

3. **Update docstring** (line 27-31):
   ```python
   # BEFORE:
   """Generate complete STARK proof.

   Fiat-Shamir transcript is created internally. For testing purposes that require
   pre-set randomness, use the params object or testing helpers.
   """

   # AFTER:
   """Generate complete STARK proof.

   Args:
       setup_ctx: Setup context with AIR configuration
       params: Prover parameters and witness data
       skip_challenge_derivation: Skip challenge derivation (testing)
       global_challenge: Optional pre-computed challenge for VADCOP mode.
           If provided, seeds transcript at Stage 0 for external challenge use.
           Shape: (3,) numpy array of FF elements or None.

   Returns:
       Dictionary containing serialized proof.

   Notes:
       - When global_challenge is None: Normal mode, derives all challenges from transcript
       - When global_challenge is provided: VADCOP mode, seeds transcript with pre-computed value
       - Verifier expects this pattern: prover/verifier must use identical Stage 0 seeding
   """
   ```

4. **Find Stage 0 initialization** (search for where transcript is created and first used):
   - Will be in stages.py orchestration or in commitStage calls
   - Look for: `transcript = Transcript(...)` or similar
   - Context: This is where `verkey` and `publics` are added to transcript

5. **Implement Stage 0 Seeding Logic**:
   - **BEFORE commitStage Stage 1** (after transcript initialization, before any other transcript operations):
   ```python
   # Stage 0: Seed transcript with global_challenge if provided (VADCOP mode)
   # Otherwise, seed with public inputs and root1 (normal mode)
   if global_challenge is not None:
       # VADCOP verification mode: Use externally provided challenge
       # This matches verifier.py:318 pattern for external challenge provision
       transcript.put(global_challenge[:3].tolist())
   else:
       # Normal mode: Initialize transcript with proof metadata
       # This matches verifier.py:303-314 pattern for standard verification
       # (The actual seeding is already done in commitStage/stages, but document this)
       pass  # Normal flow - already seeding with verkey, publics, root1
   ```

6. **Location Specifics** (to be determined after Stage 0 orchestration review):
   - The transcript seeding happens in `Starks.commitStage()`
   - Add `global_challenge` parameter to `gen_proof()` and pass to Starks
   - OR: Seed transcript in gen_proof before calling Starks
   - **Decision**: Should inspect stages.py to see where transcript is created

**Acceptance Criteria**:
- [ ] Function signature accepts optional `global_challenge` parameter
- [ ] Docstring clearly documents VADCOP mode vs normal mode
- [ ] When global_challenge is provided, transcript.put(global_challenge[:3].tolist()) is called at Stage 0
- [ ] When global_challenge is None, normal transcript initialization proceeds
- [ ] Backwards compatible - all existing callers work without modification
- [ ] Tests verify that global_challenge seeding produces correct challenges

#### Task #2: Extract and Pass global_challenge in Tests

**File**: `tests/test_stark_e2e.py`

**Changes Required**:

1. **Update create_params_from_vectors()** (line 74-end):
   - Add return value: also return global_challenge when available
   - Extract from test vectors intermediates
   - Check if "global_challenge" exists in vectors["intermediates"]

   ```python
   # BEFORE signature:
   def create_params_from_vectors(stark_info, vectors: dict,
                                   inject_challenges: bool = False) -> ProofContext:

   # AFTER signature:
   def create_params_from_vectors(stark_info, vectors: dict,
                                   inject_challenges: bool = False) -> tuple:
       # Returns: (ProofContext, Optional[np.ndarray])
   ```

   - Extract global_challenge:
   ```python
   global_challenge = None
   if "intermediates" in vectors and "global_challenge" in vectors["intermediates"]:
       gc = vectors["intermediates"]["global_challenge"]
       # Convert to numpy array if needed
       if isinstance(gc, list):
           global_challenge = np.array(gc, dtype=np.uint64)
       else:
           global_challenge = gc
   ```

2. **Update all test methods** that call create_params_from_vectors():
   - Change from: `params = create_params_from_vectors(...)`
   - Change to: `params, global_challenge = create_params_from_vectors(...)`
   - Pass global_challenge to gen_proof():
   ```python
   proof = gen_proof(setup_ctx, params, global_challenge=global_challenge)
   ```

3. **Handle missing global_challenge gracefully**:
   - If not in test vectors, use None (falls back to normal mode)
   - No error if missing - just don't pass it
   - Tests will still work, but won't validate challenge seeding

4. **Affected test methods** (find all that call create_params_from_vectors):
   - Search grep for "create_params_from_vectors"
   - Update each call site to extract and use global_challenge

**Acceptance Criteria**:
- [ ] create_params_from_vectors returns tuple (params, global_challenge)
- [ ] All test methods updated to unpack global_challenge
- [ ] gen_proof called with global_challenge=global_challenge parameter
- [ ] Tests pass and verify correct challenge derivation
- [ ] Backwards compatible - works whether global_challenge in vectors or not

## Implementation Workflow

This plan file serves as the authoritative checklist for implementation. When implementing:

### Required Process
1. **Load Plan**: Read this entire plan file before starting
2. **Inspect stages.py**: Determine where Stage 0 transcript seeding actually happens
3. **Implement Task #1**: Add parameter to gen_proof and implement Stage 0 seeding logic
4. **Implement Task #2**: Update test infrastructure to extract and pass global_challenge
5. **Run Tests**: Execute full test suite to verify
6. **Update Checkboxes**: Mark each sub-task as complete in this file

### Critical Rules
- Task #1 is the core work - must add global_challenge parameter and Stage 0 seeding
- Task #2 depends on Task #1 - tests need updated gen_proof signature
- Both tasks must be completed for tests to pass
- Never make placeholder implementations - every change must be complete and working
- Keep changes minimal and focused - only what's needed to restore the pattern

### Investigation Step (First)
Before implementing, investigate:
1. Where is transcript created? (likely in Starks.__init__ or commitStage)
2. Where is Stage 0 seeding currently happening? (verkey, publics, root1 additions)
3. Should global_challenge be passed to Starks or handled in gen_proof?
4. What's the exact flow from Stage 0 to Stage 1 commitment?

## Next Steps

1. Read stages.py to understand transcript initialization pattern
2. Determine if global_challenge should be:
   - Passed to Starks.commitStage()
   - Handled in gen_proof before calling Starks
3. Implement Task #1 with correct placement of Stage 0 seeding logic
4. Implement Task #2 with test infrastructure updates
5. Run tests and verify all 142 tests pass with correct challenge verification

## Technical Notes

### VADCOP Mode Explanation
VADCOP = "Verification And Distributed Computation Of Proof"
- In this mode, the verifier (or an external verification layer) computes global_challenge
- The challenge is derived from: publics + proof values + partial contributions
- This pre-computed challenge is passed to the prover to seed the transcript
- This pattern ensures prover and verifier use identical randomness
- Without it, challenges diverge and proofs fail verification

### Transcript Seeding Pattern
Both prover and verifier must follow identical seeding at Stage 0:
- **Normal Mode**: seed with verkey + publics + root1
- **VADCOP Mode**: seed with global_challenge (which was derived from publics + proof values)
- This is why global_challenge is a 3-element array - it's the result of transcript.get_field()
- The prover needs to use the same seed that the verifier will use

### Why Tests Are Failing
- Current prover doesn't accept global_challenge
- Tests derive their own challenges instead of seeding with externally-provided value
- This causes all subsequent challenges to be wrong
- Verifier computes different challenges during verification
- Challenge verification fails in proof validation
