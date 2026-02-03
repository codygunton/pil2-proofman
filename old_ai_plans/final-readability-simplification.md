# Final Readability Simplification Plan

## Executive Summary

### Problem Statement
The Python executable spec in `executable-spec/` is a faithful translation of the C++ STARK implementation. While functionally correct (byte-for-byte identical proofs with C++, Python verifier validates C++ proofs), the code retains C++ idioms that obscure the protocol logic. The goal is to make the protocol/ code read like a specification—clear, mathematical, and minimal "engineering noise."

### Proposed Solution
Systematically simplify `protocol/` modules using the `crypto-spec-simplifier` agent while preserving all E2E test invariants. Focus on:
1. Replacing C++ memory patterns with Python/numpy idioms
2. Extracting repeated engineering patterns into helpers
3. Clarifying protocol flow by separating concerns
4. Using vectorization and galois field operations idiomatically

### Technical Approach
- Use `crypto-spec-simplifier` agent for each protocol module
- Preserve vectorization and Montgomery batch inversion (performance requirements)
- Run E2E tests after each module to ensure byte-for-byte compatibility
- Skip `primitives/` (user directive)

### Critical Constraints
**These tests MUST pass after every change:**
1. `test_verifier_e2e.py` - Python verifier validates hard-coded C++ binary proofs
2. `test_stark_e2e.py::test_full_binary_proof_match` - Python prover produces byte-identical proofs to C++

**NO stubbing, shortcuts, or `return True` hacks allowed.**

### Expected Outcomes
- Protocol code reads as a clear specification of the STARK algorithm
- Engineering concerns (buffers, offsets, serialization) isolated from protocol logic
- Python/numpy/galois idioms replace C++ patterns
- All E2E tests continue passing with identical outputs

---

## Goals & Objectives

### Primary Goals
- Maximize readability of protocol/ code for cryptographers
- Maintain byte-for-byte proof compatibility with C++ implementation
- Preserve verifier correctness (Python verifies C++ proofs)

### Secondary Objectives
- Reduce code duplication across protocol modules
- Establish consistent naming conventions
- Make the STARK algorithm flow obvious from reading the code

---

## Solution Overview

### Approach
Apply the `crypto-spec-simplifier` agent to each protocol module in dependency order. The agent will:
1. Separate core protocol logic from engineering helpers
2. Introduce pythonic patterns (numpy slicing, galois operations)
3. Inline trivial helpers while preserving semantic structure
4. Ensure test compatibility throughout

### Key Components
1. **fri.py** (162 LOC): Core FRI folding - already relatively clean, light simplification
2. **pcs.py** (196 LOC): FRI PCS wrapper - simplify challenge derivation
3. **stages.py** (757 LOC): Starks class - extract buffer management, clarify stage flow
4. **prover.py** (391 LOC): gen_proof() orchestration - make high-level flow obvious
5. **verifier.py** (1,315 LOC): stark_verify() - largest file, most engineering noise
6. **expression_evaluator.py** (943 LOC): Constraint evaluation - heavily C++-ified
7. **witness_generation.py** (978 LOC): STD calculations - complex accumulation logic
8. **proof.py** (1,068 LOC): Serialization - engineering-heavy but necessary
9. **stark_info.py** (614 LOC): Config parsing - pure engineering, light touch
10. **setup_ctx.py** (383 LOC): Setup context - buffer management

### Data Flow
```
┌─────────────────────────────────────────────────────────────────┐
│                      STARK PROOF GENERATION                      │
│                                                                  │
│  Witness Trace ──► Stage 1 ──► Stage 2 ──► Stage Q ──► FRI     │
│       │              │            │           │          │       │
│       ▼              ▼            ▼           ▼          ▼       │
│  [witness_gen] → [stages.py] → [stages.py] → [pcs.py] → [fri.py]│
│                                                          │       │
│                                              STARKProof ◄┘       │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                      STARK PROOF VERIFICATION                    │
│                                                                  │
│  STARKProof ──► Parse ──► Rebuild Challenges ──► Verify FRI     │
│                   │              │                    │          │
│                   ▼              ▼                    ▼          │
│             [proof.py]    [verifier.py]         [fri.py]        │
└─────────────────────────────────────────────────────────────────┘
```

---

## Implementation Tasks

### CRITICAL IMPLEMENTATION RULES
1. **USE crypto-spec-simplifier AGENT**: Every protocol simplification task MUST use this specialized agent
2. **TEST AFTER EACH MODULE**: Run E2E tests after completing each module simplification
3. **NO BEHAVIOR CHANGES**: Output must be bit-for-bit identical - refactoring only
4. **PRESERVE VECTORIZATION**: Keep numpy vectorized operations for performance
5. **PRESERVE MONTGOMERY INVERSION**: Keep batch_inverse usage for performance

### Visual Dependency Tree

```
executable-spec/protocol/
│
├── fri.py (Task #1: Simplify FRI folding - minimal changes needed)
│
├── pcs.py (Task #2: Simplify FRI PCS wrapper)
│   └── imports: fri.py
│
├── stages.py (Task #3: Simplify Starks class)
│   └── imports: pcs.py, fri.py
│
├── witness_generation.py (Task #4: Simplify witness/STD computation)
│   └── imports: (primitives only)
│
├── expression_evaluator.py (Task #5: Simplify constraint evaluation)
│   └── imports: expressions_bin.py
│
├── prover.py (Task #6: Simplify proof generation orchestration)
│   └── imports: stages.py, witness_generation.py, expression_evaluator.py
│
├── verifier.py (Task #7: Simplify verification logic - largest task)
│   └── imports: fri.py, expression_evaluator.py, proof.py
│
├── proof.py (Task #8: Light cleanup of serialization)
│   └── imports: (standalone)
│
├── stark_info.py (Task #9: Light cleanup of config parsing)
│   └── imports: (standalone)
│
└── setup_ctx.py (Task #10: Light cleanup of setup context)
    └── imports: stark_info.py
```

### Execution Plan

#### Group A: Core FRI Layer (Execute sequentially - dependencies)

- [x] **Task #1**: Simplify FRI folding (fri.py)
  - Folder: `executable-spec/protocol/`
  - File: `fri.py` (162 LOC)
  - Agent: `crypto-spec-simplifier`
  - Focus areas:
    - FRI.fold() - ensure vectorized galois operations are idiomatic
    - FRI.verify_fold() - clarify verification logic
    - FRI.merkelize() - simplify Merkle tree construction
  - Preserve: Vectorized numpy operations
  - Context: This is the innermost FRI logic, used by pcs.py and verifier.py
  - Validation: Run `pytest tests/test_fri.py -v` after changes

- [x] **Task #2**: Simplify FRI PCS wrapper (pcs.py)
  - Folder: `executable-spec/protocol/`
  - File: `pcs.py` (196 LOC)
  - Agent: `crypto-spec-simplifier`
  - Focus areas:
    - FriPcs.prove() - clarify the prove loop with FRI folding
    - _compute_grinding_nonce() - simplify PoW logic
    - _derive_query_indices() - clarify query sampling
  - Preserve: Transcript state management (Fiat-Shamir)
  - Context: Wraps FRI for polynomial commitment scheme
  - Validation: Run `pytest tests/test_fri.py -v` after changes

#### Group B: Prover Pipeline (Execute sequentially - dependencies)

- [x] **Task #3**: Simplify Starks class (stages.py)
  - Folder: `executable-spec/protocol/`
  - File: `stages.py` (757 LOC)
  - Agent: `crypto-spec-simplifier`
  - Focus areas:
    - commitStage() - clarify stage commitment flow
    - extendAndMerkelize() - simplify polynomial extension
    - calculateQuotientPolynomial() - make quotient computation clear
    - calculateFRIPolynomial() - simplify FRI polynomial assembly
    - Buffer management patterns - extract or inline appropriately
  - Preserve: Vectorized NTT operations, buffer layout for compatibility
  - Context: Orchestrates the three STARK stages (witness, quotient, FRI)
  - Validation: Run `pytest tests/test_stark_e2e.py -v` after changes

- [x] **Task #4**: Simplify witness generation (witness_generation.py)
  - Folder: `executable-spec/protocol/`
  - File: `witness_generation.py` (978 LOC)
  - Agent: `crypto-spec-simplifier`
  - Focus areas:
    - calculate_witness_std() - clarify main witness computation
    - gsum/gprod accumulation - make running sum/product logic clear
    - Hint field evaluation - simplify field operation patterns
    - Field arithmetic helpers - use galois idioms
  - Preserve: batch_inverse_ff/ff3 usage (Montgomery), vectorization
  - Context: Computes witness polynomials for lookup/permutation arguments
  - Validation: Run `pytest tests/test_stark_e2e.py -v` after changes

- [x] **Task #5**: Simplify expression evaluator (expression_evaluator.py)
  - Folder: `executable-spec/protocol/`
  - File: `expression_evaluator.py` (943 LOC)
  - Agent: `crypto-spec-simplifier`
  - Focus areas:
    - ExpressionsPack class - clarify evaluation orchestration
    - _load_galois/_store_galois - simplify field loading patterns
    - _goldilocks_op/_goldilocks3_op - clarify field arithmetic
    - calculate_expression() - make bytecode execution clear
    - Buffer access patterns - use numpy idioms
  - Preserve: Vectorized evaluation (nrows_pack), field extension handling
  - Context: Evaluates AIR constraint expressions from bytecode
  - Validation: Run `pytest tests/test_stark_e2e.py -v` after changes

- [x] **Task #6**: Simplify proof generation (prover.py)
  - Folder: `executable-spec/protocol/`
  - File: `prover.py` (391 LOC)
  - Agent: `crypto-spec-simplifier`
  - Focus areas:
    - gen_proof() - make high-level orchestration obvious
    - Stage progression - clarify challenge derivation at each stage
    - Final assembly - simplify proof construction
  - Preserve: Exact transcript update order (Fiat-Shamir)
  - Context: Top-level entry point for proof generation
  - Validation: Run `pytest tests/test_stark_e2e.py::TestFullBinaryComparison -v` after changes

#### Group C: Verifier (Largest task, execute alone)

- [x] **Task #7**: Simplify verification logic (verifier.py)
  - Folder: `executable-spec/protocol/`
  - File: `verifier.py` (1,315 LOC - largest file)
  - Agent: `crypto-spec-simplifier`
  - Focus areas:
    - stark_verify() - make verification flow clear
    - Challenge reconstruction - simplify Fiat-Shamir rebuild
    - _verify_evaluations() - clarify constraint checking
    - _verify_fri_consistency() - simplify FRI verification
    - _verify_*_merkle_tree() - consolidate Merkle verification patterns
    - Buffer/offset management - extract or simplify
    - Proof parsing - separate from verification logic
  - Preserve: Exact verification logic, no shortcuts, no `return True` stubs
  - Context: Verifies STARK proofs - CRITICAL for security
  - Validation: Run `pytest tests/test_verifier_e2e.py -v` after changes
  - **CRITICAL**: This test loads binary C++ proofs and verifies them. ANY logic change breaks it.

#### Group D: Support Modules (Execute in parallel - independent)

- [x] **Task #8**: Light cleanup of proof serialization (proof.py)
  - Folder: `executable-spec/protocol/`
  - File: `proof.py` (1,068 LOC)
  - Agent: `crypto-spec-simplifier`
  - Focus areas:
    - Separate proof data structures from serialization logic
    - Clarify STARKProof, FriProof, MerkleProof classes
    - Simplify JSON/binary conversion where possible
  - Preserve: Exact binary format (byte-for-byte compatibility)
  - Context: Proof structures and serialization - mostly engineering
  - Validation: Run `pytest tests/test_proof.py -v && pytest tests/test_stark_e2e.py::TestFullBinaryComparison -v`

- [x] **Task #9**: Light cleanup of config parsing (stark_info.py)
  - Folder: `executable-spec/protocol/`
  - File: `stark_info.py` (614 LOC)
  - Agent: `crypto-spec-simplifier`
  - Focus areas:
    - StarkInfo class - clarify configuration structure
    - Parsing logic - use pythonic patterns
    - Offset computation - simplify if possible
  - Preserve: All parsed values must match C++ interpretation
  - Context: Parses starkinfo.json - pure engineering, low priority
  - Validation: Run `pytest tests/test_stark_info.py -v`

- [x] **Task #10**: Light cleanup of setup context (setup_ctx.py)
  - Folder: `executable-spec/protocol/`
  - File: `setup_ctx.py` (383 LOC)
  - Agent: `crypto-spec-simplifier`
  - Focus areas:
    - SetupCtx class - clarify what it bundles
    - ProverHelpers - simplify buffer management if possible
    - Zerofier computation - clarify mathematical intent
  - Preserve: Computed values must match C++ for compatibility
  - Context: Bundles configuration and precomputed values
  - Validation: Run `pytest tests/test_stark_e2e.py -v`

#### Group E: Final Validation (Execute after all simplifications)

- [x] **Task #11**: Final E2E validation
  - Run full test suite: `cd executable-spec && uv run python -m pytest -v`
  - Verify:
    - [ ] test_verifier_e2e.py passes (Python verifies C++ proofs)
    - [ ] test_stark_e2e.py::TestFullBinaryComparison passes (byte-identical proofs)
    - [ ] test_fri.py passes (FRI layer correctness)
    - [ ] All other tests pass
  - If any test fails: identify which task introduced the regression and fix

---

## Task Execution Instructions

### For Each Task (Tasks #1-#10)

Each task should be executed as follows:

1. **Launch the crypto-spec-simplifier agent** with a prompt like:
   ```
   Simplify [FILE] for readability while maintaining test compatibility.

   CRITICAL CONSTRAINTS:
   - Output must be bit-for-bit identical (tests verify this)
   - NO behavior changes, refactoring only
   - Preserve vectorization (numpy operations)
   - Preserve Montgomery batch inversion where used
   - Use Python/numpy/galois idioms

   Focus areas: [SPECIFIC AREAS FROM TASK]

   After changes, run: [VALIDATION COMMAND]
   ```

2. **Review changes** - ensure no logic changes, only readability improvements

3. **Run validation tests** - must pass before proceeding to next task

4. **If tests fail** - revert and retry with smaller changes

### Agent Prompt Template

```
You are simplifying the Python executable spec for a STARK prover/verifier.
The code must produce byte-identical output to the C++ implementation.

FILE TO SIMPLIFY: executable-spec/protocol/[FILENAME]

CONSTRAINTS:
1. NO behavior changes - output must be bit-for-bit identical
2. Preserve vectorized numpy operations for performance
3. Preserve batch_inverse_ff/ff3 usage for performance
4. Use Python/numpy/galois idioms instead of C++ patterns
5. Separate protocol logic from engineering where possible
6. The file must still pass: [TEST COMMAND]

FOCUS AREAS:
[LIST FROM TASK]

DO NOT:
- Change the order of transcript updates (Fiat-Shamir)
- Change how challenges are derived
- Change how Merkle roots are computed
- Stub out any verification logic
- Use `return True` shortcuts

After making changes, run the validation tests to ensure compatibility.
```

---

## Implementation Workflow

This plan file serves as the authoritative checklist for implementation. When implementing:

### Required Process
1. **Load Plan**: Read this entire plan file before starting
2. **Sync Tasks**: Create TodoWrite tasks matching the checkboxes above
3. **Execute & Update**: For each task:
   - Mark TodoWrite as `in_progress` when starting
   - Use `crypto-spec-simplifier` agent with appropriate prompt
   - Update checkbox `[ ]` to `[x]` when completing
   - Mark TodoWrite as `completed` when done
4. **Maintain Sync**: Keep this file and TodoWrite synchronized throughout

### Critical Rules
- This plan file is the source of truth for progress
- Update checkboxes in real-time as work progresses
- Never lose synchronization between plan file and TodoWrite
- Mark tasks complete only when fully implemented AND tests pass
- Tasks #1-#7 must be run sequentially due to dependencies
- Tasks #8-#10 can run in parallel after Group C completes

### Progress Tracking
The checkboxes above represent the authoritative status of each task. Keep them updated as you work.

---

## Risk Mitigation

### If a simplification breaks tests:
1. Immediately revert the change
2. Identify the specific line/pattern that caused the failure
3. Try a more conservative simplification
4. If stuck, skip that specific simplification and document why

### Common pitfalls to avoid:
- Reordering operations that affect Fiat-Shamir transcript
- Changing numpy dtype (uint64 is required for Goldilocks field)
- Simplifying "complex" index calculations that are actually necessary
- Removing "redundant" field conversions that ensure correct bit patterns
