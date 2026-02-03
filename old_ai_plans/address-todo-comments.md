# Address ##-- TODO Comments Implementation Plan

## Executive Summary

This plan addresses 5 `##--` comments scattered across the protocol layer that highlight code quality issues:

1. **setup_ctx.py:2** - Module name "setup_ctx" is unenlightening, docstring unhelpful
2. **verifier.py:35** - `JProof = dict` provides no type safety for JSON proof structure
3. **prover.py:125** - NTT instantiation leaks implementation details into protocol layer
4. **prover.py:158** - Starks class instantiation poorly documented
5. **proof.py:12** - Audit needed to remove unused code from proof.py

### Technical Approach

- **Rename setup_ctx.py → air_config.py** with better docstrings explaining purpose
- **Create TypedDict for JProof** with all expected keys documented
- **Abstract NTT into commitment scheme** by moving NTT creation into Starks class
- **Improve Starks documentation** with clear explanation of its role
- **Audit proof.py** and remove unused types/functions

### Data Flow (Unchanged)

```
SetupCtx (air_config.py)
    ↓
gen_proof() ← ProofContext (witness data)
    ↓
Starks (stages.py) ← NTT (now internal)
    ↓
proof_dict → to_bytes_full_from_dict() → binary proof
                         ↓
              stark_verify() ← JProof (typed)
```

### Expected Outcomes

- Module names clearly communicate purpose
- Type safety for proof structures enables IDE support and catches bugs
- Protocol layer (prover.py) free of implementation details like NTT
- All code in proof.py is actively used
- Better onboarding experience for new contributors

---

## Goals & Objectives

### Primary Goals
- Improve code clarity by renaming setup_ctx.py to air_config.py
- Add type safety to JProof with TypedDict
- Hide NTT implementation detail from protocol layer

### Secondary Objectives
- Remove dead code from proof.py
- Improve documentation throughout
- Maintain byte-identical proof output (no behavioral changes)

---

## Solution Overview

### Approach

Each `##--` comment represents a distinct improvement. Changes are structured to be backward-compatible where possible (deprecated aliases for renamed modules) and to maintain test compatibility.

### Key Components

1. **air_config.py (renamed from setup_ctx.py)**: Contains AIR configuration bundle and prover helpers. The new name "air_config" clearly indicates it holds AIR (Algebraic Intermediate Representation) configuration.

2. **JProof TypedDict**: A typed dictionary specifying all keys the verifier expects, enabling IDE autocomplete and type checking.

3. **Starks with internal NTT**: Move NTT instantiation into Starks class, exposing only high-level methods like `commit_stage()`.

4. **Cleaned proof.py**: Only types and functions that are actively used remain.

---

## Implementation Tasks

### CRITICAL IMPLEMENTATION RULES
1. **NO PLACEHOLDER CODE**: Every implementation must be production-ready
2. **MAINTAIN TEST COMPATIBILITY**: All 142 tests must pass after changes
3. **BYTE-IDENTICAL PROOFS**: No changes to proof generation behavior
4. **BACKWARD COMPATIBILITY**: Provide deprecated aliases where practical

### Visual Dependency Tree

```
protocol/
├── air_config.py (Task #1: Rename setup_ctx.py → air_config.py)
│   ├── ProverHelpers class (unchanged)
│   └── SetupCtx class → AirConfig class (with alias)
│
├── proof.py (Task #2: Audit and remove unused code)
│   ├── JProof TypedDict (NEW - Task #3)
│   ├── MerkleProof (KEEP - used by STARKProof)
│   ├── ProofTree (KEEP - used by FriProof)
│   ├── FriProof (KEEP - used by STARKProof)
│   ├── STARKProof (KEEP - used in tests)
│   ├── FRIProofFull (REMOVE - unused)
│   ├── Hash alias (REMOVE - never imported)
│   ├── from_bytes_full_to_jproof() (KEEP - used by verifier tests)
│   ├── to_bytes_full_from_dict() (KEEP - used by prover tests)
│   ├── load_proof_from_binary() (REMOVE - raises NotImplementedError)
│   ├── proof_to_pointer_layout() (REMOVE - incomplete legacy)
│   └── ... (other functions - audit individually)
│
├── verifier.py (Task #3: Add JProof TypedDict)
│   └── JProof = dict → JProof(TypedDict)
│
├── stages.py (Task #4: Internalize NTT in Starks)
│   └── Starks class gains _ntt and _ntt_extended members
│
├── prover.py (Task #4 + Task #5: Remove NTT, improve docs)
│   ├── Remove: ntt = NTT(N), ntt_extended = NTT(N_extended)
│   └── Update: starks.commitStage() no longer takes ntt parameter
│
└── setup_ctx.py (Task #1: Deprecated re-export module)
    └── from protocol.air_config import * (backward compat)
```

### Execution Plan

#### Group A: Foundation (Execute in parallel)

- [x] **Task #1**: Rename setup_ctx.py → air_config.py
  - Folder: `protocol/`
  - Files: `setup_ctx.py` → `air_config.py`, new `setup_ctx.py` (deprecated re-export)
  - Changes:
    1. Rename `protocol/setup_ctx.py` to `protocol/air_config.py`
    2. Update module docstring:
       ```python
       """AIR configuration and precomputed prover data.

       This module provides the configuration bundle for STARK proving/verification:
       - AirConfig: Bundles StarkInfo (AIR specification), ExpressionsBin (compiled
         constraint expressions), and optional GlobalInfo (cross-AIR coordination).
       - ProverHelpers: Precomputed zerofiers and evaluation points needed by both
         prover and verifier for constraint evaluation.

       The 'AIR' (Algebraic Intermediate Representation) defines the constraint system
       that the STARK proves. AirConfig packages everything needed to evaluate those
       constraints.
       """
       ```
    3. Rename `SetupCtx` class to `AirConfig` with backward-compatible alias:
       ```python
       class AirConfig:
           """Configuration bundle: StarkInfo + ExpressionsBin + GlobalInfo.

           This is the read-only configuration for a STARK proof. It contains:
           - stark_info: The AIR specification (domains, stages, constraints, etc.)
           - expressions_bin: Compiled constraint expressions for evaluation
           - global_info: Optional cross-AIR coordination data (for VADCOP)
           """
           ...

       # Backward compatibility alias
       SetupCtx = AirConfig
       ```
    4. Create new `setup_ctx.py` with deprecation warning:
       ```python
       """Deprecated: Use air_config.py instead.

       This module re-exports from air_config for backward compatibility.
       """
       import warnings
       warnings.warn(
           "setup_ctx module is deprecated, use air_config instead",
           DeprecationWarning,
           stacklevel=2
       )
       from protocol.air_config import *
       ```
  - Exports: AirConfig, SetupCtx (alias), ProverHelpers
  - Context: Foundation for all other tasks - must be done first or in parallel with Task #2

- [x] **Task #2**: Audit proof.py and remove unused code
  - Folder: `protocol/`
  - File: `proof.py`
  - Research findings (from usage analysis):
    - **KEEP**: MerkleProof, ProofTree, FriProof, STARKProof (used in tests/serialization)
    - **KEEP**: proof_to_json, load_proof_from_json (used in test_proof.py)
    - **KEEP**: from_bytes_full_to_jproof (used in test_verifier_e2e.py)
    - **KEEP**: to_bytes_partial, to_bytes_full, to_bytes_full_from_dict (used in test_stark_e2e.py)
    - **KEEP**: validate_proof_structure (used in test_proof.py)
    - **KEEP**: _is_galois_array, _is_extension_field, _to_list (helpers for serialization)
    - **REMOVE**: FRIProofFull (never instantiated outside this file)
    - **REMOVE**: Hash type alias (never imported by any module)
    - **REMOVE**: load_proof_from_binary (raises NotImplementedError, unused)
    - **REMOVE**: proof_to_pointer_layout (incomplete, marked as "reference implementation")
  - Changes:
    1. Delete `FRIProofFull` dataclass (lines 56-63)
    2. Delete `Hash = List[int]` type alias (line 15)
    3. Delete `load_proof_from_binary()` function (lines 150-152)
    4. Delete `proof_to_pointer_layout()` function (lines 699-718)
    5. Update module docstring to remove references to deleted items
    6. Remove the `##--dothis` comment
  - Exports: All remaining types and functions
  - Context: Cleanup task, no dependencies on other tasks

---

#### Group B: Type Safety (Execute after Group A)

- [x] **Task #3**: Create JProof TypedDict for verifier
  - Folder: `protocol/`
  - File: `proof.py` (add TypedDict), `verifier.py` (import and use)
  - Changes to `proof.py`:
    1. Add import: `from typing import TypedDict, NotRequired`
    2. Add JProof TypedDict after the `# --- Type Aliases ---` section:
       ```python
       class JProofStageData(TypedDict, total=False):
           """Stage-specific proof data (dynamic keys handled separately)."""
           pass

       class JProof(TypedDict, total=False):
           """JSON-decoded STARK proof structure.

           This TypedDict documents the expected structure of a deserialized proof
           as returned by from_bytes_full_to_jproof() or loaded from JSON.

           Keys follow the pattern:
           - root{stage}: Merkle root for stage commitment (1-indexed)
           - s0_vals{stage}: Query values for stage polynomials
           - s0_siblings{stage}: Merkle path siblings for stage
           - s0_last_levels{stage}: Last-level nodes for stage (if enabled)
           - s{step}_root: FRI folding step root (1-indexed)
           - s{step}_vals: FRI step query values
           - s{step}_siblings: FRI step Merkle paths
           - s{step}_last_levels: FRI step last-level nodes

           Note: Due to dynamic key patterns (root1, root2, etc.), this TypedDict
           uses total=False and documents the structure rather than enforcing it
           statically. Use from_bytes_full_to_jproof() for proper parsing.
           """
           # AIR values
           airgroupvalues: list[list[int]]  # [[c0,c1,c2], ...] - airgroup values
           airvalues: list[list[int]]       # [[c0,c1,c2], ...] or [[c0], ...] - air values

           # Polynomial evaluations at challenge point xi
           evals: list[list[int]]           # [[c0,c1,c2], ...] - FF3 evaluations

           # Final polynomial and nonce
           finalPol: list[list[int]]        # [[c0,c1,c2], ...] - FF3 coefficients
           nonce: int                       # Proof-of-work nonce

           # Stage roots (root1, root2, ..., rootQ) - dynamic keys
           # Each root is List[int] with HASH_SIZE elements

           # Constant polynomial proofs
           s0_valsC: list[list[int]]        # Query values [query][col]
           s0_siblingsC: list[list[list[int]]]  # Merkle paths [query][level][sibling]
           s0_last_levelsC: list[list[int]]     # Last-level nodes [node][hash_elem]

           # Stage polynomial proofs (s0_vals1, s0_vals2, etc.) - dynamic keys
           # s0_vals{stage}: list[list[int]] - Query values [query][col]
           # s0_siblings{stage}: list[list[list[int]]] - Merkle paths
           # s0_last_levels{stage}: list[list[int]] - Last-level nodes

           # FRI step proofs (s1_root, s1_vals, etc.) - dynamic keys
           # s{step}_root: list[int] - FRI step Merkle root
           # s{step}_vals: list[list[int]] - FRI query values
           # s{step}_siblings: list[list[list[int]]] - FRI Merkle paths
           # s{step}_last_levels: list[list[int]] - FRI last-level nodes
       ```
  - Changes to `verifier.py`:
    1. Update import: `from protocol.proof import JProof`
    2. Remove local `JProof = dict` alias (line 36)
    3. Remove the `##--dothis` comment (line 35)
    4. Update type hints in functions to use imported JProof
  - Exports: JProof from proof.py
  - Context: Depends on Task #2 completing proof.py cleanup first

---

#### Group C: Protocol Purity (Execute after Group A)

- [x] **Task #4**: Internalize NTT in Starks class
  - Folder: `protocol/`
  - Files: `stages.py`, `prover.py`
  - Changes to `stages.py` (Starks class):
    1. Add NTT imports:
       ```python
       from primitives.ntt import NTT
       ```
    2. Update `Starks.__init__()`:
       ```python
       def __init__(self, setup_ctx: 'AirConfig'):
           """Initialize polynomial commitment orchestrator.

           The Starks class manages polynomial commitment via Merkle trees:
           - Maintains one Merkle tree per polynomial commitment stage
           - Handles polynomial extension (NTT) and tree construction
           - Provides query proof generation for FRI verification

           Args:
               setup_ctx: AIR configuration with domain sizes and parameters

           Note: NTT (Number Theoretic Transform) objects are created internally
           to hide FFT implementation details from the protocol layer. The protocol
           only needs to know about polynomial commitment, not how it's implemented.
           """
           self.setupCtx = setup_ctx
           self.stage_trees: dict[int, MerkleTree] = {}
           self.const_tree: Optional[MerkleTree] = None

           # Internal NTT instances for polynomial operations
           # These are created lazily or eagerly based on domain sizes
           si = setup_ctx.stark_info
           N = 1 << si.starkStruct.nBits
           N_extended = 1 << si.starkStruct.nBitsExt
           self._ntt = NTT(N)
           self._ntt_extended = NTT(N_extended)
       ```
    3. Update `commitStage()` to not require ntt parameter:
       ```python
       def commitStage(self, stage: int, params: 'ProofContext') -> list[int]:
           """Commit to stage polynomials and return Merkle root.

           Args:
               stage: Stage number (1 = witness, 2 = intermediate, nStages+1 = quotient)
               params: Proof context with polynomial data

           Returns:
               Merkle root (HASH_SIZE integers)
           """
           # Use internal NTT based on stage
           q_stage = self.setupCtx.stark_info.nStages + 1
           ntt = self._ntt_extended if stage == q_stage else self._ntt
           # ... rest of implementation uses ntt internally
       ```
    4. Update all internal methods that use NTT to use `self._ntt` or `self._ntt_extended`
  - Changes to `prover.py`:
    1. Remove NTT import: ~~`from primitives.ntt import NTT`~~
    2. Remove NTT instantiation (lines 137-138):
       ```python
       # DELETE these lines:
       # ntt = NTT(N)
       # ntt_extended = NTT(N_extended)
       ```
    3. Update `commitStage()` calls to not pass ntt:
       ```python
       # Before: root1 = starks.commitStage(1, params, ntt)
       # After:  root1 = starks.commitStage(1, params)
       ```
    4. Update `_compute_all_evals()` to not require ntt parameter:
       - Pass starks instead, which has internal NTT
       - Or move the Lagrange evaluation logic into Starks
    5. Remove the `##--NTT` comment (line 125)
    6. Remove the `##--this seems to be a boorly` comment (line 158)
  - Exports: Starks with updated interface (no NTT parameter)
  - Context: Changes Starks API - must update all callers (prover.py, tests)

- [x] **Task #5**: Improve Starks class documentation
  - Folder: `protocol/`
  - File: `stages.py`
  - Changes:
    1. Update module docstring:
       ```python
       """Polynomial commitment stage orchestration.

       This module provides the Starks class which manages the polynomial commitment
       phase of STARK proof generation. For each "stage" of the protocol, Starks:

       1. Takes polynomial evaluations from ProofContext
       2. Extends them to the evaluation domain (via NTT)
       3. Builds a Merkle tree commitment
       4. Returns the Merkle root

       Stages in the STARK protocol:
       - Stage 1: Witness polynomials (execution trace)
       - Stage 2: Intermediate polynomials (lookup/permutation support)
       - Stage Q (nStages+1): Quotient polynomial (constraint checking)

       The Merkle trees are retained for later query proof generation during FRI.
       """
       ```
    2. Update Starks class docstring (already covered in Task #4)
    3. Add docstrings to all public methods explaining their role in the protocol
  - Exports: No API changes
  - Context: Documentation only, can be done with Task #4

---

#### Group D: Import Updates (Execute after Group C)

- [x] **Task #6**: Update all imports across codebase
  - Folders: `protocol/`, `tests/`
  - Files to update:
    - `protocol/prover.py`: Update import from setup_ctx to air_config
    - `protocol/verifier.py`: Update import from setup_ctx to air_config, add JProof import
    - `protocol/stages.py`: Update import from setup_ctx to air_config
    - `protocol/expression_evaluator.py`: Update import if using SetupCtx
    - `protocol/__init__.py`: Update exports
    - `tests/test_stark_e2e.py`: Update imports
    - `tests/test_verifier_e2e.py`: Update imports
    - All other test files using SetupCtx
  - Changes:
    1. For each file, replace:
       ```python
       # Before:
       from protocol.setup_ctx import SetupCtx, ProverHelpers
       # After (option A - use new name):
       from protocol.air_config import AirConfig, ProverHelpers
       # After (option B - use backward-compatible alias):
       from protocol.air_config import SetupCtx, ProverHelpers  # SetupCtx is alias
       ```
    2. Consider using `AirConfig` in new code, `SetupCtx` alias for minimal diff
  - Context: Must be done after Task #1 creates air_config.py

---

## Implementation Workflow

This plan file serves as the authoritative checklist for implementation. When implementing:

### Required Process
1. **Load Plan**: Read this entire plan file before starting
2. **Sync Tasks**: Create TodoWrite tasks matching the checkboxes above
3. **Execute & Update**: For each task:
   - Mark TodoWrite as `in_progress` when starting
   - Update checkbox `[ ]` to `[x]` when completing
   - Mark TodoWrite as `completed` when done
4. **Maintain Sync**: Keep this file and TodoWrite synchronized throughout

### Critical Rules
- This plan file is the source of truth for progress
- Update checkboxes in real-time as work progresses
- Never lose synchronization between plan file and TodoWrite
- Mark tasks complete only when fully implemented (no placeholders)
- Run `uv run python -m pytest tests/ -v` after each task to verify tests pass
- Tasks in the same group can run in parallel using subtasks

### Testing Strategy
- After each task, run the full test suite: `cd executable-spec && uv run python -m pytest tests/ -v`
- All 142 tests must pass after every change
- Verify byte-identical proof output by running E2E tests

### Progress Tracking
The checkboxes above represent the authoritative status of each task. Keep them updated as you work.

---

## Risk Mitigation

### Backward Compatibility
- `SetupCtx` alias ensures existing code continues working
- Deprecation warning helps migrate over time
- No changes to proof binary format

### Test Coverage
- Existing 142 tests cover all modified code paths
- E2E tests verify byte-identical proof output
- Run tests after each task

### Rollback Plan
- Each task is self-contained
- Git commits should be atomic per task
- Can revert individual tasks without affecting others
