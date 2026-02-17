# Verifier Configuration Simplification Plan

## Executive Summary

The verifier configuration in `executable-spec/` has grown organically from the C++ implementation and contains significant complexity that is unnecessary for the Python executable spec:

**Problems identified:**
1. **SetupCtx** is a useless alias for **AirConfig** - creates confusion without benefit
2. **StarkStruct** contains 11 fields, but 8 are identical across all test AIRs and could be defaulted
3. **StarkInfo** contains ~15 unused fields (C++ legacy, expression IDs, proof estimates)
4. **camelCase naming** throughout violates Python conventions (PEP 8)

**Solution:**
- Remove the SetupCtx alias entirely, use AirConfig consistently
- Remove all unused fields from StarkInfo and StarkStruct
- Default constant-value fields in StarkStruct
- Convert all field names to snake_case

**Impact:**
- ~30 unused fields removed
- ~50 camelCase → snake_case renames
- Cleaner, more Pythonic code
- Zero functional change (all tests must pass)

## Goals & Objectives

### Primary Goals
- Remove all unused configuration fields from StarkInfo and StarkStruct
- Convert all field names to Python snake_case convention
- Eliminate the confusing SetupCtx alias

### Secondary Objectives
- Simplify JSON parsing by removing unused field handling
- Improve code readability for cryptographers reviewing the spec
- Reduce maintenance burden

## Solution Overview

### Approach
This is a mechanical refactoring with three phases:
1. **Remove SetupCtx** - Find/replace alias with AirConfig
2. **Remove unused fields** - Delete fields never accessed in execution
3. **Rename to snake_case** - Systematic rename of all camelCase fields

### Key Components

1. **AirConfig consolidation**: Remove SetupCtx alias from air_config.py, stages.py, setup_ctx.py, and all imports
2. **StarkStruct simplification**: Keep only n_bits, n_bits_ext, n_queries, fri_fold_steps; default others
3. **StarkInfo cleanup**: Remove 15+ unused fields (expression IDs, C++ flags, proof estimates)
4. **snake_case conversion**: Rename ~50 fields across 6 files

### Data Flow
```
starkinfo.json (camelCase)
    ↓ parse
StarkInfo (snake_case, minimal fields)
    ↓
AirConfig (no SetupCtx alias)
    ↓
verifier.py / prover.py
```

### Expected Outcomes
- All 164 tests pass with identical binary output
- No SetupCtx references remain in codebase
- All field names follow snake_case convention
- StarkInfo has only fields actually used by prover/verifier

## Implementation Tasks

### CRITICAL IMPLEMENTATION RULES
1. **NO PLACEHOLDER CODE**: Every change must be complete and tested
2. **CROSS-DIRECTORY TASKS**: Group related changes to avoid breaking imports
3. **TESTS MUST PASS**: Run `./run-tests.sh` after each task group
4. **PRESERVE BINARY COMPATIBILITY**: Proof output must be byte-identical

### Visual Dependency Tree

```
executable-spec/
├── primitives/
│   └── pol_map.py (Task #1: Rename camelCase fields in data classes)
│
├── protocol/
│   ├── stark_info.py (Task #2: Remove unused fields, rename to snake_case)
│   ├── air_config.py (Task #3: Remove SetupCtx alias, rename usages)
│   ├── setup_ctx.py (Task #3: DELETE this deprecated file)
│   ├── __init__.py (Task #3: Remove SetupCtx from exports)
│   ├── stages.py (Task #4: Update all stark_info field accesses)
│   ├── prover.py (Task #4: Update all stark_info field accesses)
│   ├── verifier.py (Task #4: Update all stark_info field accesses)
│   ├── fri.py (Task #4: Update all stark_info field accesses)
│   ├── pcs.py (Task #4: Update all stark_info field accesses)
│   ├── fri_polynomial.py (Task #4: Update all stark_info field accesses)
│   ├── proof_context.py (Task #4: Update all stark_info field accesses)
│   ├── data.py (Task #4: Update any stark_info field accesses)
│   ├── proof.py (Task #4: Update all stark_info field accesses)
│   └── challenge_utils.py (Task #4: Update all stark_info field accesses)
│
├── constraints/
│   └── *.py (Task #5: Update any stark_info field accesses)
│
├── witness/
│   └── *.py (Task #5: Update any stark_info field accesses)
│
└── tests/
    └── *.py (Task #6: Update test helpers and imports)
```

### Execution Plan

#### Group A: Data Class Foundation (Execute first)

- [x] **Task #1**: Rename camelCase fields in pol_map.py data classes
  - Folder: `executable-spec/primitives/`
  - File: `pol_map.py`
  - Changes:
    ```python
    # PolMap
    stagePos → stage_pos
    stageId → stage_id
    imPol → im_pol
    commitId → commit_id
    expId → exp_id
    polsMapId → pols_map_id

    # EvMap
    commitId → commit_id
    openingPos → opening_pos

    # ChallengeMap
    stageId → stage_id

    # CustomCommits
    stageWidths → stage_widths
    publicValues → public_values

    # Boundary
    offsetMin → offset_min
    offsetMax → offset_max
    ```
  - Context: These are fundamental data classes used throughout. Must rename here first.

#### Group B: Core Config (Execute after Group A)

- [x] **Task #2**: Simplify StarkInfo and StarkStruct in stark_info.py
  - Folder: `executable-spec/protocol/`
  - File: `stark_info.py`
  - **Remove these StarkInfo fields** (never accessed):
    ```python
    # Expression IDs (parsed but never used)
    friExpId, cExpId

    # Unused maps (parsed but never accessed)
    proofValuesMap, publicsMap, boundaries
    proofValuesSize

    # Proof size estimates (never used)
    maxProofBuffSize, maxProofSize, maxTreeWidth

    # C++ execution parameters (never used)
    maxNBlocks, nrowsPack

    # C++ flags (set but never read)
    verify_constraints, verify, gpu, preallocate, calculateFixedExtended

    # Unused identifiers
    airgroupId, airId
    ```
  - **Remove these parsing methods**:
    ```python
    _parse_publics()  # Remove entirely
    # In _parse_values_maps(): remove proofValuesMap parsing
    # In _parse_opening_points_and_boundaries(): remove boundaries parsing
    ```
  - **Rename StarkStruct fields to snake_case**:
    ```python
    nBits → n_bits
    nBitsExt → n_bits_ext
    nQueries → n_queries
    verificationHashType → verification_hash_type
    friFoldSteps → fri_fold_steps
    merkleTreeArity → merkle_tree_arity
    merkleTreeCustom → merkle_tree_custom
    transcriptArity → transcript_arity
    lastLevelVerification → last_level_verification
    powBits → pow_bits
    hashCommits → hash_commits
    ```
  - **Rename FriFoldStep field**:
    ```python
    domainBits → domain_bits
    ```
  - **Rename StarkInfo fields to snake_case**:
    ```python
    starkStruct → stark_struct
    nPublics → n_publics
    nConstants → n_constants
    nStages → n_stages
    proofSize → proof_size
    customCommits → custom_commits
    cmPolsMap → cm_pols_map
    constPolsMap → const_pols_map
    challengesMap → challenges_map
    airgroupValuesMap → airgroup_values_map
    airValuesMap → air_values_map
    customCommitsMap → custom_commits_map
    evMap → ev_map
    openingPoints → opening_points
    qDeg → q_deg
    qDim → q_dim
    mapSectionsN → map_sections_n
    mapOffsets → map_offsets
    mapTotalN → map_total_n
    mapTotalNCustomCommitsFixed → map_total_n_custom_commits_fixed
    airValuesSize → air_values_size
    airgroupValuesSize → airgroup_values_size
    ```
  - **Update from_json()**: Remove unused parameters (verify_constraints, verify, gpu, preallocate)
  - **Update _parse_stark_struct()**: Use new snake_case field names
  - **Update all internal methods**: Use new field names throughout
  - Context: This is the core refactoring. All downstream files depend on these names.

- [x] **Task #3**: Remove SetupCtx alias and deprecated module
  - Folder: `executable-spec/protocol/`
  - Files: `air_config.py`, `setup_ctx.py`, `__init__.py`
  - In `air_config.py`:
    - Remove line: `SetupCtx = AirConfig`
    - Remove `SetupCtx` from `__all__`
  - **DELETE** `setup_ctx.py` entirely (deprecated module)
  - In `__init__.py`:
    - Remove `SetupCtx` from imports
    - Remove `SetupCtx` from `__all__`
    - Remove comment about deprecated alias
  - Context: Eliminates confusing alias. All code will use AirConfig directly.

#### Group C: Protocol Layer Updates (Execute after Group B, can parallelize within group)

- [x] **Task #4a**: Update verifier.py for new field names
  - File: `executable-spec/protocol/verifier.py`
  - Changes:
    - Replace `SetupCtx` with `AirConfig` in type hints (lines 24, 60)
    - Replace all `stark_info.starkStruct` → `stark_info.stark_struct`
    - Replace all field accesses with snake_case equivalents
    - Example renames:
      ```python
      stark_struct.nBits → stark_struct.n_bits
      stark_struct.nBitsExt → stark_struct.n_bits_ext
      stark_struct.nQueries → stark_struct.n_queries
      stark_struct.friFoldSteps → stark_struct.fri_fold_steps
      stark_struct.merkleTreeArity → stark_struct.merkle_tree_arity
      stark_struct.merkleTreeCustom → stark_struct.merkle_tree_custom
      stark_struct.transcriptArity → stark_struct.transcript_arity
      stark_struct.lastLevelVerification → stark_struct.last_level_verification
      stark_struct.powBits → stark_struct.pow_bits
      stark_struct.hashCommits → stark_struct.hash_commits
      step.domainBits → step.domain_bits
      stark_info.nStages → stark_info.n_stages
      stark_info.nConstants → stark_info.n_constants
      stark_info.challengesMap → stark_info.challenges_map
      stark_info.evMap → stark_info.ev_map
      stark_info.cmPolsMap → stark_info.cm_pols_map
      stark_info.constPolsMap → stark_info.const_pols_map
      stark_info.airgroupValuesMap → stark_info.airgroup_values_map
      stark_info.airValuesMap → stark_info.air_values_map
      stark_info.customCommits → stark_info.custom_commits
      stark_info.mapSectionsN → stark_info.map_sections_n
      stark_info.openingPoints → stark_info.opening_points
      stark_info.qDeg → stark_info.q_deg
      pol.stagePos → pol.stage_pos
      pol.stageId → pol.stage_id
      pol.polsMapId → pol.pols_map_id
      pol.imPol → pol.im_pol
      ev.openingPos → ev.opening_pos
      ev.commitId → ev.commit_id
      ch.stageId → ch.stage_id
      ```
    - Remove `stark_info.verify = True` line (field removed)
  - Context: Verifier is the primary consumer; most field accesses are here.

- [x] **Task #4b**: Update prover.py for new field names
  - File: `executable-spec/protocol/prover.py`
  - Changes:
    - Replace `SetupCtx` with `AirConfig` in type hints and imports
    - Replace all stark_info/stark_struct field accesses with snake_case
    - Same field mapping as Task #4a
  - Context: Prover is the other primary consumer.

- [x] **Task #4c**: Update stages.py for new field names
  - File: `executable-spec/protocol/stages.py`
  - Changes:
    - Remove local `SetupCtx = AirConfig` alias (line 47)
    - Update `AirConfig` import (already exists)
    - Replace all stark_info/stark_struct field accesses with snake_case
  - Context: Stage orchestration uses many config fields.

- [x] **Task #4d**: Update proof.py for new field names
  - File: `executable-spec/protocol/proof.py`
  - Changes:
    - Replace all stark_info/stark_struct field accesses with snake_case
    - Update PolMap field accesses (stage_pos, stage_id, etc.)
  - Context: Proof serialization uses config for layout.

- [x] **Task #4e**: Update fri.py for new field names
  - File: `executable-spec/protocol/fri.py`
  - Changes:
    - Replace all stark_struct field accesses with snake_case
    - `friFoldSteps` → `fri_fold_steps`
    - `domainBits` → `domain_bits`
  - Context: FRI protocol uses StarkStruct parameters.

- [x] **Task #4f**: Update pcs.py for new field names
  - File: `executable-spec/protocol/pcs.py`
  - Changes:
    - Replace all stark_info/stark_struct field accesses with snake_case
  - Context: Polynomial commitment uses config.

- [x] **Task #4g**: Update fri_polynomial.py for new field names
  - File: `executable-spec/protocol/fri_polynomial.py`
  - Changes:
    - Replace all stark_info field accesses with snake_case
    - `evMap` → `ev_map`
    - `cmPolsMap` → `cm_pols_map`
    - `constPolsMap` → `const_pols_map`
    - `openingPoints` → `opening_points`
    - `mapOffsets` → `map_offsets`
  - Context: FRI polynomial computation uses mappings.

- [x] **Task #4h**: Update challenge_utils.py for new field names
  - File: `executable-spec/protocol/challenge_utils.py`
  - Changes:
    - Replace all stark_info/stark_struct field accesses with snake_case
  - Context: Challenge derivation uses config parameters.

- [x] **Task #4i**: Update proof_context.py for new field names
  - File: `executable-spec/protocol/proof_context.py`
  - Changes:
    - Replace all stark_info field accesses with snake_case
  - Context: Buffer management uses memory layout fields.

- [x] **Task #4j**: Update data.py for new field names (if any)
  - File: `executable-spec/protocol/data.py`
  - Changes:
    - Check for and update any stark_info field accesses
  - Context: Prover/verifier data structures may reference config.

#### Group D: Constraint and Witness Modules (Execute after Group B)

- [x] **Task #5**: Update constraint and witness modules
  - Folders: `executable-spec/constraints/`, `executable-spec/witness/`
  - Files to check: `base.py`, `simple_left.py`, `lookup2_12.py`, `permutation1_6.py` in both folders
  - Changes:
    - Search for any stark_info field accesses and update to snake_case
    - Most likely minimal changes needed (these use data.py abstraction)
  - Context: Constraint modules may access config indirectly.

#### Group E: Test Updates (Execute after Groups C and D)

- [x] **Task #6**: Update test files
  - Folder: `executable-spec/tests/`
  - Files: `test_stark_e2e.py`, `test_verifier_e2e.py`, `test_constraint_verifier.py`, `test_stark_info.py`, `__init__.py`
  - Changes:
    - Replace `SetupCtx` with `AirConfig` in all imports and type hints
    - Rename `load_setup_ctx()` helper functions to `load_air_config()`
    - Update any test assertions that check field names
    - In `test_stark_info.py`: Remove tests for deleted fields (friExpId, cExpId, etc.)
    - Update all field access assertions to use snake_case
  - Context: Tests must verify new structure matches expectations.

#### Group F: Verification (Execute after all groups)

- [x] **Task #7**: Run full test suite and verify binary compatibility
  - Commands:
    ```bash
    cd executable-spec
    ./run-tests.sh  # All 164 tests must pass
    ```
  - Verification:
    - All E2E tests produce byte-identical proofs
    - No import errors
    - No runtime attribute errors
  - Context: Final verification that refactoring is complete and correct.

---

## Implementation Workflow

This plan file serves as the authoritative checklist for implementation. When implementing:

### Required Process
1. **Load Plan**: Read this entire plan file before starting
2. **Sync Tasks**: Create TodoWrite tasks matching the checkboxes below
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
- Tasks should be run in parallel, unless there are dependencies, using subtasks, to avoid context bloat.
- **RUN TESTS FREQUENTLY**: After each task group, run `./run-tests.sh` to catch regressions early

### Progress Tracking
The checkboxes above represent the authoritative status of each task. Keep them updated as you work.

---

## Appendix: Complete Field Rename Reference

### StarkStruct (protocol/stark_info.py)
| Old Name | New Name |
|----------|----------|
| nBits | n_bits |
| nBitsExt | n_bits_ext |
| nQueries | n_queries |
| verificationHashType | verification_hash_type |
| friFoldSteps | fri_fold_steps |
| merkleTreeArity | merkle_tree_arity |
| merkleTreeCustom | merkle_tree_custom |
| transcriptArity | transcript_arity |
| lastLevelVerification | last_level_verification |
| powBits | pow_bits |
| hashCommits | hash_commits |

### FriFoldStep (protocol/stark_info.py)
| Old Name | New Name |
|----------|----------|
| domainBits | domain_bits |

### StarkInfo (protocol/stark_info.py)
| Old Name | New Name |
|----------|----------|
| starkStruct | stark_struct |
| nPublics | n_publics |
| nConstants | n_constants |
| nStages | n_stages |
| proofSize | proof_size |
| customCommits | custom_commits |
| cmPolsMap | cm_pols_map |
| constPolsMap | const_pols_map |
| challengesMap | challenges_map |
| airgroupValuesMap | airgroup_values_map |
| airValuesMap | air_values_map |
| customCommitsMap | custom_commits_map |
| evMap | ev_map |
| openingPoints | opening_points |
| qDeg | q_deg |
| qDim | q_dim |
| mapSectionsN | map_sections_n |
| mapOffsets | map_offsets |
| mapTotalN | map_total_n |
| mapTotalNCustomCommitsFixed | map_total_n_custom_commits_fixed |
| airValuesSize | air_values_size |
| airgroupValuesSize | airgroup_values_size |

### PolMap (primitives/pol_map.py)
| Old Name | New Name |
|----------|----------|
| stagePos | stage_pos |
| stageId | stage_id |
| imPol | im_pol |
| commitId | commit_id |
| expId | exp_id |
| polsMapId | pols_map_id |

### EvMap (primitives/pol_map.py)
| Old Name | New Name |
|----------|----------|
| commitId | commit_id |
| openingPos | opening_pos |

### ChallengeMap (primitives/pol_map.py)
| Old Name | New Name |
|----------|----------|
| stageId | stage_id |

### CustomCommits (primitives/pol_map.py)
| Old Name | New Name |
|----------|----------|
| stageWidths | stage_widths |
| publicValues | public_values |

### Boundary (primitives/pol_map.py)
| Old Name | New Name |
|----------|----------|
| offsetMin | offset_min |
| offsetMax | offset_max |

### Fields to REMOVE from StarkInfo
- friExpId
- cExpId
- proofValuesMap
- publicsMap
- boundaries
- proofValuesSize
- maxProofBuffSize
- maxProofSize
- maxTreeWidth
- maxNBlocks
- nrowsPack
- verify_constraints
- verify
- gpu
- preallocate
- calculateFixedExtended
- airgroupId
- airId
