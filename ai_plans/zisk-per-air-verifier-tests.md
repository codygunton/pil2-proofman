# ZisK Per-AIR Verifier Tests Implementation Plan

## Executive Summary

This plan implements individual verifier tests for each of the 12 production ZisK AIRs that have proof fixtures from the Fibonacci(10) guest program. Currently, all 12 AIRs are tested together in a single test file (`test_zisk_verifier_e2e.py`). We will refactor this into:

1. **Individual test files per AIR** - Each AIR gets its own test file for isolation and clarity
2. **Shared test utilities** - Extract common infrastructure (fixture loading, challenge derivation) into reusable modules
3. **Documentation for untested AIRs** - Clear path for adding the 9 AIRs that need new guest programs

**Current State:**
- 12 AIRs tested together in one file (Main, Rom, Mem, RomData, InputData, MemAlign, BinaryExtension, BinaryAdd, Binary, SpecifiedRanges, VirtualTable0, VirtualTable1)
- All fixtures exist in `tests/test-data/zisk/proofs/`
- Verifier infrastructure is functional

**Target State:**
- 12 independent test files, one per AIR
- Reusable test utilities in `tests/zisk_test_utils/`
- Each AIR can be tested independently
- Clear documentation for adding the 9 remaining AIRs

## Goals & Objectives

### Primary Goals
- **Testability**: Each production AIR can be verified independently with `pytest -k test_zisk_main`
- **Maintainability**: Test infrastructure is DRY - common code extracted into utilities
- **Clarity**: Test failures clearly indicate which specific AIR has an issue

### Secondary Objectives
- **Documentation**: Clear guidance for adding tests for the 9 untested AIRs
- **Consistency**: All per-AIR tests follow the same pattern and structure
- **Extensibility**: Easy to add new AIR tests when fixtures become available

## Solution Overview

### Approach

Refactor the monolithic `test_zisk_verifier_e2e.py` into:

1. **Test utilities module** (`tests/zisk_test_utils/`) - Shared infrastructure
   - Fixture loading (starkinfo, verkey, proofs)
   - Challenge derivation
   - Path resolution

2. **Per-AIR test files** (`tests/test_zisk_*_verifier.py`) - Individual AIR tests
   - Each file tests one AIR
   - Uses utilities for common operations
   - Follows pytest conventions

3. **Documentation** (`tests/test-data/zisk/README.md`) - Testing guide
   - Lists all 21 ZisK AIRs
   - Documents which 12 have fixtures
   - Explains how to add tests for remaining 9

### Key Components

1. **ZisK Test Utilities Module**: Centralized fixture loading and challenge derivation
2. **Per-AIR Test Files**: 12 independent test files, one per tested AIR
3. **Documentation**: Clear guide for test coverage and extension

### Architecture Diagram

```
tests/
├── zisk_test_utils/           (NEW: Shared utilities)
│   ├── __init__.py            (Exports: load_air_test_data, derive_challenge)
│   ├── fixture_loader.py      (StarkInfo, verkey, proof loading)
│   └── challenge_utils.py     (Challenge derivation from multi-AIR proofs)
│
├── test_zisk_main_verifier.py      (NEW: Main AIR test)
├── test_zisk_rom_verifier.py       (NEW: Rom AIR test)
├── test_zisk_mem_verifier.py       (NEW: Mem AIR test)
├── test_zisk_romdata_verifier.py   (NEW: RomData AIR test)
├── ... (8 more per-AIR test files)
│
├── test_zisk_verifier_e2e.py       (KEEP: Existing multi-AIR test)
└── test-data/zisk/
    ├── proofs/                     (EXISTING: 12 binary proofs)
    ├── publics.json                (EXISTING: Public inputs)
    ├── proof_values.json           (EXISTING: Proof values)
    └── README.md                   (NEW: Testing documentation)
```

### Expected Outcomes

- Each production AIR can be verified independently with targeted pytest commands
- Test failures clearly indicate which AIR failed without needing to parse multi-AIR logs
- New contributors can easily understand test coverage and add tests for remaining AIRs
- Refactored code eliminates duplication while maintaining existing test coverage

## Implementation Tasks

### CRITICAL IMPLEMENTATION RULES
1. **NO PLACEHOLDER CODE**: All implementations must be production-ready
2. **COMPLETE IMPLEMENTATIONS**: Each task must fully implement its feature
3. **CONTEXT AWARENESS**: Specify imports, exports, and integration points
4. **NO BREAKING CHANGES TO EXISTING TESTS**: Keep `test_zisk_verifier_e2e.py` working

### Visual Dependency Tree

```
tests/
├── zisk_test_utils/
│   ├── __init__.py (Task #0: Package exports)
│   ├── fixture_loader.py (Task #1: Load fixtures from proving key)
│   └── challenge_utils.py (Task #2: Derive global challenge)
│
├── test_zisk_main_verifier.py (Task #3: Main AIR verifier test)
├── test_zisk_rom_verifier.py (Task #3: Rom AIR verifier test)
├── test_zisk_mem_verifier.py (Task #3: Mem AIR verifier test)
├── test_zisk_romdata_verifier.py (Task #3: RomData AIR verifier test)
├── test_zisk_inputdata_verifier.py (Task #3: InputData AIR verifier test)
├── test_zisk_memalign_verifier.py (Task #3: MemAlign AIR verifier test)
├── test_zisk_binaryextension_verifier.py (Task #3: BinaryExtension AIR verifier test)
├── test_zisk_binaryadd_verifier.py (Task #3: BinaryAdd AIR verifier test)
├── test_zisk_binary_verifier.py (Task #3: Binary AIR verifier test)
├── test_zisk_specifiedranges_verifier.py (Task #3: SpecifiedRanges AIR verifier test)
├── test_zisk_virtualtable0_verifier.py (Task #3: VirtualTable0 AIR verifier test)
├── test_zisk_virtualtable1_verifier.py (Task #3: VirtualTable1 AIR verifier test)
│
└── test-data/zisk/
    └── README.md (Task #4: Testing documentation)
```

### Execution Plan

#### Group A: Foundation (Execute in sequence)

- [x] **Task #0**: Create zisk_test_utils package structure
  - Folder: `tests/zisk_test_utils/`
  - File: `__init__.py`
  - Purpose: Package initialization and public API exports
  - Imports: None (this is the root package)
  - Exports:
    ```python
    from .fixture_loader import (
        load_starkinfo,
        load_verkey,
        load_publics,
        load_proof_values,
        load_binary_proof,
        get_proving_key_dir,
    )
    from .challenge_utils import derive_global_challenge_from_proofs
    ```
  - Context: Provides clean import path for test files: `from zisk_test_utils import load_starkinfo, ...`

- [x] **Task #1**: Implement fixture_loader module
  - Folder: `tests/zisk_test_utils/`
  - File: `fixture_loader.py`
  - Purpose: Load starkinfo, verkey, proofs, and public inputs from filesystem
  - Imports:
    ```python
    import json
    from pathlib import Path
    import numpy as np
    from protocol.stark_info import StarkInfo
    from protocol.proof import Proof
    ```
  - Implements:
    ```python
    def get_proving_key_dir() -> Path:
        """Get ZISK_PROVING_KEY directory, checking env var first."""
        # Check ZISK_PROVING_KEY env var, fall back to default
        # Returns: Path("/home/cody/zisk-for-spec/provingKey")

    def load_starkinfo(air_name: str) -> StarkInfo:
        """Load starkinfo.json for given AIR from proving key."""
        # Path: {proving_key}/zisk/Zisk/airs/{air_name}/air/{air_name}.starkinfo.json
        # Returns: StarkInfo.from_json(path)

    def load_verkey(air_name: str) -> list[int]:
        """Load verification key (Merkle root) for given AIR."""
        # Path: {proving_key}/zisk/Zisk/airs/{air_name}/air/{air_name}.verkey.json
        # Returns: List[int] with 4 elements (Poseidon2 hash)

    def load_publics() -> np.ndarray:
        """Load publics.json (shared across all AIRs)."""
        # Path: tests/test-data/zisk/publics.json
        # Returns: numpy array of public inputs

    def load_proof_values() -> dict:
        """Load proof_values.json (shared across all AIRs)."""
        # Path: tests/test-data/zisk/proof_values.json
        # Returns: Dict with stage1 proof values

    def load_binary_proof(proof_stem: str) -> Proof:
        """Load binary proof from test fixtures."""
        # Path: tests/test-data/zisk/proofs/{proof_stem}.proof.bin
        # Returns: Proof.from_bytes_full(binary_data)
    ```
  - Error Handling: Raise FileNotFoundError with clear messages if files missing
  - Context: These functions encapsulate all filesystem access for test fixtures

- [x] **Task #2**: Implement challenge_utils module
  - Folder: `tests/zisk_test_utils/`
  - File: `challenge_utils.py`
  - Purpose: Derive global VADCOP challenge from per-AIR proof data
  - Imports:
    ```python
    from pathlib import Path
    import numpy as np
    from protocol.utils.challenge_utils import derive_global_challenge
    from protocol.stark_info import StarkInfo
    from .fixture_loader import (
        load_starkinfo,
        load_verkey,
        load_publics,
        load_proof_values,
        load_binary_proof,
        get_proving_key_dir,
    )
    ```
  - Implements:
    ```python
    def derive_global_challenge_from_proofs(
        air_names: list[str],
        proof_stems: list[str],
    ) -> list[int]:
        """Derive global VADCOP challenge from all per-AIR proofs.

        Args:
            air_names: List of AIR names (e.g., ["Main", "Rom", "Mem", ...])
            proof_stems: List of proof filenames without extension (e.g., ["Main_0", "Rom_1", ...])

        Returns:
            Global challenge as [c0, c1, c2] (3 Goldilocks field elements)

        Process:
            1. Load publics and proof_values (shared across AIRs)
            2. For each AIR:
               - Load starkinfo, verkey, binary proof
               - Extract root1 from proof
               - Extract air_values_stage1 from proof (if present)
               - Call derive_global_challenge() with lattice_size=368
            3. Accumulate all per-AIR contributions (element-wise addition mod p)
            4. Final hash produces 3-element global challenge
        """
        # Implementation matches test_zisk_verifier_e2e.py:_derive_global_challenge()
        # Reference: C++ challenge_accumulation.rs
    ```
  - Context: This is the complex VADCOP challenge derivation logic, extracted for reuse
  - Note: Should match existing implementation in test_zisk_verifier_e2e.py exactly

#### Group B: Per-AIR Test Files (Execute all in parallel after Group A)

**Pattern for All 12 Test Files:**

Each test file follows this exact structure:

```python
"""Verifier E2E test for {AIR_NAME} AIR using GPU-generated proof from Fibonacci(10)."""
import pytest
from zisk_test_utils import (
    load_starkinfo,
    load_verkey,
    load_publics,
    load_binary_proof,
    derive_global_challenge_from_proofs,
)
from protocol.verifier import stark_verify


# List of all 12 AIRs with their proof stems (instance IDs may vary)
ZISK_AIR_PARAMS = [
    ("Main", "Main_0"),
    ("Rom", "Rom_1"),
    ("Mem", "Mem_2"),
    # ... (full list of 12)
]


def test_{air_name_lower}_verifier():
    """Verify {AIR_NAME} AIR proof from Fibonacci(10) guest program."""
    air_name = "{AIR_NAME}"
    proof_stem = "{PROOF_STEM}"  # e.g., "Main_0"

    # Derive global VADCOP challenge from all 12 per-AIR proofs
    air_names = [name for name, _ in ZISK_AIR_PARAMS]
    proof_stems = [stem for _, stem in ZISK_AIR_PARAMS]
    global_challenge = derive_global_challenge_from_proofs(air_names, proof_stems)

    # Load AIR-specific fixtures
    starkinfo = load_starkinfo(air_name)
    verkey = load_verkey(air_name)
    publics = load_publics()
    proof = load_binary_proof(proof_stem)

    # Verify proof
    result = stark_verify(
        proof=proof,
        starkinfo=starkinfo,
        const_root=verkey,
        global_challenge=global_challenge,
        publics=publics,
    )

    assert result is True, f"{air_name} AIR proof verification failed"
```

**Specific Tasks:**

- [x] **Task #3-A**: Create test_zisk_main_verifier.py
  - File: `tests/test_zisk_main_verifier.py`
  - AIR Name: "Main"
  - Proof Stem: "Main_0"
  - Description: Main execution control AIR (instruction dispatch)

- [x] **Task #3-B**: Create test_zisk_rom_verifier.py
  - File: `tests/test_zisk_rom_verifier.py`
  - AIR Name: "Rom"
  - Proof Stem: "Rom_1"
  - Description: ROM data AIR (read-only memory)

- [x] **Task #3-C**: Create test_zisk_mem_verifier.py
  - File: `tests/test_zisk_mem_verifier.py`
  - AIR Name: "Mem"
  - Proof Stem: "Mem_2"
  - Description: Main memory AIR (reads/writes)

- [x] **Task #3-D**: Create test_zisk_romdata_verifier.py
  - File: `tests/test_zisk_romdata_verifier.py`
  - AIR Name: "RomData"
  - Proof Stem: "RomData_3"
  - Description: ROM data segment AIR

- [x] **Task #3-E**: Create test_zisk_inputdata_verifier.py
  - File: `tests/test_zisk_inputdata_verifier.py`
  - AIR Name: "InputData"
  - Proof Stem: "InputData_4"
  - Description: Input data AIR (stdin/public inputs)

- [x] **Task #3-F**: Create test_zisk_memalign_verifier.py
  - File: `tests/test_zisk_memalign_verifier.py`
  - AIR Name: "MemAlign"
  - Proof Stem: "MemAlign_5"
  - Description: Memory alignment AIR (aligned memory operations)

- [x] **Task #3-G**: Create test_zisk_binaryextension_verifier.py
  - File: `tests/test_zisk_binaryextension_verifier.py`
  - AIR Name: "BinaryExtension"
  - Proof Stem: "BinaryExtension_6"
  - Description: Binary extension AIR (extended binary operations)

- [x] **Task #3-H**: Create test_zisk_binaryadd_verifier.py
  - File: `tests/test_zisk_binaryadd_verifier.py`
  - AIR Name: "BinaryAdd"
  - Proof Stem: "BinaryAdd_7"
  - Description: Binary addition AIR (add/subtract operations)

- [x] **Task #3-I**: Create test_zisk_binary_verifier.py
  - File: `tests/test_zisk_binary_verifier.py`
  - AIR Name: "Binary"
  - Proof Stem: "Binary_8"
  - Description: Binary operations AIR (AND/OR/XOR/comparisons)

- [x] **Task #3-J**: Create test_zisk_specifiedranges_verifier.py
  - File: `tests/test_zisk_specifiedranges_verifier.py`
  - AIR Name: "SpecifiedRanges"
  - Proof Stem: "SpecifiedRanges_9"
  - Description: Range constraint AIR (specified range checks)

- [x] **Task #3-K**: Create test_zisk_virtualtable0_verifier.py
  - File: `tests/test_zisk_virtualtable0_verifier.py`
  - AIR Name: "VirtualTable0"
  - Proof Stem: "VirtualTable0_10"
  - Description: Virtual table 0 AIR (table lookups)

- [x] **Task #3-L**: Create test_zisk_virtualtable1_verifier.py
  - File: `tests/test_zisk_virtualtable1_verifier.py`
  - AIR Name: "VirtualTable1"
  - Proof Stem: "VirtualTable1_11"
  - Description: Virtual table 1 AIR (table lookups)

#### Group C: Documentation (Execute in parallel with Group B)

- [x] **Task #4**: Create testing documentation
  - File: `tests/test-data/zisk/README.md`
  - Purpose: Document test coverage, fixture requirements, and how to add tests
  - Content:
    ```markdown
    # ZisK AIR Test Fixtures

    This directory contains test fixtures for ZisK AIR verification tests.

    ## Test Coverage Status

    ### Tested AIRs (12/21) - Have Fixtures

    Fixtures generated from Fibonacci(10) guest program on GPU prover:

    | # | AIR Name | Proof Fixture | Category | Test File |
    |---|----------|---------------|----------|-----------|
    | 1 | Main | Main_0.proof.bin | Control | test_zisk_main_verifier.py |
    | 2 | Rom | Rom_1.proof.bin | Memory | test_zisk_rom_verifier.py |
    | 3 | Mem | Mem_2.proof.bin | Memory | test_zisk_mem_verifier.py |
    | 4 | RomData | RomData_3.proof.bin | Memory | test_zisk_romdata_verifier.py |
    | 5 | InputData | InputData_4.proof.bin | Data | test_zisk_inputdata_verifier.py |
    | 6 | MemAlign | MemAlign_5.proof.bin | Memory | test_zisk_memalign_verifier.py |
    | 7 | BinaryExtension | BinaryExtension_6.proof.bin | Computation | test_zisk_binaryextension_verifier.py |
    | 8 | BinaryAdd | BinaryAdd_7.proof.bin | Computation | test_zisk_binaryadd_verifier.py |
    | 9 | Binary | Binary_8.proof.bin | Computation | test_zisk_binary_verifier.py |
    | 10 | SpecifiedRanges | SpecifiedRanges_9.proof.bin | Utility | test_zisk_specifiedranges_verifier.py |
    | 11 | VirtualTable0 | VirtualTable0_10.proof.bin | Utility | test_zisk_virtualtable0_verifier.py |
    | 12 | VirtualTable1 | VirtualTable1_11.proof.bin | Utility | test_zisk_virtualtable1_verifier.py |

    ### Untested AIRs (9/21) - Need Fixtures

    These AIRs are not exercised by Fibonacci guest and require custom test programs:

    | # | AIR Name | Category | Required Guest Program |
    |---|----------|----------|------------------------|
    | 13 | MemAlignByte | Memory | Program with byte-aligned memory ops |
    | 14 | MemAlignReadByte | Memory | Program with byte read operations |
    | 15 | MemAlignWriteByte | Memory | Program with byte write operations |
    | 16 | Arith | Computation | Program with arithmetic operations |
    | 17 | ArithEq | Computation | Program with field arithmetic (secp256k1) |
    | 18 | ArithEq384 | Computation | Program with 384-bit arithmetic (BLS12-381) |
    | 19 | Add256 | Computation | Program with 256-bit addition |
    | 20 | Keccakf | Cryptography | Program calling Keccak-f permutation |
    | 21 | Sha256f | Cryptography | Program calling SHA256 compression |

    ## Fixture Files

    - `proofs/*.proof.bin` - Binary proof files (one per AIR instance)
    - `publics.json` - Public inputs (shared across all AIRs)
    - `proof_values.json` - Stage 1 proof values (shared across all AIRs)

    ## Generating New Fixtures

    To generate fixtures for untested AIRs:

    1. **Create guest program** that exercises the target AIR
       - Example: `sha256_guest.rs` for Sha256f AIR
       - Compile to ELF with `cargo-zisk build`

    2. **Run proof generation**:
       ```bash
       cd /path/to/pil2-proofman
       export ZISK_PROVING_KEY=/path/to/zisk-for-spec/provingKey
       ./generate-zisk-test-vectors.sh
       ```

    3. **Verify fixtures created** in `tests/test-data/zisk/proofs/`

    4. **Create test file** following the pattern in existing `test_zisk_*_verifier.py` files

    ## Running Tests

    ```bash
    # Run all ZisK AIR tests
    pytest tests/test_zisk_*_verifier.py

    # Run specific AIR test
    pytest tests/test_zisk_main_verifier.py

    # Run with verbose output
    pytest tests/test_zisk_rom_verifier.py -v
    ```

    ## Test Infrastructure

    - `tests/zisk_test_utils/` - Shared utilities for fixture loading and challenge derivation
    - `tests/test_zisk_verifier_e2e.py` - Original multi-AIR test (kept for regression)
    ```
  - Context: Provides complete reference for test coverage and how to extend

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
- Group A tasks must complete before Group B (fixture loading needed first)
- Group B and C tasks can run in parallel (independent)

### Progress Tracking
The checkboxes above represent the authoritative status of each task. Keep them updated as you work.

## Testing the Implementation

After completing all tasks, verify:

1. **Individual tests work**:
   ```bash
   pytest tests/test_zisk_main_verifier.py -v
   pytest tests/test_zisk_rom_verifier.py -v
   # ... test each file individually
   ```

2. **All 12 AIR tests pass together**:
   ```bash
   pytest tests/test_zisk_*_verifier.py -v
   ```

3. **Original E2E test still works**:
   ```bash
   pytest tests/test_zisk_verifier_e2e.py -v
   ```

4. **Utilities are properly imported**:
   ```bash
   python -c "from zisk_test_utils import load_starkinfo, derive_global_challenge_from_proofs; print('OK')"
   ```

## Success Criteria

- [x] All 12 per-AIR test files created and passing
- [x] Test utilities module properly structured and importable
- [x] Each AIR can be tested independently with targeted pytest commands
- [x] Original `test_zisk_verifier_e2e.py` still passes (no regression)
- [x] Documentation clearly lists tested vs untested AIRs
- [x] No code duplication between test files (utilities handle common logic)
