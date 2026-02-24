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

**Always use `-n auto` for parallel execution** (8.5x faster - 2 minutes vs 17 minutes):

```bash
# Run all ZisK AIR tests (recommended - parallel execution)
pytest tests/test_zisk_*_verifier.py -n auto -v

# Run specific AIR test
pytest tests/test_zisk_main_verifier.py -n auto -v

# Run multiple specific AIRs
pytest tests/test_zisk_main_verifier.py tests/test_zisk_rom_verifier.py tests/test_zisk_mem_verifier.py -n auto -v

# Sequential execution (slower, for debugging only)
pytest tests/test_zisk_*_verifier.py -v
```

**Performance:**
- Parallel (`-n auto`): ~2 minutes for all 12 AIRs
- Sequential: ~17 minutes for all 12 AIRs

## Test Infrastructure

- `tests/zisk_test_utils/` - Shared utilities for fixture loading and challenge derivation
  - `fixture_loader.py` - Load starkinfo, verkey, proofs, publics
  - `challenge_utils.py` - Derive VADCOP global challenge from per-AIR proofs
  - `GLOBAL_CHALLENGE` - Pre-computed global challenge (computed once at import time)
- `tests/test_zisk_verifier_e2e.py` - Original multi-AIR test (kept for regression)

**Performance optimization:** The global challenge is computed once when the test module is imported, then shared across all tests. This eliminates duplicate proof loading (12 loads instead of 144).

## Test Pattern

Each per-AIR test follows this structure:

```python
from tests.zisk_test_utils import (
    load_air_config,
    load_verkey,
    load_publics,
    load_binary_proof,
    GLOBAL_CHALLENGE,  # Pre-computed, shared across all tests
)
from protocol.verifier import stark_verify

def test_<air_name>_verifier():
    """Verify <AIR_NAME> AIR proof from Fibonacci(10) guest program."""
    air_name = "<AIR_NAME>"
    proof_stem = "<AIR_NAME>_<ID>"

    # Load AIR-specific fixtures
    air_config = load_air_config(air_name)
    verkey = load_verkey(air_name)
    publics = load_publics()
    proof = load_binary_proof(proof_stem, air_config.stark_info)

    # Verify proof (using shared global challenge)
    result = stark_verify(
        proof=proof,
        air_config=air_config,
        verkey=verkey,
        global_challenge=GLOBAL_CHALLENGE,
        publics=publics,
    )

    assert result is True, f"{air_name} AIR proof verification failed"
```

## Adding Tests for New AIRs

When you generate fixtures for one of the untested AIRs:

1. **Copy an existing test file** as a template (e.g., `test_zisk_main_verifier.py`)
2. **Update the air_name and proof_stem** in the test function
3. **Update the function name** to match (e.g., `test_keccakf_verifier`)
4. **Update the docstring** to describe the AIR
5. **Add the AIR to ZISK_AIR_PARAMS** in `tests/zisk_test_utils/__init__.py`
6. **Run the test** to verify it passes

Example for adding Keccakf AIR test:

```bash
# After generating Keccakf fixtures
cp tests/test_zisk_main_verifier.py tests/test_zisk_keccakf_verifier.py

# Edit tests/test_zisk_keccakf_verifier.py:
# - Change air_name = "Keccakf"
# - Change proof_stem = "Keccakf_<ID>"  (check actual ID in proofs/ directory)
# - Change function name to test_keccakf_verifier()
# - Update docstring

# Edit tests/zisk_test_utils/__init__.py:
# - Add ("Keccakf", "Keccakf_<ID>") to ZISK_AIR_PARAMS list

# Run the test with parallel execution
pytest tests/test_zisk_keccakf_verifier.py -n auto -v
```

**Important:** When adding a new AIR, you must update `ZISK_AIR_PARAMS` in `tests/zisk_test_utils/__init__.py` so the global challenge includes the new AIR's proof.
