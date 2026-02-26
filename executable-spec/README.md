# Executable Specification

A Python implementation of the STARK proving system from pil2-proofman. This serves as an executable specification for cross-validating the C++ implementation.

## Directory Structure

```
executable-spec/
├── constraints/                 # Per-AIR constraint polynomial modules
│   ├── base.py                 # ConstraintModule ABC, ProverConstraintContext
│   ├── simple_left.py          # SimpleLeft constraint implementation
│   ├── lookup2_12.py           # Lookup2_12 constraint implementation
│   └── permutation1_6.py       # Permutation1_6 constraint implementation
│
├── witness/                     # Per-AIR witness generation modules
│   ├── base.py                 # WitnessModule ABC
│   ├── simple_left.py          # SimpleLeft witness (im_cluster, gsum)
│   ├── lookup2_12.py           # Lookup2_12 witness
│   └── permutation1_6.py       # Permutation1_6 witness
│
├── protocol/                    # Core STARK protocol implementation
│   ├── prover.py               # Top-level proof generation (gen_proof)
│   ├── verifier.py             # Top-level verification (stark_verify)
│   ├── stages.py               # Stage computations (PolynomialCommitter class)
│   ├── fri.py                  # FRI folding and query generation
│   ├── pcs.py                  # FRI polynomial commitment scheme
│   ├── fri_polynomial.py       # FRI polynomial computation
│   ├── stark_info.py           # STARK configuration parser
│   ├── air_config.py           # AIR config and ProverHelpers
│   ├── data.py                 # ProverData/VerifierData for modules
│   └── proof.py                # Proof data structures
│
├── primitives/                  # Low-level cryptographic primitives
│   ├── field.py                # Goldilocks field (p = 2^64 - 2^32 + 1)
│   ├── ntt.py                  # NTT/INTT polynomial operations
│   ├── transcript.py           # Fiat-Shamir transcript (Poseidon2)
│   ├── merkle_tree.py          # Poseidon2 Merkle trees
│   └── poseidon2-ffi/          # Rust FFI for Poseidon2 hash
│
├── tests/                       # Test suite (164 tests)
│   ├── test_stark_e2e.py       # Full STARK proof vs C++ golden values
│   ├── test_verifier_e2e.py    # Verifier vs C++ proofs
│   ├── test_fri.py             # FRI folding vs C++ golden values
│   ├── test_constraint_*.py    # Constraint module tests
│   ├── test_*_witness.py       # Witness module tests
│   ├── test_stark_info.py      # Config parsing validation
│   ├── test_proof.py           # Proof JSON serialization
│   ├── test_ntt.py             # NTT mathematical properties
│   └── test-data/              # Golden test vectors (gitignored)
│
├── setup.sh                     # Environment setup (uv sync + poseidon2-ffi)
├── run-tests.sh                 # Test runner with filters
└── pyproject.toml
```

## Reading Guide

### Start Here: The Prover Flow

1. **`protocol/prover.py`** - Entry point. `gen_proof()` orchestrates the full proving flow
2. **`protocol/stages.py`** - `PolynomialCommitter` class implements each proving stage:
   - `commitStage()` - Commit witness polynomials
   - `calculateQuotientPolynomial()` - Compute Q polynomial
   - `calculateFRIPolynomial()` - Compute FRI polynomial
   - `computeFRIFolding()` / `computeFRIQueries()` - FRI protocol

### Key Abstractions

| File | Purpose |
|------|---------|
| `constraints/*.py` | Per-AIR constraint polynomial evaluation |
| `witness/*.py` | Per-AIR witness generation (im_cluster, gsum) |
| `protocol/pcs.py` | FRI polynomial commitment scheme |
| `protocol/air_config.py` | `AirConfig` bundles config, `ProverHelpers` manages buffers |
| `protocol/data.py` | `ProverData`/`VerifierData` for constraint/witness modules |

### Data Model

Protocol internals (Merkle trees, NTT, FRI) work directly with numpy arrays.
Constraint and witness modules use **ProverData** / **VerifierData** dict-based
storage with named columns, enabling readable AIR-specific code.

### Primitives

| File | Purpose |
|------|---------|
| `primitives/field.py` | `FF` class - Goldilocks field with cubic extension |
| `primitives/ntt.py` | `NTT` class - Forward/inverse NTT, coset operations |
| `primitives/transcript.py` | `Transcript` class - Fiat-Shamir with Poseidon2 |
| `primitives/merkle_tree.py` | `MerkleTree` class - Poseidon2 Merkle commitments |

## Setup

```bash
cd executable-spec
./setup.sh                # Install deps + build poseidon2-ffi
```

Generate test vectors (from repo root, requires pil2-compiler and pil2-proofman-js):
```bash
./setup.sh && ./generate-test-vectors.sh
```

## Running Tests

```bash
./run-tests.sh                # all 164 tests
./run-tests.sh e2e            # E2E tests (prover + verifier vs C++)
./run-tests.sh prover         # prover E2E only
./run-tests.sh verifier       # verifier E2E only
./run-tests.sh fri            # FRI protocol tests
./run-tests.sh constraints    # constraint module tests
./run-tests.sh witness        # witness module tests
./run-tests.sh simple         # SimpleLeft AIR tests
./run-tests.sh lookup         # Lookup2_12 AIR tests
./run-tests.sh permutation    # Permutation1_6 AIR tests
./run-tests.sh unit           # unit tests (non-E2E, fast)
./run-tests.sh -k "pattern"   # pytest -k filter
```

## Supported AIRs

| AIR | Rows | FRI Folding | Description |
|-----|------|-------------|-------------|
| SimpleLeft | 8 | No | Basic constraints, part of Simple pilout |
| SimpleRight | 8 | No | Permutation + lookup proves, part of Simple pilout |
| U8Air | 128 | No | U8 range-check multiplicity table, part of Simple pilout |
| U16Air | 16384 | No | U16 range-check multiplicity table, part of Simple pilout |
| SpecifiedRanges | 64 | No | Custom range-check multiplicities, part of Simple pilout |
| Lookup2_12 | 4096 | Yes | Complex lookup operations |
| Permutation1_6 | 64 | Yes | Permutation constraints |
