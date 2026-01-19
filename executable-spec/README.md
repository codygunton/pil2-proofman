# Executable Specification

A Python implementation of the STARK proving system from pil2-proofman. This serves as an executable specification for cross-validating the C++ implementation.

## Directory Structure

```
executable-spec/
├── protocol/                    # Core STARK protocol implementation
│   ├── prover.py               # Top-level proof generation (gen_proof)
│   ├── verifier.py             # Top-level verification (stark_verify)
│   ├── stages.py               # Stage computations (Starks class)
│   ├── fri.py                  # FRI folding and query generation
│   ├── pcs.py                  # FRI polynomial commitment scheme
│   ├── expression_evaluator.py # Constraint/expression evaluation engine
│   ├── witness_generation.py   # Witness polynomial computation
│   ├── stark_info.py           # STARK configuration parser
│   ├── setup_ctx.py            # Setup context and ProverHelpers
│   ├── steps_params.py         # Runtime parameter container
│   ├── expressions_bin.py      # Expression bytecode parser
│   └── proof.py                # Proof data structures
│
├── primitives/                  # Low-level cryptographic primitives
│   ├── field.py                # Goldilocks field (p = 2^64 - 2^32 + 1)
│   ├── ntt.py                  # NTT/INTT polynomial operations
│   ├── transcript.py           # Fiat-Shamir transcript (Poseidon2)
│   ├── merkle_tree.py          # Poseidon2 Merkle trees
│   ├── pol_map.py              # Polynomial mapping structures
│   └── poseidon2-ffi/          # Rust FFI for Poseidon2 hash
│
├── tests/                       # Test suite (121 tests)
│   ├── test_stark_e2e.py       # Full STARK proof vs C++ golden values
│   ├── test_fri.py             # FRI folding vs C++ golden values
│   ├── test_ntt.py             # NTT mathematical properties
│   ├── test_stark_info.py      # Config parsing validation
│   ├── test_proof.py           # Proof JSON serialization
│   └── test-data/              # Golden test vectors (gitignored)
│
└── pyproject.toml
```

## Reading Guide

### Start Here: The Prover Flow

1. **`protocol/prover.py`** - Entry point. `gen_proof()` orchestrates the full proving flow
2. **`protocol/stages.py`** - `Starks` class implements each proving stage:
   - `commitStage()` - Commit witness polynomials
   - `calculateQuotientPolynomial()` - Compute Q polynomial
   - `calculateFRIPolynomial()` - Compute FRI polynomial
   - `computeFRIFolding()` / `computeFRIQueries()` - FRI protocol

### Key Abstractions

| File | Purpose |
|------|---------|
| `protocol/expression_evaluator.py` | Evaluates constraint expressions from bytecode |
| `protocol/pcs.py` | FRI polynomial commitment scheme |
| `protocol/setup_ctx.py` | `SetupCtx` bundles config, `ProverHelpers` manages buffers |
| `protocol/steps_params.py` | `StepsParams` holds runtime state (trace, challenges, evals) |

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
uv sync
cd primitives/poseidon2-ffi && maturin develop && cd ../..
```

Generate test vectors (from repo root):
```bash
./setup.sh && ./generate-test-vectors.sh
```

## Running Tests

From repo root:
```bash
./run-all-tests.sh              # Full test suite (121 tests)
./run-e2e-tests.sh              # E2E tests only (vs C++ golden values)
```

From executable-spec/:
```bash
uv run python -m pytest tests/ -v                    # All tests
uv run python -m pytest tests/test_fri.py -v         # FRI validation
uv run python -m pytest tests/test_stark_e2e.py -v   # STARK e2e validation
```

## Supported AIRs

| AIR | Rows | FRI Folding | Description |
|-----|------|-------------|-------------|
| SimpleLeft | 8 | No | Basic constraints only |
| Lookup2_12 | 4096 | Yes | Complex lookup operations |
| Permutation1_6 | 64 | Yes | Permutation constraints |
