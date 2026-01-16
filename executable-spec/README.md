# Executable Specification

A Python implementation of the STARK proving system from pil2-proofman. This serves as an executable specification for cross-validating the C++ implementation.

## Directory Structure

```
executable-spec/
├── Core Implementation
│   ├── field.py              # Goldilocks field arithmetic
│   ├── ntt.py                # NTT/INTT polynomial operations
│   ├── transcript.py         # Fiat-Shamir transcript
│   ├── merkle_tree.py        # Poseidon2 Merkle trees
│   ├── fri.py                # FRI folding and queries
│   ├── fri_pcs.py            # FRI polynomial commitment scheme
│   │
│   ├── stark_info.py         # STARK configuration parser
│   ├── pol_map.py            # Polynomial mapping structures
│   ├── setup_ctx.py          # Setup context and ProverHelpers
│   ├── steps_params.py       # Parameter container
│   ├── expressions_bin.py    # Expression binary parser
│   ├── expressions.py        # Expression evaluation engine
│   ├── starks.py             # Starks orchestrator class
│   ├── gen_proof.py          # Top-level prover
│   ├── stark_verify.py       # Top-level verifier
│   └── proof.py              # Proof data structures
│
├── Poseidon2 FFI
│   └── poseidon2-ffi/        # Rust FFI for Poseidon2
│
├── Tests (164 total)
│   ├── test_fri.py           # FRI golden value validation (vs C++)
│   ├── test_stark_e2e.py     # STARK golden value validation (vs C++)
│   ├── test_ntt.py           # NTT mathematical properties
│   ├── test_stark_info.py    # Config parsing validation
│   ├── test_expressions_bin.py   # Binary format parsing
│   └── test_proof.py         # JSON serialization/loading
│
└── test-data/                # Golden test vectors (gitignored)
    ├── simple-left.json
    ├── lookup2-12.json
    └── permutation1-6.json
```

## Setup

```bash
cd executable-spec
uv sync
cd poseidon2-ffi && maturin develop && cd ..
```

Generate test vectors (from repo root):
```bash
./setup.sh && ./generate-test-vectors.sh
```

## Running Tests

```bash
uv run python -m pytest -v              # All tests
uv run python -m pytest test_fri.py -v  # FRI validation
uv run python -m pytest test_stark_e2e.py -v  # STARK e2e validation
```

## Supported AIRs

| AIR | Rows | Description |
|-----|------|-------------|
| SimpleLeft | 8 | Basic constraints, no FRI folding |
| Lookup2_12 | 4096 | Complex lookups, full FRI folding |
| Permutation1_6 | 64 | Permutation constraints, FRI folding |
