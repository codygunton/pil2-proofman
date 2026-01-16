## ⚠️ Disclaimer: Software Under Development ⚠️

This software is currently under **active development** and has not been audited for security or correctness.

Please be aware of the following:
* The software is **not fully tested**.
* **Do not use it in production environments** until a stable production release is available. 🚧
* Additional functionalities and optimizations **are planned for future releases**.
* Future updates may introduce breaking **backward compatible changes** as development progresses.

If you encounter any errors or unexpected behavior, please report them. Your feedback is highly appreciated in improving the software.

# Proofs Manager

The Proof Manager is an adaptable Proof Manager designed to assist in the creation of proofs from a PIL2 pilout-formatted file. It is designed to be used in conjunction with the [PIL2](https://github.com/0xPolygonHermez/pilcom) compiler and proofman-js [pil2-proofman-js](https://github.com/0xPolygonHermez/pil2-proofman-js) to generate the setup.

# Python Executable Spec

A complete Python executable specification of the STARK proving system in `executable-spec/`. This provides a readable reference implementation for cross-validating the C++ prover.

### Components

| Module | Description |
|--------|-------------|
| `stark_info.py` | STARK configuration parser |
| `setup_ctx.py` | Setup context and prover helpers |
| `ntt.py` | NTT/INTT polynomial operations |
| `expressions.py` | Constraint expression evaluation |
| `starks.py` | Proof stage orchestrator |
| `gen_proof.py` | Top-level prover |
| `stark_verify.py` | Top-level verifier |
| `fri.py`, `fri_pcs.py` | FRI polynomial commitment scheme |

### Running Python Tests

```bash
cd executable-spec
uv sync                            # install dependencies
uv run python -m pytest -v         # run all 269 tests
```

Test categories:
```bash
uv run python -m pytest test_fri.py -v              # FRI tests (22)
uv run python -m pytest test_ntt.py -v              # NTT tests (41)
uv run python -m pytest test_stark_info.py -v       # Config tests (22)
uv run python -m pytest test_starks.py -v           # Orchestrator tests (18)
uv run python -m pytest test_stark_integration.py -v # Integration tests (27)
```

See `executable-spec/README.md` for full documentation.

## Rust/C++ Tests

Three test suites validate the C++ implementation:

- **pinning** - Validates C++ prover output is deterministic (SHA256 checksums)
- **fri** - Validates C++ FRI values match golden vectors
- **spec** - Validates Python produces identical output to C++

```bash
cargo test -p pinning              # all pinning tests
cargo test -p pinning pinning      # proof file checksums
cargo test -p pinning fri          # FRI output values
cargo test -p pinning spec         # Python executable spec
cargo test -p pinning simple       # simple AIR only
cargo test -p pinning lookup       # lookup AIR only
```

Prerequisites: `./setup.sh`

Regenerate FRI golden values: `./generate-fri-vectors.sh`

## License

All crates in this monorepo are licensed under one of the following options:

- The Apache License, Version 2.0 (see LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)

- The MIT License (see LICENSE-MIT or http://opensource.org/licenses/MIT)

You may choose either license at your discretion.

## Acknowledgements

ProofMan is a collaborative effort made possible by the contributions of researchers, engineers, and developers dedicated to advancing zero-knowledge technology.

We extend our gratitude to the [Polygon zkEVM](https://github.com/0xpolygonhermez) and [Plonky3](https://github.com/Plonky3/Plonky3) teams for their foundational work in zero-knowledge proving systems.

Additionally, we acknowledge the efforts of the open-source cryptography and ZK research communities, whose insights and contributions continue to shape the evolution of efficient and scalable zero-knowledge technologies.

🚀 Special thanks to all contributors who have helped develop, refine, and improve ProofMan!
