# Lean 4 STARK Verifier

A Lean 4 implementation of the PIL2 FRI-STARK verifier for the Zisk zkVM.
Faithfully translates the [Python executable spec](../executable-spec/) into
Lean, producing a typechecked specification that verifies real proofs from
the production C++/GPU prover.

## Status

All 12 per-AIR Zisk proofs and the VADCOP final aggregated proof verify
successfully against GPU-generated fixtures from `zisk-for-spec` v0.15.0
(Fibonacci(10) guest program).

## Structure

```
lean-verifier/
├── Primitives/              # Field arithmetic, hashing, Merkle trees
│   ├── Field.lean           # Goldilocks GF(p) and cubic extension GF3
│   ├── Transcript.lean      # Fiat-Shamir transcript (Poseidon2 sponge)
│   ├── MerkleVerifier.lean  # Merkle proof verification
│   ├── Polynomial.lean      # Polynomial operations (INTT, evaluation)
│   └── PolMap.lean          # PolynomialId, EvalKey, EvMap types
│
├── Protocol/                # STARK verification protocol
│   ├── Verifier.lean        # Main entry point: starkVerify (8 checks)
│   ├── FRI.lean             # FRI folding verification
│   ├── StarkInfo.lean       # StarkInfo JSON parser
│   ├── Proof.lean           # Binary proof deserialization
│   ├── Data.lean            # VerifierData (evals, challenges, values)
│   ├── AirConfig.lean       # AIR configuration helpers
│   └── ChallengeUtils.lean  # VADCOP global challenge derivation
│
├── FFI/                     # Foreign function interface (Rust staticlibs)
│   ├── Poseidon2.lean       # Poseidon2 hash bindings
│   └── Constraints.lean     # Constraint bytecode evaluator bindings
│
├── ffi/
│   ├── poseidon2/           # Rust crate: Poseidon2 over Goldilocks
│   └── constraints/         # Rust crate: bytecode constraint evaluator
│
├── Tests/                   # LSpec test suite
│   ├── TestField.lean       # GF/GF3 arithmetic
│   ├── TestTranscript.lean  # Fiat-Shamir transcript
│   ├── TestPoseidon2.lean   # Poseidon2 FFI
│   ├── TestStarkInfo.lean   # StarkInfo JSON parsing
│   ├── TestProof.lean       # Binary proof parsing
│   ├── TestData.lean        # VerifierData construction
│   ├── TestMerkle.lean      # Merkle tree verification
│   ├── TestPolynomial.lean  # Polynomial operations
│   ├── TestFRI.lean         # FRI folding
│   ├── TestVerifier.lean    # Full verifier (SimpleLeft AIR)
│   ├── TestZiskVerifier.lean    # Zisk per-AIR E2E (12 AIRs)
│   └── TestVadcopFinal.lean     # VADCOP final proof E2E
│
└── Tests/test-data/         # Bundled test fixtures
    ├── SimpleLeft.*         # SimpleLeft AIR proof + config
    └── zisk/                # Zisk fixtures (12 AIR proofs + VADCOP final)
```

## Prerequisites

- [Lean 4](https://leanprover.github.io/lean4/doc/) v4.27.0 (pinned in `lean-toolchain`)
- [Rust](https://rustup.rs/) toolchain (for FFI crates)
- [Lake](https://github.com/leanprover/lake) (ships with Lean)

## Building

```bash
# Build FFI static libraries (done automatically by Lake)
cd ffi/poseidon2 && cargo build --release
cd ffi/constraints && cargo build --release

# Build the Lean project
lake build
```

Lake is configured to automatically build the Rust FFI crates via
`extern_lib` declarations in `lakefile.lean`.

## Running Tests

```bash
# Run all tests
lake build test-all && .lake/build/bin/test-all

# Run individual test suites
lake build test-field && .lake/build/bin/test-field
lake build test-verifier && .lake/build/bin/test-verifier
lake build test-zisk-verifier && .lake/build/bin/test-zisk-verifier
lake build test-vadcop-final && .lake/build/bin/test-vadcop-final
```

## Verification Checks

The verifier (`Protocol.Verifier.starkVerify`) performs eight checks:

1. **Q(xi) = C(xi)** -- quotient polynomial matches constraint evaluation
2. **FRI consistency** -- polynomial evaluations match commitments at query points
3. **Stage Merkle trees** -- committed polynomial openings are valid
4. **Constant Merkle tree** -- constant polynomial openings are valid
5. **Custom commit Merkle trees** -- custom commitment openings are valid
6. **FRI layer Merkle trees** -- FRI intermediate layer openings are valid
7. **FRI folding** -- each FRI folding step is computed correctly
8. **Final polynomial degree** -- FRI final polynomial respects degree bound

## FFI Dependencies

Two operations use Rust FFI rather than pure Lean:

- **Poseidon2** (`ffi/poseidon2/`): The Poseidon2 hash over Goldilocks is
  performance-critical and reuses the production C implementation via a
  Rust shim exposing a Lean-compatible C ABI.

- **Constraint evaluator** (`ffi/constraints/`): Evaluates compiled constraint
  bytecode (`.bin` files from the PIL2 compiler). The bytecode interpreter
  is implemented in Rust, matching the C++ production evaluator.

## Relation to the Python Executable Spec

This Lean implementation is a line-by-line translation of the Python
executable spec in `../executable-spec/`. Each Lean function includes a
`Translates:` comment pointing to the corresponding Python source location.
Both implementations verify the same binary proofs from the C++ GPU prover.
