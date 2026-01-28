# VADCOP Architecture

## Overview

**VADCOP** (Verifiable Aggregation of Distributed Computation Over Polynomials) is a protocol for proving multiple AIR instances together, binding them cryptographically to prevent mix-and-match attacks.

## The Problem VADCOP Solves

When you have multiple AIRs (e.g., different VM components like memory, ALU, range checks), each generates its own proof. Without coordination, a malicious prover could generate valid individual proofs that don't actually correspond to the same execution.

## How It Works

1. Each AIR commits to its Stage 1 polynomials → gets `root1`
2. All AIRs contribute `[verkey, root1, air_values]` to a shared hash
3. This hash is expanded via lattice expansion (368 elements) and aggregated
4. The aggregated value becomes `global_challenge` - a shared Fiat-Shamir challenge
5. All AIRs use this same `global_challenge` to derive their Stage 2+ challenges

## Why It Matters

- Binds all AIR proofs to the same randomness
- Prevents mix-and-match attacks (can't combine proofs from different executions)
- Enables distributed proving (workers compute independently, then aggregate)

## Aggregation Pipeline

VADCOP uses **SNARKs verifying STARKs**, organized in a tree structure:

```
                    STARK Layer                          SNARK Layer
                    ───────────                          ───────────
AIR1_inst1 → Basic STARK ─→ Recursive1 (Circom) ─┐
AIR1_inst2 → Basic STARK ─→ Recursive1 (Circom) ─┼→ Recursive2 ─┐
AIR1_inst3 → Basic STARK ─→ Recursive1 (Circom) ─┘    (3→1)     │
                                                                 ├→ Recursive2 ─┐
AIR1_inst4 → Basic STARK ─→ Recursive1 (Circom) ─┐              │               │
AIR1_inst5 → Basic STARK ─→ Recursive1 (Circom) ─┼→ Recursive2 ─┘               │
AIR1_inst6 → Basic STARK ─→ Recursive1 (Circom) ─┘                              │
                                                                                 ├→ VadcopFinal
AIR2_inst1 → Basic STARK ─→ Recursive1 (Circom) ─┐                              │
AIR2_inst2 → Basic STARK ─→ Recursive1 (Circom) ─┼→ Recursive2 ─────────────────┘
AIR2_inst3 → Basic STARK ─→ Recursive1 (Circom) ─┘
                                                        │
                                                        ▼
                                                   RecursiveF → fflonk (Ethereum)
```

## Proof Types (in order)

| Type | Description |
|------|-------------|
| `Basic` | STARK proof for each AIR instance |
| `Compressor` | Optional STARK compression for large AIRs |
| `Recursive1` | Circom SNARK that verifies a Basic/Compressor STARK |
| `Recursive2` | Circom SNARK aggregating 3 Recursive1 proofs into 1 |
| `VadcopFinal` | Circom SNARK combining all airgroup proofs |
| `RecursiveF` | Final recursive STARK |
| `fflonk` | Ethereum-verifiable SNARK (groth16) |

## Lattice Expansion Algorithm

The challenge aggregation uses a 3-step lattice expansion:

1. **Hash inputs**: `[verkey, root1, air_values]` → 16-element Poseidon2 state
2. **Expand**: Chain hash 22 times to get 368 elements
3. **Derive**: Hash `[publics, proof_values, 368-element contribution]` → 3 field elements

```
values[0:16]   = initial_hash_state
values[16:32]  = poseidon2(values[0:16])
values[32:48]  = poseidon2(values[16:32])
...
values[352:368] = poseidon2(values[336:352])
```

The 368-element size (`latticeSize`) comes from `globalInfo.json` and provides:
- Room for aggregating contributions from multiple AIRs
- Security margin through entropy expansion
- Support for future post-quantum considerations

## Python Executable Spec Status

| Component | Status | Notes |
|-----------|--------|-------|
| Basic STARK prover | Complete | Byte-identical to C++ |
| Global challenge (single AIR) | Complete | Lattice expansion implemented |
| Multi-AIR challenge aggregation | Not implemented | Need to prove multiple AIRs |
| Recursive1/2/VadcopFinal | Out of scope | Requires Circom circuits |
| fflonk | Out of scope | Requires SNARK tooling |

The Python spec covers the **STARK layer only**. The recursion pipeline requires:
1. Circom circuits that verify STARKs
2. Witness generators (`.so` libraries)
3. SNARK proving infrastructure (groth16/fflonk)

## Multi-AIR Implementation Path

To extend Python for multi-AIR VADCOP:

1. **Extend test setup** - Load and prove SimpleLeft, SimpleRight, etc. together
2. **Aggregate challenges** - Combine all AIR contributions before Stage 2
3. **Generate all Basic proofs** - Multiple AIRs using shared `global_challenge`

The recursive aggregation (Recursive1/2) would still require external Circom tooling.

## References

- C++ implementation: `proofman/src/recursion.rs`
- Challenge accumulation: `proofman/src/challenge_accumulation.rs`
- Global info: `common/src/global_info.rs`
