# Spec Review Notes

## Index (ZisK Prover Specification)

---

# Part I: STARK Protocol

● The protocol has 5 phases, not 2: setup →
  commit stages → evaluation → FRI fold →
  query. Both Python and C++ follow the same
  flow.

  Expression execution differs:
  - C++: All constraints go through bytecode
  interpreter (ExpressionsPack), no
  hand-written code
  - Python: Hand-written constraint modules
  for 3 test AIRs + bytecode adapter for Zisk
   AIRs

  Organization differs:
  - C++: Flat — everything in
  pil2-stark/src/starkpil/
  - Python: Separated — protocol/ (STARK
  flow), constraints/ (per-AIR C(x)),
  witness/ (intermediates), primitives/
  (crypto)

  The Python separation is intentional —
  makes the spec readable. The protocol layer
   delegates to ConstraintModule objects
  rather than calling the bytecode
  interpreter directly.

Your words ^. Our organization shoudl reflect that rther than now bwing a more obscuure list of subsjections

## STARK Protocol (intro)


## Notation and Algebraic Setup
Rename this to Primitives
Add refs to python, explaining galois dep and saying what our fork adds.

### Fields

### Domains

### Polynomials

### Key Quantities
Merge with below section an name it Glossary of Notation
This should be the last subsection (not a sub-sub like it is) of the STARK protocol section because it contains info on Building Blocks.

This should say what N is
Double check that these quantities are the names used in the python spec and report an answer here.

**AUDIT RESULT — Python name mapping (all verified):**
| Spec Symbol | Python Name | Match? |
|-------------|-------------|--------|
| N = 2^n (trace size) | `2 ** stark_info.stark_struct.n_bits` | Yes |
| Z_H(X) = X^N - 1 | `ProverHelpers.zi` (stores 1/Z_H, not Z_H) | Close — inverse |
| J (num constraints) | implicit (length of constraint list) | OK |
| d (Q split degree) | `stark_info.q_deg` | Yes |
| K (FRI rounds) | `len(stark_struct.fri_fold_steps)` | Yes |
| Q_queries | `stark_struct.n_queries` | Yes |
| b_pow | `stark_struct.pow_bits` | Yes |
| a (Merkle arity) | `stark_struct.merkle_tree_arity` | Yes |
| MT(.) | `MerkleTree.get_root()` | Yes |
| T (transcript) | `Transcript` class | Yes |
| T.absorb | `Transcript.put()` | Different name |
| T.squeeze | `Transcript.get_field()` | Different name |
| xi, beta_k | `xi`, `beta` | Yes |
| v_1, v_2 | `vf1`, `vf2` (in fri_polynomial.py) | Different name |
| alpha, gamma | `alpha`, `gamma` | Yes |

### Notation Conventions
Include Field
Is squeeze_indices directly in use in the python spec? If not it's a detail and you shoudl remove

**AUDIT RESULT:** `squeeze_indices` is NOT used anywhere in the Python spec. Python calls it `Transcript.get_permutations(n, n_bits)`. Removed from glossary. The `\sqidx` LaTeX macro is still used in the spec prose (query-phase.md, full-protocol.md) with inline notes showing the Python name.

## Building Blocks

### Polynomial Commitment via Merkle Trees
Need refs to python

### Fiat-Shamir Transcript
Need refs to python

## STARK Protocol: Commitment Phase

### Stage 1: Witness Commitment

### Transcript Seeding

### Stage 2: Intermediate Polynomials

#### Clustered logup intermediate (im_cluster)

#### Single logup intermediate (im_single)

#### Grand sum (gsum)

#### Grand product (gprod)

#### Low-degree reduction (im_low)

#### Application-level intermediates (ImPol)

### Stage Q: Quotient Polynomial

### Polynomial Evaluations

### FRI Polynomial Construction

### FRI Commitment Rounds

### Grinding


## STARK Protocol: Query Phase

### Transcript Reconstruction

### Constraint Check

### Grinding Check

### Final Polynomial Degree Check

### Query Derivation

### Merkle Tree Verification

### FRI Polynomial Consistency

### FRI Folding Verification


## Multi-AIR Challenge Binding

### Per-AIR Contributions

### Challenge Aggregation

### Global Constraints


## The Full Protocol, Rolled Out


## Constraint Polynomial Structure


## FRI Polynomial Batching Formula


---

# Part II: ZisK Machine

## ZisK Machine (intro)


## Architecture Overview

### Airgroup Structure

### AIR Inventory

### STARK Parameters per AIR


## Bus Architecture

### Bus Types

### Bus Inventory

### Bus Interconnection Summary


## CPU: Main AIR

### Instruction Execution

### Bus Interactions


## Memory Subsystem

### Mem AIR

### RomData AIR

### InputData AIR

### MemAlign Subsystem


## Computation Coprocessors

### Binary

### BinaryAdd

### BinaryExtension

### Arith


## Precompiles

### Add256

### ArithEq

### ArithEq384

### Keccakf

### Sha256f


## Lookup Tables

### SpecifiedRanges

### VirtualTable0

### VirtualTable1


## Global Constraints

### Bus Balance Equations

### Continuation Anchoring

### Airgroup Value Aggregation


---

# Part III: Recursion Pipeline

## Recursion Pipeline (intro)


## Pipeline Overview

### Proof Type Table

### Field


## Basic STARK Proof (Stage 1)


## Compressor (Stage 2, Optional)


## Recursive1: Per-AIR Normalization (Stage 3)


## Recursive2: Tree Aggregation (Stage 4)

### Aggregation Structure

### Airgroup Value Aggregation

### stage1Hash Chaining

### Tree Depth


## VadcopFinal (Stage 5)

### STARK Verification

### Global Challenge Recomputation

### Global Constraint Verification

### Output


## Distributed Proving


---

# API Reference (executable-spec/)

