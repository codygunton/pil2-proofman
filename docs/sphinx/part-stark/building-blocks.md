(sec:building-blocks)=
# Building Blocks

## Witness Generation

In Part I of this specification, witness generation is treated as a black box.
This part focuses exclusively on the STARK protocol parameterized by the AIR
(Algebraic Intermediate Representation), which defines the constraint system
and execution trace structure.

In the Python implementation, witness generation is handled by per-AIR witness
modules that implement the `WitnessModule` abstract base class
({src}`witness.base.WitnessModule`). The prover calls these modules during Stage 1 via
`calculate_witness_with_module` ({src}`protocol/stages.py#calc-witness`).

Part II (ZisK Machine) covers the specific witness generation logic for each
of the ZisK AIRs.

(sec:commitment)=
## Polynomial Commitment via Merkle Trees

A polynomial $f$ of degree $< N$ is committed as follows.

1. **Extend to evaluation domain.**
   Compute coefficients $\hat{f} = \INTT_N(f)$, zero-pad to $N_{\mathrm{ext}}$
   coefficients, and evaluate on the coset domain:
   $\tilde{f} = \NTT_{N_{\mathrm{ext}}}(\hat{f})$.
   This yields $N_{\mathrm{ext}}$ evaluations $\tilde{f}(x)$ for $x \in H^*$
   ({src}`primitives/ntt.py#intt-extend-ntt`, {src}`protocol/stages.py#extend-to-coset`).

2. **Build Merkle tree.**
   When committing multiple polynomials $f_1, \ldots, f_w$ jointly:

   a. Form row $i$ as the concatenation of all polynomial values at domain
      point $i$:
      $\ell_i = \bigl(\tilde{f}_1(x_i),\; \tilde{f}_2(x_i),\; \ldots,\; \tilde{f}_w(x_i)\bigr)$
      ({src}`primitives/merkle_tree.py#form-row`).

   b. Hash each row: $h_i = \LinHash(\ell_i)$ using Poseidon2 linear hashing.

   c. Build an arity-$a$ Merkle tree over leaves $h_0, \ldots, h_{N_{\mathrm{ext}}-1}$
      ({src}`primitives/merkle_tree.py#build-tree`).

3. **Output.**
   The commitment is the Merkle root $r = \MT(\tilde{f}_1, \ldots, \tilde{f}_w)$
   ({src}`primitives/merkle_tree.py#merkle-root`).

**Opening proof at index $j$.**
The prover reveals the leaf values $\ell_j$ together with the authentication path
(sibling hashes along the path from leaf $j$ to the root)
({src}`primitives/merkle_tree.py#opening-proof`, {src}`primitives/merkle_prover.py#gen-proof`).

**Verification.**
The verifier recomputes $h_j = \LinHash(\ell_j)$, walks the authentication path
using the provided siblings, and checks that the computed root matches the
committed root $r$
({src}`primitives/merkle_verifier.py#verify-proof`).

(sec:transcript)=
## Fiat-Shamir Transcript

The transcript $\T$ is a Poseidon2 sponge with width $w = 4a$,
where $a \in \{2, 3, 4\}$ is the sponge arity.
The state is partitioned into a *rate* portion of $4(a-1)$ elements
and a *capacity* portion of $4$ elements
({src}`primitives/transcript.py#transcript-init`).

**Operations.**

- $\T.\abs(x_1, \ldots, x_k)$:
  Feed field elements into the rate portion one at a time,
  applying the Poseidon2 permutation whenever the rate portion is full
  ({src}`primitives/transcript.py#absorb`).

- $\T.\sq() \to (c_0, c_1, c_2) \in \Fext$:
  Squeeze three base-field elements from the sponge output
  (applying a permutation if needed),
  interpreted as a single extension-field challenge
  $c_0 + c_1\alpha + c_2\alpha^2$
  ({src}`primitives/transcript.py#squeeze`).

- $\T.\sqidx(q, b) \to (i_1, \ldots, i_q)$:
  Squeeze enough field elements to extract $q$ pseudorandom $b$-bit
  indices via bit packing.
  Specifically, squeeze $\lceil q \cdot b / 63 \rceil$ field elements
  and extract $b$ bits per index from the binary representations,
  using 63 bits per field element
  (called `get_permutations` in the Python spec; {src}`primitives/transcript.py#squeeze-indices`).
