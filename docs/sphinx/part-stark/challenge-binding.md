(sec:challenge-binding)=
# Multi-AIR Challenge Binding

When a computation is decomposed into multiple AIR instances
(e.g. memory, ALU, range checks in a zkVM),
each AIR produces an independent STARK proof.
To prevent a malicious prover from mixing proofs across different executions,
all per-AIR transcripts are seeded with a shared global challenge $\chi$
derived from every AIR's stage-1 commitment.

(sec:contributions)=
## Per-AIR Contributions

Suppose there are $A$ AIR instances.
Each instance $a \in [A]$ independently commits its stage-1 polynomials
to obtain a Merkle root $r_1^{(a)}$.
It then computes a *contribution* $\kappa^{(a)}$ as follows
({src}`protocol/utils/challenge_utils.py:26`).

1. Assemble input data:

   $$
   \mathbf{d}^{(a)} = \bigl(\mathrm{vk}^{(a)},\; r_1^{(a)},\; \mathrm{airValues}^{(a)}\bigr),
   $$

   where $\mathrm{vk}^{(a)}$ is the per-AIR verification key (4 base-field elements)
   and $\mathrm{airValues}^{(a)}$ are any stage-1 air values.

2. Compute a hash state:

   $$
   h^{(a)} = \Poseidon(\mathbf{d}^{(a)}) \in \F^{16}.
   $$

3. **Lattice expansion** (when no elliptic-curve mode is used).
   Chain-hash to produce a vector of $L$ elements
   (typically $L = 368$):

   $$
   \begin{aligned}
   \kappa^{(a)}[0\!:\!16] &= h^{(a)}, \\
   \kappa^{(a)}[16k\!:\!16(k\!+\!1)] &= \Poseidon\bigl(\kappa^{(a)}[16(k\!-\!1)\!:\!16k]\bigr)
   \quad \text{for } k = 1, \ldots, L/16 - 1.
   \end{aligned}
   $$

(sec:aggregation)=
## Challenge Aggregation

The partial contributions are aggregated and a shared challenge is derived
({src}`protocol/utils/challenge_utils.py:188`).

**Lattice mode.**
Sum all contribution vectors elementwise
({src}`protocol/utils/challenge_utils.py:166`):

$$
\kappa = \sum_{a=0}^{A-1} \kappa^{(a)} \in \F^L.
$$

**Elliptic-curve mode.**
Each contribution is mapped to a point on an elliptic curve
$E / \mathbb{F}_{p^5}$ via a hash-to-curve map,
then all points are summed:

$$
P = \sum_{a=0}^{A-1} \mathrm{HashToCurve}\bigl(\kappa^{(a)}[0\!:\!5],\; \kappa^{(a)}[5\!:\!10]\bigr)
\in E(\mathbb{F}_{p^5}).
$$

The aggregated value is $(P.x \,\|\, P.y) \in \F^{10}$.

**Global challenge derivation.**
From the aggregated value $\kappa$ (or the curve-mode representation),
derive the global challenge
({src}`protocol/utils/challenge_utils.py:216`):

1. Initialize a fresh transcript $\T_G$.
2. $\T_G.\abs(\mathrm{publics})$.
3. $\T_G.\abs(\mathrm{proofValues}_{\mathrm{stage\,1}})$ (if any).
4. $\T_G.\abs(\kappa)$.
5. Squeeze: $\chi \leftarrow \T_G.\sq()$, yielding $\chi \in \Fext$
   ({src}`protocol/utils/challenge_utils.py:228`).

Every AIR instance then uses $\chi$ as its transcript seed
(as described in {ref}`sec:seed`),
binding all per-AIR proofs to the same shared randomness.

(sec:global-constraints)=
## Global Constraints

After all per-AIR proofs are generated, the system verifies cross-AIR
consistency via *global constraints*.
These enforce that airgroup values accumulated during individual AIR
executions (such as $\mathrm{gsum}$ and $\mathrm{gprod}$ boundary values)
satisfy the required aggregate relationships:

- **Sum type (logup):**
  the sum of all $\mathrm{gsum}$ boundary values across AIRs sharing a bus equals zero.
- **Product type (permutation):**
  the product of all $\mathrm{gprod}$ boundary values across AIRs sharing a bus equals one.

The concrete global constraints for a specific machine
(e.g. bus balance equations, continuation anchoring)
are defined by the machine specification.
For the verification circuit that enforces these constraints,
see the *Recursion Pipeline* (VadcopFinal).
