(sec:vadcop-final)=
# VadcopFinal (Stage 5)

The VadcopFinal circuit is itself an AIR whose constraints enforce
cross-airgroup consistency.
It takes one Recursive2 proof per airgroup and produces a single STARK proof.

(sec:vf-stark)=
## STARK Verification

For each airgroup $g$, the VadcopFinal circuit verifies the Recursive2 proof
$\pi^{(g)}_{\mathrm{R2}}$
using the appropriate verification key
(selected between Basic and aggregation keys
depending on the circuit type flag).

(sec:vf-challenge)=
## Global Challenge Recomputation

The circuit recomputes the global challenge from the public inputs:

$$
\chi' = \T_G\bigl(\mathrm{publics},\;
                  \mathrm{proofValues},\;
                  \mathrm{stage1Hash}^{(0)}, \ldots,
                  \mathrm{stage1Hash}^{(G-1)}\bigr),
$$

where each $\mathrm{stage1Hash}^{(g)}$ is the chained Poseidon2 hash
accumulated through the Recursive2 tree for airgroup $g$.

**Check:** $\chi' = \chi$ (the global challenge used by all per-AIR proofs).

(sec:vf-global)=
## Global Constraint Verification

The circuit enforces all cross-airgroup constraints.
For a concrete machine, these are defined by the machine specification
(e.g. bus balance equations, continuation anchoring;
see the *ZisK Machine* specification).

In general, global constraints take two forms:

- **Sum type (logup):**
  the sum of all $\mathrm{gsum}$ boundary values across AIRs
  sharing a bus equals zero.

  $$
  \sum_{a \in \mathrm{bus}(b)} \mathrm{gsum}^{(a)}[N-1] = 0
  \quad \text{for each bus } b.
  $$

- **Product type (permutation):**
  the product of all $\mathrm{gprod}$ boundary values across AIRs
  sharing a bus equals one.

  $$
  \prod_{a \in \mathrm{bus}(b)} \mathrm{gprod}^{(a)}[N-1] = 1
  \quad \text{for each bus } b.
  $$

(sec:vf-output)=
## Output

The VadcopFinal proof $\pi_{\mathrm{VF}}$ is itself a STARK proof
over the Goldilocks field,
verified by the standard STARK verifier
(see the *STARK Protocol*, Query Phase).
Its transcript is seeded directly with
$(\mathrm{vk},\; \Hash(\mathrm{pub}),\; r_1)$
rather than with a global challenge,
since it *is* the outermost layer.

In the current deployment, this is the **final proof** submitted to
the ethproofs service.
The proof is serialized as a flat array of Goldilocks field elements
(`Vec<u64>`) and transmitted as base64-encoded binary.
