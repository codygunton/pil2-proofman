(sec:vadcop-final)=
# VadcopFinal (Stage 5)

The {src}`VadcopFinal circuit <stark-recurser/src/pil2circom/joinzkinFinal.js#joinZkinFinal>`
is itself an AIR whose constraints enforce cross-airgroup consistency.
It takes {src}`one Recursive2 proof per airgroup <stark-recurser/src/pil2circom/joinzkinFinal.js#joinZkinFinal>`
and produces a single STARK proof.

(sec:vf-stark)=
## STARK Verification

For each airgroup $g$, the VadcopFinal circuit {src}`verifies <stark-recurser/src/pil2circom/pil2circom.js#pil2circom>`
the Recursive2 proof $\pi^{(g)}_{\mathrm{R2}}$
using the appropriate {src}`verification key <stark-recurser/src/pil2circom/circuits.gl/stark_verifier.circom.ejs:1>`
(selected between Basic and aggregation keys
depending on the {src}`circuit type flag <stark-recurser/src/pil2circom/proof2zkin.js#proof2zkin>`).

(sec:vf-challenge)=
## Global Challenge Recomputation

The circuit {src}`recomputes the global challenge <stark-recurser/src/pil2circom/publics2zkin.js#publics2zkin>`
from the {src}`public inputs <stark-recurser/src/pil2circom/publics2zkin.js#publics2zkin>`:

$$
\chi' = \T_G\bigl(\mathrm{publics},\;
                  \mathrm{proofValues},\;
                  \mathrm{stage1Hash}^{(0)}, \ldots,
                  \mathrm{stage1Hash}^{(G-1)}\bigr),
$$

where each {src}`stage1Hash <stark-recurser/src/pil2circom/proof2zkin.js#proof2zkin>`$^{(g)}$ is the chained
{src}`Poseidon2 <stark-recurser/src/utils/f3g.js:1>` hash
accumulated through the Recursive2 tree for airgroup $g$.

**Check:** $\chi' = \chi$ (the global challenge used by all per-AIR proofs).

(sec:vf-global)=
## Global Constraint Verification

The circuit enforces all {src}`cross-airgroup constraints <stark-recurser/src/pil2circom/joinzkinFinal.js#joinZkinFinal>`.
For a concrete machine, these are defined by the machine specification
(e.g. {ref}`bus balance equations <sec:bus-balance>`, {ref}`continuation anchoring <sec:continuation>`;
see the {ref}`ZisK Machine <sec:airgroup>` specification).

In general, global constraints take two forms:

- **Sum type (logup):**
  the sum of all {src}`gsum <stark-recurser/src/pil2circom/joinzkinFinal.js#joinZkinFinal>` boundary values across AIRs
  sharing a {src}`bus <zisk/data-bus/src/data_bus.rs#DataBusTrait>` equals zero.

  $$
  \sum_{a \in \mathrm{bus}(b)} \mathrm{gsum}^{(a)}[N-1] = 0
  \quad \text{for each bus } b.
  $$

- **Product type (permutation):**
  the product of all {src}`gprod <stark-recurser/src/pil2circom/joinzkinFinal.js#joinZkinFinal>` boundary values across AIRs
  sharing a {src}`bus <zisk/data-bus/src/data_bus.rs#DataBusTrait>` equals one.

  $$
  \prod_{a \in \mathrm{bus}(b)} \mathrm{gprod}^{(a)}[N-1] = 1
  \quad \text{for each bus } b.
  $$

(sec:vf-output)=
## Output

The {src}`VadcopFinal proof <stark-recurser/src/pil2circom/joinzkinFinal.js#joinZkinFinal>` $\pi_{\mathrm{VF}}$ is itself a STARK proof
over the Goldilocks field,
verified by the standard {src}`STARK verifier <stark-recurser/src/pil2circom/pil2circom.js#pil2circom>`
(see the *STARK Protocol*, Query Phase).
Its {src}`transcript <stark-recurser/src/utils/f3g.js:1>` is seeded directly with
$(\mathrm{vk},\; \Hash(\mathrm{pub}),\; r_1)$
rather than with a global challenge,
since it *is* the outermost layer.

In the current deployment, this is the **final proof** submitted to
the ethproofs service.
The proof is {src}`serialized <stark-recurser/src/pil2circom/joinzkinFinal.js#joinZkinFinal>` as a flat array of Goldilocks field elements
(`Vec<u64>`) and transmitted as base64-encoded binary.
