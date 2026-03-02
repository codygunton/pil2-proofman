(sec:recursive2)=
# Recursive2: Tree Aggregation (Stage 4)

Recursive2 {src}`aggregates proofs <stark-recurser/src/pil2circom/pil2circom.js#pil2circom>`
within the same airgroup using a {src}`3-to-1
tree reduction <stark-recurser/src/pil2circom/pil2circom.js#pil2circom>`.

(sec:r2-structure)=
## Aggregation Structure

1. **Fan-in.**
   Each Recursive2 {src}`circuit <stark-recurser/src/pil2circom/pil2circom.js#pil2circom>` takes up to
   $N_{\mathrm{agg}} = 3$ input proofs.
   These may be Recursive1 proofs or other Recursive2 proofs
   from the same airgroup.

2. **Null-proof padding.**
   If the number of proofs is not divisible by 3,
   {src}`null proofs <stark-recurser/src/pil2circom/proof2zkin.js#proof2zkin>` are used as padding.
   The circuit distinguishes null proofs via a {src}`circuit type flag <stark-recurser/src/pil2circom/proof2zkin.js#proof2zkin>`
   (circuit type $= 0$ indicates a null proof that is not verified).

3. **Verification key selection.**
   The circuit selects the appropriate {src}`verification key <stark-recurser/src/pil2circom/circuits.gl/stark_verifier.circom.ejs:1>` based on
   the {src}`circuit type <stark-recurser/src/pil2circom/proof2zkin.js#proof2zkin>` of each input:
   - Type 0: null proof (skip verification).
   - Type 1: aggregated proof (Recursive2 verification key).
   - Type $\geq 2$: basic proof (Recursive1 verification key,
     with type encoding the specific AIR).

(sec:r2-airgroup-values)=
## Airgroup Value Aggregation

Each input proof carries {src}`airgroup values <stark-recurser/src/pil2circom/joinzkinFinal.js#joinZkinFinal>`
(accumulated $\mathrm{gsum}$ and $\mathrm{gprod}$ boundary values).
Recursive2 {src}`aggregates <stark-recurser/src/pil2circom/pil2circom.js#pil2circom>` these:

- **Sum type** ({src}`gsum <stark-recurser/src/pil2circom/joinzkinFinal.js#joinZkinFinal>`):
  add the values from all non-null inputs.
- **Product type** ({src}`gprod <stark-recurser/src/pil2circom/joinzkinFinal.js#joinZkinFinal>`):
  multiply the values from all non-null inputs.

(sec:r2-stage1hash)=
## stage1Hash Chaining

The {src}`stage1Hash <stark-recurser/src/pil2circom/proof2zkin.js#proof2zkin>` values from input proofs are chained
using {src}`Poseidon2 <stark-recurser/src/utils/f3g.js:1>`:

$$
\mathrm{stage1Hash}_{\mathrm{out}}
= \Poseidon\bigl(\mathrm{stage1Hash}_A \;\|\; \mathrm{stage1Hash}_B\bigr).
$$

For three inputs $A, B, C$:
first combine $A$ and $B$, then combine the result with $C$.
Null proofs contribute a zero hash.

(sec:r2-depth)=
## Tree Depth

For an airgroup with $N_{\mathrm{AIR}}$ instances, the tree has depth

$$
D = \lceil \log_3(N_{\mathrm{AIR}}) \rceil.
$$

The output is a single proof $\pi^{(g)}_{\mathrm{R2}}$ per airgroup $g$.
