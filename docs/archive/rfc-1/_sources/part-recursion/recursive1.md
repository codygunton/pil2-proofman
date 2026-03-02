(sec:recursive1)=
# Recursive1: Per-AIR Normalization (Stage 3)

Recursive1 wraps each {src}`Basic <stark-recurser/src/circom2pil/compressor_exec.js#compressorExec>` or
{src}`Compressor <stark-recurser/src/circom2pil/compressor_exec.js#compressorExec>` STARK proof
in a {src}`SNARK circuit <stark-recurser/src/pil2circom/pil2circom.js#pil2circom>`,
producing a {src}`normalized proof format <stark-recurser/src/pil2circom/proof2zkin.js#proof2zkin>`
suitable for tree aggregation.

1. **Circuit.**
   A {src}`Circom SNARK circuit <stark-recurser/src/pil2circom/pil2circom.js#pil2circom>`
   that verifies one STARK proof.
   The {src}`verification key <stark-recurser/src/pil2circom/circuits.gl/stark_verifier.circom.ejs:1>`
   is selected based on the input proof's {src}`circuit type <stark-recurser/src/pil2circom/proof2zkin.js#proof2zkin>`:
   - Circuit type = "basic": use the Basic STARK verification key.
   - Circuit type = "compressor": use the Compressor verification key.

2. **Input.**
   One STARK proof $\pi^{(a)}$ (either Basic or Compressor).

3. **Output.**
   A normalized proof $\pi^{(a)}_{\mathrm{R1}}$ with a {src}`standardized
   output format <stark-recurser/src/pil2circom/proof2zkin.js#proof2zkin>`
   containing:
   - {src}`Public inputs <stark-recurser/src/pil2circom/publics2zkin.js#publics2zkin>` and proof values.
   - The {src}`global challenge <stark-recurser/src/pil2circom/proof2zkin.js#proof2zkin>` $\chi$.
   - The root of the aggregated challenge computation $\mathrm{rootCAgg}$.
   - The {src}`stage1Hash <stark-recurser/src/pil2circom/proof2zkin.js#proof2zkin>` for this AIR instance.
