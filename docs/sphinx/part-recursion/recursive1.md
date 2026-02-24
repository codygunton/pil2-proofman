(sec:recursive1)=
# Recursive1: Per-AIR Normalization (Stage 3)

Recursive1 wraps each Basic or Compressor STARK proof in a SNARK circuit
({src}`stark-recurser/src/pil2circom/pil2circom.js#pil2circom`),
producing a normalized proof format suitable for tree aggregation.

1. **Circuit.**
   A Circom SNARK circuit that verifies one STARK proof.
   The verification key is selected based on the input proof's circuit type:
   - Circuit type = "basic": use the Basic STARK verification key.
   - Circuit type = "compressor": use the Compressor verification key.

2. **Input.**
   One STARK proof $\pi^{(a)}$ (either Basic or Compressor).

3. **Output.**
   A normalized proof $\pi^{(a)}_{\mathrm{R1}}$ with a standardized
   output format
   ({src}`stark-recurser/src/pil2circom/proof2zkin.js#proof2zkin`)
   containing:
   - Public inputs and proof values.
   - The global challenge $\chi$.
   - The root of the aggregated challenge computation $\mathrm{rootCAgg}$.
   - The $\mathrm{stage1Hash}$ for this AIR instance.
