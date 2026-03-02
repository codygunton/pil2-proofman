(sec:compressor)=
# Compressor (Stage 2, Optional)

The Compressor is an optional stage applied when the {src}`STARK verifier circuit
for a particular AIR exceeds $2^{17}$ rows <stark-recurser/src/vadcop/is_compressor_needed.js#isCompressorNeeded>`.

1. **Circuit.**
   A {src}`Circom circuit <stark-recurser/src/circom2pil/compressor_exec.js#compressorExec>` over the Goldilocks field that verifies one Basic STARK proof.
   The circuit's execution trace forms a new AIR.

2. **When needed.**
   If the {src}`number of verifier circuit rows <stark-recurser/src/circom2pil/compressor_constraints.js#getCompressorConstraints>` is $\leq 2^{17}$,
   the Compressor is skipped and the Basic proof proceeds directly
   to Recursive1.

3. **Output.**
   A new STARK proof $\pi^{(a)}_{\mathrm{Comp}}$ with a smaller
   verification circuit than the original Basic proof.

4. **stage1Hash.**
   The Compressor computes a commitment hash:

   $$
   \mathrm{stage1Hash}^{(a)} = \Poseidon\bigl(\mathrm{vk}^{(a)},\;
   r_1^{(a)},\; \mathrm{airValues}^{(a)}\bigr),
   $$

   which chains through subsequent recursive layers.
