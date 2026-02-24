(sec:recursive2)=
# Recursive2: Tree Aggregation (Stage 4)

Recursive2 aggregates proofs within the same airgroup using a {src}`3-to-1
tree reduction <stark-recurser/src/pil2circom/pil2circom.js#pil2circom>`.

(sec:r2-structure)=
## Aggregation Structure

1. **Fan-in.**
   Each Recursive2 circuit takes up to
   $N_{\mathrm{agg}} = 3$ input proofs.
   These may be Recursive1 proofs or other Recursive2 proofs
   from the same airgroup.

2. **Null-proof padding.**
   If the number of proofs is not divisible by 3,
   null proofs are used as padding.
   The circuit distinguishes null proofs via a circuit type flag
   (circuit type $= 0$ indicates a null proof that is not verified).

3. **Verification key selection.**
   The circuit selects the appropriate verification key based on
   the circuit type of each input:
   - Type 0: null proof (skip verification).
   - Type 1: aggregated proof (Recursive2 verification key).
   - Type $\geq 2$: basic proof (Recursive1 verification key,
     with type encoding the specific AIR).

(sec:r2-airgroup-values)=
## Airgroup Value Aggregation

Each input proof carries airgroup values (accumulated $\mathrm{gsum}$ and
$\mathrm{gprod}$ boundary values).
Recursive2 aggregates these:

- **Sum type** ($\mathrm{gsum}$):
  add the values from all non-null inputs.
- **Product type** ($\mathrm{gprod}$):
  multiply the values from all non-null inputs.

(sec:r2-stage1hash)=
## stage1Hash Chaining

The $\mathrm{stage1Hash}$ values from input proofs are chained
using Poseidon2:

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
