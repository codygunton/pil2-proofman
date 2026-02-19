# ZisK Prover Specification

````{only} html
This is the complete specification for the PIL2 proving system
as used by the ZisK zkVM.
It specifies *exactly* what the prover and verifier compute, in sequence,
using mathematical notation.
It contains no proofs and no security analysis---only the concrete protocol.

The specification comprises three parts:

1. **STARK Protocol** --- the parametric FRI-STARK proving system
   that works with any AIR over the Goldilocks field.
2. **ZisK Machine** --- the concrete chip architecture:
   21 AIRs, bus interconnections, memory layout, coprocessors,
   precompile circuits, lookup tables, and global constraints.
3. **Recursion Pipeline** --- the VADCOP recursive aggregation
   from per-AIR STARKs to a single proof.

This specification is accompanied by a
[Python executable specification](https://github.com/pil2-proofman/pil2-proofman/tree/python-spec/executable-spec)
that implements the complete STARK prover and verifier,
producing byte-identical proofs to the production C++ implementation.
````

```{toctree}
:maxdepth: 3
:hidden:

part-stark/index
part-machine/index
part-recursion/index
```

```{toctree}
:hidden:

executable-spec/ <api/index>
```

