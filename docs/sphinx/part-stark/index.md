(part:stark)=
# STARK Protocol

````{only} html
The parametric FRI-STARK proving system that works with any AIR
over the Goldilocks field $\F$.
````

The protocol proceeds in five phases:

1. **Setup** — field definitions, domain construction, and Merkle tree / transcript primitives ({ref}`sec:notation`, {ref}`sec:building-blocks`).
2. **Commit** — witness commitment, intermediate polynomial computation, and quotient polynomial construction ({ref}`sec:stage1` through {ref}`sec:stageQ`).
3. **Evaluate** — polynomial evaluations at the challenge point and FRI polynomial batching ({ref}`sec:evals`, {ref}`sec:fri-poly`).
4. **FRI fold** — iterated degree reduction via FRI commitment rounds and grinding ({ref}`sec:fri-rounds`, {ref}`sec:grinding`).
5. **Query** — Merkle opening proofs, FRI consistency checks, and folding verification ({ref}`sec:query-phase`).

For the complete protocol as a single self-contained description,
see {ref}`sec:full-protocol`.

```{toctree}
:maxdepth: 2

notation
building-blocks
commitment-phase
query-phase
challenge-binding
appendix-constraints
appendix-batching
full-protocol
glossary
```
