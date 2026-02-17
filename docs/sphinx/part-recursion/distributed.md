(sec:distributed)=
# Distributed Proving

The VADCOP architecture enables distributed proving:
workers independently compute per-AIR proofs
and contribute to challenge aggregation
without sharing witness data.
The three-phase workflow is:

1. **Phase 1: Contributions.**
   Each worker computes stage-1 commitments and
   lattice contributions for its assigned AIR instances.
   Contributions are sent to the coordinator.

2. **Phase 2: Prove.**
   The coordinator aggregates all contributions
   into the global challenge $\chi$
   and distributes it to all workers.
   Workers generate per-AIR STARK proofs (Basic stage)
   and perform internal Recursive1/Recursive2 aggregation
   for their assigned airgroups.

3. **Phase 3: Aggregate.**
   A designated aggregator receives all per-airgroup
   Recursive2 proofs, performs final Recursive2 tree reduction
   (if needed), and generates the VadcopFinal proof.
   This is the terminal stage of the pipeline.

**MPI worker aggregation.**
In the MPI deployment model, each worker process handles a subset
of AIR instances.
The coordinator process (rank 0) performs the aggregation
of contributions and final proof assembly.

**Coordinator-mediated multi-machine proving.**
For large computations spanning multiple machines,
the coordinator mediates challenge distribution and proof collection
over the network.
Each machine runs an independent set of workers,
and only the aggregated contributions and final proofs
traverse machine boundaries.
