(sec:distributed)=
# Distributed Proving

The VADCOP architecture enables {src}`distributed proving <zisk/distributed/crates/coordinator/src/coordinator.rs#Coordinator>`:
{src}`workers <zisk/distributed/crates/worker/src/worker.rs#Worker>` independently compute per-AIR proofs
and contribute to challenge aggregation
without sharing witness data.
The three-phase workflow is:

1. **Phase 1: Contributions.**
   Each {src}`worker <zisk/distributed/crates/worker/src/worker.rs#Worker>` computes
   {src}`stage-1 commitments <zisk/distributed/crates/worker/src/worker.rs#partial_contribution>` and
   {src}`lattice contributions <zisk/distributed/crates/common/src/dto.rs#ContributionParamsDto>` for its assigned AIR instances.
   Contributions are sent to the {src}`coordinator <zisk/distributed/crates/coordinator/src/coordinator.rs#Coordinator>`.

2. **Phase 2: Prove.**
   The {src}`coordinator <zisk/distributed/crates/coordinator/src/coordinator.rs#Coordinator>`
   {src}`aggregates <zisk/distributed/crates/coordinator/src/coordinator.rs#handle_contributions_completion>` all contributions
   into the {src}`global challenge <stark-recurser/src/pil2circom/publics2zkin.js#publics2zkin>` $\chi$
   and distributes it to all workers.
   Workers {src}`generate per-AIR STARK proofs <zisk/distributed/crates/worker/src/worker.rs#prove>` (Basic stage)
   and perform internal {src}`Recursive1 <stark-recurser/src/pil2circom/pil2circom.js#pil2circom>`/{src}`Recursive2 <stark-recurser/src/pil2circom/pil2circom.js#pil2circom>` aggregation
   for their assigned airgroups.

3. **Phase 3: Aggregate.**
   A designated {src}`aggregator <zisk/distributed/crates/worker/src/worker.rs#aggregate>` receives all per-airgroup
   Recursive2 proofs, performs final Recursive2 tree reduction
   (if needed), and generates the {src}`VadcopFinal proof <stark-recurser/src/pil2circom/joinzkinFinal.js#joinZkinFinal>`.
   This is the terminal stage of the pipeline.

**MPI worker aggregation.**
In the {src}`MPI deployment model <zisk/distributed/crates/worker/src/worker.rs#partial_contribution_mpi_broadcast>`,
each {src}`worker process <zisk/distributed/crates/worker/src/worker.rs#Worker>` handles a subset
of AIR instances.
The {src}`coordinator process <zisk/distributed/crates/coordinator/src/coordinator.rs#Coordinator>` (rank 0) performs the
{src}`aggregation of contributions <zisk/distributed/crates/coordinator/src/coordinator.rs#handle_contributions_completion>`
and {src}`final proof assembly <zisk/distributed/crates/coordinator/src/coordinator.rs#launch_proof>`.

**Coordinator-mediated multi-machine proving.**
For large computations spanning multiple machines,
the {src}`coordinator <zisk/distributed/crates/coordinator/src/coordinator_grpc.rs:1>` mediates
{src}`challenge distribution <zisk/distributed/crates/coordinator/src/coordinator.rs#handle_contributions_completion>` and
{src}`proof collection <zisk/distributed/crates/coordinator/src/coordinator.rs#handle_stream_execute_task_response>` over the network.
Each machine runs an independent set of {src}`workers <zisk/distributed/crates/worker/src/worker.rs#Worker>`,
and only the aggregated {src}`contributions <zisk/distributed/crates/common/src/dto.rs#ContributionParamsDto>`
and final proofs traverse machine boundaries.
