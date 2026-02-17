# Two Kinds of Aggregation in Zisk

There are **two distinct aggregation mechanisms** that operate at different levels. They share the same Recursive2 Circom circuit but are triggered by different coordination protocols.

## 1. Intra-Worker Recursion (within a single GPU process)

This is the SNARK recursion tree that happens **inside a single worker process**. Each worker has one or more GPUs and handles a subset of AIR instances.

**Pipeline per worker:**
```
Per-AIR Basic STARK proof
  → [optional Compressor STARK — shrinks large proofs before Circom wrapping]
  → Recursive1 (Circom SNARK wrapping one STARK proof — ALWAYS used)
  → Recursive2 tree (3-to-1 Circom aggregation within this worker)
```

**Note on Compressor vs Recursive1:**
- **Recursive1** is always used. It converts a STARK proof into a Circom SNARK proof.
- **Compressor** is an optional STARK-to-STARK step for AIRs whose Basic proof is too large
  for the Recursive1 Circom circuit. Controlled by `hasCompressor` in `globalInfo.json` per-AIR.
- **Zisk never uses Compressor** — none of its 21 AIRs set `hasCompressor`, so all go
  straight from Basic → Recursive1.

**Key code locations:**

- **`proofman.rs:1530-1541`** — Sets up the internal Recursive2 tree. When `options.aggregation` is true, for each airgroup it pre-calculates how many Recursive2 rounds are needed and creates null-proof padding:
  ```rust
  let n_recursive2_proofs = total_recursive_proofs(n_proofs);
  ```

- **`proofman.rs:1564-1681`** — The internal recursion callback loop. When a Basic proof finishes on the GPU, this thread receives it and:
  1. Decides the next step: Basic → Compressor (if needed) → Recursive1 → Recursive2
  2. At line 1578: `if p == ProofType::Basic` → check if compressor needed, else go to Recursive1
  3. At line 1598-1618: When type is Recursive2, it accumulates proofs 3 at a time (`N_RECURSIVE_PROOFS_PER_AGGREGATION = 3`) and calls `gen_witness_aggregation()` to merge them
  4. Each merged Recursive2 proof re-enters the same pipeline until only one Recursive2 proof remains per airgroup

- **`recursion.rs:57`** — `gen_witness_recursive()`: Converts a Basic/Compressor STARK proof into Circom witness for Recursive1
- **`recursion.rs:156`** — `gen_witness_aggregation()`: Takes 3 Recursive2 proofs and generates Circom witness for the next-level Recursive2

**Result:** Each worker produces **one Recursive2 proof per airgroup** (for Zisk, there's 1 airgroup, so one proof per worker).

## 2. Inter-Worker/GPU Aggregation (across multiple machines)

This happens at two different scales:

### 2a. MPI-based aggregation (multiple GPUs, same job, legacy path)

When multiple MPI ranks participate in the same proof job (the `!options.rma` path), they synchronize via MPI barriers.

**Key code locations:**

- **`proofman.rs:1995-2030`** — After inner proofs finish, workers hit an MPI barrier (`self.mpi_ctx.barrier()`) then call:
  ```rust
  aggregate_worker_proofs(...)   // proofman.rs:2013
  ```

- **`recursion.rs:386-549`** — `aggregate_worker_proofs()`: This is the MPI-synchronized aggregation loop:
  1. **Line 440**: `mpi_ctx.barrier()` — All workers synchronize
  2. **Line 441**: `mpi_ctx.distribute_recursive2_proofs()` — Workers exchange their Recursive2 proofs via MPI
  3. **Lines 443-533**: Each worker does its share of the 3-to-1 Recursive2 merging on the exchanged proofs
  4. **Loop repeats** until only one Recursive2 proof per airgroup remains (across all workers)
  5. **Line 539**: Only rank 0 collects the final aggregated proofs

**This is classic distributed HPC-style aggregation** — workers directly exchange data via MPI without a coordinator.

### 2b. Coordinator-mediated aggregation (distributed workers, gRPC)

In the distributed zisk deployment (the `zisk-for-spec/distributed/` crate), a **coordinator** orchestrates the three-phase protocol over gRPC:

**Phase 1: Contributions** — Each worker computes its challenge contribution independently.
- **`worker.rs:419`**: `ProvePhaseInputs::Contributions(proof_info)`
- **`proofman.rs:1291-1478`**: Worker runs witness + STARK proofs, computes `calculate_internal_contributions()` (line 1452), returns via `ProvePhaseResult::Contributions`

**Phase 2: Prove** — Coordinator aggregates all contributions into a global challenge, sends it to all workers. Workers generate internal STARK + recursion proofs.
- **`coordinator.rs:1022-1088`**: `handle_contributions_completion()` — Collects all Phase 1 results, computes combined challenges, transitions to Phase 2
- **`worker.rs:453`**: `ProvePhaseInputs::Internal(challenges)` — Worker receives aggregated challenges
- **`proofman.rs:1507`**: `calculate_global_challenge()` — Sets the binding global challenge
- Workers produce per-airgroup Recursive2 proofs (via the intra-worker recursion above)
- **`worker.rs:619-635`**: `prove_phase(Internal)` → returns `ProvePhaseResult::Internal(proof)` which is a `Vec<AggProofs>`

**Phase 3: Aggregate** — Coordinator assigns one worker as aggregator. As other workers finish Phase 2, their proofs stream to the aggregator.
- **`coordinator.rs:1336-1381`**: `handle_proofs_completion()` — As each worker finishes, sends its proofs to the aggregator
- **`coordinator.rs:1496-1532`**: `resolve_aggregator_assignment()` — First worker to finish Phase 2 becomes the aggregator
- **`coordinator.rs:1378`**: `send_aggregation_task()` — Ships proofs to aggregator worker incrementally
- **`worker.rs:640-696`**: `aggregate()` — Calls `prover.aggregate_proofs()` which maps to `receive_aggregated_proofs()`
- **`proofman.rs:2181-2349`**: `receive_aggregated_proofs()` — Aggregator:
  1. Verifies incoming Recursive2 proofs (line 2236: `verify_recursive2()`)
  2. Validates accumulated challenges match (line 2247-2255)
  3. Feeds them into `outer_aggregations()` which runs the same 3-to-1 Recursive2 tree
  4. When `last_proof=true` and `final_proof=true`, produces the VadcopFinal proof (line 2332: `generate_vadcop_final_proof()`)

## Summary Table

| Aspect | Intra-Worker (1) | MPI Aggregation (2a) | Coordinator (2b) |
|--------|------------------|---------------------|-------------------|
| **Scope** | Single process, 1+ GPUs | Multiple MPI ranks, same binary | Multiple machines, gRPC |
| **Communication** | In-memory channels (`crossbeam`) | MPI `barrier` + `distribute_recursive2_proofs` | gRPC via coordinator |
| **Entry point** | `proofman.rs:1564` callback loop | `recursion.rs:386` `aggregate_worker_proofs` | `worker.rs:640` `aggregate()` → `proofman.rs:2181` |
| **Circuit used** | Recursive2 (3→1) | Recursive2 (3→1) | Recursive2 (3→1) + VadcopFinal |
| **Result** | 1 Recursive2 proof/airgroup/worker | 1 Recursive2 proof/airgroup (rank 0) | VadcopFinal proof |
| **When used** | Always (when `aggregation=true`) | Multi-GPU single-machine jobs | Distributed deployment (ethproofs) |

## The Final Step: VadcopFinal

After all inter-worker Recursive2 proofs are reduced to one per airgroup, the **VadcopFinal** circuit combines them:

- **`recursion.rs:552-635`** — `generate_vadcop_final_proof()`: Takes one Recursive2 proof per airgroup + publics + proof_values, generates a single VadcopFinal STARK proof
- **`proofman.rs:2088-2091`** — In the MPI path, rank 0 calls `receive_aggregated_proofs([], true, true)` which triggers VadcopFinal generation
- **`proofman.rs:2102-2118`** — If `final_snark=true` (currently never triggered in ethproofs), would chain RecursiveF → fflonk
