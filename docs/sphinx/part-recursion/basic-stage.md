(sec:basic)=
# Basic STARK Proof (Stage 1)

Each AIR instance produces an independent STARK proof using the protocol
described in the *STARK Protocol*.

1. The prover commits stage-1 polynomials and computes a
   contribution $\kappa^{(a)}$ for challenge aggregation
   (see the *STARK Protocol*, Multi-AIR Challenge Binding).

2. After the global challenge $\chi$ is derived from all contributions
   (see the *STARK Protocol*, Challenge Aggregation),
   each AIR seeds its transcript with $\chi$ and runs the full
   commitment and query phases.

3. The output is a binary proof $\pi^{(a)}_{\mathrm{Basic}}$
   containing Merkle roots, polynomial evaluations,
   FRI layers, proof-of-work nonce, and Merkle opening proofs.
