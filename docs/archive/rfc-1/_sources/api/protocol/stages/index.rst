protocol.stages
===============

.. py:module:: protocol.stages

.. autoapi-nested-parse::

   Polynomial commitment stage orchestration.

   This module provides the PolynomialCommitter class which manages the polynomial commitment
   phase of STARK proof generation. For each "stage" of the protocol, PolynomialCommitter:

   1. Takes polynomial evaluations from explicit buffers
   2. Extends them to the evaluation domain (via NTT)
   3. Builds a Merkle tree commitment
   4. Returns the Merkle root

   Stages in the STARK protocol:
   - Stage 1: Witness polynomials (execution trace)
   - Stage 2: Intermediate polynomials (lookup/permutation support)
   - Stage Q (nStages+1): Quotient polynomial (constraint checking)

   The Merkle trees are retained for later query proof generation during FRI.



Attributes
----------

.. autoapisummary::

   protocol.stages.BufferOffset
   protocol.stages.StageIndex
   protocol.stages.ChallengesDict


Classes
-------

.. autoapisummary::

   protocol.stages.PolynomialCommitter


Functions
---------

.. autoapisummary::

   protocol.stages.calculate_witness


Module Contents
---------------

.. py:data:: BufferOffset

.. py:data:: StageIndex

.. py:data:: ChallengesDict

.. py:function:: calculate_witness(stark_info: protocol.stark_info.StarkInfo, trace: numpy.ndarray, aux_trace: numpy.ndarray, const_pols: numpy.ndarray, challenges: ChallengesDict, expressions_bin: str | None = None) -> numpy.ndarray

   Calculate witness polynomials using per-AIR witness modules.

   Computes im_cluster and gsum columns using the AIR-specific witness module.
   If the hand-written module defers Stage-2 (returns empty dicts), falls back
   to the compiled expression bytecode at expressions_bin.

   Args:
       stark_info: StarkInfo with AIR name and polynomial mappings
       trace: Stage 1 trace buffer
       aux_trace: Auxiliary trace buffer
       const_pols: Base domain constant polynomials
       challenges: Named challenges dict for stage 2
       expressions_bin: Optional path to .bin bytecode for Stage-2 fallback.
           Used when the hand-written module returns empty dicts from
           compute_intermediates/compute_grand_sums.

   Returns:
       airgroup_values: Cross-AIR accumulator values (gsum/gprod boundaries)
           Array of FF3 elements in interleaved format, empty for standalone AIRs


.. py:class:: PolynomialCommitter(setupCtx: protocol.air_config.AirConfig)

   Polynomial commitment orchestrator for STARK proof generation.

   The PolynomialCommitter class manages polynomial commitment via Merkle trees:
   - Maintains one Merkle tree per polynomial commitment stage
   - Handles polynomial extension (NTT) and tree construction
   - Provides query proof generation for FRI verification

   NTT (Number Theoretic Transform) objects are created internally to hide
   FFT implementation details from the protocol layer. The protocol only
   needs to know about polynomial commitment, not how it's implemented.

   Attributes:
       setupCtx: AIR configuration with domain sizes and parameters
       stage_trees: Merkle trees for each commitment stage (1, 2, Q)
       const_tree: Merkle tree for constant polynomials (if present)


   .. py:attribute:: setupCtx


   .. py:attribute:: stage_trees
      :type:  dict[StageIndex, primitives.merkle_tree.MerkleTree]


   .. py:attribute:: const_tree
      :type:  primitives.merkle_tree.MerkleTree | None
      :value: None



   .. py:method:: build_const_tree(constPolsExtended: numpy.ndarray) -> primitives.merkle_tree.MerkleRoot

      Build Merkle tree for constant polynomials.



   .. py:method:: get_const_query_proof(idx: int, elem_size: int = 1) -> primitives.merkle_tree.QueryProof

      Extract query proof from constant polynomial tree.



   .. py:method:: extendAndMerkelize(step: int, trace: numpy.ndarray, auxTrace: numpy.ndarray) -> primitives.merkle_tree.MerkleRoot

      Extend polynomial from N to N_ext and build Merkle tree commitment.



   .. py:method:: get_stage_query_proof(step: int, idx: int, elem_size: int = 1) -> primitives.merkle_tree.QueryProof

      Extract query proof from a stored stage tree.



   .. py:method:: get_stage_tree(step: int) -> primitives.merkle_tree.MerkleTree

      Get the Merkle tree for a specific stage.



   .. py:method:: commitStage(step: int, trace: numpy.ndarray, auxTrace: numpy.ndarray) -> primitives.merkle_tree.MerkleRoot

      Execute a commitment stage (witness or quotient polynomial).

      Args:
          step: Stage number (1 = witness, 2 = intermediate, n_stages+1 = quotient)
          trace: Stage 1 trace buffer
          auxTrace: Auxiliary trace buffer

      Returns:
          Merkle root (HASH_SIZE integers)



   .. py:method:: computeFriPol(auxTrace: numpy.ndarray) -> None

      Compute quotient polynomial Q for FRI commitment.

      1. INTT constraint polynomial (extended domain -> coefficients)
      2. Apply shift factors S[p] = (shift^-1)^(N*p) for coset correction
      3. Reorganize from degree-major to evaluation-major layout
      4. NTT back to extended domain evaluations



   .. py:method:: calculateQuotientPolynomial(trace: numpy.ndarray, aux_trace: numpy.ndarray, const_pols_extended: numpy.ndarray, challenges: ChallengesDict, prover_helpers: protocol.air_config.ProverHelpers, airgroup_values: numpy.ndarray | None = None) -> None

      Evaluate constraint expression across the extended domain.

      Args:
          trace: Stage 1 trace buffer
          aux_trace: Auxiliary trace buffer
          const_pols_extended: Extended constant polynomials
          challenges: Named challenges dict
          prover_helpers: ProverHelpers with zerofiers
          airgroup_values: Airgroup values array (interleaved FF3)



   .. py:method:: calculateFRIPolynomial(trace: numpy.ndarray, aux_trace: numpy.ndarray, const_pols_extended: numpy.ndarray, evals: numpy.ndarray, xi: primitives.field.FF3, vf1: primitives.field.FF3, vf2: primitives.field.FF3, prover_helpers: protocol.air_config.ProverHelpers) -> None

      Compute FRI polynomial F = linear combination of committed polys at xi*w^offset.

      Args:
          trace: Stage 1 trace buffer
          aux_trace: Auxiliary trace buffer
          const_pols_extended: Extended constant polynomials
          evals: Polynomial evaluations array
          xi: Evaluation point challenge
          vf1: FRI batching challenge 1
          vf2: FRI batching challenge 2
          prover_helpers: ProverHelpers with precomputed domain values



   .. py:method:: computeLEv(xiChallenge: numpy.ndarray, openingPoints: list) -> numpy.ndarray

      Compute Lagrange evaluation coefficients.

      LEv[k, i] = ((xi * w^openingPoint[i]) * shift^-1)^k

      Vectorized: compute all opening points in parallel for each k.

      Args:
          xiChallenge: Challenge point (FF3 as numpy array)
          openingPoints: List of opening point indices

      Returns:
          Lagrange evaluation coefficients in flattened numpy array



   .. py:method:: computeEvals(trace: numpy.ndarray, aux_trace: numpy.ndarray, const_pols_extended: numpy.ndarray, evals: numpy.ndarray, LEv: numpy.ndarray, openingPoints: list) -> None

      Compute polynomial evaluations at opening points.



   .. py:method:: evmap(trace: numpy.ndarray, aux_trace: numpy.ndarray, const_pols_extended: numpy.ndarray, evals: numpy.ndarray, LEv: numpy.ndarray, openingPoints: list) -> None

      Evaluate polynomials at opening points using vectorized operations.



