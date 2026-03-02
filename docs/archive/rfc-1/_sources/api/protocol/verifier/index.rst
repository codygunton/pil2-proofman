protocol.verifier
=================

.. py:module:: protocol.verifier

.. autoapi-nested-parse::

   STARK proof verification.



Attributes
----------

.. autoapisummary::

   protocol.verifier.FRIQueryIndex
   protocol.verifier.QueryPolynomials
   protocol.verifier.EVALS_HASH_WIDTH
   protocol.verifier.QUOTIENT_STAGE_OFFSET
   protocol.verifier.EVAL_STAGE_OFFSET
   protocol.verifier.FRI_STAGE_OFFSET


Functions
---------

.. autoapisummary::

   protocol.verifier.stark_verify


Module Contents
---------------

.. py:data:: FRIQueryIndex

.. py:data:: QueryPolynomials

.. py:data:: EVALS_HASH_WIDTH
   :value: 16


.. py:data:: QUOTIENT_STAGE_OFFSET
   :value: 1


.. py:data:: EVAL_STAGE_OFFSET
   :value: 2


.. py:data:: FRI_STAGE_OFFSET
   :value: 3


.. py:function:: stark_verify(proof: protocol.proof.STARKProof, air_config: protocol.air_config.AirConfig, verkey: primitives.merkle_tree.MerkleRoot, global_challenge: primitives.field.InterleavedFF3 | None = None, publics: primitives.field.FFArray | None = None, proof_values: primitives.field.FFArray | None = None) -> bool

   Verify a STARK proof. Returns True if valid.

   Args:
       proof: Deserialized STARK proof
       air_config: AIR configuration with stark_info
       verkey: Merkle root of constant polynomial tree
       global_challenge: The 3-element transcript seed from proof['global_challenge'].
           Always provided for per-AIR VADCOP proofs.
           None only for VadcopFinal (outer coordinator verifier).
       publics: Public input values (if any)
       proof_values: Cross-AIR proof values (if any)

   Verification phases:
   1. Parse proof components (evals, air values, trace values)
   2. Reconstruct Fiat-Shamir transcript to derive challenges
   3. Run verification checks:
      - Q(xi) = C(xi): quotient matches constraint evaluation
      - FRI consistency: polynomial evaluations match commitments
      - Merkle proofs: all commitment openings are valid
      - Degree bound: final FRI polynomial has correct degree


