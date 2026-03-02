protocol.proof
==============

.. py:module:: protocol.proof

.. autoapi-nested-parse::

   STARK proof data structures and serialization.



Attributes
----------

.. autoapisummary::

   protocol.proof.Hash


Classes
-------

.. autoapisummary::

   protocol.proof.MerkleProof
   protocol.proof.ProofTree
   protocol.proof.FriProof
   protocol.proof.STARKProof


Functions
---------

.. autoapisummary::

   protocol.proof.proof_to_json
   protocol.proof.load_proof_from_json
   protocol.proof.from_vadcop_final_bytes
   protocol.proof.from_bytes_full
   protocol.proof.to_bytes_partial
   protocol.proof.to_bytes_full
   protocol.proof.to_bytes_full_from_dict
   protocol.proof.validate_proof_structure


Module Contents
---------------

.. py:data:: Hash

.. py:class:: MerkleProof

   Merkle authentication path: leaf values and sibling hashes.


   .. py:attribute:: v
      :type:  list[list[int]]
      :value: []



   .. py:attribute:: mp
      :type:  list[list[int]]
      :value: []



.. py:class:: ProofTree

   Merkle tree commitment with query proofs.


   .. py:attribute:: root
      :type:  Hash
      :value: []



   .. py:attribute:: last_levels
      :type:  list[int]
      :value: []



   .. py:attribute:: pol_queries
      :type:  list[list[MerkleProof]]
      :value: []



.. py:class:: FriProof

   FRI opening proof: folding trees and final polynomial.


   .. py:attribute:: trees
      :type:  ProofTree


   .. py:attribute:: trees_fri
      :type:  list[ProofTree]
      :value: []



   .. py:attribute:: pol
      :type:  list[list[int]]
      :value: []



.. py:class:: STARKProof

   Complete STARK proof for a single AIR.

   Contains all components needed to verify that a prover knows a valid
   execution trace satisfying the AIR constraints.

   Attributes:
       roots: Merkle roots for each stage commitment (stages 1 to n_stages+1).
              roots[0] is stage 1 (witness), roots[-1] is quotient polynomial.
       last_levels: Pre-verified Merkle nodes for last_level_verification optimization.
                    Indexed by tree: [stage_0, ..., stage_n, const_tree].
       evals: Polynomial evaluations at challenge point xi. Each entry is
              [c0, c1, c2] coefficients of an FF3 extension field element.
       airgroup_values: Values shared across all AIRs in an airgroup (e.g., gsum_result).
                        Used for cross-AIR boundary constraints. Each is [c0, c1, c2].
       air_values: Values specific to this individual AIR instance.
                   Stage 1 values are single FF, stage 2+ are FF3 [c0, c1, c2].
       custom_commits: Names of custom commitment schemes used (if any).
       fri: FRI protocol data - folding trees, query proofs, and final polynomial.
       nonce: Grinding nonce satisfying the grinding constraint.


   .. py:attribute:: roots
      :type:  list[Hash]
      :value: []



   .. py:attribute:: last_levels
      :type:  list[list[int]]
      :value: []



   .. py:attribute:: evals
      :type:  list[list[int]]
      :value: []



   .. py:attribute:: airgroup_values
      :type:  list[list[int]]
      :value: []



   .. py:attribute:: air_values
      :type:  list[list[int]]
      :value: []



   .. py:attribute:: custom_commits
      :type:  list[str]
      :value: []



   .. py:attribute:: fri
      :type:  FriProof


   .. py:attribute:: nonce
      :type:  int
      :value: 0



.. py:function:: proof_to_json(proof: STARKProof, n_stages: int, n_field_elements: int = HASH_SIZE) -> dict[str, Any]

   Convert STARK proof to JSON-serializable dictionary.


.. py:function:: load_proof_from_json(path: str) -> tuple[STARKProof, dict[str, Any]]

   Load STARK proof from JSON file.


.. py:function:: from_vadcop_final_bytes(data: bytes, stark_info: Any) -> tuple[STARKProof, numpy.ndarray]

   Parse a VadcopFinal proof binary with embedded publics header.

   VadcopFinal proofs prepend [n_publics: u64] [publics: n_publics * u64]
   before the standard proof body (ref: recursion.rs lines 622-627).

   Returns:
       Tuple of (STARKProof, publics_array) where publics_array is numpy uint64.


.. py:function:: from_bytes_full(data: bytes, stark_info: Any) -> STARKProof

   Deserialize binary proof to STARKProof structure.

   Parses the binary format produced by C++ proof2pointer() into a structured
   STARKProof dataclass with typed fields for all proof components.


.. py:function:: to_bytes_partial(proof_dict: dict[str, Any], stark_info: Any) -> tuple[bytes, bytes]

   Serialize proof header and footer (without query proofs) for partial comparison.


.. py:function:: to_bytes_full(proof: STARKProof, stark_info: Any) -> bytes

   Serialize complete STARK proof to binary format (requires query proofs).


.. py:function:: to_bytes_full_from_dict(proof_dict: dict[str, Any], stark_info: Any) -> bytes

   Serialize proof dictionary to binary format matching C++ proof2pointer().


.. py:function:: validate_proof_structure(proof: STARKProof, stark_info: Any) -> list[str]

   Validate that proof structure matches STARK configuration.


