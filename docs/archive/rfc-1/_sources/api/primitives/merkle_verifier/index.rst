primitives.merkle_verifier
==========================

.. py:module:: primitives.merkle_verifier

.. autoapi-nested-parse::

   Merkle tree verification abstraction.

   This module provides a clean interface for Merkle tree verification that hides
   the complexity of the `last_level_verification` optimization internally.

   The `last_level_verification` optimization allows skipping proof verification
   for the top N levels of the tree by including pre-computed hashes at that level
   directly in the proof. This reduces proof size for each query while adding a
   small fixed overhead.



Attributes
----------

.. autoapisummary::

   primitives.merkle_verifier.MerkleRoot
   primitives.merkle_verifier.SiblingHash


Classes
-------

.. autoapisummary::

   primitives.merkle_verifier.MerkleConfig
   primitives.merkle_verifier.MerkleVerifier


Module Contents
---------------

.. py:data:: MerkleRoot

.. py:data:: SiblingHash

.. py:class:: MerkleConfig

   Merkle tree configuration for verification.

   Frozen dataclass that captures all tree parameters needed for verification.
   The sponge_width and n_siblings are computed properties.

   Attributes:
       arity: Tree branching factor (2, 3, or 4)
       domain_bits: Log2 of the number of leaves
       last_level_verification: Number of top levels to skip in per-query verification


   .. py:attribute:: arity
      :type:  int


   .. py:attribute:: domain_bits
      :type:  int


   .. py:attribute:: last_level_verification
      :type:  int


   .. py:property:: sponge_width
      :type: int


      Poseidon2 sponge width for this arity.



   .. py:property:: n_siblings
      :type: int


      Number of sibling levels in each query proof.



   .. py:property:: siblings_per_level
      :type: int


      Number of sibling hash elements per level.



.. py:class:: MerkleVerifier(root: MerkleRoot, config: MerkleConfig, last_level_nodes: list[int] | None = None)

   Merkle tree verifier with encapsulated last_level_verification logic.

   This class provides a clean verify_query() interface that hides whether
   verification checks against the root directly or against pre-verified
   last-level nodes.

   Usage:
       verifier = MerkleVerifier.for_stage(proof, stark_info, root, stage=1)
       for query_idx in range(n_queries):
           if not verifier.verify_query(query_idx, leaf_values, siblings):
               return False
       return True


   .. py:attribute:: root


   .. py:attribute:: config


   .. py:method:: for_stage(proof: protocol.proof.STARKProof, stark_info: protocol.stark_info.StarkInfo, root: MerkleRoot, stage: int) -> MerkleVerifier
      :classmethod:


      Create verifier for a stage commitment tree.

      Args:
          proof: STARK proof containing last_levels
          stark_info: STARK configuration
          root: Expected root for this stage
          stage: Stage number (1-indexed)

      Returns:
          Configured MerkleVerifier for this stage



   .. py:method:: for_const(proof: protocol.proof.STARKProof, stark_info: protocol.stark_info.StarkInfo, verkey: MerkleRoot) -> MerkleVerifier
      :classmethod:


      Create verifier for constant polynomial tree.

      Args:
          proof: STARK proof containing last_levels
          stark_info: STARK configuration
          verkey: Verification key (root of constant polynomial tree)

      Returns:
          Configured MerkleVerifier for constant tree



   .. py:method:: for_custom_commit(proof: protocol.proof.STARKProof, stark_info: protocol.stark_info.StarkInfo, root: MerkleRoot, commit_idx: int) -> MerkleVerifier
      :classmethod:


      Create verifier for a custom commit tree.

      Custom commits are additional polynomial commitments beyond the standard
      stage trees (e.g., the Rom AIR commits its lookup table separately).
      Each custom commit has its own Merkle tree stored at a distinct index:
      tree_idx = n_stages + 2 + commit_idx (after stage trees and const tree).

      This is separate from for_stage/for_const because:
      - The tree index formula differs (stage uses stage-1, const uses n_stages+1)
      - The root comes from public inputs rather than the proof or verkey
      - Only certain AIRs have custom commits (e.g., Rom in Zisk)

      Args:
          proof: STARK proof containing last_levels
          stark_info: STARK configuration
          root: Expected root, reconstructed from publics[custom_commit.public_values]
          commit_idx: Index of the custom commit (0-based)

      Returns:
          Configured MerkleVerifier for this custom commit tree



   .. py:method:: for_fri_step(proof: protocol.proof.STARKProof, stark_info: protocol.stark_info.StarkInfo, step: int) -> MerkleVerifier
      :classmethod:


      Create verifier for a FRI folding step tree.

      Args:
          proof: STARK proof containing FRI trees
          stark_info: STARK configuration
          step: FRI step number (1-indexed, since step 0 is the initial domain)

      Returns:
          Configured MerkleVerifier for this FRI step



   .. py:method:: verify_query(query_index: int, leaf_values: list[int], siblings: list[list[int]]) -> bool

      Verify a single query proof.

      This method hides the last_level_verification logic internally:
      - If last_level_verification == 0: verify up to root
      - Otherwise: verify up to last-level boundary, check against pre-verified nodes

      The last-level nodes are verified once (lazily) against the root on first query.

      Args:
          query_index: Index of the leaf being verified
          leaf_values: Leaf data to hash
          siblings: Sibling hashes per level (n_siblings levels)

      Returns:
          True if query proof is valid



