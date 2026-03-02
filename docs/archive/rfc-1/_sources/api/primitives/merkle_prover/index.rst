primitives.merkle_prover
========================

.. py:module:: primitives.merkle_prover

.. autoapi-nested-parse::

   Merkle tree commitment abstraction for proof generation.

   Mirrors MerkleVerifier: provides factory methods that construct properly-configured
   Merkle trees from StarkInfo, hiding arity and last_level_verification details.



Classes
-------

.. autoapisummary::

   primitives.merkle_prover.MerkleProver


Module Contents
---------------

.. py:class:: MerkleProver(config: primitives.merkle_verifier.MerkleConfig, custom: bool = False)

   Merkle tree builder with encapsulated configuration.

   Usage:
       prover = MerkleProver.for_stage(stark_info)
       root = prover.commit(data, height, n_cols)
       proof = prover.get_query_proof(idx, elem_size=1)


   .. py:attribute:: config


   .. py:method:: for_stage(stark_info: protocol.stark_info.StarkInfo) -> MerkleProver
      :classmethod:


      Create prover for stage commitment trees (cm1, cm2, ..., cmQ).



   .. py:method:: for_const(stark_info: protocol.stark_info.StarkInfo) -> MerkleProver
      :classmethod:


      Create prover for constant polynomial tree.



   .. py:method:: for_fri_step(stark_info: protocol.stark_info.StarkInfo) -> MerkleProver
      :classmethod:


      Create prover for FRI folding step trees.



   .. py:method:: commit(data: list[int], height: int, n_cols: int) -> primitives.merkle_tree.MerkleRoot

      Build Merkle tree and return root.

      Args:
          data: Flattened leaf data (height * n_cols elements)
          height: Number of leaves
          n_cols: Number of columns per leaf

      Returns:
          Merkle root (HASH_SIZE elements)



   .. py:method:: get_query_proof(idx: int, elem_size: int = 1) -> primitives.merkle_tree.QueryProof

      Get Merkle proof for a query index.



   .. py:method:: get_last_level_nodes() -> list[int]

      Get flattened last-level nodes for proof serialization.



   .. py:property:: tree
      :type: primitives.merkle_tree.MerkleTree


      Access the underlying MerkleTree (for backward compatibility).



