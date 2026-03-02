protocol.fri
============

.. py:module:: protocol.fri

.. autoapi-nested-parse::

   FRI folding protocol.



Classes
-------

.. autoapisummary::

   protocol.fri.FRI


Module Contents
---------------

.. py:class:: FRI

   FRI protocol: folding, commitment, and verification.


   .. py:method:: fold(fri_round: int, pol: primitives.field.FF3Poly, challenge: list[int], n_bits_ext: int, prev_bits: int, current_bits: int) -> primitives.field.FF3Poly
      :staticmethod:


      Fold polynomial by factor 2^(prev_bits - current_bits) using challenge.



   .. py:method:: merkelize(fri_round: int, pol: primitives.field.FF3Poly, tree: primitives.merkle_tree.MerkleTree, current_bits: int, next_bits: int) -> primitives.merkle_tree.MerkleRoot
      :staticmethod:


      Commit to FRI layer via Merkle tree.



   .. py:method:: verify_fold(value: list[int], fri_round: int, n_bits_ext: int, current_bits: int, prev_bits: int, challenge: list[int], idx: int, siblings: list[list[int]]) -> primitives.field.FF3
      :staticmethod:


      Verify fold step: recompute expected value from siblings and challenge.



   .. py:method:: prove_queries(queries: list[int], trees: list[primitives.merkle_tree.MerkleTree], current_bits: int) -> list[list[int]]
      :staticmethod:


      Generate Merkle proofs for query indices.



