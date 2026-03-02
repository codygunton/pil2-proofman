protocol.pcs
============

.. py:module:: protocol.pcs

.. autoapi-nested-parse::

   FRI Polynomial Commitment Scheme.



Attributes
----------

.. autoapisummary::

   protocol.pcs.EvalPoly
   protocol.pcs.Nonce
   protocol.pcs.QueryIndex


Classes
-------

.. autoapisummary::

   protocol.pcs.FriPcsConfig
   protocol.pcs.FriProof
   protocol.pcs.FriPcs


Module Contents
---------------

.. py:data:: EvalPoly

.. py:data:: Nonce

.. py:data:: QueryIndex

.. py:class:: FriPcsConfig

   FRI PCS parameters.


   .. py:attribute:: n_bits_ext
      :type:  int


   .. py:attribute:: fri_round_log_sizes
      :type:  list[int]


   .. py:attribute:: n_queries
      :type:  int


   .. py:attribute:: merkle_arity
      :type:  int
      :value: 4



   .. py:attribute:: pow_bits
      :type:  int
      :value: 16



   .. py:attribute:: last_level_verification
      :type:  int
      :value: 0



   .. py:attribute:: hash_commits
      :type:  bool
      :value: True



   .. py:attribute:: transcript_arity
      :type:  int
      :value: 4



   .. py:attribute:: merkle_tree_custom
      :type:  bool
      :value: False



.. py:class:: FriProof

   FRI proof: roots, final polynomial, grinding nonce, and query proofs.


   .. py:attribute:: fri_roots
      :type:  list[primitives.merkle_tree.MerkleRoot]
      :value: []



   .. py:attribute:: final_pol
      :type:  primitives.field.FF3Poly


   .. py:attribute:: nonce
      :type:  Nonce
      :value: 0



   .. py:attribute:: query_proofs
      :type:  list[list[primitives.merkle_tree.QueryProof]]
      :value: []



   .. py:attribute:: query_indices
      :type:  list[QueryIndex]
      :value: []



.. py:class:: FriPcs(config: FriPcsConfig)

   FRI Polynomial Commitment Scheme.


   .. py:attribute:: config


   .. py:attribute:: fri_trees


   .. py:method:: prove(polynomial: EvalPoly, transcript: primitives.transcript.Transcript, stage_trees: list[primitives.merkle_tree.MerkleTree] | None = None) -> FriProof

      Generate FRI proof: commit-fold, finalize, grind, query.



   .. py:method:: get_fri_tree(fri_round: int) -> primitives.merkle_tree.MerkleTree

      Get Merkle tree for given FRI layer.



