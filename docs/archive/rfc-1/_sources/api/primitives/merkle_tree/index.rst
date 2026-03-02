primitives.merkle_tree
======================

.. py:module:: primitives.merkle_tree

.. autoapi-nested-parse::

   Merkle tree commitment using Poseidon2.



Attributes
----------

.. autoapisummary::

   primitives.merkle_tree.HASH_SIZE
   primitives.merkle_tree.MerkleRoot
   primitives.merkle_tree.LeafData


Classes
-------

.. autoapisummary::

   primitives.merkle_tree.QueryProof
   primitives.merkle_tree.MerkleTree


Functions
---------

.. autoapisummary::

   primitives.merkle_tree.transpose_for_merkle


Module Contents
---------------

.. py:data:: HASH_SIZE
   :value: 4


.. py:data:: MerkleRoot

.. py:data:: LeafData

.. py:class:: QueryProof

   Query proof containing leaf values and Merkle authentication path.

   Corresponds to C++ MerkleProof in proof_stark.hpp lines 39-69.

   Attributes:
       v: Leaf values at query index - list of columns, each column is a list of elements
          For base field polynomials: [[val1], [val2], ...] (one element per column)
          For extension field: [[v0, v1, v2], ...] (FIELD_EXTENSION elements per column)
       mp: Merkle path - list of sibling hashes per level, from leaf to root
          Each level has (arity - 1) * HASH_SIZE elements


   .. py:attribute:: v
      :type:  list[list[int]]
      :value: []



   .. py:attribute:: mp
      :type:  list[list[int]]
      :value: []



.. py:function:: transpose_for_merkle(data: list[int], height: int, width: int, elem_size: int) -> list[int]

   Transpose data layout for Merkle tree construction.

   Reorders elements so that those belonging to the same Merkle leaf are contiguous.
   This matches the pil2-stark C++ memory layout convention.


.. py:class:: MerkleTree(arity: int = 4, last_level_verification: int = 0, custom: bool = False)

   Variable-arity Merkle tree using Poseidon2 hashing.


   .. py:attribute:: arity
      :value: 4



   .. py:attribute:: last_level_verification
      :value: 0



   .. py:attribute:: custom
      :value: False



   .. py:attribute:: n_field_elements
      :value: 4



   .. py:attribute:: sponge_width
      :value: 16



   .. py:attribute:: height
      :value: 0



   .. py:attribute:: width
      :value: 0



   .. py:attribute:: nodes
      :type:  list[int]
      :value: []



   .. py:attribute:: num_nodes
      :value: 0



   .. py:attribute:: source_data
      :type:  list[int] | None
      :value: None



   .. py:attribute:: n_cols
      :type:  int
      :value: 0



   .. py:method:: merkelize(source: LeafData, height: int, width: int, n_cols: int = 0) -> None

      Build Merkle tree from source data.

      Args:
          source: Flattened leaf data (height * width elements)
          height: Number of leaves (rows)
          width: Elements per leaf (columns * elem_size)
          n_cols: Number of polynomial columns (for query proof extraction)



   .. py:method:: get_root() -> MerkleRoot

      Return the Merkle root commitment.



   .. py:method:: get_group_proof(idx: int) -> list[int]

      Generate Merkle proof (siblings only) for leaf at index.



   .. py:method:: get_query_proof(idx: int, elem_size: int = 1) -> QueryProof

      Extract complete query proof with leaf values and Merkle path.

      This is the main method for generating query proofs for STARK proofs.
      It returns both the polynomial values at the query index and the
      Merkle authentication path.

      Args:
          idx: Query index (leaf index in the tree)
          elem_size: Elements per column (1 for base field, 3 for extension)

      Returns:
          QueryProof with:
          - v: List of column values at idx, each is [elem_size] elements
          - mp: List of sibling hashes per level, structured for C++ compatibility

      Raises:
          ValueError: If source_data not available or idx out of range



   .. py:method:: get_last_level_nodes() -> list[int]

      Extract last level verification nodes.

      When lastLevelVerification > 0, the verifier needs access to
      the internal nodes at (total_levels - lastLevelVerification) from bottom.
      This is equivalent to lastLevelVerification levels below the root.

      Returns:
          List of arity^lastLevelVerification * HASH_SIZE elements,
          or empty list if lastLevelVerification == 0.
          The actual nodes are at the beginning, followed by zero padding
          if the actual node count is less than arity^lastLevelVerification.



   .. py:method:: verify_merkle_root(root: MerkleRoot, level: list[int], height: int, last_level_verification: int, arity: int, sponge_width: int) -> bool
      :staticmethod:


      Verify Merkle root from last-level nodes.

      C++ reference: merkleTreeGL.hpp lines 70-99

      Computes the root by hashing up from the last level and compares
      against the expected root.

      Args:
          root: Expected root (HASH_SIZE elements)
          level: Last level nodes (num_nodes * HASH_SIZE elements)
          height: Tree height (number of leaves)
          last_level_verification: Number of levels to skip from bottom
          arity: Tree arity (2, 3, or 4)
          sponge_width: Hash sponge width

      Returns:
          True if computed root matches expected root



   .. py:method:: verify_group_proof(root: MerkleRoot, proof: list[list[int]], idx: int, leaf_data: LeafData) -> bool

      Verify Merkle proof for a leaf.



   .. py:method:: get_merkle_proof_length() -> int

      Number of levels in a Merkle proof.



   .. py:method:: get_num_siblings() -> int

      Number of sibling elements per proof level.



   .. py:method:: get_merkle_proof_size() -> int

      Total size of a Merkle proof in field elements.



