protocol.stark_info
===================

.. py:module:: protocol.stark_info

.. autoapi-nested-parse::

   STARK configuration parser.

   This module provides two key configuration classes:

   **StarkStruct** (from starkstruct.json):
       Protocol-level parameters that define the STARK proof system structure.
       Includes: domain sizes (n_bits, n_bits_ext), FRI configuration (fold steps,
       blowup factor), Merkle tree parameters (arity, last_level_verification),
       and security parameters (n_queries, pow_bits).

   **StarkInfo** (from starkinfo.json):
       AIR-specific metadata that defines the constraint system and polynomial layout.
       Includes: polynomial maps (cm_pols_map, const_pols_map), evaluation map (ev_map),
       challenge derivation (challenges_map), and memory layout (map_sections_n).

   The distinction: StarkStruct is reusable across AIRs with the same domain size,
   while StarkInfo is specific to each AIR's constraint polynomial structure.



Attributes
----------

.. autoapisummary::

   protocol.stark_info.HASH_SIZE


Classes
-------

.. autoapisummary::

   protocol.stark_info.FriFoldStep
   protocol.stark_info.StarkStruct
   protocol.stark_info.StarkInfo


Module Contents
---------------

.. py:data:: HASH_SIZE
   :value: 4


.. py:class:: FriFoldStep

   FRI recursive folding layer configuration.


   .. py:attribute:: domain_bits
      :type:  int


.. py:class:: StarkStruct

   Core STARK protocol parameters.


   .. py:attribute:: n_bits
      :type:  int


   .. py:attribute:: n_bits_ext
      :type:  int


   .. py:attribute:: n_queries
      :type:  int


   .. py:attribute:: verification_hash_type
      :type:  str


   .. py:attribute:: fri_fold_steps
      :type:  list[FriFoldStep]
      :value: []



   .. py:attribute:: merkle_tree_arity
      :type:  int
      :value: 16



   .. py:attribute:: merkle_tree_custom
      :type:  bool
      :value: False



   .. py:attribute:: transcript_arity
      :type:  int
      :value: 16



   .. py:attribute:: last_level_verification
      :type:  int
      :value: 0



   .. py:attribute:: pow_bits
      :type:  int
      :value: 0



   .. py:attribute:: hash_commits
      :type:  bool
      :value: False



.. py:class:: StarkInfo

   STARK configuration loaded from starkinfo.json.


   .. py:attribute:: stark_struct


   .. py:attribute:: name
      :value: ''



   .. py:attribute:: n_publics
      :value: 0



   .. py:attribute:: n_constants
      :value: 0



   .. py:attribute:: n_stages
      :value: 0



   .. py:attribute:: proof_size
      :value: 0



   .. py:attribute:: custom_commits
      :type:  list[primitives.pol_map.CustomCommits]
      :value: []



   .. py:attribute:: cm_pols_map
      :type:  list[primitives.pol_map.PolMap]
      :value: []



   .. py:attribute:: const_pols_map
      :type:  list[primitives.pol_map.PolMap]
      :value: []



   .. py:attribute:: challenges_map
      :type:  list[primitives.pol_map.ChallengeMap]
      :value: []



   .. py:attribute:: airgroup_values_map
      :type:  list[primitives.pol_map.PolMap]
      :value: []



   .. py:attribute:: air_values_map
      :type:  list[primitives.pol_map.PolMap]
      :value: []



   .. py:attribute:: custom_commits_map
      :type:  list[list[primitives.pol_map.PolMap]]
      :value: []



   .. py:attribute:: ev_map
      :type:  list[primitives.pol_map.EvMap]
      :value: []



   .. py:attribute:: opening_points
      :type:  list[int]
      :value: []



   .. py:attribute:: boundaries
      :type:  list[primitives.pol_map.Boundary]
      :value: []



   .. py:attribute:: q_deg
      :value: 0



   .. py:attribute:: q_dim
      :value: 0



   .. py:attribute:: c_exp_id
      :value: 0



   .. py:attribute:: fri_exp_id
      :value: 0



   .. py:attribute:: map_sections_n
      :type:  dict[str, int]


   .. py:attribute:: map_offsets
      :type:  dict[tuple[str, bool], int]


   .. py:attribute:: map_total_n
      :value: 0



   .. py:attribute:: map_total_n_custom_commits_fixed
      :value: 0



   .. py:attribute:: air_values_size
      :value: 0



   .. py:attribute:: airgroup_values_size
      :value: 0



   .. py:method:: from_json(path: str) -> StarkInfo
      :classmethod:


      Load StarkInfo from starkinfo.json file.



   .. py:method:: get_offset(section: str, extended: bool) -> int

      Get buffer offset for a section.



   .. py:method:: get_n_cols(section: str) -> int

      Get number of columns in a section.



   .. py:method:: get_column_key(name: str, index: int = 0) -> tuple[str, int]

      Get the (name, index) key for a column.

      Args:
          name: Column name (e.g., 'a', 'im_cluster')
          index: Index for array columns (default 0)

      Returns:
          Tuple (name, index) for use as dict key



   .. py:method:: has_challenge(name: str) -> bool

      Check if a challenge with given name exists.



   .. py:method:: get_challenge_index(name: str) -> int

      Get the index of a challenge by name.



   .. py:method:: build_column_name_map() -> dict[str, list[int]]

      Build mapping from column names to their pols_map_id indices.

      Returns:
          Dict mapping name -> list of pols_map_id values
          e.g., {'a': [0], 'im_cluster': [16, 17, 18, 19, 20, 21]}



