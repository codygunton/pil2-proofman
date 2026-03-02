protocol.global_info
====================

.. py:module:: protocol.global_info

.. autoapi-nested-parse::

   GlobalInfo parser for pilout.globalInfo.json configuration.



Classes
-------

.. autoapisummary::

   protocol.global_info.GlobalInfo


Module Contents
---------------

.. py:class:: GlobalInfo

   Global configuration from pilout.globalInfo.json.

   Matches C++ GlobalInfo struct from common/src/global_info.rs

   Fields:
       name: Build name (e.g., "build")
       curve: Curve type ("None", "BN128", "BLS12-381")
       lattice_size: Size for lattice expansion (368 for CurveType::None)
       n_publics: Number of public inputs
       num_challenges: Challenge counts per stage
       transcript_arity: Poseidon2 transcript arity (typically 4)


   .. py:attribute:: name
      :type:  str


   .. py:attribute:: curve
      :type:  str


   .. py:attribute:: lattice_size
      :type:  int


   .. py:attribute:: n_publics
      :type:  int


   .. py:attribute:: num_challenges
      :type:  list[int]


   .. py:attribute:: transcript_arity
      :type:  int


   .. py:attribute:: air_groups
      :type:  list[str] | None
      :value: None



   .. py:attribute:: airs
      :type:  list[list[Any]] | None
      :value: None



   .. py:attribute:: agg_types
      :type:  list[list[Any]] | None
      :value: None



   .. py:attribute:: publics_map
      :type:  list[Any] | None
      :value: []



   .. py:attribute:: proof_values_map
      :type:  list[Any] | None
      :value: []



   .. py:method:: from_json(path: str) -> GlobalInfo
      :classmethod:


      Load from pilout.globalInfo.json file.

      Example JSON structure:
      {
        "name": "build",
        "curve": "None",
        "latticeSize": 368,
        "nPublics": 0,
        "numChallenges": [0, 2],
        "transcriptArity": 4,
        "air_groups": ["Simple"],
        "publicsMap": [],
        "proofValuesMap": []
      }



   .. py:method:: default() -> GlobalInfo
      :classmethod:


      Create default GlobalInfo for tests without globalInfo.json.

      Uses latticeSize=368 which is standard for CurveType::None.



