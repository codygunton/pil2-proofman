primitives.pol_map
==================

.. py:module:: primitives.pol_map

.. autoapi-nested-parse::

   Polynomial mapping data structures.

   This module provides faithful Python translations of the C++ mapping structures
   from pil2-stark/src/starkpil/stark_info.hpp.

   These structures describe how polynomials are organized in memory and how they
   map to different stages of the STARK proof system.



Classes
-------

.. autoapisummary::

   primitives.pol_map.PolynomialId
   primitives.pol_map.FieldType
   primitives.pol_map.PolMap
   primitives.pol_map.EvMap
   primitives.pol_map.ChallengeMap
   primitives.pol_map.CustomCommits
   primitives.pol_map.Boundary


Module Contents
---------------

.. py:class:: PolynomialId

   Bases: :py:obj:`NamedTuple`


   Identifies a polynomial in verification context.

   Used as dict key for buffer-free polynomial access in the verifier.
   The verifier parses proof data into dict[PolynomialId, FF3] where
   values are vectorized across all query points.

   Attributes:
       type: 'cm' (committed), 'const' (constant), 'custom' (custom commit)
       name: Polynomial name from starkinfo (e.g., 'a', 'gsum')
       index: Array index for multi-instance polynomials (0 for scalars)
       stage: Stage number (1+ for committed, 0 for constants)


   .. py:attribute:: type
      :type:  str


   .. py:attribute:: name
      :type:  str


   .. py:attribute:: index
      :type:  int


   .. py:attribute:: stage
      :type:  int


.. py:class:: FieldType

   Bases: :py:obj:`enum.Enum`


   Field element type for type-safe field discrimination.


   .. py:attribute:: FF
      :value: 1



   .. py:attribute:: FF3
      :value: 3



.. py:class:: PolMap

   Maps a polynomial to its location in the proof system.


   .. py:attribute:: stage
      :type:  int


   .. py:attribute:: name
      :type:  str


   .. py:attribute:: field_type
      :type:  FieldType


   .. py:attribute:: stage_pos
      :type:  int


   .. py:attribute:: stage_id
      :type:  int


   .. py:attribute:: im_pol
      :type:  bool
      :value: False



   .. py:attribute:: lengths
      :type:  list[int]
      :value: []



   .. py:attribute:: commit_id
      :type:  int
      :value: 0



   .. py:attribute:: exp_id
      :type:  int
      :value: 0



   .. py:attribute:: pols_map_id
      :type:  int
      :value: 0



   .. py:property:: dim
      :type: int


      Backwards compatibility: returns 1 for FF, 3 for FF3.



.. py:class:: EvMap

   Maps an evaluation point to its polynomial source.

   Corresponds to C++ class EvMap in stark_info.hpp (lines 108-135).

   Attributes:
       type: Source type (cm=committed, const_=constant, custom=custom commit)
       id: Polynomial ID within source type
       row_offset: Row offset for evaluation (-1, 0, or 1). C++ name: "prime"
       commit_id: Commitment ID (only for custom type)
       opening_pos: Position in opening points array


   .. py:class:: Type

      Bases: :py:obj:`enum.Enum`


      Evaluation source type.

      Corresponds to C++ enum eType in EvMap (lines 111-116).


      .. py:attribute:: cm
         :value: 0



      .. py:attribute:: const_
         :value: 1



      .. py:attribute:: custom
         :value: 2




   .. py:attribute:: type
      :type:  EvMap.Type


   .. py:attribute:: id
      :type:  int


   .. py:attribute:: row_offset
      :type:  int


   .. py:attribute:: commit_id
      :type:  int
      :value: 0



   .. py:attribute:: opening_pos
      :type:  int
      :value: 0



   .. py:method:: type_from_string(s: str) -> EvMap
      :staticmethod:


      Convert string to Type enum.

      Corresponds to C++ EvMap::setType() (lines 124-134).

      Args:
          s: Type string ("cm", "const", or "custom")

      Returns:
          Corresponding Type enum value

      Raises:
          ValueError: If string is not a valid type



.. py:class:: ChallengeMap

   Maps a challenge to its derivation stage.


   .. py:attribute:: name
      :type:  str


   .. py:attribute:: stage
      :type:  int


   .. py:attribute:: field_type
      :type:  FieldType


   .. py:attribute:: stage_id
      :type:  int


   .. py:property:: dim
      :type: int


      Backwards compatibility: returns 1 for FF, 3 for FF3.



.. py:class:: CustomCommits

   Custom commitment configuration.

   Corresponds to C++ class CustomCommits in stark_info.hpp (lines 52-58).

   Attributes:
       name: Custom commit name
       stage_widths: Number of columns at each stage
       public_values: Indices of public values used


   .. py:attribute:: name
      :type:  str


   .. py:attribute:: stage_widths
      :type:  list[int]
      :value: []



   .. py:attribute:: public_values
      :type:  list[int]
      :value: []



.. py:class:: Boundary

   Constraint boundary specification.

   Corresponds to C++ class Boundary in stark_info.hpp (lines 60-66).

   Attributes:
       name: Boundary name (e.g., "everyRow", "everyFrame")
       offset_min: Minimum row offset (only for "everyFrame")
       offset_max: Maximum row offset (only for "everyFrame")


   .. py:attribute:: name
      :type:  str


   .. py:attribute:: offset_min
      :type:  int
      :value: 0



   .. py:attribute:: offset_max
      :type:  int
      :value: 0



