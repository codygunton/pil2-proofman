protocol.simple_pilout
======================

.. py:module:: protocol.simple_pilout

.. autoapi-nested-parse::

   Multi-AIR proving coordination for the Simple pilout.

   The Simple pilout contains five AIRs: SimpleLeft, SimpleRight, U8Air, U16Air,
   SpecifiedRanges. C++ proofman proves all five simultaneously and derives the
   global_challenge by element-wise accumulating each AIR's Poseidon2 lattice
   contribution before any AIR advances to Stage 2.

   prove_simple_pilout() implements the full protocol, producing byte-identical
   proofs to C++ proofman.

   Usage::

       from protocol.simple_pilout import AIRProveData, prove_simple_pilout

       proofs = prove_simple_pilout({
           'SimpleLeft': AIRProveData(air_config=..., trace=..., ...),
           ...
       })
       # proofs['SimpleLeft'] is the full proof dict for that AIR



Attributes
----------

.. autoapisummary::

   protocol.simple_pilout.LATTICE_SIZE
   protocol.simple_pilout.TRANSCRIPT_ARITY


Classes
-------

.. autoapisummary::

   protocol.simple_pilout.AIRStage1Data
   protocol.simple_pilout.SimplePiloutStage1Result
   protocol.simple_pilout.AIRProveData


Functions
---------

.. autoapisummary::

   protocol.simple_pilout.prove_simple_pilout
   protocol.simple_pilout.prove_simple_pilout_stage1


Module Contents
---------------

.. py:data:: LATTICE_SIZE
   :value: 368


.. py:data:: TRANSCRIPT_ARITY
   :value: 4


.. py:class:: AIRStage1Data

   All data needed to commit Stage 1 for one AIR in the Simple pilout.


   .. py:attribute:: air_config
      :type:  protocol.air_config.AirConfig


   .. py:attribute:: trace
      :type:  numpy.ndarray


   .. py:attribute:: const_pols
      :type:  numpy.ndarray


   .. py:attribute:: const_pols_extended
      :type:  numpy.ndarray


.. py:class:: SimplePiloutStage1Result

   Stage-1 results for all five Simple AIRs.


   .. py:attribute:: verkeys
      :type:  dict[str, list[int]]


   .. py:attribute:: stage1_commitments
      :type:  dict[str, list[int]]


   .. py:attribute:: global_challenge
      :type:  list[int]


.. py:class:: AIRProveData

   All data needed to fully prove one AIR in the Simple pilout.


   .. py:attribute:: air_config
      :type:  protocol.air_config.AirConfig


   .. py:attribute:: trace
      :type:  numpy.ndarray


   .. py:attribute:: const_pols
      :type:  numpy.ndarray


   .. py:attribute:: const_pols_extended
      :type:  numpy.ndarray


   .. py:attribute:: public_inputs
      :type:  numpy.ndarray | None
      :value: None



.. py:function:: prove_simple_pilout(air_data: dict[str, AIRProveData]) -> dict[str, dict]

   Prove all Simple pilout AIRs with the shared multi-AIR global challenge.

   Implements the full C++ proofman VADCOP protocol:
     1. Commit Stage 1 for all AIRs (exactly once per AIR).
     2. Compute each AIR's Poseidon2 lattice contribution from (verkey, root1).
     3. Accumulate contributions element-wise → shared global challenge.
     4. Run Stage 2+ for each AIR using the shared challenge.

   Args:
       air_data: Dict mapping AIR name → AIRProveData for all five Simple AIRs.

   Returns:
       Dict mapping AIR name → proof dict (same structure as gen_proof() returns).


.. py:function:: prove_simple_pilout_stage1(air_data: dict[str, AIRStage1Data]) -> SimplePiloutStage1Result

   Commit Stage 1 for all Simple pilout AIRs and derive the multi-AIR global challenge.

   Implements the C++ proofman pattern from challenge_accumulation.rs:
     1. For each AIR: build const tree (verkey) and commit Stage-1 witness (root1).
     2. For each AIR: compute Poseidon2 lattice contribution from (verkey, root1).
     3. Accumulate all contributions element-wise (mod Goldilocks prime).
     4. Hash accumulated contribution with publics → global_challenge.

   The Simple pilout has n_publics=0 and no proof_values_stage1, so only the
   five AIR contributions enter the challenge hash.

   Args:
       air_data: Dict mapping AIR name → AIRStage1Data for all five Simple AIRs.
           Keys must include: 'SimpleLeft', 'SimpleRight', 'U8Air', 'U16Air',
           'SpecifiedRanges' (order determines accumulation order).

   Returns:
       SimplePiloutStage1Result with verkeys, stage1_commitments, and global_challenge.


