protocol.prover
===============

.. py:module:: protocol.prover

.. autoapi-nested-parse::

   Top-level STARK proof generation.



Attributes
----------

.. autoapisummary::

   protocol.prover.MerkleRoot
   protocol.prover.StageNum
   protocol.prover.ChallengesDict
   protocol.prover.DEFAULT_LATTICE_SIZE
   protocol.prover.POSEIDON2_LINEAR_HASH_WIDTH


Functions
---------

.. autoapisummary::

   protocol.prover.derive_challenges_for_stage
   protocol.prover.gen_proof


Module Contents
---------------

.. py:data:: MerkleRoot

.. py:data:: StageNum

.. py:data:: ChallengesDict

.. py:data:: DEFAULT_LATTICE_SIZE
   :value: 368


.. py:data:: POSEIDON2_LINEAR_HASH_WIDTH
   :value: 16


.. py:function:: derive_challenges_for_stage(transcript: primitives.transcript.Transcript, challenges_map: list[primitives.pol_map.ChallengeMap], stage: int) -> ChallengesDict

   Derive all challenges for a stage from the transcript.

   Args:
       transcript: Fiat-Shamir transcript for challenge generation
       challenges_map: List of challenge specifications from AIR
       stage: Stage number to derive challenges for

   Returns:
       Dict mapping challenge name to FF3 value


.. py:function:: gen_proof(air_config: protocol.air_config.AirConfig, trace: numpy.ndarray, const_pols: numpy.ndarray, const_pols_extended: numpy.ndarray, public_inputs: numpy.ndarray | None = None) -> dict

   Generate complete STARK proof via VADCOP protocol.

   Commits stage-1 witness, derives global challenge via lattice expansion,
   then runs stages 2 through FRI to produce the full proof.

   Args:
       air_config: AIR configuration with stark_info and global_info
       trace: Stage 1 witness trace buffer (N * cm1_cols)
       const_pols: Constant polynomials on base domain
       const_pols_extended: Constant polynomials on extended domain
       public_inputs: Public inputs array (optional)

   Returns:
       Dictionary containing serialized proof, including global_challenge.


