primitives.transcript
=====================

.. py:module:: primitives.transcript

.. autoapi-nested-parse::

   Fiat-Shamir transcript using Poseidon2 sponge.



Attributes
----------

.. autoapisummary::

   primitives.transcript.SpongeState
   primitives.transcript.Hash
   primitives.transcript.Challenge
   primitives.transcript.HASH_SIZE


Classes
-------

.. autoapisummary::

   primitives.transcript.Transcript


Module Contents
---------------

.. py:data:: SpongeState

.. py:data:: Hash

.. py:data:: Challenge

.. py:data:: HASH_SIZE
   :value: 4


.. py:class:: Transcript(arity: int = 4, custom: bool = False)

   Fiat-Shamir transcript using Poseidon2 sponge construction.


   .. py:attribute:: arity
      :value: 4



   .. py:attribute:: transcript_state_size
      :value: 4



   .. py:attribute:: transcript_pending_size
      :value: 12



   .. py:attribute:: transcript_out_size
      :value: 16



   .. py:attribute:: sponge_width
      :value: 16



   .. py:attribute:: state
      :type:  SpongeState
      :value: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]



   .. py:attribute:: pending
      :type:  list[int]
      :value: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]



   .. py:attribute:: out
      :type:  list[int]
      :value: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]



   .. py:attribute:: pending_cursor
      :value: 0



   .. py:attribute:: out_cursor
      :value: 0



   .. py:method:: put(elements: list[int] | list) -> None

      Absorb field elements into the sponge.



   .. py:method:: get_field() -> Challenge

      Squeeze 3 field elements as a cubic extension challenge.



   .. py:method:: get_state(n_outputs: int = None) -> SpongeState

      Get current sponge state (for grinding challenge).



   .. py:method:: get_permutations(n: int, n_bits: int) -> list[int]

      Generate n pseudorandom indices, each using n_bits bits.



   .. py:method:: set_state(state: list[int], out: list[int], out_cursor: int, pending_cursor: int, pending: list[int] = None) -> None

      Restore transcript state from captured values.

      Used to replay Fiat-Shamir transcript from a known state,
      enabling deterministic proof generation matching C++ output.

      Args:
          state: Sponge state (16 elements)
          out: Output buffer (16 elements)
          out_cursor: Position in output buffer
          pending_cursor: Position in pending buffer
          pending: Pending buffer contents (optional, defaults to zeros)



