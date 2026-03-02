witness.u8_air
==============

.. py:module:: witness.u8_air

.. autoapi-nested-parse::

   U8Air AIR witness generation.

   U8Air proves U8 range lookups used by SimpleLeft. The table covers all 256 U8
   values (0–255) packed two per row across 128 rows:

     Row i covers values: [2i, 2i+1]
     Column mul[0] at row i: count of value 2i
     Column mul[1] at row i: count of value 2i+1

   SimpleLeft's columns subject to U8 range checks (bus ids 100):
     k[0]: range_check(k[0], 0, 255)
     k[2]: range_check(k[2]-1, 0, 254) — i.e. k[2] in 1..255
     k[3]: range_check(k[3], 0, 255) and range_check(256-k[3], 1, 256)

   Stage-2 intermediates and grand sums are handled by the bytecode adapter.



Classes
-------

.. autoapisummary::

   witness.u8_air.U8AirWitness


Module Contents
---------------

.. py:class:: U8AirWitness

   Bases: :py:obj:`witness.base.WitnessModule`


   Stage-1 witness generator for U8Air AIR.

   Computes multiplicity columns mul[0], mul[1] by counting how many times
   each U8 value (0–255) appears across SimpleLeft's U8 range-check columns.

   For byte-identical C++ comparison tests, Stage-1 trace is loaded directly
   from C++ test vectors and this module is not invoked.


   .. py:method:: compute_trace(simple_left_k0: numpy.ndarray, simple_left_k2: numpy.ndarray, simple_left_k3: numpy.ndarray, N: int = 128) -> numpy.ndarray
      :staticmethod:


      Compute U8Air's cm1 trace from SimpleLeft's U8 range-check columns.

      Args:
          simple_left_k0: SimpleLeft's k[0] column (8 elements, values 0..255)
          simple_left_k2: SimpleLeft's k[2] column (8 elements, values 1..255)
          simple_left_k3: SimpleLeft's k[3] column (8 elements, values 0..255)
          N: Trace size = 128 rows

      Returns:
          cm1 buffer (128 * 2 field elements) interleaved as [mul0_0, mul1_0, ...]
          mul[j] at row i = count of value (2*i + j) across k[0], k[2]-1, k[3]



   .. py:method:: compute_intermediates(ctx: constraints.base.ConstraintContext) -> dict[str, dict[int, primitives.field.FF3Poly]]

      Delegated to bytecode adapter; this module only computes Stage 1.



   .. py:method:: compute_grand_sums(ctx: constraints.base.ConstraintContext) -> dict[str, primitives.field.FF3Poly]

      Delegated to bytecode adapter; this module only computes Stage 1.



