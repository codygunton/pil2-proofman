witness.u16_air
===============

.. py:module:: witness.u16_air

.. autoapi-nested-parse::

   U16Air AIR witness generation.

   U16Air proves U16 range lookups used by SimpleLeft. The table covers all 65536 U16
   values (0–65535) packed four per row across 16384 rows:

     Row i covers values: [4i, 4i+1, 4i+2, 4i+3]
     Column mul[j] at row i: count of value 4i+j

   SimpleLeft's column subject to U16 range check (bus id 101):
     k[1]: range_check(k[1], 0, 65535)
     Also: k[3] range check via 256-k[3] contributes to U16 space

   Stage-2 intermediates and grand sums are handled by the bytecode adapter.



Classes
-------

.. autoapisummary::

   witness.u16_air.U16AirWitness


Module Contents
---------------

.. py:class:: U16AirWitness

   Bases: :py:obj:`witness.base.WitnessModule`


   Stage-1 witness generator for U16Air AIR.

   Computes multiplicity columns mul[0..3] by counting how many times each U16
   value (0–65535) appears in SimpleLeft's k[1] column (and related columns).

   For byte-identical C++ comparison tests, Stage-1 trace is loaded directly
   from C++ test vectors and this module is not invoked.


   .. py:method:: compute_trace(simple_left_k1: numpy.ndarray, simple_left_k3: numpy.ndarray, N: int = 16384) -> numpy.ndarray
      :staticmethod:


      Compute U16Air's cm1 trace from SimpleLeft's U16 range-check columns.

      Args:
          simple_left_k1: SimpleLeft's k[1] column (8 elements, values 0..65535)
          simple_left_k3: SimpleLeft's k[3] column (8 elements); contributes
              256-k[3] to U16 range (values 1..256)
          N: Trace size = 16384 rows

      Returns:
          cm1 buffer (16384 * 4 field elements) interleaved as [mul0_0, ..., mul3_0, ...]
          mul[j] at row i = count of value (4*i + j) across all U16 sources



   .. py:method:: compute_intermediates(ctx: constraints.base.ConstraintContext) -> dict[str, dict[int, primitives.field.FF3Poly]]

      Delegated to bytecode adapter; this module only computes Stage 1.



   .. py:method:: compute_grand_sums(ctx: constraints.base.ConstraintContext) -> dict[str, primitives.field.FF3Poly]

      Delegated to bytecode adapter; this module only computes Stage 1.



