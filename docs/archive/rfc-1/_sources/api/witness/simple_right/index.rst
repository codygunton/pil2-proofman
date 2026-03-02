witness.simple_right
====================

.. py:module:: witness.simple_right

.. autoapi-nested-parse::

   SimpleRight AIR witness generation.

   SimpleRight proves two bus operations against values that SimpleLeft assumes:

   - permutation_proves(2, [a, b]): [a, b] is a permutation of SimpleLeft's [e, f]
     (SimpleLeft assumes bus 2 with [e,f]; SimpleRight proves it by providing the
     same multiset in a potentially different order)

   - lookup_proves(3, [c, d], mul): [c, d] are the distinct lookup table entries
     for bus 3; mul counts how many times each row's [c,d] appears in SimpleLeft's
     [g, h] column pair.

   Stage-2 intermediates and grand sums are handled by the bytecode adapter.



Classes
-------

.. autoapisummary::

   witness.simple_right.SimpleRightWitness


Module Contents
---------------

.. py:class:: SimpleRightWitness

   Bases: :py:obj:`witness.base.WitnessModule`


   Stage-1 witness generator for SimpleRight AIR.

   SimpleRight proves the permutation and lookup operations that SimpleLeft
   assumes. Given SimpleLeft's witness columns, this derives consistent
   SimpleRight values for use in purely-Python round-trip tests.

   For byte-identical C++ comparison tests, Stage-1 trace is loaded directly
   from C++ test vectors and this module is not invoked.


   .. py:method:: compute_trace(simple_left_e: numpy.ndarray, simple_left_f: numpy.ndarray, simple_left_g: numpy.ndarray, simple_left_h: numpy.ndarray, N: int = 8) -> numpy.ndarray
      :staticmethod:


      Compute SimpleRight's cm1 trace from SimpleLeft's Stage-1 columns.

      Args:
          simple_left_e: SimpleLeft's e column (N field elements)
          simple_left_f: SimpleLeft's f column (N field elements)
          simple_left_g: SimpleLeft's g column (N field elements)
          simple_left_h: SimpleLeft's h column (N field elements)
          N: Trace size (8 rows)

      Returns:
          cm1 buffer (N * 5 field elements) interleaved as [a0,b0,c0,d0,mul0, ...]
          Columns: [a, b, c, d, mul]



   .. py:method:: compute_intermediates(ctx: constraints.base.ConstraintContext) -> dict[str, dict[int, primitives.field.FF3Poly]]

      Delegated to bytecode adapter; this module only computes Stage 1.



   .. py:method:: compute_grand_sums(ctx: constraints.base.ConstraintContext) -> dict[str, primitives.field.FF3Poly]

      Delegated to bytecode adapter; this module only computes Stage 1.



