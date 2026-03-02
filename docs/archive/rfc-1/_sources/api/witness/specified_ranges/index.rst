witness.specified_ranges
========================

.. py:module:: witness.specified_ranges

.. autoapi-nested-parse::

   SpecifiedRanges AIR witness generation.

   SpecifiedRanges proves custom (non-predefined) range lookups used by SimpleLeft.
   The table has 64 rows and 11 multiplicity columns covering three custom ranges:

   SimpleLeft's columns subject to custom range checks:
     k[4]: range_check(k[4], 0, 255)     → bus 102, 256 values
     k[5]: range_check(k[5], -128, -1)   → bus 103, 128 values (negative range)
     k[6]: range_check(k[6], -129, 127)  → bus 104, 257 values

   The constant polynomial columns (RANGE[0..10]) define what value each (row, col)
   cell covers. Multiplicity mul[j] at row i = number of occurrences of RANGE[j][i]
   in the corresponding SimpleLeft k column.

   Stage-2 intermediates and grand sums are handled by the bytecode adapter.



Classes
-------

.. autoapisummary::

   witness.specified_ranges.SpecifiedRangesWitness


Module Contents
---------------

.. py:class:: SpecifiedRangesWitness

   Bases: :py:obj:`witness.base.WitnessModule`


   Stage-1 witness generator for SpecifiedRanges AIR.

   Computes 11 multiplicity columns for the three custom range-check buses
   derived from SimpleLeft's k[4], k[5], k[6] columns.

   The const_pols RANGE columns define what value each (row, mul_idx) cell
   covers, so we use them directly to avoid hardcoding the layout.

   For byte-identical C++ comparison tests, Stage-1 trace is loaded directly
   from C++ test vectors and this module is not invoked.


   .. py:method:: compute_trace(simple_left_k456: numpy.ndarray, const_pols: numpy.ndarray, N: int = 64, n_constants: int = 12) -> numpy.ndarray
      :staticmethod:


      Compute SpecifiedRanges cm1 trace using const_pols RANGE layout.

      Args:
          simple_left_k456: Array of shape (8, 3) with SimpleLeft's k[4], k[5], k[6]
              columns. k[4] uses bus 102, k[5] uses bus 103, k[6] uses bus 104.
          const_pols: SpecifiedRanges constant polynomials (N * n_constants elements).
              Columns 0..10 are RANGE values defining coverage per (row, col).
              Column 11 is __L1__ (selector).
          N: Trace size = 64 rows
          n_constants: Number of constant polynomial columns (default 12)

      Returns:
          cm1 buffer (64 * 11 field elements) interleaved as [mul0_0, mul1_0, ...]
          mul[j] at row i = count of value const_pols[j][i] in the corresponding k column.



   .. py:method:: compute_intermediates(ctx: constraints.base.ConstraintContext) -> dict[str, dict[int, primitives.field.FF3Poly]]

      Delegated to bytecode adapter; this module only computes Stage 1.



   .. py:method:: compute_grand_sums(ctx: constraints.base.ConstraintContext) -> dict[str, primitives.field.FF3Poly]

      Delegated to bytecode adapter; this module only computes Stage 1.



