witness.lookup2_12
==================

.. py:module:: witness.lookup2_12

.. autoapi-nested-parse::

   Lookup2_12 AIR witness generation.

   Lookup2_12 logup terms (from gsum_debug_data hints):
   0. Lookup assumes, busid=4, sel=1, cols=[a1, b1]  -- direct term in gsum
   1. Lookup proves, busid=4, mul=1, cols=[c1, d1]   -- stored_num = +1
   2. Lookup assumes, busid=5, sel=1, cols=[a2, b2]  -- stored_num = -1
   3. Lookup assumes, busid=6, sel=sel1, cols=[a3, b3]  -- stored_num = -sel1
   4. Lookup proves, busid=6, mul=mul, cols=[c2, d2]    -- stored_num = +mul
   5. Lookup assumes, busid=7, sel=sel2, cols=[a4, b4]  -- stored_num = -sel2

   Intermediate columns clustering (from expressionsinfo constraint lines):
   - im_cluster[0]: busid=4 proves [c1,d1] + busid=5 assumes [a2,b2] = terms 1,2
   - im_cluster[1]: busid=6 assumes [a3,b3] + busid=6 proves [c2,d2] = terms 3,4
   - im_single: busid=7 assumes [a4,b4] = term 5

   Convention: stored_num = -selector for assumes, +multiplicity for proves.
   Term 0 (busid=4 assumes) is used directly in gsum, not in intermediate columns.



Classes
-------

.. autoapisummary::

   witness.lookup2_12.Lookup2_12Witness


Module Contents
---------------

.. py:class:: Lookup2_12Witness

   Bases: :py:obj:`witness.base.WitnessModule`


   Witness generation for Lookup2_12 AIR.

   Computes 2 im_cluster columns, 1 im_single column, and 1 gsum column.


   .. py:method:: compute_intermediates(ctx: constraints.base.ConstraintContext) -> dict[str, dict[int, primitives.field.FF3Poly]]

      Compute intermediate polynomials directly from constraint equations.

      From constraint module:
      - im_cluster[0]: (D2 - D1)/(D1*D2) where D1=compress(4,[c1,d1]), D2=compress(5,[a2,b2])
      - im_cluster[1]: ((-sel1)*D2 + mul*D1)/(D1*D2) where D1=compress(6,[a3,b3]), D2=compress(6,[c2,d2])
      - im_single: (-sel2)/D where D=compress(7,[a4,b4])

      Returns:
          {
              'im_cluster': {0: im_cluster_0, 1: im_cluster_1},
              'im_single': {0: im_single}
          }



   .. py:method:: compute_grand_sums(ctx: constraints.base.ConstraintContext) -> dict[str, primitives.field.FF3Poly]

      Compute gsum running sum polynomial.

      From constraint 3:
      (gsum - prev_gsum*(1-L1) - sum_ims) * direct_den + 1 = 0

      This means:
      gsum[i] = prev_gsum[i] * (1-L1[i]) + sum_ims[i] - 1/direct_den[i]

      Where direct_den = compress(4, [a1, b1]).

      Returns:
          {'gsum': gsum_polynomial}



