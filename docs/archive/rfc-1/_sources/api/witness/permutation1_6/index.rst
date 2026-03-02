witness.permutation1_6
======================

.. py:module:: witness.permutation1_6

.. autoapi-nested-parse::

   Permutation1_6 AIR witness generation.

   Permutation1_6 uses both sum-based (logup) and product-based permutation:

   Sum-based logup terms (5 terms, 0-indexed):
   0. Permutation assumes, busid=1, sel=1, cols=[a1, b1] -> goes to gsum direct
   1. Permutation proves, busid=1, sel=-1, cols=[c1, d1]
   2. Permutation assumes, busid=2, sel=1, cols=[a2, b2]
   3. Permutation assumes, busid=3, sel=sel1, cols=[a3, b3]
   4. Permutation proves, busid=3, sel=-sel2, cols=[c2, d2]

   Intermediate columns clustering (from constraint module):
   - im_cluster[0]: terms 1,2 (proves busid=1 + assumes busid=2)
   - im_cluster[1]: terms 3,4 (assumes busid=3 + proves busid=3)
   - Term 0 goes directly to gsum, not into im_cluster

   Product-based term (for gprod):
   Permutation assumes, busid=4, sel=sel3, cols=[a4, b4]



Classes
-------

.. autoapisummary::

   witness.permutation1_6.Permutation1_6Witness


Module Contents
---------------

.. py:class:: Permutation1_6Witness

   Bases: :py:obj:`witness.base.WitnessModule`


   Witness generation for Permutation1_6 AIR.

   Computes 2 im_cluster columns, 1 gsum column, and 1 gprod column.


   .. py:method:: compute_intermediates(ctx: constraints.base.ConstraintContext) -> dict[str, dict[int, primitives.field.FF3Poly]]

      Compute intermediate polynomials directly from constraint equations.

      From constraint module:
      - im_cluster[0]: (D2 - D1)/(D1*D2) where D1=compress(1,[c1,d1]), D2=compress(2,[a2,b2])
      - im_cluster[1]: ((-sel1)*D2 + sel2*D1)/(D1*D2) where D1=compress(3,[a3,b3]), D2=compress(3,[c2,d2])

      Returns:
          {
              'im_cluster': {0: im_cluster_0, 1: im_cluster_1}
          }



   .. py:method:: compute_grand_sums(ctx: constraints.base.ConstraintContext) -> dict[str, primitives.field.FF3Poly]

      Compute gsum and gprod polynomials.

      From constraint 2: gsum recurrence
      (gsum - prev_gsum*(1-L1) - sum_im) * direct_den + 1 = 0
      So gsum[i] = gsum[i-1] + sum_im[i] - 1/direct_den[i]
      where direct_den = compress(1,[a1,b1])

      From constraint 4: gprod recurrence
      gprod * denom = prev_gprod * (1-L1) + L1
      where denom = sel3 * (e + gamma - 1) + 1, e = (b4*alpha + a4)*alpha + 4
      For i>0: gprod[i] = gprod[i-1] / denom[i]
      For i=0: gprod[0] = 1 / denom[0]

      Returns:
          {'gsum': gsum_polynomial, 'gprod': gprod_polynomial}



