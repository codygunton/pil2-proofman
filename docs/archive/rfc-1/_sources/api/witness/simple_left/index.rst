witness.simple_left
===================

.. py:module:: witness.simple_left

.. autoapi-nested-parse::

   SimpleLeft AIR witness generation.

   SimpleLeft logup terms (from constraint module analysis):

   Term 0: busid=1, [a,b] - assumes, selector=-1 (goes directly to gsum)
   Term 1: busid=1, [c,d] - proves, selector=+1
   Term 2: busid=2, [e,f] - assumes, selector=-1
   Term 3: busid=3, [g,h] - lookup, selector=-1
   Term 4: busid=100, k[0] - range, selector=-1
   Term 5: busid=101, k[1] - range, selector=-1
   Term 6: busid=100, k[2]-1 - range, selector=-1
   Term 7: busid=100, 255-k[2] - range, selector=-1
   Term 8: busid=101, k[3] - range, selector=-1
   Term 9: busid=101, 256-k[3] - range, selector=-1
   Term 10: busid=102, k[4] - range, selector=-1
   Term 11: busid=103, k[5] - range, selector=-1
   Term 12: busid=104, k[6] - range, selector=-1

   Intermediate columns clustering (from constraint equations):
   - im_cluster[0]: term1 + term2 (proves busid=1 + assumes busid=2)
   - im_cluster[1]: term3 + term4 (lookup busid=3 + range busid=100,k[0])
   - im_cluster[2]: term5 + term6 (range busid=101,k[1] + range busid=100,k[2]-1)
   - im_cluster[3]: term7 + term8 (range busid=100,255-k[2] + range busid=101,k[3])
   - im_cluster[4]: term9 + term10 (range busid=101,256-k[3] + range busid=102,k[4])
   - im_cluster[5]: term11 + term12 (range busid=103,k[5] + range busid=104,k[6])

   Term 0 is added directly to gsum, not via intermediate columns.



Classes
-------

.. autoapisummary::

   witness.simple_left.SimpleLeftWitness


Module Contents
---------------

.. py:class:: SimpleLeftWitness

   Bases: :py:obj:`witness.base.WitnessModule`


   Witness generation for SimpleLeft AIR.

   Computes 6 im_cluster columns and 1 gsum column for the logup protocol.
   The exact clustering depends on compiler optimization, but the sum
   of all im_cluster columns equals the sum of all individual logup terms.


   .. py:method:: compute_intermediates(ctx: constraints.base.ConstraintContext) -> dict[str, dict[int, primitives.field.FF3Poly]]

      Compute im_cluster polynomials directly from constraint equations.

      Each im_cluster satisfies: im[i] * D1 * D2 = (coeff2*D2 + coeff1*D1)
      So: im[i] = (coeff2*D2 + coeff1*D1) / (D1 * D2)

      From constraint module:
      - im[0]: D1=compress(1,[c,d]), D2=compress(2,[e,f]), coeffs=(+1,-1) -> (D2-D1)/(D1*D2)
      - im[1]: D1=compress(3,[g,h]), D2=compress(100,k[0]), coeffs=(-1,-1) -> -(D1+D2)/(D1*D2)
      - im[2]: D1=compress(101,k[1]), D2=compress(100,k[2]-1), coeffs=(-1,-1)
      - im[3]: D1=compress(100,255-k[2]), D2=compress(101,k[3]), coeffs=(-1,-1)
      - im[4]: D1=compress(101,256-k[3]), D2=compress(102,k[4]), coeffs=(-1,-1)
      - im[5]: D1=compress(103,k[5]), D2=compress(104,k[6]), coeffs=(-1,-1)

      Returns:
          {'im_cluster': {0: poly0, 1: poly1, ..., 5: poly5}}



   .. py:method:: compute_grand_sums(ctx: constraints.base.ConstraintContext) -> dict[str, primitives.field.FF3Poly]

      Compute gsum running sum polynomial.

      From constraint 6:
      (gsum - prev_gsum*(1-L1) - sum_ims) * direct_den + 1 = 0

      This means:
      gsum[i] = prev_gsum[i] * (1-L1[i]) + sum_ims[i] - 1/direct_den[i]

      Where direct_den = compress(1, [a, b]).

      Returns:
          {'gsum': gsum_polynomial}



