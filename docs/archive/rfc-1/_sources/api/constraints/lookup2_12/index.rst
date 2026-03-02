constraints.lookup2_12
======================

.. py:module:: constraints.lookup2_12

.. autoapi-nested-parse::

   Lookup2_12 AIR constraint evaluation.

   Lookup2_12 logup terms (from gsum_debug_data hints):
   1. Lookup assumes, busid=4, sel=1, cols=[a1, b1]  -- used in gsum direct_denom
   2. Lookup proves, busid=4, mul=1, cols=[c1, d1]   -- stored_num = +1
   3. Lookup assumes, busid=5, sel=1, cols=[a2, b2]  -- stored_num = -1
   4. Lookup assumes, busid=6, sel=sel1, cols=[a3, b3]  -- stored_num = -sel1
   5. Lookup proves, busid=6, mul=mul, cols=[c2, d2]    -- stored_num = +mul
   6. Lookup assumes, busid=7, sel=sel2, cols=[a4, b4]  -- stored_num = -sel2

   Intermediate columns clustering (from expressionsinfo constraint lines):
   - im_cluster[0]: busid=4 proves [c1,d1] + busid=5 assumes [a2,b2]
   - im_cluster[1]: busid=6 assumes [a3,b3] + busid=6 proves [c2,d2]
   - im_single: busid=7 assumes [a4,b4]

   Convention: stored_num = -selector for assumes, +multiplicity for proves.
   This is because im_single*denom = stored_num, and im represents the negated
   contribution to the logup sum.

   5 constraints combined with std_vc powers.



Classes
-------

.. autoapisummary::

   constraints.lookup2_12.Lookup2_12Constraints


Module Contents
---------------

.. py:class:: Lookup2_12Constraints

   Bases: :py:obj:`constraints.base.ConstraintModule`


   Constraint evaluation for Lookup2_12 AIR.

   Lookup2_12 has 4096 rows (nBits=12) and exercises FRI folding.

   The 5 constraints (from expressionsinfo):
   - C0: im_cluster[0] verification: im*D1*D2 - (D2 - D1) = 0
         D1 = compress(4, [c1, d1]), D2 = compress(5, [a2, b2])
   - C1: im_cluster[1] verification: im*D1*D2 - ((-sel1)*D2 + mul*D1) = 0
         D1 = compress(6, [a3, b3]), D2 = compress(6, [c2, d2])
   - C2: im_single verification: im*D - (-sel2) = 0
         D = compress(7, [a4, b4])
   - C3: gsum recurrence: (gsum - gsum'*(1-L1) - sum_ims) * direct_den + 1 = 0
         direct_den = compress(4, [a1, b1])
   - C4: boundary constraint: L1' * (gsum_result - gsum) = 0


   .. py:method:: constraint_polynomial(ctx: constraints.base.ConstraintContext) -> primitives.field.FF3Poly | primitives.field.FF3

      Evaluate combined constraint polynomial.



