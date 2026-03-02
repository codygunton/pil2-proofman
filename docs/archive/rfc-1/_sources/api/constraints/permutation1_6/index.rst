constraints.permutation1_6
==========================

.. py:module:: constraints.permutation1_6

.. autoapi-nested-parse::

   Permutation1_6 AIR constraint evaluation.

   Permutation1_6 uses both sum-based (logup) and product-based permutation arguments:

   Sum-based logup terms (5 terms clustered into 2 im_cluster columns):
   1. Permutation assumes, busid=1, sel=1, cols=[a1, b1]
   2. Permutation proves, busid=1, sel=-1, cols=[c1, d1]
   3. Permutation assumes, busid=2, sel=1, cols=[a2, b2]
   4. Permutation assumes, busid=3, sel=sel1, cols=[a3, b3]
   5. Permutation proves, busid=3, sel=-sel2, cols=[c2, d2]

   Product-based permutation term (1 term using gprod):
   6. Permutation assumes, busid=4, sel=sel3, cols=[a4, b4]

   Clustering:
   - im_cluster[0]: terms 1,2 (busid=1,2)  -- NOT 0,1!
   - im_cluster[1]: terms 3,4,5 (busid=3)

   6 constraints combined with std_vc powers.



Classes
-------

.. autoapisummary::

   constraints.permutation1_6.Permutation1_6Constraints


Module Contents
---------------

.. py:class:: Permutation1_6Constraints

   Bases: :py:obj:`constraints.base.ConstraintModule`


   Constraint evaluation for Permutation1_6 AIR.

   Permutation1_6 has 64 rows (nBits=6) and uses both sum-based logup
   and product-based permutation arguments.

   The 6 constraints are:
   - C0: im_cluster[0] verification (busid=1,2)
   - C1: im_cluster[1] verification (busid=3)
   - C2: gsum recurrence
   - C3: gsum boundary constraint
   - C4: gprod recurrence
   - C5: gprod boundary constraint


   .. py:method:: constraint_polynomial(ctx: constraints.base.ConstraintContext) -> primitives.field.FF3Poly | primitives.field.FF3

      Evaluate combined constraint polynomial.



