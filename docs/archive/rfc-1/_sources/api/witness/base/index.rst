witness.base
============

.. py:module:: witness.base

.. autoapi-nested-parse::

   Base class for witness generation.



Classes
-------

.. autoapisummary::

   witness.base.WitnessModule


Module Contents
---------------

.. py:class:: WitnessModule

   Bases: :py:obj:`abc.ABC`


   Per-AIR witness generation. Used by prover only.

   Each AIR (Algebraic Intermediate Representation) may have its own witness
   module that computes intermediate polynomials and grand sums needed for
   lookups and permutations. Unlike ConstraintModule, this is only used by
   the prover - the verifier checks constraints but doesn't generate witnesses.


   .. py:method:: compute_intermediates(ctx: constraints.base.ConstraintContext) -> dict[str, dict[int, primitives.field.FF3Poly]]
      :abstractmethod:


      Compute im_cluster polynomials.

      Args:
          ctx: ConstraintContext providing access to columns, constants, challenges

      Returns:
          Dictionary mapping cluster names to their indexed polynomials.
          Example: {'im_cluster': {0: poly0, 1: poly1, ...}}



   .. py:method:: compute_grand_sums(ctx: constraints.base.ConstraintContext) -> dict[str, primitives.field.FF3Poly]
      :abstractmethod:


      Compute gsum/gprod running sum polynomials.

      Args:
          ctx: ConstraintContext providing access to columns, constants, challenges

      Returns:
          Dictionary mapping polynomial names to their values.
          Example: {'gsum': gsum_poly}



