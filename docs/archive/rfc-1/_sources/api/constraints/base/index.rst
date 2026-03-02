constraints.base
================

.. py:module:: constraints.base

.. autoapi-nested-parse::

   Base classes for constraint evaluation.

   ConstraintContext provides a uniform interface for constraint evaluation that works
   for both prover (returns arrays) and verifier (returns scalars). The same constraint
   code can be used in both contexts thanks to galois broadcasting.

   Example:
       def eval_constraint(ctx: ConstraintContext):
           a = ctx.col('a')
           b = ctx.col('b')
           return a * b - ctx.challenge('alpha')

       # Works for prover (arrays)
       prover_result = eval_constraint(ProverConstraintContext(prover_data))

       # Works for verifier (scalars)
       verifier_result = eval_constraint(VerifierConstraintContext(verifier_data))



Attributes
----------

.. autoapisummary::

   constraints.base.FF3Poly
   constraints.base.FFPoly


Classes
-------

.. autoapisummary::

   constraints.base.ConstraintContext
   constraints.base.ProverConstraintContext
   constraints.base.VerifierConstraintContext
   constraints.base.ConstraintModule


Functions
---------

.. autoapisummary::

   constraints.base.compress_2col


Module Contents
---------------

.. py:data:: FF3Poly

.. py:data:: FFPoly

.. py:function:: compress_2col(busid: int, col1: primitives.field.FF3, col2: primitives.field.FF3, alpha: primitives.field.FF3, gamma: primitives.field.FF3, n: int | None = None) -> primitives.field.FF3

   Compress 2-column expression: ((col2*α + col1)*α + busid) + γ.


.. py:class:: ConstraintContext

   Bases: :py:obj:`abc.ABC`


   Uniform interface for constraint evaluation - works for prover and verifier.


   .. py:method:: col(name: str, index: int = 0) -> FF3Poly | primitives.field.FF3
      :abstractmethod:


      Get column at current row.

      Args:
          name: Column name
          index: Column index for multi-column polynomials (default 0)

      Returns:
          Prover: array of values at all domain points
          Verifier: scalar evaluation at xi



   .. py:method:: next_col(name: str, index: int = 0) -> FF3Poly | primitives.field.FF3
      :abstractmethod:


      Get column at next row (offset +1).

      Args:
          name: Column name
          index: Column index for multi-column polynomials (default 0)

      Returns:
          Prover: array shifted by -1 (circular)
          Verifier: evaluation at xi * omega



   .. py:method:: prev_col(name: str, index: int = 0) -> FF3Poly | primitives.field.FF3
      :abstractmethod:


      Get column at previous row (offset -1).

      Args:
          name: Column name
          index: Column index for multi-column polynomials (default 0)

      Returns:
          Prover: array shifted by +1 (circular)
          Verifier: evaluation at xi * omega^(-1)



   .. py:method:: const(name: str, index: int = 0) -> FF3Poly | primitives.field.FF3
      :abstractmethod:


      Get constant polynomial at current row (converted to extension field).

      Args:
          name: Constant name (e.g., '__L1__' for Lagrange polynomial)
          index: Column index for AIRs with multiple constants sharing a name

      Returns:
          Prover: array of constant values (as FF3 for arithmetic compatibility)
          Verifier: scalar evaluation at xi



   .. py:method:: next_const(name: str, index: int = 0) -> FF3Poly | primitives.field.FF3
      :abstractmethod:


      Get constant polynomial at next row (offset +1).

      Args:
          name: Constant name
          index: Column index for AIRs with multiple constants sharing a name

      Returns:
          Prover: array shifted by -1 (circular)
          Verifier: evaluation at xi * omega



   .. py:method:: prev_const(name: str, index: int = 0) -> FF3Poly | primitives.field.FF3
      :abstractmethod:


      Get constant polynomial at previous row (offset -1).

      Args:
          name: Constant name
          index: Column index for AIRs with multiple constants sharing a name

      Returns:
          Prover: array shifted by +1 (circular)
          Verifier: evaluation at xi * omega^(-1)



   .. py:method:: challenge(name: str) -> primitives.field.FF3
      :abstractmethod:


      Get Fiat-Shamir challenge (always scalar).

      Args:
          name: Challenge name (e.g., 'std_alpha')

      Returns:
          Scalar challenge value



   .. py:method:: airgroup_value(index: int) -> primitives.field.FF3
      :abstractmethod:


      Get airgroup value (accumulated result across AIR instances).

      Args:
          index: Airgroup value index

      Returns:
          Scalar airgroup value (FF3)



.. py:class:: ProverConstraintContext(data: protocol.data.ProverData)

   Bases: :py:obj:`ConstraintContext`


   Prover implementation - returns polynomial arrays.

   The prover evaluates constraints at all domain points simultaneously,
   producing arrays of constraint evaluations.


   .. py:method:: col(name: str, index: int = 0) -> FF3Poly

      Get column at current row.

      Args:
          name: Column name
          index: Column index for multi-column polynomials (default 0)

      Returns:
          Prover: array of values at all domain points
          Verifier: scalar evaluation at xi



   .. py:method:: next_col(name: str, index: int = 0) -> FF3Poly

      Get column at next row (offset +1).

      Args:
          name: Column name
          index: Column index for multi-column polynomials (default 0)

      Returns:
          Prover: array shifted by -1 (circular)
          Verifier: evaluation at xi * omega



   .. py:method:: prev_col(name: str, index: int = 0) -> FF3Poly

      Get column at previous row (offset -1).

      Args:
          name: Column name
          index: Column index for multi-column polynomials (default 0)

      Returns:
          Prover: array shifted by +1 (circular)
          Verifier: evaluation at xi * omega^(-1)



   .. py:method:: const(name: str, index: int = 0) -> FF3Poly

      Get constant polynomial at current row (converted to extension field).

      Args:
          name: Constant name (e.g., '__L1__' for Lagrange polynomial)
          index: Column index for AIRs with multiple constants sharing a name

      Returns:
          Prover: array of constant values (as FF3 for arithmetic compatibility)
          Verifier: scalar evaluation at xi



   .. py:method:: next_const(name: str, index: int = 0) -> FF3Poly

      Get constant polynomial at next row (offset +1).

      Args:
          name: Constant name
          index: Column index for AIRs with multiple constants sharing a name

      Returns:
          Prover: array shifted by -1 (circular)
          Verifier: evaluation at xi * omega



   .. py:method:: prev_const(name: str, index: int = 0) -> FF3Poly

      Get constant polynomial at previous row (offset -1).

      Args:
          name: Constant name
          index: Column index for AIRs with multiple constants sharing a name

      Returns:
          Prover: array shifted by +1 (circular)
          Verifier: evaluation at xi * omega^(-1)



   .. py:method:: challenge(name: str) -> primitives.field.FF3

      Get Fiat-Shamir challenge (always scalar).

      Args:
          name: Challenge name (e.g., 'std_alpha')

      Returns:
          Scalar challenge value



   .. py:method:: airgroup_value(index: int) -> primitives.field.FF3

      Get airgroup value (accumulated result across AIR instances).

      Args:
          index: Airgroup value index

      Returns:
          Scalar airgroup value (FF3)



.. py:class:: VerifierConstraintContext(data: protocol.data.VerifierData)

   Bases: :py:obj:`ConstraintContext`


   Verifier implementation - returns scalar evaluations.

   The verifier evaluates constraints at a single random point xi,
   checking that the constraint polynomial evaluates to zero.


   .. py:method:: col(name: str, index: int = 0) -> primitives.field.FF3

      Get column at current row.

      Args:
          name: Column name
          index: Column index for multi-column polynomials (default 0)

      Returns:
          Prover: array of values at all domain points
          Verifier: scalar evaluation at xi



   .. py:method:: next_col(name: str, index: int = 0) -> primitives.field.FF3

      Get column at next row (offset +1).

      Args:
          name: Column name
          index: Column index for multi-column polynomials (default 0)

      Returns:
          Prover: array shifted by -1 (circular)
          Verifier: evaluation at xi * omega



   .. py:method:: prev_col(name: str, index: int = 0) -> primitives.field.FF3

      Get column at previous row (offset -1).

      Args:
          name: Column name
          index: Column index for multi-column polynomials (default 0)

      Returns:
          Prover: array shifted by +1 (circular)
          Verifier: evaluation at xi * omega^(-1)



   .. py:method:: const(name: str, index: int = 0) -> primitives.field.FF3

      Get constant polynomial at current row (converted to extension field).

      Args:
          name: Constant name (e.g., '__L1__' for Lagrange polynomial)
          index: Column index for AIRs with multiple constants sharing a name

      Returns:
          Prover: array of constant values (as FF3 for arithmetic compatibility)
          Verifier: scalar evaluation at xi



   .. py:method:: next_const(name: str, index: int = 0) -> primitives.field.FF3

      Get constant polynomial at next row (offset +1).

      Args:
          name: Constant name
          index: Column index for AIRs with multiple constants sharing a name

      Returns:
          Prover: array shifted by -1 (circular)
          Verifier: evaluation at xi * omega



   .. py:method:: prev_const(name: str, index: int = 0) -> primitives.field.FF3

      Get constant polynomial at previous row (offset -1).

      Args:
          name: Constant name
          index: Column index for AIRs with multiple constants sharing a name

      Returns:
          Prover: array shifted by +1 (circular)
          Verifier: evaluation at xi * omega^(-1)



   .. py:method:: challenge(name: str) -> primitives.field.FF3

      Get Fiat-Shamir challenge (always scalar).

      Args:
          name: Challenge name (e.g., 'std_alpha')

      Returns:
          Scalar challenge value



   .. py:method:: airgroup_value(index: int) -> primitives.field.FF3

      Get airgroup value (accumulated result across AIR instances).

      Args:
          index: Airgroup value index

      Returns:
          Scalar airgroup value (FF3)



.. py:class:: ConstraintModule

   Bases: :py:obj:`abc.ABC`


   Per-AIR constraint evaluation. Used by both prover and verifier.

   Each AIR (Algebraic Intermediate Representation) has its own constraint
   module that defines how constraints are evaluated. The same module works
   for both prover and verifier contexts.


   .. py:method:: constraint_polynomial(ctx: ConstraintContext) -> FF3Poly | primitives.field.FF3
      :abstractmethod:


      Evaluate all constraints combined into single polynomial.

      Args:
          ctx: ConstraintContext providing access to columns, constants, challenges

      Returns:
          Prover: array of constraint evaluations at all domain points
          Verifier: single constraint evaluation at xi



