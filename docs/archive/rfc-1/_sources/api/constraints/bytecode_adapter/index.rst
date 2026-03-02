constraints.bytecode_adapter
============================

.. py:module:: constraints.bytecode_adapter

.. autoapi-nested-parse::

   Bytecode-backed constraint module adapter.

   Wraps the expression bytecode interpreter behind the ConstraintModule ABC,
   allowing AIRs without hand-written Python to use compiled bytecode for
   constraint evaluation.



Classes
-------

.. autoapisummary::

   constraints.bytecode_adapter.BytecodeConstraintModule


Module Contents
---------------

.. py:class:: BytecodeConstraintModule(bin_path: str)

   Bases: :py:obj:`constraints.base.ConstraintModule`


   Constraint module backed by compiled expression bytecode.

   Uses the expression bytecode interpreter to evaluate constraint polynomials,
   allowing AIRs without hand-written Python modules to be proven/verified.


   .. py:method:: constraint_polynomial(ctx: constraints.base.ConstraintContext) -> primitives.field.FF3Poly | primitives.field.FF3

      Evaluate constraint polynomial using bytecode interpreter.

      Detects prover vs verifier mode from the context type.



