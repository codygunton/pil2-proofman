witness.bytecode_adapter
========================

.. py:module:: witness.bytecode_adapter

.. autoapi-nested-parse::

   Bytecode-backed witness generation adapter.

   Wraps the hint-driven witness computation behind the WitnessModule ABC,
   allowing AIRs without hand-written Python to use compiled bytecode for
   witness generation (intermediate columns and grand sums).



Classes
-------

.. autoapisummary::

   witness.bytecode_adapter.BytecodeWitnessModule


Module Contents
---------------

.. py:class:: BytecodeWitnessModule(bin_path: str)

   Bases: :py:obj:`witness.base.WitnessModule`


   Witness module backed by compiled expression bytecode.

   Uses the hint-driven witness computation to generate intermediate columns
   and grand sums, wrapping the result in the WitnessModule interface.


   .. py:method:: compute_intermediates(ctx: constraints.base.ConstraintContext) -> dict[str, dict[int, primitives.field.FF3Poly]]

      Compute intermediate columns using bytecode interpreter.

      Runs im_col hints via calculate_witness_std(prod=False), extracts
      the intermediate columns from the buffer.



   .. py:method:: compute_grand_sums(ctx: constraints.base.ConstraintContext) -> dict[str, primitives.field.FF3Poly]

      Extract grand sums from the witness computation.

      Must be called after compute_intermediates() which runs the full
      witness computation. The grand sums are already computed and stored
      in the buffers.



