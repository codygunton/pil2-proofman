primitives.expression_bytecode.witness_generation
=================================================

.. py:module:: primitives.expression_bytecode.witness_generation

.. autoapi-nested-parse::

   Witness STD computation for lookup and permutation arguments.

   Recovered from git history (731d33f4~1) and adapted to current codebase.

   Mathematical variables used throughout this module:
       N    -- domain size (number of trace rows, = 2^n_bits)
       dim  -- field element dimension (1 = base field FF, 3 = extension field FF3)



Functions
---------

.. autoapisummary::

   primitives.expression_bytecode.witness_generation.get_hint_field_values
   primitives.expression_bytecode.witness_generation.evaluate_hint_field_with_expressions
   primitives.expression_bytecode.witness_generation.multiply_hint_fields
   primitives.expression_bytecode.witness_generation.acc_mul_hint_fields
   primitives.expression_bytecode.witness_generation.update_airgroup_value
   primitives.expression_bytecode.witness_generation.calculate_witness_std


Module Contents
---------------

.. py:function:: get_hint_field_values(stark_info: protocol.stark_info.StarkInfo, expressions_bin: primitives.expression_bytecode.expressions_bin.ExpressionsBin, buffers: primitives.expression_bytecode.expression_evaluator.BufferSet, hint_id: int, field_name: str, inverse: bool = False) -> numpy.ndarray

   Fetch hint field values, multiplying multiple operands if present.


.. py:function:: evaluate_hint_field_with_expressions(stark_info: protocol.stark_info.StarkInfo, expressions_bin: primitives.expression_bytecode.expressions_bin.ExpressionsBin, buffers: primitives.expression_bytecode.expression_evaluator.BufferSet, expressions_ctx: primitives.expression_bytecode.expression_evaluator.ExpressionsPack, hint_id: int, field1_name: str, field2_name: str, field2_inverse: bool = True) -> numpy.ndarray

   Evaluate field1 * field2^(-1) using expression evaluator.


.. py:function:: multiply_hint_fields(stark_info: protocol.stark_info.StarkInfo, expressions_bin: primitives.expression_bytecode.expressions_bin.ExpressionsBin, buffers: primitives.expression_bytecode.expression_evaluator.BufferSet, expressions_ctx: primitives.expression_bytecode.expression_evaluator.ExpressionsPack, hint_ids: list[int], dest_field: str, field1: str, field2: str, field2_inverse: bool = True) -> None

   Compute dest = field1 * field2^(-1) for each hint.


.. py:function:: acc_mul_hint_fields(stark_info: protocol.stark_info.StarkInfo, expressions_bin: primitives.expression_bytecode.expressions_bin.ExpressionsBin, buffers: primitives.expression_bytecode.expression_evaluator.BufferSet, expressions_ctx: primitives.expression_bytecode.expression_evaluator.ExpressionsPack, hint_id: int, dest_field: str, airgroup_val_field: str, field1: str, field2: str, add: bool) -> None

   Compute running sum (add=True) or product (add=False) of field1 * field2^(-1).


.. py:function:: update_airgroup_value(stark_info: protocol.stark_info.StarkInfo, expressions_bin: primitives.expression_bytecode.expressions_bin.ExpressionsBin, buffers: primitives.expression_bytecode.expression_evaluator.BufferSet, expressions_ctx: primitives.expression_bytecode.expression_evaluator.ExpressionsPack, hint_id: int, airgroup_val_field: str, field1: str, field2: str, add: bool) -> None

   Update airgroup value: airgroupValue op= field1 * field2^(-1).


.. py:function:: calculate_witness_std(stark_info: protocol.stark_info.StarkInfo, expressions_bin: primitives.expression_bytecode.expressions_bin.ExpressionsBin, buffers: primitives.expression_bytecode.expression_evaluator.BufferSet, expressions_ctx: primitives.expression_bytecode.expression_evaluator.ExpressionsPack, prod: bool) -> None

   Calculate gsum (prod=False) or gprod (prod=True) witness columns.


