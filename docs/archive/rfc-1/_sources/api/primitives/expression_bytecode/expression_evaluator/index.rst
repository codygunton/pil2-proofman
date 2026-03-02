primitives.expression_bytecode.expression_evaluator
===================================================

.. py:module:: primitives.expression_bytecode.expression_evaluator

.. autoapi-nested-parse::

   Expression bytecode evaluator for STARK constraint polynomials.

   Recovered from git history (731d33f4~1) and adapted to current codebase.

   Mathematical variables used throughout this module:
       N       -- domain size (number of trace rows, = 2^n_bits)
       N_ext   -- extended domain size (= 2^n_bits_ext), used for quotient evaluation
       xi      -- challenge evaluation point (random point from Fiat-Shamir transcript)
       zh/Z_H  -- vanishing polynomial Z_H(x) = x^N - 1
       zi      -- inverse vanishing polynomial 1/Z_H(x)
       o       -- row offset for shifted polynomial evaluation (from opening points)



Attributes
----------

.. autoapisummary::

   primitives.expression_bytecode.expression_evaluator.FastValue
   primitives.expression_bytecode.expression_evaluator.NROWS_PACK
   primitives.expression_bytecode.expression_evaluator.PUBLIC_INPUTS_OFFSET
   primitives.expression_bytecode.expression_evaluator.NUMBERS_OFFSET
   primitives.expression_bytecode.expression_evaluator.AIR_VALUES_OFFSET
   primitives.expression_bytecode.expression_evaluator.PROOF_VALUES_OFFSET
   primitives.expression_bytecode.expression_evaluator.AIRGROUP_VALUES_OFFSET
   primitives.expression_bytecode.expression_evaluator.CHALLENGES_OFFSET
   primitives.expression_bytecode.expression_evaluator.EVALS_OFFSET


Classes
-------

.. autoapisummary::

   primitives.expression_bytecode.expression_evaluator.BufferSet
   primitives.expression_bytecode.expression_evaluator.Params
   primitives.expression_bytecode.expression_evaluator.Dest
   primitives.expression_bytecode.expression_evaluator.ExpressionsCtx
   primitives.expression_bytecode.expression_evaluator.ExpressionsPack


Module Contents
---------------

.. py:data:: FastValue

.. py:data:: NROWS_PACK
   :value: 65536


.. py:data:: PUBLIC_INPUTS_OFFSET
   :value: 2


.. py:data:: NUMBERS_OFFSET
   :value: 3


.. py:data:: AIR_VALUES_OFFSET
   :value: 4


.. py:data:: PROOF_VALUES_OFFSET
   :value: 5


.. py:data:: AIRGROUP_VALUES_OFFSET
   :value: 6


.. py:data:: CHALLENGES_OFFSET
   :value: 7


.. py:data:: EVALS_OFFSET
   :value: 8


.. py:class:: BufferSet

   Container for flat polynomial buffers used by the bytecode evaluator.

   This replaces the deleted ProofContext class with a minimal set of buffers
   needed by the expression interpreter.


   .. py:attribute:: trace
      :type:  numpy.ndarray


   .. py:attribute:: aux_trace
      :type:  numpy.ndarray


   .. py:attribute:: const_pols
      :type:  numpy.ndarray


   .. py:attribute:: const_pols_extended
      :type:  numpy.ndarray


   .. py:attribute:: public_inputs
      :type:  numpy.ndarray


   .. py:attribute:: challenges
      :type:  numpy.ndarray


   .. py:attribute:: evals
      :type:  numpy.ndarray


   .. py:attribute:: air_values
      :type:  numpy.ndarray


   .. py:attribute:: airgroup_values
      :type:  numpy.ndarray


   .. py:attribute:: proof_values
      :type:  numpy.ndarray


   .. py:attribute:: x_div_x_sub
      :type:  numpy.ndarray | None
      :value: None



   .. py:attribute:: custom_commits
      :type:  numpy.ndarray | None
      :value: None



.. py:class:: Params

   Operand specification for expression evaluation.


   .. py:attribute:: exp_id
      :type:  int
      :value: 0



   .. py:attribute:: dim
      :type:  int
      :value: 1



   .. py:attribute:: stage
      :type:  int
      :value: 0



   .. py:attribute:: stage_pos
      :type:  int
      :value: 0



   .. py:attribute:: pols_map_id
      :type:  int
      :value: 0



   .. py:attribute:: row_offset_index
      :type:  int
      :value: 0



   .. py:attribute:: inverse
      :type:  bool
      :value: False



   .. py:attribute:: batch
      :type:  bool
      :value: True



   .. py:attribute:: op
      :type:  str
      :value: 'tmp'



   .. py:attribute:: value
      :type:  int
      :value: 0



.. py:class:: Dest

   Destination buffer for expression results.


   .. py:attribute:: dest
      :type:  numpy.ndarray
      :value: None



   .. py:attribute:: exp_id
      :type:  int
      :value: -1



   .. py:attribute:: offset
      :type:  int
      :value: 0



   .. py:attribute:: stage_pos
      :type:  int
      :value: 0



   .. py:attribute:: stage_cols
      :type:  int
      :value: 0



   .. py:attribute:: expr
      :type:  bool
      :value: False



   .. py:attribute:: dim
      :type:  int
      :value: 1



   .. py:attribute:: domain_size
      :type:  int
      :value: 0



   .. py:attribute:: params
      :type:  list[Params]
      :value: None



.. py:class:: ExpressionsCtx(stark_info: protocol.stark_info.StarkInfo, prover_helpers: protocol.air_config.ProverHelpers | None = None, n_queries: int | None = None, verify: bool = False)

   Memory layout and stride mappings for polynomial access.


   .. py:attribute:: stark_info


   .. py:attribute:: prover_helpers
      :value: None



   .. py:attribute:: n_queries
      :value: None



   .. py:attribute:: verify
      :value: False



   .. py:attribute:: xis
      :type:  numpy.ndarray | None
      :value: None



   .. py:attribute:: next_strides


   .. py:attribute:: next_strides_extended


   .. py:attribute:: map_offsets


   .. py:attribute:: map_offsets_extended


   .. py:attribute:: map_sections_n


   .. py:attribute:: map_offsets_custom_fixed


   .. py:attribute:: map_offsets_custom_fixed_extended


   .. py:attribute:: map_sections_n_custom_fixed


   .. py:attribute:: min_row
      :value: 0



   .. py:attribute:: max_row


   .. py:attribute:: min_row_extended
      :value: 0



   .. py:attribute:: max_row_extended


   .. py:attribute:: map_offset_fri_pol


   .. py:attribute:: buffer_commits_size


   .. py:attribute:: n_stages


   .. py:attribute:: n_publics


   .. py:attribute:: n_challenges


   .. py:attribute:: n_evals


   .. py:attribute:: rows_per_batch


   .. py:method:: set_xi(xis: numpy.ndarray) -> None

      Set xi evaluation points for FRI division.

      xi = challenge evaluation point (random point from Fiat-Shamir transcript).
      Used to compute x/(x - xi) for FRI opening checks.



   .. py:method:: calculate_expression(buffers: BufferSet, dest: numpy.ndarray, expression_id: int, inverse: bool = False, compilation_time: bool = False) -> None

      Evaluate a single expression into dest buffer.



   .. py:method:: calculate_expressions(buffers: BufferSet, dest: Dest, domain_size: int, domain_extended: bool, compilation_time: bool = False, verify_constraints: bool = False, debug: bool = False) -> None
      :abstractmethod:


      Evaluate expressions across domain. Overridden by ExpressionsPack.



.. py:class:: ExpressionsPack(stark_info: protocol.stark_info.StarkInfo, expressions_bin: primitives.expression_bytecode.expressions_bin.ExpressionsBin, prover_helpers: protocol.air_config.ProverHelpers | None = None, nrows_pack: int = NROWS_PACK, n_queries: int | None = None, verify: bool = False)

   Bases: :py:obj:`ExpressionsCtx`


   Bytecode interpreter for constraint polynomial evaluation.


   .. py:attribute:: rows_per_batch


   .. py:method:: calculate_expressions(buffers: BufferSet, dest: Dest, domain_size: int, domain_extended: bool, compilation_time: bool = False, verify_constraints: bool = False, debug: bool = False) -> None

      Execute bytecode to evaluate constraint expressions.



