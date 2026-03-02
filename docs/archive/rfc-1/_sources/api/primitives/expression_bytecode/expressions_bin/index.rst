primitives.expression_bytecode.expressions_bin
==============================================

.. py:module:: primitives.expression_bytecode.expressions_bin

.. autoapi-nested-parse::

   Expression binary parser.

   Faithful translation from:
   - pil2-stark/src/starkpil/expressions_bin.hpp
   - pil2-stark/src/starkpil/expressions_bin.cpp

   Parses compiled expression bytecode from expressions.bin files.
   The binary file contains:
   1. Expression bytecode (operations and arguments)
   2. Constraint bytecode (for debugging/verification)
   3. Hints (for witness generation)

   Key types referenced by OpType:
       Zi          -- inverse vanishing polynomial 1/Z_H(x) where Z_H(x) = x^N - 1
       xDivXSubXi  -- x/(x - xi), precomputed quotient for FRI opening
       xi          -- challenge evaluation point (random point from Fiat-Shamir)



Attributes
----------

.. autoapisummary::

   primitives.expression_bytecode.expressions_bin.EXPRESSIONS_SECTION
   primitives.expression_bytecode.expressions_bin.CONSTRAINTS_SECTION
   primitives.expression_bytecode.expressions_bin.HINTS_SECTION
   primitives.expression_bytecode.expressions_bin.N_SECTIONS
   primitives.expression_bytecode.expressions_bin.GLOBAL_CONSTRAINTS_SECTION
   primitives.expression_bytecode.expressions_bin.GLOBAL_HINTS_SECTION
   primitives.expression_bytecode.expressions_bin.N_GLOBAL_SECTIONS


Classes
-------

.. autoapisummary::

   primitives.expression_bytecode.expressions_bin.OpType
   primitives.expression_bytecode.expressions_bin.ParserParams
   primitives.expression_bytecode.expressions_bin.ParserArgs
   primitives.expression_bytecode.expressions_bin.HintFieldValue
   primitives.expression_bytecode.expressions_bin.HintField
   primitives.expression_bytecode.expressions_bin.Hint
   primitives.expression_bytecode.expressions_bin.BinFileReader
   primitives.expression_bytecode.expressions_bin.ExpressionsBin


Functions
---------

.. autoapisummary::

   primitives.expression_bytecode.expressions_bin.optype_from_string


Module Contents
---------------

.. py:data:: EXPRESSIONS_SECTION
   :value: 1


.. py:data:: CONSTRAINTS_SECTION
   :value: 2


.. py:data:: HINTS_SECTION
   :value: 3


.. py:data:: N_SECTIONS
   :value: 3


.. py:data:: GLOBAL_CONSTRAINTS_SECTION
   :value: 1


.. py:data:: GLOBAL_HINTS_SECTION
   :value: 2


.. py:data:: N_GLOBAL_SECTIONS
   :value: 2


.. py:class:: OpType

   Bases: :py:obj:`enum.Enum`


   Operation argument types.

   Corresponds to C++ enum opType in stark_info.hpp (lines 30-49).
   These define the source/destination types for expression operands.


   .. py:attribute:: const_
      :value: 0



   .. py:attribute:: cm
      :value: 1



   .. py:attribute:: tmp
      :value: 2



   .. py:attribute:: public_
      :value: 3



   .. py:attribute:: airgroupvalue
      :value: 4



   .. py:attribute:: challenge
      :value: 5



   .. py:attribute:: number
      :value: 6



   .. py:attribute:: string_
      :value: 7



   .. py:attribute:: airvalue
      :value: 8



   .. py:attribute:: proofvalue
      :value: 9



   .. py:attribute:: custom
      :value: 10



   .. py:attribute:: x
      :value: 11



   .. py:attribute:: Zi
      :value: 12



   .. py:attribute:: eval
      :value: 13



   .. py:attribute:: xDivXSubXi
      :value: 14



   .. py:attribute:: q
      :value: 15



   .. py:attribute:: f
      :value: 16



.. py:function:: optype_from_string(s: str) -> OpType

   Convert string to OpType enum.


.. py:class:: ParserParams

   Parameters for a single expression.

   Corresponds to C++ struct ParserParams in expressions_bin.hpp (lines 53-69).

   Attributes:
       stage: Proof stage (0=custom, 1=trace, 2+=intermediate)
       exp_id: Expression ID in the expression database
       n_temp1: Number of scalar temporaries needed
       n_temp3: Number of field extension (dim=3) temporaries needed
       n_ops: Number of operations in this expression
       ops_offset: Offset into global ops array
       n_args: Number of arguments (8 per operation)
       args_offset: Offset into global args array
       first_row: First valid row for cyclic constraints
       last_row: Last valid row for cyclic constraints
       dest_dim: Destination dimension (1 or 3)
       dest_id: Destination identifier
       im_pol: Is intermediate polynomial
       line: Source code line (for debugging)


   .. py:attribute:: stage
      :type:  int
      :value: 0



   .. py:attribute:: exp_id
      :type:  int
      :value: 0



   .. py:attribute:: n_temp1
      :type:  int
      :value: 0



   .. py:attribute:: n_temp3
      :type:  int
      :value: 0



   .. py:attribute:: n_ops
      :type:  int
      :value: 0



   .. py:attribute:: ops_offset
      :type:  int
      :value: 0



   .. py:attribute:: n_args
      :type:  int
      :value: 0



   .. py:attribute:: args_offset
      :type:  int
      :value: 0



   .. py:attribute:: first_row
      :type:  int
      :value: 0



   .. py:attribute:: last_row
      :type:  int
      :value: 0



   .. py:attribute:: dest_dim
      :type:  int
      :value: 0



   .. py:attribute:: dest_id
      :type:  int
      :value: 0



   .. py:attribute:: im_pol
      :type:  bool
      :value: False



   .. py:attribute:: line
      :type:  str
      :value: ''



.. py:class:: ParserArgs

   Global bytecode and constants.

   Corresponds to C++ struct ParserArgs in expressions_bin.hpp (lines 71-77).

   Attributes:
       ops: Operation codes (uint8). Each value is 0-2:
           0 = dim1 x dim1 -> dim1 (scalar operation)
           1 = dim3 x dim1 -> dim3 (field extension x scalar)
           2 = dim3 x dim3 -> dim3 (field extension x field extension)
       args: Operation arguments (uint16). 8 values per operation:
           [0] = operation type (0=add, 1=sub, 2=mul, 3=sub_swap)
           [1] = destination temp index
           [2] = source A type (OpType value or temp buffer index)
           [3] = source A column/index
           [4] = source A stride index (for opening points)
           [5] = source B type
           [6] = source B column/index
           [7] = source B stride index
       numbers: Literal constants (Goldilocks field elements as uint64)
       n_numbers: Number of literal constants


   .. py:attribute:: ops
      :type:  numpy.ndarray


   .. py:attribute:: args
      :type:  numpy.ndarray


   .. py:attribute:: numbers
      :type:  numpy.ndarray


   .. py:attribute:: n_numbers
      :type:  int
      :value: 0



.. py:class:: HintFieldValue

   Hint field value.

   Corresponds to C++ struct HintFieldValue in expressions_bin.hpp (lines 30-39).


   .. py:attribute:: operand
      :type:  OpType


   .. py:attribute:: id
      :type:  int
      :value: 0



   .. py:attribute:: commit_id
      :type:  int
      :value: 0



   .. py:attribute:: row_offset_index
      :type:  int
      :value: 0



   .. py:attribute:: dim
      :type:  int
      :value: 0



   .. py:attribute:: value
      :type:  int
      :value: 0



   .. py:attribute:: string_value
      :type:  str
      :value: ''



   .. py:attribute:: pos
      :type:  list[int]
      :value: []



.. py:class:: HintField

   Hint field.

   Corresponds to C++ struct HintField in expressions_bin.hpp (lines 41-44).


   .. py:attribute:: name
      :type:  str
      :value: ''



   .. py:attribute:: values
      :type:  list[HintFieldValue]
      :value: []



.. py:class:: Hint

   Hint for witness generation.

   Corresponds to C++ struct Hint in expressions_bin.hpp (lines 47-51).


   .. py:attribute:: name
      :type:  str
      :value: ''



   .. py:attribute:: fields
      :type:  list[HintField]
      :value: []



.. py:class:: BinFileReader(file_path: str)

   Binary file reader with little-endian decoding.

   Mimics C++ BinFileUtils::BinFile interface for reading.

   Corresponds to C++ BinFile constructor in binfile_utils.cpp (lines 63-131).


   .. py:attribute:: path


   .. py:attribute:: pos
      :value: 0



   .. py:attribute:: reading_section
      :value: None



   .. py:attribute:: sections


   .. py:attribute:: n_sections


   .. py:method:: read_bytes(n: int) -> bytes

      Read n raw bytes.



   .. py:method:: read_u8_le() -> int

      Read uint8 little-endian.



   .. py:method:: read_u16_le() -> int

      Read uint16 little-endian.



   .. py:method:: read_u32_le() -> int

      Read uint32 little-endian.



   .. py:method:: read_u64_le() -> int

      Read uint64 little-endian.



   .. py:method:: read_string() -> str

      Read null-terminated string.

      Corresponds to C++ BinFile::readString() which reads until null byte.



   .. py:method:: start_read_section(section_id: int, section_pos: int = 0) -> None

      Start reading a section.

      Corresponds to C++ BinFile::startReadSection() (lines 138-157).

      Args:
          section_id: Section identifier
          section_pos: Section instance index (default 0)

      Raises:
          ValueError: If section doesn't exist



   .. py:method:: end_read_section(check: bool = True) -> None

      End reading a section.

      Corresponds to C++ BinFile::endReadSection() (lines 159-166).

      Args:
          check: If True, verify we read exactly section_size bytes



.. py:class:: ExpressionsBin

   Compiled expression database.

   Corresponds to C++ class ExpressionsBin in expressions_bin.hpp (lines 79-145).

   This class loads and manages compiled expression bytecode from .bin files.
   The bytecode represents arithmetic constraint expressions compiled into
   a stack-based operation sequence.


   .. py:attribute:: n_ops_total
      :type:  int
      :value: 0



   .. py:attribute:: n_args_total
      :type:  int
      :value: 0



   .. py:attribute:: expressions_info
      :type:  dict[int, ParserParams]


   .. py:attribute:: constraints_info_debug
      :type:  list[ParserParams]
      :value: []



   .. py:attribute:: hints
      :type:  list[Hint]
      :value: []



   .. py:attribute:: expressions_bin_args_expressions


   .. py:attribute:: expressions_bin_args_constraints


   .. py:attribute:: max_tmp1
      :type:  int
      :value: 0



   .. py:attribute:: max_tmp3
      :type:  int
      :value: 0



   .. py:attribute:: max_args
      :type:  int
      :value: 0



   .. py:attribute:: max_ops
      :type:  int
      :value: 0



   .. py:method:: from_file(file_path: str, global_bin: bool = False, verifier_bin: bool = False) -> ExpressionsBin
      :classmethod:


      Load ExpressionsBin from binary file.

      Corresponds to C++ constructor (lines 3-13 of expressions_bin.cpp).

      Args:
          file_path: Path to .bin file
          global_bin: Load as global constraints binary
          verifier_bin: Load as verifier binary

      Returns:
          Loaded ExpressionsBin instance



   .. py:method:: get_expression(exp_id: int) -> ParserParams

      Get expression parameters by ID.

      Args:
          exp_id: Expression ID

      Returns:
          ParserParams for the expression

      Raises:
          KeyError: If expression ID not found



   .. py:method:: get_hint_ids_by_name(name: str) -> list[int]

      Get hint indices by name.

      Corresponds to C++ ExpressionsBin::getHintIdsByName()
      (lines 684-691 of expressions_bin.cpp).

      Args:
          name: Hint name to search for

      Returns:
          List of hint indices with matching name



   .. py:method:: get_number_hint_ids_by_name(name: str) -> int

      Get count of hints by name.

      Corresponds to C++ ExpressionsBin::getNumberHintIdsByName()
      (lines 694-704 of expressions_bin.cpp).

      Args:
          name: Hint name to search for

      Returns:
          Number of hints with matching name



   .. py:method:: get_hint_field(hint_id: int, field_name: str) -> HintField

      Get a specific field from a hint by name.

      Args:
          hint_id: Index into self.hints
          field_name: Name of field (e.g., "numerator", "denominator", "reference")

      Returns:
          HintField containing the field values

      Raises:
          ValueError: If field not found in hint



