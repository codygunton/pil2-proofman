"""Expression binary parser.

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
"""

import struct
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import numpy as np

# Section IDs (expressions_bin.hpp lines 20-27)
EXPRESSIONS_SECTION = 1
CONSTRAINTS_SECTION = 2
HINTS_SECTION = 3
N_SECTIONS = 3

GLOBAL_CONSTRAINTS_SECTION = 1
GLOBAL_HINTS_SECTION = 2
N_GLOBAL_SECTIONS = 2


# C++: pil2-stark/src/starkpil/stark_info.hpp::opType (lines 30-49)
class OpType(Enum):
    """Operation argument types.

    Corresponds to C++ enum opType in stark_info.hpp (lines 30-49).
    These define the source/destination types for expression operands.
    """
    const_ = 0          # Constant polynomial
    cm = 1              # Committed polynomial
    tmp = 2             # Temporary value
    public_ = 3         # Public input
    airgroupvalue = 4   # AIR group value
    challenge = 5       # Fiat-Shamir challenge
    number = 6          # Literal constant
    string_ = 7         # String value
    airvalue = 8        # AIR value
    proofvalue = 9      # Proof value
    custom = 10         # Custom commit
    x = 11              # Evaluation point x
    Zi = 12             # Zerofier value
    eval = 13           # Evaluation
    xDivXSubXi = 14     # x/(x-xi) precomputed
    q = 15              # Quotient polynomial
    f = 16              # FRI polynomial


# C++: No direct equivalent (C++ uses enum directly)
def optype_from_string(s: str) -> OpType:
    """Convert string to OpType enum."""
    mapping = {
        "const": OpType.const_,
        "cm": OpType.cm,
        "tmp": OpType.tmp,
        "public": OpType.public_,
        "airgroupvalue": OpType.airgroupvalue,
        "challenge": OpType.challenge,
        "number": OpType.number,
        "string": OpType.string_,
        "airvalue": OpType.airvalue,
        "proofvalue": OpType.proofvalue,
        "custom": OpType.custom,
        "x": OpType.x,
        "Zi": OpType.Zi,
        "eval": OpType.eval,
        "xDivXSubXi": OpType.xDivXSubXi,
        "q": OpType.q,
        "f": OpType.f,
    }
    return mapping.get(s, OpType.number)


# C++: pil2-stark/src/starkpil/expressions_bin.hpp::ParserParams (lines 53-69)
@dataclass
class ParserParams:
    """Parameters for a single expression.

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
    """
    stage: int = 0
    exp_id: int = 0
    n_temp1: int = 0
    n_temp3: int = 0
    n_ops: int = 0
    ops_offset: int = 0
    n_args: int = 0
    args_offset: int = 0
    first_row: int = 0
    last_row: int = 0
    dest_dim: int = 0
    dest_id: int = 0
    im_pol: bool = False
    line: str = ""


# C++: pil2-stark/src/starkpil/expressions_bin.hpp::ParserArgs (lines 71-77)
@dataclass
class ParserArgs:
    """Global bytecode and constants.

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
    """
    ops: np.ndarray = field(default_factory=lambda: np.array([], dtype=np.uint8))
    args: np.ndarray = field(default_factory=lambda: np.array([], dtype=np.uint16))
    numbers: np.ndarray = field(default_factory=lambda: np.array([], dtype=np.uint64))
    n_numbers: int = 0


# C++: pil2-stark/src/starkpil/expressions_bin.hpp::HintFieldValue (lines 30-39)
@dataclass
class HintFieldValue:
    """Hint field value.

    Corresponds to C++ struct HintFieldValue in expressions_bin.hpp (lines 30-39).
    """
    operand: OpType = OpType.number
    id: int = 0
    commit_id: int = 0
    row_offset_index: int = 0
    dim: int = 0
    value: int = 0
    string_value: str = ""
    pos: list[int] = field(default_factory=list)


# C++: pil2-stark/src/starkpil/expressions_bin.hpp::HintField (lines 41-44)
@dataclass
class HintField:
    """Hint field.

    Corresponds to C++ struct HintField in expressions_bin.hpp (lines 41-44).
    """
    name: str = ""
    values: list[HintFieldValue] = field(default_factory=list)


# C++: pil2-stark/src/starkpil/expressions_bin.hpp::Hint (lines 47-51)
@dataclass
class Hint:
    """Hint for witness generation.

    Corresponds to C++ struct Hint in expressions_bin.hpp (lines 47-51).
    """
    name: str = ""
    fields: list[HintField] = field(default_factory=list)


# C++: No direct equivalent (C++ uses direct file I/O in expressions_bin.cpp)
class BinFileReader:
    """Binary file reader with little-endian decoding.

    Mimics C++ BinFileUtils::BinFile interface for reading.

    Corresponds to C++ BinFile constructor in binfile_utils.cpp (lines 63-131).
    """

    # C++: Inline file reading in ExpressionsBin::load methods
    def __init__(self, file_path: str) -> None:
        """Open binary file for reading.

        Args:
            file_path: Path to .bin file

        Raises:
            ValueError: If file format is invalid
        """
        self.path = Path(file_path)
        with open(self.path, 'rb') as f:
            self.data = f.read()

        self.pos = 0
        self.reading_section = None
        self.sections = {}  # Map from section_id to list of (start, size) tuples

        # Parse header - magic "chps" (4 bytes)
        magic = self.data[0:4]
        if magic != b'chps':
            raise ValueError(f"Invalid magic: expected b'chps', got {magic}")
        self.pos = 4

        # Read version (uint32)
        version = self.read_u32_le()
        if version > 1:
            raise ValueError(f"Unsupported version: expected <=1, got {version}")

        # Read number of sections (uint32)
        self.n_sections = self.read_u32_le()

        # Parse section table of contents
        for _ in range(self.n_sections):
            section_type = self.read_u32_le()
            section_size = self.read_u64_le()

            # Store section metadata (offset and size)
            if section_type not in self.sections:
                self.sections[section_type] = []
            self.sections[section_type].append((self.pos, section_size))

            # Advance past section data
            self.pos += section_size

        # Reset position for section reading
        self.pos = 0

    # C++: Inline file reading in ExpressionsBin::load methods
    def read_bytes(self, n: int) -> bytes:
        """Read n raw bytes."""
        result = self.data[self.pos:self.pos + n]
        self.pos += n
        return result

    # C++: Inline file reading in ExpressionsBin::load methods
    def read_u8_le(self) -> int:
        """Read uint8 little-endian."""
        val = struct.unpack('<B', self.data[self.pos:self.pos + 1])[0]
        self.pos += 1
        return val

    # C++: Inline file reading in ExpressionsBin::load methods
    def read_u16_le(self) -> int:
        """Read uint16 little-endian."""
        val = struct.unpack('<H', self.data[self.pos:self.pos + 2])[0]
        self.pos += 2
        return val

    # C++: Inline file reading in ExpressionsBin::load methods
    def read_u32_le(self) -> int:
        """Read uint32 little-endian."""
        val = struct.unpack('<I', self.data[self.pos:self.pos + 4])[0]
        self.pos += 4
        return val

    # C++: Inline file reading in ExpressionsBin::load methods
    def read_u64_le(self) -> int:
        """Read uint64 little-endian."""
        val = struct.unpack('<Q', self.data[self.pos:self.pos + 8])[0]
        self.pos += 8
        return val

    # C++: Inline file reading in ExpressionsBin::load methods
    def read_string(self) -> str:
        """Read null-terminated string.

        Corresponds to C++ BinFile::readString() which reads until null byte.
        """
        # Find null terminator
        start = self.pos
        while self.pos < len(self.data) and self.data[self.pos] != 0:
            self.pos += 1

        # Extract string bytes (excluding null terminator)
        s_bytes = self.data[start:self.pos]

        # Skip null terminator
        if self.pos < len(self.data):
            self.pos += 1

        # Decode UTF-8
        return s_bytes.decode('utf-8')

    # C++: Section reading in expressions_bin.cpp
    def start_read_section(self, section_id: int, section_pos: int = 0) -> None:
        """Start reading a section.

        Corresponds to C++ BinFile::startReadSection() (lines 138-157).

        Args:
            section_id: Section identifier
            section_pos: Section instance index (default 0)

        Raises:
            ValueError: If section doesn't exist
        """
        if section_id not in self.sections:
            raise ValueError(f"Section {section_id} does not exist")

        if section_pos >= len(self.sections[section_id]):
            raise ValueError(
                f"Section pos {section_pos} out of range. "
                f"Section {section_id} has {len(self.sections[section_id])} instances."
            )

        # Set current position to start of section data
        section_start, section_size = self.sections[section_id][section_pos]
        self.pos = section_start
        self.section_start = section_start
        self.section_end = section_start + section_size
        self.reading_section = section_id

    # C++: Section reading in expressions_bin.cpp
    def end_read_section(self, check: bool = True) -> None:
        """End reading a section.

        Corresponds to C++ BinFile::endReadSection() (lines 159-166).

        Args:
            check: If True, verify we read exactly section_size bytes
        """
        if check and self.reading_section is not None:
            if self.pos != self.section_end:
                raise ValueError(
                    f"Section size mismatch: read {self.pos - self.section_start} bytes, "
                    f"expected {self.section_end - self.section_start}"
                )

        self.reading_section = None


# --- Hint Parsing Helpers ---

def _parse_hint_field_value(reader: BinFileReader) -> HintFieldValue:
    """Parse a single HintFieldValue from the binary reader.

    Reads the operand type and its associated data (id, dim, value, etc.)
    depending on the operand kind.
    """
    hfv = HintFieldValue()

    operand_str = reader.read_string()
    hfv.operand = optype_from_string(operand_str)

    if hfv.operand == OpType.number:
        hfv.value = reader.read_u64_le()
    elif hfv.operand == OpType.string_:
        hfv.string_value = reader.read_string()
    else:
        hfv.id = reader.read_u32_le()

    if hfv.operand in [OpType.custom, OpType.const_, OpType.cm]:
        hfv.row_offset_index = reader.read_u32_le()

    if hfv.operand == OpType.tmp:
        hfv.dim = reader.read_u32_le()

    if hfv.operand == OpType.custom:
        hfv.commit_id = reader.read_u32_le()

    n_pos = reader.read_u32_le()
    for _ in range(n_pos):
        hfv.pos.append(reader.read_u32_le())

    return hfv


def _parse_hint_field(reader: BinFileReader) -> HintField:
    """Parse a single HintField (name + list of values) from the binary reader."""
    hf = HintField()
    hf.name = reader.read_string()

    n_values = reader.read_u32_le()
    for _ in range(n_values):
        hf.values.append(_parse_hint_field_value(reader))

    return hf


def _parse_hint(reader: BinFileReader) -> Hint:
    """Parse a single Hint (name + list of fields) from the binary reader."""
    hint = Hint()
    hint.name = reader.read_string()

    n_fields = reader.read_u32_le()
    for _ in range(n_fields):
        hint.fields.append(_parse_hint_field(reader))

    return hint


def _parse_global_hint_field_value(reader: BinFileReader) -> HintFieldValue:
    """Parse a HintFieldValue from a global hints section.

    Global hints have a different format than per-AIR hints: they use
    explicit dim fields for airgroupvalue/airvalue and restrict the
    set of allowed operand types.
    """
    hfv = HintFieldValue()

    operand_str = reader.read_string()
    hfv.operand = optype_from_string(operand_str)

    if hfv.operand == OpType.number:
        hfv.value = reader.read_u64_le()
    elif hfv.operand == OpType.string_:
        hfv.string_value = reader.read_string()
    elif hfv.operand in [OpType.airgroupvalue, OpType.airvalue]:
        hfv.dim = reader.read_u32_le()
        hfv.id = reader.read_u32_le()
    elif hfv.operand in [OpType.tmp, OpType.public_, OpType.proofvalue]:
        hfv.id = reader.read_u32_le()
    else:
        raise ValueError(f"Invalid operand type in global hints: {operand_str}")

    n_pos = reader.read_u32_le()
    for _ in range(n_pos):
        hfv.pos.append(reader.read_u32_le())

    return hfv


def _parse_global_hint_field(reader: BinFileReader) -> HintField:
    """Parse a HintField from a global hints section."""
    hf = HintField()
    hf.name = reader.read_string()

    n_values = reader.read_u32_le()
    for _ in range(n_values):
        hf.values.append(_parse_global_hint_field_value(reader))

    return hf


def _parse_global_hint(reader: BinFileReader) -> Hint:
    """Parse a Hint from a global hints section."""
    hint = Hint()
    hint.name = reader.read_string()

    n_fields = reader.read_u32_le()
    for _ in range(n_fields):
        hint.fields.append(_parse_global_hint_field(reader))

    return hint


# C++: pil2-stark/src/starkpil/expressions_bin.hpp::ExpressionsBin (lines 79-145)
class ExpressionsBin:
    """Compiled expression database.

    Corresponds to C++ class ExpressionsBin in expressions_bin.hpp (lines 79-145).

    This class loads and manages compiled expression bytecode from .bin files.
    The bytecode represents arithmetic constraint expressions compiled into
    a stack-based operation sequence.
    """

    # C++: ExpressionsBin constructor
    def __init__(self) -> None:
        """Initialize empty expressions database."""
        self.n_ops_total: int = 0
        self.n_args_total: int = 0

        # Expression metadata indexed by expression ID
        self.expressions_info: dict[int, ParserParams] = {}

        # Constraint metadata (for debugging)
        self.constraints_info_debug: list[ParserParams] = []

        # Hints for witness generation
        self.hints: list[Hint] = []

        # Global bytecode for expressions
        self.expressions_bin_args_expressions = ParserArgs()

        # Global bytecode for constraints
        self.expressions_bin_args_constraints = ParserArgs()

        # Maximum temporary storage needed
        self.max_tmp1: int = 0
        self.max_tmp3: int = 0
        self.max_args: int = 0
        self.max_ops: int = 0

    # C++: ExpressionsBin::load (expressions_bin.cpp)
    @classmethod
    def from_file(cls, file_path: str, global_bin: bool = False, verifier_bin: bool = False) -> 'ExpressionsBin':
        """Load ExpressionsBin from binary file.

        Corresponds to C++ constructor (lines 3-13 of expressions_bin.cpp).

        Args:
            file_path: Path to .bin file
            global_bin: Load as global constraints binary
            verifier_bin: Load as verifier binary

        Returns:
            Loaded ExpressionsBin instance
        """
        expr_bin = cls()
        reader = BinFileReader(file_path)

        if global_bin:
            expr_bin._load_global_bin(reader)
        elif verifier_bin:
            expr_bin._load_verifier_bin(reader)
        else:
            expr_bin._load_expressions_bin(reader)

        return expr_bin

    # C++: ExpressionsBin::loadExpressionsBin
    def _load_expressions_bin(self, reader: BinFileReader) -> None:
        """Load expressions binary file.

        Corresponds to C++ ExpressionsBin::loadExpressionsBin()
        (lines 364-526 of expressions_bin.cpp).

        File format:
        - Section 1 (EXPRESSIONS_SECTION): Expression bytecode
        - Section 2 (CONSTRAINTS_SECTION): Constraint bytecode
        - Section 3 (HINTS_SECTION): Witness generation hints
        """
        # Load expressions section (lines 365-419)
        reader.start_read_section(EXPRESSIONS_SECTION)

        self.max_tmp1 = reader.read_u32_le()
        self.max_tmp3 = reader.read_u32_le()
        self.max_args = reader.read_u32_le()
        self.max_ops = reader.read_u32_le()

        n_ops_expressions = reader.read_u32_le()
        self.n_ops_total = n_ops_expressions
        n_args_expressions = reader.read_u32_le()
        self.n_args_total = n_args_expressions
        n_numbers_expressions = reader.read_u32_le()

        n_expressions = reader.read_u32_le()

        # Read expression metadata (lines 385-407)
        for i in range(n_expressions):
            params = ParserParams()

            exp_id = reader.read_u32_le()
            params.exp_id = exp_id
            params.dest_dim = reader.read_u32_le()
            params.dest_id = reader.read_u32_le()
            params.stage = reader.read_u32_le()

            params.n_temp1 = reader.read_u32_le()
            params.n_temp3 = reader.read_u32_le()

            params.n_ops = reader.read_u32_le()
            params.ops_offset = reader.read_u32_le()

            params.n_args = reader.read_u32_le()
            params.args_offset = reader.read_u32_le()

            params.line = reader.read_string()

            self.expressions_info[exp_id] = params

        # Read bytecode arrays (lines 409-417)
        ops = np.zeros(n_ops_expressions, dtype=np.uint8)
        for j in range(n_ops_expressions):
            ops[j] = reader.read_u8_le()
        self.expressions_bin_args_expressions.ops = ops

        args = np.zeros(n_args_expressions, dtype=np.uint16)
        for j in range(n_args_expressions):
            args[j] = reader.read_u16_le()
        self.expressions_bin_args_expressions.args = args

        numbers = np.zeros(n_numbers_expressions, dtype=np.uint64)
        for j in range(n_numbers_expressions):
            numbers[j] = reader.read_u64_le()
        self.expressions_bin_args_expressions.numbers = numbers
        self.expressions_bin_args_expressions.n_numbers = n_numbers_expressions

        reader.end_read_section()

        # Load constraints section (lines 420-472)
        reader.start_read_section(CONSTRAINTS_SECTION)

        n_ops_debug = reader.read_u32_le()
        n_args_debug = reader.read_u32_le()
        n_numbers_debug = reader.read_u32_le()

        n_constraints = reader.read_u32_le()

        # Read constraint metadata (lines 433-459)
        for i in range(n_constraints):
            params = ParserParams()

            params.stage = reader.read_u32_le()
            params.exp_id = 0

            params.dest_dim = reader.read_u32_le()
            params.dest_id = reader.read_u32_le()

            params.first_row = reader.read_u32_le()
            params.last_row = reader.read_u32_le()

            params.n_temp1 = reader.read_u32_le()
            params.n_temp3 = reader.read_u32_le()

            params.n_ops = reader.read_u32_le()
            params.ops_offset = reader.read_u32_le()

            params.n_args = reader.read_u32_le()
            params.args_offset = reader.read_u32_le()

            params.im_pol = bool(reader.read_u32_le())
            params.line = reader.read_string()

            self.constraints_info_debug.append(params)

        # Read constraint bytecode (lines 462-470)
        ops_debug = np.zeros(n_ops_debug, dtype=np.uint8)
        for j in range(n_ops_debug):
            ops_debug[j] = reader.read_u8_le()
        self.expressions_bin_args_constraints.ops = ops_debug

        args_debug = np.zeros(n_args_debug, dtype=np.uint16)
        for j in range(n_args_debug):
            args_debug[j] = reader.read_u16_le()
        self.expressions_bin_args_constraints.args = args_debug

        numbers_debug = np.zeros(n_numbers_debug, dtype=np.uint64)
        for j in range(n_numbers_debug):
            numbers_debug[j] = reader.read_u64_le()
        self.expressions_bin_args_constraints.numbers = numbers_debug
        self.expressions_bin_args_constraints.n_numbers = n_numbers_debug

        reader.end_read_section()

        # Load hints section (lines 473-525)
        reader.start_read_section(HINTS_SECTION)

        n_hints = reader.read_u32_le()
        for _ in range(n_hints):
            self.hints.append(_parse_hint(reader))

        reader.end_read_section()

    # C++: ExpressionsBin::loadVerifierBin
    def _load_verifier_bin(self, reader: BinFileReader) -> None:
        """Load verifier binary file.

        Corresponds to C++ ExpressionsBin::loadVerifierBin()
        (lines 528-582 of expressions_bin.cpp).

        Verifier binary only contains expressions section (no constraints or hints).
        """
        reader.start_read_section(EXPRESSIONS_SECTION)

        self.max_tmp1 = reader.read_u32_le()
        self.max_tmp3 = reader.read_u32_le()
        self.max_args = reader.read_u32_le()
        self.max_ops = reader.read_u32_le()

        n_ops_expressions = reader.read_u32_le()
        self.n_ops_total = n_ops_expressions
        n_args_expressions = reader.read_u32_le()
        self.n_args_total = n_args_expressions
        n_numbers_expressions = reader.read_u32_le()

        n_expressions = reader.read_u32_le()

        # Read expression metadata
        for i in range(n_expressions):
            params = ParserParams()

            exp_id = reader.read_u32_le()
            params.exp_id = exp_id
            params.dest_dim = reader.read_u32_le()
            params.dest_id = reader.read_u32_le()
            params.stage = reader.read_u32_le()

            params.n_temp1 = reader.read_u32_le()
            params.n_temp3 = reader.read_u32_le()

            params.n_ops = reader.read_u32_le()
            params.ops_offset = reader.read_u32_le()

            params.n_args = reader.read_u32_le()
            params.args_offset = reader.read_u32_le()

            params.line = reader.read_string()

            self.expressions_info[exp_id] = params

        # Read bytecode arrays
        ops = np.zeros(n_ops_expressions, dtype=np.uint8)
        for j in range(n_ops_expressions):
            ops[j] = reader.read_u8_le()
        self.expressions_bin_args_expressions.ops = ops

        args = np.zeros(n_args_expressions, dtype=np.uint16)
        for j in range(n_args_expressions):
            args[j] = reader.read_u16_le()
        self.expressions_bin_args_expressions.args = args

        numbers = np.zeros(n_numbers_expressions, dtype=np.uint64)
        for j in range(n_numbers_expressions):
            numbers[j] = reader.read_u64_le()
        self.expressions_bin_args_expressions.numbers = numbers
        self.expressions_bin_args_expressions.n_numbers = n_numbers_expressions

        reader.end_read_section()

    # C++: ExpressionsBin::loadGlobalBin
    def _load_global_bin(self, reader: BinFileReader) -> None:
        """Load global binary file.

        Corresponds to C++ ExpressionsBin::loadGlobalBin()
        (lines 584-682 of expressions_bin.cpp).

        Global binary contains global constraints and hints (no expressions).
        """
        reader.start_read_section(GLOBAL_CONSTRAINTS_SECTION)

        n_ops_debug = reader.read_u32_le()
        n_args_debug = reader.read_u32_le()
        n_numbers_debug = reader.read_u32_le()

        n_global_constraints = reader.read_u32_le()

        # Read constraint metadata
        for i in range(n_global_constraints):
            params = ParserParams()

            params.dest_dim = reader.read_u32_le()
            params.dest_id = reader.read_u32_le()

            params.n_temp1 = reader.read_u32_le()
            params.n_temp3 = reader.read_u32_le()

            params.n_ops = reader.read_u32_le()
            params.ops_offset = reader.read_u32_le()

            params.n_args = reader.read_u32_le()
            params.args_offset = reader.read_u32_le()

            params.line = reader.read_string()

            self.constraints_info_debug.append(params)

        # Read bytecode
        ops_debug = np.zeros(n_ops_debug, dtype=np.uint8)
        for j in range(n_ops_debug):
            ops_debug[j] = reader.read_u8_le()
        self.expressions_bin_args_constraints.ops = ops_debug

        args_debug = np.zeros(n_args_debug, dtype=np.uint16)
        for j in range(n_args_debug):
            args_debug[j] = reader.read_u16_le()
        self.expressions_bin_args_constraints.args = args_debug

        numbers_debug = np.zeros(n_numbers_debug, dtype=np.uint64)
        for j in range(n_numbers_debug):
            numbers_debug[j] = reader.read_u64_le()
        self.expressions_bin_args_constraints.numbers = numbers_debug
        self.expressions_bin_args_constraints.n_numbers = n_numbers_debug

        reader.end_read_section()

        # Load global hints section
        reader.start_read_section(GLOBAL_HINTS_SECTION)

        n_hints = reader.read_u32_le()
        for _ in range(n_hints):
            self.hints.append(_parse_global_hint(reader))

        reader.end_read_section()

    # C++: ExpressionsBin::getExpression
    def get_expression(self, exp_id: int) -> ParserParams:
        """Get expression parameters by ID.

        Args:
            exp_id: Expression ID

        Returns:
            ParserParams for the expression

        Raises:
            KeyError: If expression ID not found
        """
        return self.expressions_info[exp_id]

    # C++: ExpressionsBin::getHintIdsByName
    def get_hint_ids_by_name(self, name: str) -> list[int]:
        """Get hint indices by name.

        Corresponds to C++ ExpressionsBin::getHintIdsByName()
        (lines 684-691 of expressions_bin.cpp).

        Args:
            name: Hint name to search for

        Returns:
            List of hint indices with matching name
        """
        hint_ids = []
        for i, hint in enumerate(self.hints):
            if hint.name == name:
                hint_ids.append(i)
        return hint_ids

    # C++: ExpressionsBin::getNumberHintIdsByName
    def get_number_hint_ids_by_name(self, name: str) -> int:
        """Get count of hints by name.

        Corresponds to C++ ExpressionsBin::getNumberHintIdsByName()
        (lines 694-704 of expressions_bin.cpp).

        Args:
            name: Hint name to search for

        Returns:
            Number of hints with matching name
        """
        return len(self.get_hint_ids_by_name(name))

    # C++: ExpressionsBin::getHintField
    def get_hint_field(self, hint_id: int, field_name: str) -> HintField:
        """Get a specific field from a hint by name.

        Args:
            hint_id: Index into self.hints
            field_name: Name of field (e.g., "numerator", "denominator", "reference")

        Returns:
            HintField containing the field values

        Raises:
            ValueError: If field not found in hint
        """
        hint = self.hints[hint_id]
        for hf in hint.fields:
            if hf.name == field_name:
                return hf
        raise ValueError(f"Field '{field_name}' not found in hint '{hint.name}'")
