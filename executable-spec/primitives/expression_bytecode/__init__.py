"""Expression bytecode interpreter package.

Provides parsing and evaluation of compiled PIL expression bytecode (.bin files).
This package is isolated from the protocol layer and used by the bytecode adapter
wrappers in constraints/ and witness/ to support AIRs without hand-written Python.
"""

from primitives.expression_bytecode.expressions_bin import (
    BinFileReader,
    ExpressionsBin,
    Hint,
    HintField,
    HintFieldValue,
    OpType,
    ParserArgs,
    ParserParams,
)

__all__ = [
    'ExpressionsBin',
    'BinFileReader',
    'OpType',
    'ParserArgs',
    'ParserParams',
    'Hint',
    'HintField',
    'HintFieldValue',
]
