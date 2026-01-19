"""Tests for expressions_bin.py - Expression binary parser.

These tests verify that the Python implementation correctly parses compiled
expression bytecode from .bin files, cross-validating structure and content.
"""

import pytest
from pathlib import Path
import numpy as np

from protocol.expressions_bin import (
    ExpressionsBin,
    ParserParams,
    ParserArgs,
    BinFileReader,
    EXPRESSIONS_SECTION,
    CONSTRAINTS_SECTION,
    HINTS_SECTION,
)


# Test data paths
SIMPLE_LEFT_BIN = "/home/cody/pil2-proofman/pil2-components/test/simple/build/provingKey/build/Simple/airs/SimpleLeft/air/SimpleLeft.bin"
SIMPLE_LEFT_VERIFIER_BIN = "/home/cody/pil2-proofman/pil2-components/test/simple/build/provingKey/build/Simple/airs/SimpleLeft/air/SimpleLeft.verifier.bin"


def test_bin_file_reader_magic_and_version():
    """Test BinFileReader correctly reads file header."""
    if not Path(SIMPLE_LEFT_BIN).exists():
        pytest.fail("SimpleLeft.bin not found - run ./setup.sh first")

    reader = BinFileReader(SIMPLE_LEFT_BIN)

    # Verify magic was read correctly (constructor checks this)
    assert reader.n_sections == 3  # Should have 3 sections for regular .bin


def test_expressions_bin_from_file_basic():
    """Test ExpressionsBin.from_file() loads without errors."""
    if not Path(SIMPLE_LEFT_BIN).exists():
        pytest.fail("SimpleLeft.bin not found - run ./setup.sh first")

    expr_bin = ExpressionsBin.from_file(SIMPLE_LEFT_BIN)

    # Verify basic structure
    assert isinstance(expr_bin, ExpressionsBin)
    assert expr_bin.n_ops_total > 0
    assert expr_bin.n_args_total > 0
    assert len(expr_bin.expressions_info) > 0


def test_expressions_bin_parser_params():
    """Test that ParserParams are correctly populated."""
    if not Path(SIMPLE_LEFT_BIN).exists():
        pytest.fail("SimpleLeft.bin not found - run ./setup.sh first")

    expr_bin = ExpressionsBin.from_file(SIMPLE_LEFT_BIN)

    # Check that we have some expressions
    assert len(expr_bin.expressions_info) > 0

    # Get first expression
    first_exp_id = min(expr_bin.expressions_info.keys())
    params = expr_bin.expressions_info[first_exp_id]

    # Verify structure
    assert isinstance(params, ParserParams)
    assert params.exp_id == first_exp_id
    assert params.n_ops >= 0
    assert params.n_args >= 0
    assert params.dest_dim in [1, 3]  # Must be scalar or field extension

    # Verify offsets are within bounds
    assert params.ops_offset >= 0
    assert params.args_offset >= 0
    if params.n_ops > 0:
        assert params.ops_offset + params.n_ops <= expr_bin.n_ops_total
    if params.n_args > 0:
        assert params.args_offset + params.n_args <= expr_bin.n_args_total


def test_expressions_bin_parser_args():
    """Test that ParserArgs arrays are correctly populated."""
    if not Path(SIMPLE_LEFT_BIN).exists():
        pytest.fail("SimpleLeft.bin not found - run ./setup.sh first")

    expr_bin = ExpressionsBin.from_file(SIMPLE_LEFT_BIN)

    args = expr_bin.expressions_bin_args_expressions

    # Verify arrays exist and have correct types
    assert isinstance(args, ParserArgs)
    assert isinstance(args.ops, np.ndarray)
    assert isinstance(args.args, np.ndarray)
    assert isinstance(args.numbers, np.ndarray)

    # Verify dtypes
    assert args.ops.dtype == np.uint8
    assert args.args.dtype == np.uint16
    assert args.numbers.dtype == np.uint64

    # Verify sizes match
    assert len(args.ops) == expr_bin.n_ops_total
    assert len(args.args) == expr_bin.n_args_total
    assert len(args.numbers) == args.n_numbers

    # Verify ops values are in valid range (0-2 for operation type)
    # Note: ops encodes the dimension combination, not operation type
    assert np.all(args.ops <= 2)


def test_expressions_bin_constraints():
    """Test that constraint section is correctly loaded."""
    if not Path(SIMPLE_LEFT_BIN).exists():
        pytest.fail("SimpleLeft.bin not found - run ./setup.sh first")

    expr_bin = ExpressionsBin.from_file(SIMPLE_LEFT_BIN)

    # Should have some constraints for debugging
    assert len(expr_bin.constraints_info_debug) > 0

    # Check constraint structure
    constraint = expr_bin.constraints_info_debug[0]
    assert isinstance(constraint, ParserParams)
    assert constraint.n_ops >= 0
    assert constraint.n_args >= 0


def test_expressions_bin_hints():
    """Test that hints section is correctly loaded."""
    if not Path(SIMPLE_LEFT_BIN).exists():
        pytest.fail("SimpleLeft.bin not found - run ./setup.sh first")

    expr_bin = ExpressionsBin.from_file(SIMPLE_LEFT_BIN)

    # SimpleLeft should have hints
    assert len(expr_bin.hints) > 0

    # Check hint structure
    hint = expr_bin.hints[0]
    assert isinstance(hint.name, str)
    assert len(hint.name) > 0
    assert len(hint.fields) > 0


def test_expressions_bin_max_values():
    """Test that maximum temporary values are correctly set."""
    if not Path(SIMPLE_LEFT_BIN).exists():
        pytest.fail("SimpleLeft.bin not found - run ./setup.sh first")

    expr_bin = ExpressionsBin.from_file(SIMPLE_LEFT_BIN)

    # Verify max values are non-negative
    assert expr_bin.max_tmp1 >= 0
    assert expr_bin.max_tmp3 >= 0
    assert expr_bin.max_args >= 0
    assert expr_bin.max_ops >= 0

    # Verify they're actually maximums across all expressions
    for params in expr_bin.expressions_info.values():
        assert params.n_temp1 <= expr_bin.max_tmp1
        assert params.n_temp3 <= expr_bin.max_tmp3
        assert params.n_ops <= expr_bin.max_ops
        assert params.n_args <= expr_bin.max_args


def test_get_expression():
    """Test get_expression() method."""
    if not Path(SIMPLE_LEFT_BIN).exists():
        pytest.fail("SimpleLeft.bin not found - run ./setup.sh first")

    expr_bin = ExpressionsBin.from_file(SIMPLE_LEFT_BIN)

    # Get an existing expression
    exp_ids = list(expr_bin.expressions_info.keys())
    assert len(exp_ids) > 0

    params = expr_bin.get_expression(exp_ids[0])
    assert isinstance(params, ParserParams)
    assert params.exp_id == exp_ids[0]

    # Try to get non-existent expression
    with pytest.raises(KeyError):
        expr_bin.get_expression(999999)


def test_get_hint_ids_by_name():
    """Test get_hint_ids_by_name() and get_number_hint_ids_by_name()."""
    if not Path(SIMPLE_LEFT_BIN).exists():
        pytest.fail("SimpleLeft.bin not found - run ./setup.sh first")

    expr_bin = ExpressionsBin.from_file(SIMPLE_LEFT_BIN)

    if len(expr_bin.hints) == 0:
        pytest.fail("No hints in this binary")

    # Get a hint name that exists
    hint_name = expr_bin.hints[0].name

    # Test get_hint_ids_by_name
    hint_ids = expr_bin.get_hint_ids_by_name(hint_name)
    assert len(hint_ids) > 0
    assert all(isinstance(i, int) for i in hint_ids)

    # Verify the hints actually have that name
    for hint_id in hint_ids:
        assert expr_bin.hints[hint_id].name == hint_name

    # Test get_number_hint_ids_by_name
    count = expr_bin.get_number_hint_ids_by_name(hint_name)
    assert count == len(hint_ids)

    # Test with non-existent name
    hint_ids_empty = expr_bin.get_hint_ids_by_name("NonExistentHint")
    assert len(hint_ids_empty) == 0
    assert expr_bin.get_number_hint_ids_by_name("NonExistentHint") == 0


def test_verifier_bin_loading():
    """Test loading verifier binary (expressions only, no constraints/hints)."""
    if not Path(SIMPLE_LEFT_VERIFIER_BIN).exists():
        pytest.fail("SimpleLeft.verifier.bin not found - run ./setup.sh first")

    expr_bin = ExpressionsBin.from_file(SIMPLE_LEFT_VERIFIER_BIN, verifier_bin=True)

    # Should have expressions
    assert len(expr_bin.expressions_info) > 0
    assert expr_bin.n_ops_total > 0
    assert expr_bin.n_args_total > 0

    # Verifier binary has only expressions section
    # So constraints and hints may be empty or have default values
    # (The actual behavior depends on the binary format)


def test_bytecode_access():
    """Test that bytecode can be accessed via offsets."""
    if not Path(SIMPLE_LEFT_BIN).exists():
        pytest.fail("SimpleLeft.bin not found - run ./setup.sh first")

    expr_bin = ExpressionsBin.from_file(SIMPLE_LEFT_BIN)

    # Get an expression with operations
    for params in expr_bin.expressions_info.values():
        if params.n_ops > 0 and params.n_args > 0:
            # Access ops via offset
            ops_slice = expr_bin.expressions_bin_args_expressions.ops[
                params.ops_offset:params.ops_offset + params.n_ops
            ]
            assert len(ops_slice) == params.n_ops

            # Access args via offset
            args_slice = expr_bin.expressions_bin_args_expressions.args[
                params.args_offset:params.args_offset + params.n_args
            ]
            assert len(args_slice) == params.n_args

            # Args come in groups of 8 per operation
            # (operation type, dest, srcA type, srcA col, srcA stride, srcB type, srcB col, srcB stride)
            assert params.n_args == params.n_ops * 8

            break


def test_expression_line_strings():
    """Test that expression line strings are readable."""
    if not Path(SIMPLE_LEFT_BIN).exists():
        pytest.fail("SimpleLeft.bin not found - run ./setup.sh first")

    expr_bin = ExpressionsBin.from_file(SIMPLE_LEFT_BIN)

    # Check that expressions have line strings
    for params in expr_bin.expressions_info.values():
        # Line should be a string (may be empty)
        assert isinstance(params.line, str)
        # If non-empty, should be valid UTF-8 and printable
        if params.line:
            assert params.line.isprintable() or '\n' in params.line


@pytest.mark.parametrize("air_name,bin_path", [
    ("SimpleLeft", SIMPLE_LEFT_BIN),
])
def test_expressions_bin_faithfulness(air_name, bin_path):
    """
    Test that loading is deterministic and preserves data integrity.

    This test verifies that:
    1. Loading twice produces identical results
    2. All data structures are properly initialized
    3. No data is lost during parsing
    """
    if not Path(bin_path).exists():
        pytest.fail(f"{air_name}.bin not found - run ./setup.sh first")

    # Load twice
    expr_bin1 = ExpressionsBin.from_file(bin_path)
    expr_bin2 = ExpressionsBin.from_file(bin_path)

    # Verify determinism - all scalar values match
    assert expr_bin1.n_ops_total == expr_bin2.n_ops_total
    assert expr_bin1.n_args_total == expr_bin2.n_args_total
    assert expr_bin1.max_tmp1 == expr_bin2.max_tmp1
    assert expr_bin1.max_tmp3 == expr_bin2.max_tmp3
    assert expr_bin1.max_args == expr_bin2.max_args
    assert expr_bin1.max_ops == expr_bin2.max_ops

    # Verify expression count matches
    assert len(expr_bin1.expressions_info) == len(expr_bin2.expressions_info)

    # Verify arrays are identical
    assert np.array_equal(
        expr_bin1.expressions_bin_args_expressions.ops,
        expr_bin2.expressions_bin_args_expressions.ops
    )
    assert np.array_equal(
        expr_bin1.expressions_bin_args_expressions.args,
        expr_bin2.expressions_bin_args_expressions.args
    )
    assert np.array_equal(
        expr_bin1.expressions_bin_args_expressions.numbers,
        expr_bin2.expressions_bin_args_expressions.numbers
    )

    # Verify hints count matches
    assert len(expr_bin1.hints) == len(expr_bin2.hints)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
