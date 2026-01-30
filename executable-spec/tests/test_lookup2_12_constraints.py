"""Tests for Lookup2_12 constraint module."""

import pytest
from primitives.field import FF3


def test_lookup2_12_constraint_module_loads():
    from constraints.lookup2_12 import Lookup2_12Constraints
    module = Lookup2_12Constraints()
    assert hasattr(module, 'constraint_polynomial')
