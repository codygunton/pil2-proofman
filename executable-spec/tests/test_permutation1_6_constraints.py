import pytest
from primitives.field import FF3


def test_permutation1_6_constraint_module_loads():
    from constraints.permutation1_6 import Permutation1_6Constraints
    module = Permutation1_6Constraints()
    assert hasattr(module, 'constraint_polynomial')
