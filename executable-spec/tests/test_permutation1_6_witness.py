import pytest
from primitives.field import FF3


def test_permutation1_6_witness_module_loads():
    from witness.permutation1_6 import Permutation1_6Witness
    module = Permutation1_6Witness()
    assert hasattr(module, 'compute_intermediates')
    assert hasattr(module, 'compute_grand_sums')
