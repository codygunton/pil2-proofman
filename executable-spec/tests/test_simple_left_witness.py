import pytest
from primitives.field import FF3


def test_simple_left_witness_module_loads():
    from witness.simple_left import SimpleLeftWitness
    module = SimpleLeftWitness()
    assert hasattr(module, 'compute_intermediates')
    assert hasattr(module, 'compute_grand_sums')
