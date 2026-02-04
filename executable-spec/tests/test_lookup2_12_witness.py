"""Tests for Lookup2_12 witness module."""



def test_lookup2_12_witness_module_loads() -> None:
    from witness.lookup2_12 import Lookup2_12Witness
    module = Lookup2_12Witness()
    assert hasattr(module, 'compute_intermediates')
    assert hasattr(module, 'compute_grand_sums')
