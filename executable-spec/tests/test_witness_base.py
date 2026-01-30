# tests/test_witness_base.py
import pytest
from primitives.field import FF3


def test_witness_module_is_abstract():
    from witness.base import WitnessModule

    with pytest.raises(TypeError):
        WitnessModule()  # Can't instantiate abstract class


def test_witness_module_subclass_must_implement_methods():
    from witness.base import WitnessModule
    from constraints.base import ConstraintContext

    class IncompleteWitness(WitnessModule):
        pass

    with pytest.raises(TypeError):
        IncompleteWitness()
