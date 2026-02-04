# tests/test_witness_base.py
import pytest


def test_witness_module_is_abstract() -> None:
    from witness.base import WitnessModule

    with pytest.raises(TypeError):
        WitnessModule()  # Can't instantiate abstract class


def test_witness_module_subclass_must_implement_methods() -> None:
    from witness.base import WitnessModule

    class IncompleteWitness(WitnessModule):
        pass

    with pytest.raises(TypeError):
        IncompleteWitness()
