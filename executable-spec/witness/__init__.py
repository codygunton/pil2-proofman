"""Witness generation modules.

This module provides per-AIR witness generation that replaces the generic
hint-driven witness computation. Each AIR has its own WitnessModule that
computes intermediate columns and grand sums directly in readable Python code.
"""

from .base import WitnessModule
from .lookup2_12 import Lookup2_12Witness
from .permutation1_6 import Permutation1_6Witness
from .simple_left import SimpleLeftWitness

# Registry mapping AIR names to witness module classes
WITNESS_REGISTRY: dict[str, type[WitnessModule]] = {
    'SimpleLeft': SimpleLeftWitness,
    'Lookup2_12': Lookup2_12Witness,
    'Permutation1_6': Permutation1_6Witness,
}


def get_witness_module(air_name: str) -> WitnessModule:
    """Get witness module instance for an AIR.

    Args:
        air_name: Name of the AIR (e.g., 'SimpleLeft', 'Lookup2_12')

    Returns:
        WitnessModule instance for the AIR

    Raises:
        KeyError: If no witness module is registered for the AIR
    """
    if air_name not in WITNESS_REGISTRY:
        raise KeyError(f"No witness module registered for AIR '{air_name}'. "
                      f"Available: {list(WITNESS_REGISTRY.keys())}")
    return WITNESS_REGISTRY[air_name]()


__all__ = [
    'WitnessModule',
    'SimpleLeftWitness',
    'Lookup2_12Witness',
    'Permutation1_6Witness',
    'WITNESS_REGISTRY',
    'get_witness_module',
]
