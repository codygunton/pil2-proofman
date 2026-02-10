"""Witness generation modules.

This module provides per-AIR witness generation that replaces the generic
hint-driven witness computation. Each AIR has its own WitnessModule that
computes intermediate columns and grand sums directly in readable Python code.

For AIRs without hand-written modules, the bytecode adapter provides a fallback
using compiled expression bytecode. The BYTECODE_AIRS dict controls which AIRs
use bytecode vs hand-written modules.

Zisk AIRs are auto-discovered from the proving key directory. All discovered
AIRs without hand-written modules are registered for bytecode evaluation.
"""

from constraints import _discover_zisk_airs

from .base import WitnessModule
from .lookup2_12 import Lookup2_12Witness
from .permutation1_6 import Permutation1_6Witness
from .simple_left import SimpleLeftWitness

# Registry mapping AIR names to hand-written witness module classes
WITNESS_REGISTRY: dict[str, type[WitnessModule]] = {
    'SimpleLeft': SimpleLeftWitness,
    'Lookup2_12': Lookup2_12Witness,
    'Permutation1_6': Permutation1_6Witness,
}

# AIRs that should use bytecode interpreter for witness generation.
# Includes auto-discovered Zisk AIRs (shared with constraints.BYTECODE_AIRS).
BYTECODE_AIRS: dict[str, str] = _discover_zisk_airs()


def get_witness_module(air_name: str) -> WitnessModule:
    """Get witness module instance for an AIR.

    Checks BYTECODE_AIRS first (allowing bytecode override for validation),
    then falls back to hand-written modules in WITNESS_REGISTRY.

    Args:
        air_name: Name of the AIR (e.g., 'SimpleLeft', 'Lookup2_12')

    Returns:
        WitnessModule instance for the AIR

    Raises:
        KeyError: If no witness module is registered for the AIR
    """
    if air_name in BYTECODE_AIRS:
        from .bytecode_adapter import BytecodeWitnessModule
        return BytecodeWitnessModule(BYTECODE_AIRS[air_name])
    if air_name in WITNESS_REGISTRY:
        return WITNESS_REGISTRY[air_name]()
    raise KeyError(f"No witness module for AIR '{air_name}'. "
                  f"Available: {list(WITNESS_REGISTRY.keys())}")


__all__ = [
    'WitnessModule',
    'SimpleLeftWitness',
    'Lookup2_12Witness',
    'Permutation1_6Witness',
    'WITNESS_REGISTRY',
    'BYTECODE_AIRS',
    'get_witness_module',
]
