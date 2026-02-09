"""Constraint evaluation modules.

This module provides per-AIR constraint evaluation that replaces the generic
expression binary interpreter. Each AIR has its own ConstraintModule that
evaluates the constraint polynomial directly in readable Python code.

For AIRs without hand-written modules, the bytecode adapter provides a fallback
using compiled expression bytecode. The BYTECODE_AIRS dict controls which AIRs
use bytecode vs hand-written modules.
"""

from .base import (
    ConstraintContext,
    ConstraintModule,
    ProverConstraintContext,
    VerifierConstraintContext,
)
from .lookup2_12 import Lookup2_12Constraints
from .permutation1_6 import Permutation1_6Constraints
from .simple_left import SimpleLeftConstraints

# Registry mapping AIR names to hand-written constraint module classes
CONSTRAINT_REGISTRY: dict[str, type[ConstraintModule]] = {
    'SimpleLeft': SimpleLeftConstraints,
    'Lookup2_12': Lookup2_12Constraints,
    'Permutation1_6': Permutation1_6Constraints,
}

# AIRs that should use bytecode interpreter instead of hand-written modules.
# To validate bytecode, add a test AIR here; to use bytecode for a new AIR
# that has no hand-written module, add it here with its .bin path.
BYTECODE_AIRS: dict[str, str] = {
    # 'SimpleLeft': '/path/to/SimpleLeft.bin',   # uncomment to use bytecode
    # 'SomeZiskAir': '/path/to/SomeZiskAir.bin', # no hand-written module exists
}


def get_constraint_module(air_name: str) -> ConstraintModule:
    """Get constraint module instance for an AIR.

    Checks BYTECODE_AIRS first (allowing bytecode override for validation),
    then falls back to hand-written modules in CONSTRAINT_REGISTRY.

    Args:
        air_name: Name of the AIR (e.g., 'SimpleLeft', 'Lookup2_12')

    Returns:
        ConstraintModule instance for the AIR

    Raises:
        KeyError: If no constraint module is registered for the AIR
    """
    if air_name in BYTECODE_AIRS:
        from .bytecode_adapter import BytecodeConstraintModule
        return BytecodeConstraintModule(BYTECODE_AIRS[air_name])
    if air_name in CONSTRAINT_REGISTRY:
        return CONSTRAINT_REGISTRY[air_name]()
    raise KeyError(f"No constraint module for AIR '{air_name}'. "
                  f"Available: {list(CONSTRAINT_REGISTRY.keys())}")


__all__ = [
    'ConstraintContext',
    'ProverConstraintContext',
    'VerifierConstraintContext',
    'ConstraintModule',
    'SimpleLeftConstraints',
    'Lookup2_12Constraints',
    'Permutation1_6Constraints',
    'CONSTRAINT_REGISTRY',
    'BYTECODE_AIRS',
    'get_constraint_module',
]
