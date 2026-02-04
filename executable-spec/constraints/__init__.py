"""Constraint evaluation modules.

This module provides per-AIR constraint evaluation that replaces the generic
expression binary interpreter. Each AIR has its own ConstraintModule that
evaluates the constraint polynomial directly in readable Python code.
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

# Registry mapping AIR names to constraint module classes
CONSTRAINT_REGISTRY: dict[str, type[ConstraintModule]] = {
    'SimpleLeft': SimpleLeftConstraints,
    'Lookup2_12': Lookup2_12Constraints,
    'Permutation1_6': Permutation1_6Constraints,
}


def get_constraint_module(air_name: str) -> ConstraintModule:
    """Get constraint module instance for an AIR.

    Args:
        air_name: Name of the AIR (e.g., 'SimpleLeft', 'Lookup2_12')

    Returns:
        ConstraintModule instance for the AIR

    Raises:
        KeyError: If no constraint module is registered for the AIR
    """
    if air_name not in CONSTRAINT_REGISTRY:
        raise KeyError(f"No constraint module registered for AIR '{air_name}'. "
                      f"Available: {list(CONSTRAINT_REGISTRY.keys())}")
    return CONSTRAINT_REGISTRY[air_name]()


__all__ = [
    'ConstraintContext',
    'ProverConstraintContext',
    'VerifierConstraintContext',
    'ConstraintModule',
    'SimpleLeftConstraints',
    'Lookup2_12Constraints',
    'Permutation1_6Constraints',
    'CONSTRAINT_REGISTRY',
    'get_constraint_module',
]
