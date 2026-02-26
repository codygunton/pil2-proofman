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
from constraints.base import ConstraintContext
from primitives.field import FF3Poly

from .base import WitnessModule
from .lookup2_12 import Lookup2_12Witness
from .permutation1_6 import Permutation1_6Witness
from .simple_left import SimpleLeftWitness
from .simple_right import SimpleRightWitness
from .specified_ranges import SpecifiedRangesWitness
from .u8_air import U8AirWitness
from .u16_air import U16AirWitness

# Registry mapping AIR names to hand-written witness module classes
WITNESS_REGISTRY: dict[str, type[WitnessModule]] = {
    'SimpleLeft': SimpleLeftWitness,
    'SimpleRight': SimpleRightWitness,
    'U8Air': U8AirWitness,
    'U16Air': U16AirWitness,
    'SpecifiedRanges': SpecifiedRangesWitness,
    'Lookup2_12': Lookup2_12Witness,
    'Permutation1_6': Permutation1_6Witness,
}

# AIRs that should use bytecode interpreter for witness generation.
# Includes auto-discovered Zisk AIRs (shared with constraints.BYTECODE_AIRS).
BYTECODE_AIRS: dict[str, str] = _discover_zisk_airs()


class _FallbackWitnessModule(WitnessModule):
    """Wraps a primary module, falling back to bytecode when it returns empty dicts.

    Used when an AIR has a hand-written module that does not implement Stage-2
    (compute_intermediates / compute_grand_sums), deferring to the compiled
    expression bytecode for those columns.
    """

    def __init__(self, primary: WitnessModule, expressions_bin: str) -> None:
        self._primary = primary
        self._expressions_bin = expressions_bin
        self._bytecode: WitnessModule | None = None

    def compute_intermediates(self, ctx: ConstraintContext) -> dict[str, dict[int, FF3Poly]]:
        result = self._primary.compute_intermediates(ctx)
        if result:
            return result
        from .bytecode_adapter import BytecodeWitnessModule
        self._bytecode = BytecodeWitnessModule(self._expressions_bin)
        return self._bytecode.compute_intermediates(ctx)

    def compute_grand_sums(self, ctx: ConstraintContext) -> dict[str, FF3Poly]:
        if self._bytecode is not None:
            result = self._bytecode.compute_grand_sums(ctx)
            self._bytecode = None
            return result
        return self._primary.compute_grand_sums(ctx)


def get_witness_module(air_name: str, expressions_bin: str | None = None) -> WitnessModule:
    """Get witness module instance for an AIR.

    When expressions_bin is provided (from AirConfig), prefers hand-written modules
    in WITNESS_REGISTRY to avoid naming collisions between pilouts that share an
    AIR name (e.g., SpecifiedRanges appears in both Simple pilout and Zisk). If the
    hand-written module does not implement Stage-2, wraps it with a bytecode fallback.

    Without expressions_bin, checks BYTECODE_AIRS first (Zisk AIRs), then falls
    back to hand-written modules in WITNESS_REGISTRY.

    Args:
        air_name: Name of the AIR (e.g., 'SimpleLeft', 'Lookup2_12')
        expressions_bin: Optional path to .bin bytecode. When provided, takes priority
            over BYTECODE_AIRS to prevent cross-pilout naming collisions.

    Returns:
        WitnessModule instance for the AIR

    Raises:
        KeyError: If no witness module is registered for the AIR (and no expressions_bin)
    """
    from .bytecode_adapter import BytecodeWitnessModule

    if expressions_bin is not None:
        if air_name in WITNESS_REGISTRY:
            return _FallbackWitnessModule(WITNESS_REGISTRY[air_name](), expressions_bin)
        return BytecodeWitnessModule(expressions_bin)
    if air_name in BYTECODE_AIRS:
        return BytecodeWitnessModule(BYTECODE_AIRS[air_name])
    if air_name in WITNESS_REGISTRY:
        return WITNESS_REGISTRY[air_name]()
    raise KeyError(f"No witness module for AIR '{air_name}'. "
                   f"Available: {list(WITNESS_REGISTRY.keys())}")


__all__ = [
    'WitnessModule',
    'SimpleLeftWitness',
    'SimpleRightWitness',
    'U8AirWitness',
    'U16AirWitness',
    'SpecifiedRangesWitness',
    'Lookup2_12Witness',
    'Permutation1_6Witness',
    'WITNESS_REGISTRY',
    'BYTECODE_AIRS',
    'get_witness_module',
]
