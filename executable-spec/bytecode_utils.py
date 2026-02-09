"""Shared utilities for bytecode adapter modules.

Contains helper functions used by both constraints/bytecode_adapter.py
and witness/bytecode_adapter.py.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from protocol.stark_info import StarkInfo


def compute_column_index(stark_info: StarkInfo, name: str, stage_pos: int) -> int:
    """Compute the column index for a polynomial with the given name and stage position.

    Multiple columns can share the same name (e.g., multi-instance polynomials).
    The index is determined by counting how many columns with the same name have
    a lower stage_pos.

    Args:
        stark_info: StarkInfo containing cm_pols_map
        name: Polynomial name to look up
        stage_pos: Stage position of the target column

    Returns:
        Zero-based index among columns sharing this name
    """
    index = 0
    for other in stark_info.cm_pols_map:
        if other.name == name and other.stage_pos < stage_pos:
            index += 1
    return index
