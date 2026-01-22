"""Montgomery batch inversion for Goldilocks field and cubic extension.

This module provides batch inversion functions that delegate to the
generalized batch_inverse() in field.py.

The Montgomery trick converts N field inversions into 3N-3 multiplications + 1 inversion.

Reference: pil2-stark/src/goldilocks/src/goldilocks_base_field.hpp::batchInverse
"""

from typing import List
import numpy as np
from primitives.field import FF, FF3, ff3, ff3_coeffs, batch_inverse


def batch_inverse_ff(values: List[FF]) -> List[FF]:
    """Montgomery batch inversion for base Goldilocks field (list interface).

    Args:
        values: List of FF elements to invert (must all be non-zero)

    Returns:
        List of FF elements where result[i] = values[i]^(-1)
    """
    if len(values) == 0:
        return []
    # Convert list to array, invert, convert back
    arr = FF(values)
    inv_arr = batch_inverse(arr)
    return list(inv_arr)


def batch_inverse_ff3(values: List[FF3]) -> List[FF3]:
    """Montgomery batch inversion for cubic extension field (list interface).

    Args:
        values: List of FF3 elements to invert (must all be non-zero)

    Returns:
        List of FF3 elements where result[i] = values[i]^(-1)
    """
    if len(values) == 0:
        return []
    # Convert list to array, invert, convert back
    arr = FF3(values)
    inv_arr = batch_inverse(arr)
    return list(inv_arr)


# Array-based interfaces (preferred for performance)

def batch_inverse_ff_array(values: FF) -> FF:
    """Montgomery batch inversion for FF galois array.

    Args:
        values: FF galois array to invert (must all be non-zero)

    Returns:
        FF galois array where result[i] = values[i]^(-1)
    """
    return batch_inverse(values)


def batch_inverse_ff3_array(values: FF3) -> FF3:
    """Montgomery batch inversion for FF3 galois array.

    Args:
        values: FF3 galois array to invert (must all be non-zero)

    Returns:
        FF3 galois array where result[i] = values[i]^(-1)
    """
    return batch_inverse(values)
