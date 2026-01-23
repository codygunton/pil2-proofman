"""Montgomery batch inversion for Goldilocks field and cubic extension."""

from typing import List
from primitives.field import FF, FF3, batch_inverse


def batch_inverse_ff(values: List[FF]) -> List[FF]:
    """Montgomery batch inversion for base field (list interface)."""
    if len(values) == 0:
        return []
    return list(batch_inverse(FF(values)))


def batch_inverse_ff3(values: List[FF3]) -> List[FF3]:
    """Montgomery batch inversion for cubic extension (list interface)."""
    if len(values) == 0:
        return []
    return list(batch_inverse(FF3(values)))


# Array-based interfaces (preferred for performance)
# These are thin wrappers; callers can use batch_inverse() directly from field.py

def batch_inverse_ff_array(values: FF) -> FF:
    """Montgomery batch inversion for FF galois array."""
    return batch_inverse(values)


def batch_inverse_ff3_array(values: FF3) -> FF3:
    """Montgomery batch inversion for FF3 galois array."""
    return batch_inverse(values)
