"""Abstract polynomial operations.

This module provides protocol-level polynomial operations without exposing
implementation details like NTT/INTT. The protocol layer should use these
abstractions rather than directly invoking NTT primitives.

Protocol Invariant: If you can change an implementation detail without changing
the resulting proof bytes, that detail does NOT belong in the protocol specification.
"""

import numpy as np
from typing import List

import galois
from primitives.field import FF, FF3, ff3_coeffs, FIELD_EXTENSION_DEGREE, get_omega_inv
from primitives.ntt import NTT


def to_coefficients(
    evaluations: np.ndarray,
    domain_size: int,
    n_cols: int = 1,
) -> np.ndarray:
    """Convert polynomial from evaluation form to coefficient form.

    This is the protocol-level abstraction for interpolation. The fact that
    we use NTT/INTT internally is an implementation detail - the protocol
    only cares that we can convert between representations.

    Args:
        evaluations: Polynomial values at domain points (shape: (domain_size, n_cols) or flat)
        domain_size: Size of evaluation domain (must be power of 2)
        n_cols: Number of columns (for batched operations)

    Returns:
        Polynomial coefficients in same shape as input
    """
    ntt = NTT(domain_size)
    return ntt.intt(evaluations, n_cols=n_cols)


def to_evaluations(
    coefficients: np.ndarray,
    domain_size: int,
    n_cols: int = 1,
) -> np.ndarray:
    """Convert polynomial from coefficient form to evaluation form.

    This is the protocol-level abstraction for evaluation. The fact that
    we use NTT internally is an implementation detail.

    Args:
        coefficients: Polynomial coefficients (shape: (domain_size, n_cols) or flat)
        domain_size: Size of evaluation domain (must be power of 2)
        n_cols: Number of columns (for batched operations)

    Returns:
        Polynomial evaluations in same shape as input
    """
    ntt = NTT(domain_size)
    return ntt.ntt(coefficients, n_cols=n_cols)


def extend_to_domain(
    evaluations: np.ndarray,
    original_size: int,
    extended_size: int,
    n_cols: int = 1,
) -> np.ndarray:
    """Extend polynomial from smaller domain to larger domain (Low-Degree Extension).

    This is the protocol-level operation for LDE. Implementation uses:
    1. Convert to coefficients (INTT)
    2. Zero-pad
    3. Convert back to evaluations (NTT on larger domain)

    But the protocol doesn't need to know these steps.

    Args:
        evaluations: Values on original domain
        original_size: Original domain size
        extended_size: Target extended domain size
        n_cols: Number of columns

    Returns:
        Values on extended domain
    """
    ntt_original = NTT(original_size)
    return ntt_original.extend_pol(evaluations, extended_size, original_size, n_cols)


def to_coefficients_cubic(
    values: List[FF3],
    n: int,
) -> List[FF3]:
    """Convert cubic extension field elements from evaluation to coefficient form.

    For FF3 polynomials, we apply the transform component-wise over the base field.
    This is a protocol operation because it's about converting polynomial representations,
    not about how we implement the transform.

    Args:
        values: List of FF3 evaluations
        n: Domain size

    Returns:
        List of FF3 coefficients
    """
    # Extract coefficients from each FF3 element
    coeffs = [ff3_coeffs(v) for v in values]

    # Get inverse root of unity
    n_bits = _log2(n)
    w_inv = int(get_omega_inv(n_bits))

    # Separate into base field components and transform each
    components = [FF([c[i] for c in coeffs]) for i in range(FIELD_EXTENSION_DEGREE)]
    results = [galois.intt(comp, omega=w_inv) for comp in components]

    # Recombine into FF3 elements (galois uses descending order [c2,c1,c0])
    return [FF3.Vector([int(results[2][i]), int(results[1][i]), int(results[0][i])]) for i in range(n)]


def _log2(size: int) -> int:
    """Compute log2 of size (must be power of 2)."""
    assert size != 0
    res = 0
    while size != 1:
        size >>= 1
        res += 1
    return res
