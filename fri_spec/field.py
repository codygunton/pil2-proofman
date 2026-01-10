"""
Goldilocks field and cubic extension using galois library.

This module provides a thin wrapper around galois for the Goldilocks prime field
and its cubic extension used in the FRI protocol.

C++ Reference: pil2-stark/src/goldilocks/src/goldilocks_base_field.hpp
               pil2-stark/src/goldilocks/src/goldilocks_cubic_extension.hpp
"""

import galois
import numpy as np
from typing import Union

# Goldilocks prime: p = 2^64 - 2^32 + 1
GOLDILOCKS_PRIME = 0xFFFFFFFF00000001

# Base field GF(p)
GF = galois.GF(GOLDILOCKS_PRIME)

# Cubic extension GF(p^3) with irreducible polynomial x^3 - x - 1
# In galois, polynomial coefficients are [x^3, x^2, x^1, x^0]
# x^3 - x - 1 = x^3 + 0*x^2 + (p-1)*x + (p-1)
_irr_poly = galois.Poly([1, 0, GOLDILOCKS_PRIME - 1, GOLDILOCKS_PRIME - 1], field=GF)
GF3 = galois.GF(GOLDILOCKS_PRIME**3, irreducible_poly=_irr_poly)

# NTT functions (direct from galois)
ntt = galois.ntt
intt = galois.intt


def get_root_of_unity(n_bits: int) -> GF:
    """
    Get primitive 2^n_bits-th root of unity in the Goldilocks field.

    The Goldilocks field has 2-adicity of 32, meaning it supports NTT
    of size up to 2^32.

    Args:
        n_bits: The log2 of the desired root order (must be <= 32)

    Returns:
        A primitive 2^n_bits-th root of unity
    """
    if n_bits > 32:
        raise ValueError(f"n_bits must be <= 32, got {n_bits}")
    N = 1 << n_bits
    # The multiplicative group has order p-1 = 2^64 - 2^32
    # primitive_element^((p-1)/N) gives an N-th root of unity
    return GF.primitive_element ** ((GOLDILOCKS_PRIME - 1) // N)


def get_roots_of_unity(n_bits: int) -> np.ndarray:
    """
    Get all 2^n_bits-th roots of unity.

    Args:
        n_bits: The log2 of the number of roots

    Returns:
        Array of all N-th roots of unity where N = 2^n_bits
    """
    N = 1 << n_bits
    omega = get_root_of_unity(n_bits)
    roots = GF([1] * N)
    for i in range(1, N):
        roots[i] = roots[i-1] * omega
    return roots


def batch_inverse(elements: np.ndarray) -> np.ndarray:
    """
    Compute batch inverse using Montgomery's trick.

    This is more efficient than inverting each element individually
    when many inversions are needed.

    Args:
        elements: Array of field elements to invert

    Returns:
        Array of inverses

    C++ Reference: Goldilocks::batchInverse
    """
    n = len(elements)
    if n == 0:
        return GF([])

    # Compute prefix products
    products = GF([1] * n)
    products[0] = elements[0]
    for i in range(1, n):
        products[i] = products[i-1] * elements[i]

    # Invert the final product
    inv_all = products[n-1] ** (-1)

    # Compute individual inverses
    result = GF([0] * n)
    for i in range(n-1, 0, -1):
        result[i] = inv_all * products[i-1]
        inv_all = inv_all * elements[i]
    result[0] = inv_all

    return result
