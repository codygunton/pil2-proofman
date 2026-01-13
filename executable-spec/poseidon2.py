# QUESTION: What is the utility of this wrapper rather than just using the library inline? ANS: Three reasons: (1) Provides Python-native types (List[int]) instead of the Rust FFI's numpy arrays, making calling code cleaner. (2) Adds docstrings documenting the C++ reference and expected behavior. (3) Creates a stable API - if we ever swap FFI implementations (e.g., pure Python fallback, different Rust binding), only this file changes. The wrapper is thin but improves ergonomics and maintainability. Can simplify at cost of C++ divergence? Y - could import FFI directly everywhere, but loses abstraction layer. Not a C++ structural choice.
# TODO: this is not adding enough. Make it go away or move these into the ffi itself.
"""
Poseidon2 hash implementation for Goldilocks field.

This module provides the Poseidon2 permutation and related hash functions
matching the C++ implementation exactly via Rust FFI.

C++ Reference: pil2-stark/src/goldilocks/src/poseidon2_goldilocks.cpp
"""

from typing import List

from poseidon2_ffi import (
    poseidon2_hash as _poseidon2_hash,
    linear_hash as _linear_hash,
    hash_seq as _hash_seq,
    grinding as _grinding,
    verify_grinding as _verify_grinding,
    CAPACITY,
)


def poseidon2_hash(input_data: List[int], width: int = 12) -> List[int]:
    """
    Compute the full Poseidon2 permutation.

    Args:
        input_data: List of field elements (as integers) of length `width`
        width: Sponge width (4, 8, 12, or 16)

    Returns:
        List of `width` field elements after the permutation
    """
    return list(_poseidon2_hash(input_data, width))


def linear_hash(input_data: List[int], width: int = 8) -> List[int]:
    """
    Hash variable-length input using sponge construction.

    Args:
        input_data: List of field elements (as integers)
        width: Sponge width (4, 8, 12, or 16), default 8

    Returns:
        List of CAPACITY (4) field elements
    """
    return list(_linear_hash(input_data, width))


def hash_seq(input_data: List[int], width: int = 12) -> List[int]:
    """
    Wrapper that returns only the first CAPACITY elements.
    """
    return list(_hash_seq(input_data, width))


def grinding(challenge: List[int], pow_bits: int) -> int:
    """
    Find a proof-of-work nonce.

    Args:
        challenge: List of 3 field elements
        pow_bits: Number of leading zero bits required

    Returns:
        Nonce value that satisfies the PoW requirement
    """
    return _grinding(challenge, pow_bits)


def verify_grinding(challenge: List[int], nonce: int, pow_bits: int) -> bool:
    """
    Verify a proof-of-work nonce.

    Args:
        challenge: List of 3 field elements
        nonce: Nonce value to verify
        pow_bits: Number of leading zero bits required

    Returns:
        True if the nonce is valid, False otherwise
    """
    return _verify_grinding(challenge, nonce, pow_bits)


__all__ = [
    'poseidon2_hash',
    'linear_hash',
    'hash_seq',
    'grinding',
    'verify_grinding',
    'CAPACITY',
]
