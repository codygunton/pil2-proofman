"""
Poseidon2 hash implementation for Goldilocks field.

This module implements the Poseidon2 permutation and related hash functions
matching the C++ implementation exactly.

C++ Reference: pil2-stark/src/goldilocks/src/poseidon2_goldilocks.cpp
"""

from typing import List
from .field import GF, GOLDILOCKS_PRIME
from .constants import (
    ROUNDS_F, ROUNDS_P, HASH_SIZE,
    POSEIDON2_RC, POSEIDON2_DIAG
)


# Capacity is always 4 (hash output size)
CAPACITY = 4


def _pow7(x: int) -> int:
    """
    Compute x^7 in the Goldilocks field.

    Uses the decomposition x^7 = x^3 * x^4 for efficiency.

    C++ Reference: Poseidon2Goldilocks::pow7
    """
    x2 = (x * x) % GOLDILOCKS_PRIME
    x3 = (x * x2) % GOLDILOCKS_PRIME
    x4 = (x2 * x2) % GOLDILOCKS_PRIME
    return (x3 * x4) % GOLDILOCKS_PRIME


def _matmul_m4(x: List[int]) -> List[int]:
    """
    Apply the 4x4 matrix multiplication.

    This is the core matrix used in the external linear layer.
    The specific matrix is designed for efficient computation.

    C++ Reference: Poseidon2Goldilocks::matmul_m4_
    """
    t0 = (x[0] + x[1]) % GOLDILOCKS_PRIME
    t1 = (x[2] + x[3]) % GOLDILOCKS_PRIME
    t2 = (x[1] + x[1] + t1) % GOLDILOCKS_PRIME
    t3 = (x[3] + x[3] + t0) % GOLDILOCKS_PRIME
    t1_2 = (t1 + t1) % GOLDILOCKS_PRIME
    t0_2 = (t0 + t0) % GOLDILOCKS_PRIME
    t4 = (t1_2 + t1_2 + t3) % GOLDILOCKS_PRIME
    t5 = (t0_2 + t0_2 + t2) % GOLDILOCKS_PRIME
    t6 = (t3 + t5) % GOLDILOCKS_PRIME
    t7 = (t2 + t4) % GOLDILOCKS_PRIME

    return [t6, t5, t7, t4]


def _matmul_external(state: List[int], width: int) -> List[int]:
    """
    Apply the external matrix multiplication.

    For width == 4, this is just matmul_m4.
    For larger widths, applies matmul_m4 to each 4-element block,
    then adds the column sums.

    C++ Reference: Poseidon2Goldilocks::matmul_external_
    """
    result = list(state)

    # Apply matmul_m4 to each 4-element block
    for i in range(0, width, 4):
        block = _matmul_m4(result[i:i+4])
        result[i:i+4] = block

    # For width > 4, add column sums
    if width > 4:
        stored = [0, 0, 0, 0]
        for i in range(0, width, 4):
            stored[0] = (stored[0] + result[i]) % GOLDILOCKS_PRIME
            stored[1] = (stored[1] + result[i+1]) % GOLDILOCKS_PRIME
            stored[2] = (stored[2] + result[i+2]) % GOLDILOCKS_PRIME
            stored[3] = (stored[3] + result[i+3]) % GOLDILOCKS_PRIME

        for i in range(width):
            result[i] = (result[i] + stored[i % 4]) % GOLDILOCKS_PRIME

    return result


def _pow7add(state: List[int], constants: List[int], width: int) -> List[int]:
    """
    Compute (state + constants)^7 element-wise.

    C++ Reference: Poseidon2Goldilocks::pow7add_
    """
    result = []
    for i in range(width):
        xi = (state[i] + constants[i]) % GOLDILOCKS_PRIME
        result.append(_pow7(xi))
    return result


def poseidon2_hash(input_data: List[int], width: int = 12) -> List[int]:
    """
    Compute the full Poseidon2 permutation.

    This is the core hash function that transforms a state of `width` elements.

    Args:
        input_data: List of field elements (as integers) of length `width`
        width: Sponge width (4, 8, 12, or 16)

    Returns:
        List of `width` field elements after the permutation

    C++ Reference: Poseidon2Goldilocks::hash_full_result_seq
    """
    if width not in [4, 8, 12, 16]:
        raise ValueError(f"width must be 4, 8, 12, or 16, got {width}")

    if len(input_data) != width:
        raise ValueError(f"input_data must have {width} elements, got {len(input_data)}")

    # Get constants for this width
    C = POSEIDON2_RC[width]
    D = POSEIDON2_DIAG[width]
    n_partial_rounds = ROUNDS_P[width]
    half_full_rounds = ROUNDS_F // 2

    # Copy input to state
    state = [x % GOLDILOCKS_PRIME for x in input_data]

    # Initial external matrix multiplication
    state = _matmul_external(state, width)

    # First half of full rounds
    for r in range(half_full_rounds):
        state = _pow7add(state, C[r * width:(r + 1) * width], width)
        state = _matmul_external(state, width)

    # Partial rounds
    for r in range(n_partial_rounds):
        # Add round constant only to first element
        state[0] = (state[0] + C[half_full_rounds * width + r]) % GOLDILOCKS_PRIME
        # Apply S-box only to first element
        state[0] = _pow7(state[0])
        # Compute sum of all elements
        sum_val = sum(state) % GOLDILOCKS_PRIME
        # Apply internal matrix: x[i] = x[i] * D[i] + sum
        for i in range(width):
            state[i] = (state[i] * D[i] + sum_val) % GOLDILOCKS_PRIME

    # Second half of full rounds
    for r in range(half_full_rounds):
        rc_offset = half_full_rounds * width + n_partial_rounds + r * width
        state = _pow7add(state, C[rc_offset:rc_offset + width], width)
        state = _matmul_external(state, width)

    return state


def linear_hash(input_data: List[int], width: int = 8) -> List[int]:
    """
    Hash variable-length input using sponge construction.

    This function handles inputs of any length by absorbing them in chunks
    of size (width - CAPACITY) and squeezing out CAPACITY elements.

    Args:
        input_data: List of field elements (as integers)
        width: Sponge width (4, 8, 12, or 16), default 8

    Returns:
        List of CAPACITY (4) field elements

    C++ Reference: Poseidon2Goldilocks::linear_hash_seq
    """
    if width not in [4, 8, 12, 16]:
        raise ValueError(f"width must be 4, 8, 12, or 16, got {width}")

    rate = width - CAPACITY
    size = len(input_data)

    # If input fits in capacity, just return padded input
    if size <= CAPACITY:
        output = list(input_data) + [0] * (CAPACITY - size)
        return output

    state = [0] * width
    remaining = size

    while remaining > 0:
        if remaining == size:
            # First iteration: initialize capacity to zero
            for i in range(rate, width):
                state[i] = 0
        else:
            # Copy previous output (first CAPACITY elements) to capacity position
            for i in range(CAPACITY):
                state[rate + i] = state[i]

        # Absorb: copy up to `rate` elements from input
        n = min(remaining, rate)
        offset = size - remaining

        # Zero-pad the rate portion
        for i in range(rate):
            state[i] = 0

        # Copy input chunk
        for i in range(n):
            state[i] = input_data[offset + i]

        # Apply permutation
        state = poseidon2_hash(state, width)
        remaining -= n

    # Return first CAPACITY elements
    return state[:CAPACITY]


def hash_seq(input_data: List[int], width: int = 12) -> List[int]:
    """
    Wrapper that returns only the first CAPACITY elements.

    C++ Reference: Poseidon2Goldilocks::hash_seq
    """
    result = poseidon2_hash(input_data, width)
    return result[:CAPACITY]


def grinding(challenge: List[int], pow_bits: int) -> int:
    """
    Find a proof-of-work nonce.

    Searches for a nonce such that when appended to the challenge and hashed,
    the first element of the result is less than 2^(64 - pow_bits).

    Args:
        challenge: List of (SPONGE_WIDTH - 1) field elements
        pow_bits: Number of leading zero bits required

    Returns:
        Nonce value that satisfies the PoW requirement

    Raises:
        RuntimeError: If no valid nonce is found within the search space

    C++ Reference: Poseidon2GoldilocksGrinding::grinding
    """
    # Use width 4 for grinding (matches C++ Poseidon2GoldilocksGrinding)
    width = 4

    if len(challenge) != width - 1:
        raise ValueError(f"challenge must have {width - 1} elements, got {len(challenge)}")

    level = 1 << (64 - pow_bits)
    max_attempts = (1 << pow_bits) * 512

    for nonce in range(max_attempts):
        # Construct state: challenge + nonce
        state = list(challenge) + [nonce]

        # Hash
        result = poseidon2_hash(state, width)

        # Check if first element is below threshold
        if result[0] < level:
            return nonce

    raise RuntimeError("grinding: could not find a valid nonce")
