"""
Goldilocks field and cubic extension using galois library.

Uses a forked galois library with custom omega support for INTT:
https://github.com/codygunton/galois (branch: custom-omega)

This module provides a thin wrapper around galois for the Goldilocks prime field
and its cubic extension used in the FRI protocol.

C++ Reference: pil2-stark/src/goldilocks/src/goldilocks_base_field.hpp
               pil2-stark/src/goldilocks/src/goldilocks_cubic_extension.hpp
"""

import galois

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


# Precomputed roots of unity from C++ goldilocks_base_field.cpp
# W[i] is the primitive 2^i-th root of unity
W = [
    1,                        # W[0]  = 1
    18446744069414584320,     # W[1]  = -1
    281474976710656,          # W[2]
    16777216,                 # W[3]
    4096,                     # W[4]
    64,                       # W[5]
    8,                        # W[6]
    2198989700608,            # W[7]
    4404853092538523347,      # W[8]
    6434636298004421797,      # W[9]
    4255134452441852017,      # W[10]
    9113133275150391358,      # W[11]
    4355325209153869931,      # W[12]
    4308460244895131701,      # W[13]
    7126024226993609386,      # W[14]
    1873558160482552414,      # W[15]
    8167150655112846419,      # W[16]
    5718075921287398682,      # W[17]
    3411401055030829696,      # W[18]
    8982441859486529725,      # W[19]
    1971462654193939361,      # W[20]
    6553637399136210105,      # W[21]
    8124823329697072476,      # W[22]
    5936499541590631774,      # W[23]
    2709866199236980323,      # W[24]
    8877499657461974390,      # W[25]
    3757607247483852735,      # W[26]
    4969973714567017225,      # W[27]
    2147253751702802259,      # W[28]
    2530564950562219707,      # W[29]
    1905180297017055339,      # W[30]
    3524815499551269279,      # W[31]
    7277203076849721926,      # W[32]
]


def pow_mod(base: int, exp: int, mod: int = GOLDILOCKS_PRIME) -> int:
    """
    Modular exponentiation.

    C++ Reference: Goldilocks::pow() in goldilocks_base_field.hpp:112
    """
    result = 1
    base = base % mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        exp >>= 1
        base = (base * base) % mod
    return result


def inv_mod(x: int, mod: int = GOLDILOCKS_PRIME) -> int:
    """
    Modular inverse using Fermat's little theorem.

    C++ Reference: Goldilocks::inv() in goldilocks_base_field.hpp:126
    """
    return pow_mod(x, mod - 2, mod)


def get_shift() -> int:
    """
    Get the shift constant (generator) for the Goldilocks field.

    This is the multiplicative generator used to shift the evaluation domain.

    C++ Reference: Goldilocks::shift()
    """
    return 7


def get_omega(n_bits: int) -> int:
    """
    Get primitive 2^n_bits-th root of unity.

    C++ Reference: Goldilocks::w(n_bits)

    Uses precomputed values matching the C++ implementation exactly.
    """
    if n_bits < 0 or n_bits >= len(W):
        raise ValueError(f"n_bits must be in [0, {len(W)-1}], got {n_bits}")
    return W[n_bits]


def get_root_of_unity(n_bits: int) -> GF:
    """
    Get primitive 2^n_bits-th root of unity in the Goldilocks field.

    The Goldilocks field has 2-adicity of 32, meaning it supports NTT
    of size up to 2^32.

    C++ Reference: Uses Goldilocks::primitive_element in goldilocks_base_field.hpp

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


