"""Goldilocks field GF(p) and cubic extension GF(p^3).

Uses galois library for all field arithmetic. FF and FF3 are the field types.

FF3 is loaded from a pre-computed cache file (ff3_cache.pkl) to avoid the ~7s
initialization cost of galois.GF() for extension fields. To regenerate the cache:
    python -c "from primitives.field import _regenerate_ff3_cache; _regenerate_ff3_cache()"
"""

import galois
import pickle
from pathlib import Path
from typing import List

# --- Field Construction ---

GOLDILOCKS_PRIME = 0xFFFFFFFF00000001

FF = galois.GF(GOLDILOCKS_PRIME)
"""Base field GF(p) - Goldilocks prime field."""

# Load FF3 from cache to avoid ~7s galois initialization
_FF3_CACHE_PATH = Path(__file__).parent / "ff3_cache.pkl"

with open(_FF3_CACHE_PATH, "rb") as _f:
    FF3 = pickle.load(_f)
"""Cubic extension field GF(p^3) with irreducible polynomial x^3 - x - 1."""


def _regenerate_ff3_cache():
    """Regenerate the FF3 cache file. Only needed if galois version changes."""
    _irr_poly = galois.Poly([1, 0, GOLDILOCKS_PRIME - 1, GOLDILOCKS_PRIME - 1], field=FF)
    ff3 = galois.GF(GOLDILOCKS_PRIME**3, irreducible_poly=_irr_poly)
    with open(_FF3_CACHE_PATH, "wb") as f:
        pickle.dump(ff3, f)
    print(f"Regenerated {_FF3_CACHE_PATH}")


# --- Coefficient Order Conversion ---
# Galois uses descending order [a2, a1, a0], we use ascending [a0, a1, a2].


def ff3(coeffs: List[int]) -> FF3:
    """Construct FF3 element from ascending-order coefficients [a0, a1, a2]."""
    return FF3.Vector(coeffs[::-1])


def ff3_coeffs(elem: FF3) -> List[int]:
    """Extract ascending-order coefficients [a0, a1, a2] from FF3 element."""
    return [int(c) for c in elem.vector()[::-1]]


# --- NTT Support ---

ntt = galois.ntt
intt = galois.intt

# Domain shift for coset LDE
SHIFT = FF(7)
SHIFT_INV = SHIFT ** -1

# Precomputed roots of unity: W[n] is a primitive 2^n-th root of unity
W: List[int] = [
    1,
    18446744069414584320,
    281474976710656,
    16777216,
    4096,
    64,
    8,
    2198989700608,
    4404853092538523347,
    6434636298004421797,
    4255134452441852017,
    9113133275150391358,
    4355325209153869931,
    4308460244895131701,
    7126024226993609386,
    1873558160482552414,
    8167150655112846419,
    5718075921287398682,
    3411401055030829696,
    8982441859486529725,
    1971462654193939361,
    6553637399136210105,
    8124823329697072476,
    5936499541590631774,
    2709866199236980323,
    8877499657461974390,
    3757607247483852735,
    4969973714567017225,
    2147253751702802259,
    2530564950562219707,
    1905180297017055339,
    3524815499551269279,
    7277203076849721926,
]

# Precomputed inverses: W_INV[n] = W[n]^(-1) mod p
W_INV: List[int] = [
    1,
    18446744069414584320,
    18446462594437873665,
    18446742969902956801,
    18442240469788262401,
    18158513693329981441,
    16140901060737761281,
    274873712576,
    9171943329124577373,
    5464760906092500108,
    4088309022520035137,
    6141391951880571024,
    386651765402340522,
    11575992183625933494,
    2841727033376697931,
    8892493137794983311,
    9071788333329385449,
    15139302138664925958,
    14996013474702747840,
    5708508531096855759,
    6451340039662992847,
    5102364342718059185,
    10420286214021487819,
    13945510089405579673,
    17538441494603169704,
    16784649996768716373,
    8974194941257008806,
    16194875529212099076,
    5506647088734794298,
    7731871677141058814,
    16558868196663692994,
    9896756522253134970,
    1644488454024429189,
]


def get_omega(n_bits: int) -> int:
    """Return primitive 2^n_bits-th root of unity."""
    return W[n_bits]


def get_omega_inv(n_bits: int) -> int:
    """Return inverse of primitive 2^n_bits-th root of unity."""
    return W_INV[n_bits]


# --- Montgomery Batch Inversion ---

def batch_inverse(values):
    """Montgomery batch inversion for any galois array.

    Converts N field inversions into 3N-3 multiplications + 1 inversion.
    Works with any galois FieldArray type (FF, FF3, or any GF).

    Algorithm:
    1. Forward pass: Compute prefix products cumprods[i] = a[0] * a[1] * ... * a[i]
    2. Single inversion: inv_total = cumprods[N-1]^(-1)
    3. Backward pass: Extract individual inverses using cumprods

    Args:
        values: Galois FieldArray to invert (must all be non-zero)

    Returns:
        Galois FieldArray where result[i] = values[i]^(-1)

    Raises:
        ZeroDivisionError: If any element is zero

    Reference: pil2-stark/src/goldilocks/src/goldilocks_base_field.hpp::batchInverse
    """
    n = len(values)
    if n == 0:
        return values
    if n == 1:
        return values ** -1

    # Get the field type from the input array
    field_type = type(values)

    # Forward pass: compute prefix products
    cumprods = field_type.Zeros(n)
    cumprods[0] = values[0]
    for i in range(1, n):
        cumprods[i] = cumprods[i - 1] * values[i]

    # Single inversion of the total product (only 1 expensive inversion)
    inv_total = cumprods[n - 1] ** -1

    # Backward pass: extract individual inverses
    results = field_type.Zeros(n)
    z = inv_total
    for i in range(n - 1, 0, -1):
        results[i] = z * cumprods[i - 1]
        z = z * values[i]
    results[0] = z

    return results
