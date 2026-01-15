"""Goldilocks field GF(p) and cubic extension GF(p^3)."""

import galois

# --- Type Aliases ---

Fe = int
Fe3 = list[Fe]

# --- Field Constants ---

GOLDILOCKS_PRIME: Fe = 0xFFFFFFFF00000001

GF = galois.GF(GOLDILOCKS_PRIME)

_irr_poly = galois.Poly([1, 0, GOLDILOCKS_PRIME - 1, GOLDILOCKS_PRIME - 1], field=GF)
GF3 = galois.GF(GOLDILOCKS_PRIME**3, irreducible_poly=_irr_poly)

ntt = galois.ntt
intt = galois.intt

SHIFT: Fe = 7

# Precomputed roots of unity: W[n] is a primitive 2^n-th root of unity
W: list[Fe] = [
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

# Precomputed inverses of roots of unity: W_INV[n] = W[n]^(-1) mod p
W_INV: list[Fe] = [
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


# --- Base Field Operations ---


def pow_mod(base: Fe, exp: int, mod: Fe = GOLDILOCKS_PRIME) -> Fe:
    """Modular exponentiation: base^exp mod p."""
    result = 1
    base = base % mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        exp >>= 1
        base = (base * base) % mod
    return result


def inv_mod(x: Fe, mod: Fe = GOLDILOCKS_PRIME) -> Fe:
    """Modular inverse via Fermat's little theorem."""
    return pow_mod(x, mod - 2, mod)


# Derived constant: SHIFT^(-1) mod p
SHIFT_INV: Fe = inv_mod(SHIFT)


def get_shift() -> Fe:
    """Return the domain shift constant."""
    return SHIFT


def get_shift_inv() -> Fe:
    """Return the inverse of the domain shift constant."""
    return SHIFT_INV


def get_omega(n_bits: int) -> Fe:
    """Return primitive 2^n_bits-th root of unity."""
    if n_bits < 0 or n_bits >= len(W):
        raise ValueError(f"n_bits must be in [0, {len(W)-1}], got {n_bits}")
    return W[n_bits]


def get_omega_inv(n_bits: int) -> Fe:
    """Return inverse of primitive 2^n_bits-th root of unity."""
    if n_bits < 0 or n_bits >= len(W_INV):
        raise ValueError(f"n_bits must be in [0, {len(W_INV)-1}], got {n_bits}")
    return W_INV[n_bits]


def get_root_of_unity(n_bits: int) -> GF:
    """Compute primitive 2^n_bits-th root of unity using galois."""
    if n_bits > 32:
        raise ValueError(f"n_bits must be <= 32, got {n_bits}")
    N = 1 << n_bits
    return GF.primitive_element ** ((GOLDILOCKS_PRIME - 1) // N)


# --- Cubic Extension Field GF(p^3) ---


def fe3_mul(a: Fe3, b: Fe3) -> Fe3:
    """Multiply two cubic extension elements. Reduction: x^3 = x + 1."""
    p = GOLDILOCKS_PRIME

    c0 = (a[0] * b[0]) % p
    c1 = (a[0] * b[1] + a[1] * b[0]) % p
    c2 = (a[0] * b[2] + a[1] * b[1] + a[2] * b[0]) % p
    c3 = (a[1] * b[2] + a[2] * b[1]) % p
    c4 = (a[2] * b[2]) % p

    # Reduce by x^3 = x + 1
    r0 = (c0 + c3) % p
    r1 = (c1 + c3 + c4) % p
    r2 = (c2 + c4) % p

    return [r0, r1, r2]


def fe3_add(a: Fe3, b: Fe3) -> Fe3:
    """Add two cubic extension elements."""
    p = GOLDILOCKS_PRIME
    return [(a[i] + b[i]) % p for i in range(3)]


def fe3_sub(a: Fe3, b: Fe3) -> Fe3:
    """Subtract two cubic extension elements."""
    p = GOLDILOCKS_PRIME
    return [(a[i] - b[i]) % p for i in range(3)]


def fe3_scalar_mul(a: Fe3, s: Fe) -> Fe3:
    """Multiply cubic extension element by base field scalar."""
    p = GOLDILOCKS_PRIME
    return [(a[i] * s) % p for i in range(3)]


def fe3_from_base(x: Fe) -> Fe3:
    """Embed base field element into cubic extension."""
    return [x, 0, 0]


def fe3_zero() -> Fe3:
    """Return zero element of GF(p^3)."""
    return [0, 0, 0]


def fe3_one() -> Fe3:
    """Return multiplicative identity of GF(p^3)."""
    return [1, 0, 0]
