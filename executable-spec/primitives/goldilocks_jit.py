"""Fast Goldilocks field arithmetic via Numba JIT.

Provides scalar and vectorized operations for GF(p) and GF(p³) that bypass
galois library's python-calculate mode for significant performance gains.

GF(p):  Goldilocks prime p = 2^64 - 2^32 + 1 = 0xFFFFFFFF00000001
GF(p³): cubic extension with irreducible polynomial x³ - x - 1  (so x³ = x + 1)

FF3 multiplication formula (derived from x³ = x + 1):
    Let t = a1*b2 + a2*b1
    c0 = a0*b0 + t
    c1 = a0*b1 + a1*b0 + t + a2*b2
    c2 = a0*b2 + a1*b1 + a2*b0 + a2*b2
"""

import numba
import numpy as np

# ── scalar GF(p) operations ───────────────────────────────────────────────────


@numba.jit(numba.uint64(numba.uint64, numba.uint64), nopython=True, cache=True)
def _gl_add(a, b):
    """(a + b) mod p for Goldilocks prime p = 2^64 - 2^32 + 1, a,b in [0,p)."""
    P = np.uint64(0xFFFFFFFF00000001)
    MASK32 = np.uint64(0xFFFFFFFF)
    s = a + b  # wrapping uint64 add
    if s < a:  # overflow: true_sum = s + 2^64, result = s + (2^32-1) mod p
        s += MASK32  # s < p so s + MASK32 < p + MASK32 = 2^64, no overflow
        if s >= P:
            s -= P
    elif s >= P:
        s -= P
    return s


@numba.jit(numba.uint64(numba.uint64, numba.uint64), nopython=True, cache=True)
def _gl_sub(a, b):
    """(a - b) mod p for Goldilocks prime p = 2^64 - 2^32 + 1, a,b in [0,p)."""
    MASK32 = np.uint64(0xFFFFFFFF)
    if a >= b:
        return a - b
    # a < b: wrapping uint64 gives a - b + 2^64; subtract 2^64 - p = 2^32 - 1
    return (a - b) - MASK32  # = a - b + p, in [1, p)


@numba.jit(numba.uint64(numba.uint64, numba.uint64), nopython=True, cache=True)
def _gl_mul(a, b):
    """(a * b) mod p for Goldilocks prime p = 2^64 - 2^32 + 1, a,b in [0,p).

    Uses 32-bit schoolbook decomposition to avoid 128-bit intermediates.
    Key identity: 2^64 ≡ 2^32 - 1  (mod p)
    """
    M = np.uint64(0xFFFFFFFF)
    SHIFT = np.uint64(32)

    a0 = a & M;  a1 = a >> SHIFT
    b0 = b & M;  b1 = b >> SHIFT

    c00 = a0 * b0
    c01 = a0 * b1
    c10 = a1 * b0
    c11 = a1 * b1

    # Reduce c11*2^64 using 2^64 ≡ 2^32-1
    c11_lo = c11 & M;  c11_hi = c11 >> SHIFT
    t1 = c11_hi * M
    t2 = c11_lo << SHIFT
    T = _gl_add(t1, t2)
    T = _gl_sub(T, c11)

    # Reduce (c01+c10)*2^32  (track carry: 2^96 ≡ -1 mod p)
    c_mid = c01 + c10
    carry = np.uint64(1) if c_mid < c01 else np.uint64(0)
    c_mid_lo = c_mid & M;  c_mid_hi = c_mid >> SHIFT
    t3 = c_mid_hi * M
    t4 = c_mid_lo << SHIFT
    Mid = _gl_add(t3, t4)
    if carry:
        Mid = _gl_sub(Mid, np.uint64(1))

    result = _gl_add(T, Mid)
    result = _gl_add(result, c00)
    return result


@numba.njit(cache=True)
def _gl_inv(a):
    """Multiplicative inverse: a^(p-2) mod p via square-and-multiply."""
    exp = np.uint64(0xFFFFFFFEFFFFFFFF)  # p - 2
    result = np.uint64(1)
    base = a
    while exp > np.uint64(0):
        if exp & np.uint64(1):
            result = _gl_mul(result, base)
        base = _gl_mul(base, base)
        exp >>= np.uint64(1)
    return result


# ── vectorized GF(p) ufuncs (numpy broadcasting, SIMD-compiled) ───────────────


@numba.vectorize([numba.uint64(numba.uint64, numba.uint64)], cache=True)
def gl_add_vec(a, b):
    """Element-wise (a + b) mod p over uint64 arrays."""
    return _gl_add(a, b)


@numba.vectorize([numba.uint64(numba.uint64, numba.uint64)], cache=True)
def gl_sub_vec(a, b):
    """Element-wise (a - b) mod p over uint64 arrays."""
    return _gl_sub(a, b)


@numba.vectorize([numba.uint64(numba.uint64, numba.uint64)], cache=True)
def gl_mul_vec(a, b):
    """Element-wise (a * b) mod p over uint64 arrays."""
    return _gl_mul(a, b)


@numba.vectorize([numba.uint64(numba.uint64)], cache=True)
def gl_inv_vec(a):
    """Element-wise a^(p-2) mod p over uint64 arrays."""
    return _gl_inv(a)


# ── scalar GF(p³) operations ──────────────────────────────────────────────────


@numba.njit(cache=True)
def _ff3_mul(a0, a1, a2, b0, b1, b2):
    """Multiply two FF3 elements: (a0,a1,a2) * (b0,b1,b2) mod x³-x-1."""
    t  = _gl_add(_gl_mul(a1, b2), _gl_mul(a2, b1))
    c0 = _gl_add(_gl_mul(a0, b0), t)
    c1 = _gl_add(_gl_add(_gl_add(_gl_mul(a0, b1), _gl_mul(a1, b0)), t), _gl_mul(a2, b2))
    c2 = _gl_add(_gl_add(_gl_add(_gl_mul(a0, b2), _gl_mul(a1, b1)), _gl_mul(a2, b0)), _gl_mul(a2, b2))
    return c0, c1, c2


@numba.njit(cache=True)
def _ff3_inv(a0, a1, a2):
    """Invert a non-zero FF3 element via Fermat: a^(p³-2).

    p³ - 2 has three 64-bit limbs (little-endian), verified offline:
        p = 0xFFFFFFFF00000001
        e_lo  = (p³-2) & 0xFFFF...  = 0xFFFFFFFCFFFFFFFF
        e_mid = (p³-2)>>64  & ...   = 0xFFFFFFF900000005
        e_hi  = (p³-2)>>128 & ...   = 0xFFFFFFFD00000005
    """
    r0, r1, r2 = np.uint64(1), np.uint64(0), np.uint64(0)
    b0, b1, b2 = a0, a1, a2

    limb = np.uint64(0xFFFFFFFCFFFFFFFF)  # e_lo
    for _ in range(64):
        if limb & np.uint64(1):
            r0, r1, r2 = _ff3_mul(r0, r1, r2, b0, b1, b2)
        b0, b1, b2 = _ff3_mul(b0, b1, b2, b0, b1, b2)
        limb >>= np.uint64(1)

    limb = np.uint64(0xFFFFFFF900000005)  # e_mid
    for _ in range(64):
        if limb & np.uint64(1):
            r0, r1, r2 = _ff3_mul(r0, r1, r2, b0, b1, b2)
        b0, b1, b2 = _ff3_mul(b0, b1, b2, b0, b1, b2)
        limb >>= np.uint64(1)

    limb = np.uint64(0xFFFFFFFD00000005)  # e_hi
    for _ in range(64):
        if limb & np.uint64(1):
            r0, r1, r2 = _ff3_mul(r0, r1, r2, b0, b1, b2)
        b0, b1, b2 = _ff3_mul(b0, b1, b2, b0, b1, b2)
        limb >>= np.uint64(1)

    return r0, r1, r2


# ── FF3 batch inverse (Montgomery's trick) ────────────────────────────────────


@numba.njit(cache=True)
def ff3_batch_inverse(c0s, c1s, c2s):
    """Batch-invert N FF3 elements using Montgomery's trick.

    Cost: 2(N-1) FF3 multiplications + 1 FF3 inversion  (vs N inversions).
    Each of the three component arrays must have the same length N > 0.
    """
    n = len(c0s)
    p0 = np.empty(n, np.uint64)
    p1 = np.empty(n, np.uint64)
    p2 = np.empty(n, np.uint64)

    # Forward pass: prefix products  p[i] = c[0] * c[1] * ... * c[i]
    p0[0], p1[0], p2[0] = c0s[0], c1s[0], c2s[0]
    for i in range(1, n):
        p0[i], p1[i], p2[i] = _ff3_mul(p0[i-1], p1[i-1], p2[i-1],
                                         c0s[i],  c1s[i],  c2s[i])

    # Single inversion of the final prefix product
    inv0, inv1, inv2 = _ff3_inv(p0[n-1], p1[n-1], p2[n-1])

    # Backward pass: inv[i] = inv(p[i]) = inv * p[i-1]; then inv *= c[i]
    out0 = np.empty(n, np.uint64)
    out1 = np.empty(n, np.uint64)
    out2 = np.empty(n, np.uint64)
    for i in range(n - 1, 0, -1):
        out0[i], out1[i], out2[i] = _ff3_mul(inv0, inv1, inv2,
                                               p0[i-1], p1[i-1], p2[i-1])
        inv0, inv1, inv2 = _ff3_mul(inv0, inv1, inv2, c0s[i], c1s[i], c2s[i])
    out0[0], out1[0], out2[0] = inv0, inv1, inv2

    return out0, out1, out2
