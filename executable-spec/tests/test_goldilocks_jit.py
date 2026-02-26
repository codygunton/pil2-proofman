"""Unit tests for Numba JIT Goldilocks field arithmetic."""

import numpy as np
import pytest

from primitives.goldilocks_jit import (
    _ff3_inv,
    _ff3_mul,
    _gl_add,
    _gl_inv,
    _gl_mul,
    _gl_sub,
    ff3_batch_inverse,
    gl_add_vec,
    gl_inv_vec,
    gl_mul_vec,
    gl_sub_vec,
)

P = np.uint64(0xFFFFFFFF00000001)


# ── GF(p) scalar ──────────────────────────────────────────────────────────────

class TestGLScalar:
    def test_add_basic(self):
        assert int(_gl_add(np.uint64(5), np.uint64(3))) == 8

    def test_add_wrap(self):
        # (P-1) + 1 = 0
        assert int(_gl_add(P - np.uint64(1), np.uint64(1))) == 0

    def test_add_overflow(self):
        # (P-1) + (P-1) = P-2  (true sum 2P-2, subtract P)
        assert int(_gl_add(P - np.uint64(1), P - np.uint64(1))) == int(P) - 2

    def test_sub_basic(self):
        assert int(_gl_sub(np.uint64(10), np.uint64(3))) == 7

    def test_sub_wrap(self):
        # 0 - 1 = P - 1
        assert int(_gl_sub(np.uint64(0), np.uint64(1))) == int(P) - 1

    def test_mul_basic(self):
        assert int(_gl_mul(np.uint64(6), np.uint64(7))) == 42

    def test_mul_identity(self):
        x = np.uint64(123456789)
        assert int(_gl_mul(x, np.uint64(1))) == int(x)

    def test_mul_zero(self):
        assert int(_gl_mul(np.uint64(12345), np.uint64(0))) == 0

    def test_mul_large(self):
        # (P-1)^2 mod P = 1  since (P-1)^2 = P^2 - 2P + 1 ≡ 1
        assert int(_gl_mul(P - np.uint64(1), P - np.uint64(1))) == 1

    def test_inv_basic(self):
        x = np.uint64(7)
        inv_x = _gl_inv(x)
        assert int(_gl_mul(x, inv_x)) == 1

    def test_inv_one(self):
        assert int(_gl_inv(np.uint64(1))) == 1

    def test_inv_large(self):
        x = np.uint64(0xABCDEF0123456789)
        x = x % P  # ensure in range
        if x == np.uint64(0):
            x = np.uint64(1)
        inv_x = _gl_inv(x)
        assert int(_gl_mul(x, inv_x)) == 1


# ── GF(p) vectorized ──────────────────────────────────────────────────────────

class TestGLVec:
    def test_add_vec(self):
        a = np.array([0, 1, P - 1], dtype=np.uint64)
        b = np.array([0, 1, 1], dtype=np.uint64)
        r = gl_add_vec(a, b)
        assert list(r) == [0, 2, 0]

    def test_sub_vec(self):
        a = np.array([5, 0], dtype=np.uint64)
        b = np.array([3, 1], dtype=np.uint64)
        r = gl_sub_vec(a, b)
        assert int(r[0]) == 2
        assert int(r[1]) == int(P) - 1

    def test_mul_vec(self):
        a = np.array([2, 3, P - 1], dtype=np.uint64)
        b = np.array([4, 5, P - 1], dtype=np.uint64)
        r = gl_mul_vec(a, b)
        assert int(r[0]) == 8
        assert int(r[1]) == 15
        assert int(r[2]) == 1  # (-1)*(-1) = 1

    def test_inv_vec(self):
        a = np.array([1, 2, 7, 100], dtype=np.uint64)
        inv_a = gl_inv_vec(a)
        product = gl_mul_vec(a, inv_a)
        assert all(int(x) == 1 for x in product)

    def test_broadcast_scalar(self):
        arr = np.array([1, 2, 3], dtype=np.uint64)
        r = gl_add_vec(arr, np.uint64(10))
        assert list(r) == [11, 12, 13]


# ── GF(p³) scalar ─────────────────────────────────────────────────────────────

class TestFF3Scalar:
    def test_mul_identity(self):
        a0, a1, a2 = np.uint64(12345), np.uint64(67890), np.uint64(11111)
        c0, c1, c2 = _ff3_mul(a0, a1, a2, np.uint64(1), np.uint64(0), np.uint64(0))
        assert (int(c0), int(c1), int(c2)) == (int(a0), int(a1), int(a2))

    def test_mul_zero(self):
        a0, a1, a2 = np.uint64(12345), np.uint64(67890), np.uint64(11111)
        c0, c1, c2 = _ff3_mul(a0, a1, a2, np.uint64(0), np.uint64(0), np.uint64(0))
        assert (int(c0), int(c1), int(c2)) == (0, 0, 0)

    def test_mul_commutative(self):
        a0, a1, a2 = np.uint64(100), np.uint64(200), np.uint64(300)
        b0, b1, b2 = np.uint64(400), np.uint64(500), np.uint64(600)
        c0, c1, c2 = _ff3_mul(a0, a1, a2, b0, b1, b2)
        d0, d1, d2 = _ff3_mul(b0, b1, b2, a0, a1, a2)
        assert (int(c0), int(c1), int(c2)) == (int(d0), int(d1), int(d2))

    def test_mul_x_cubed_equals_x_plus_1(self):
        # x^3 = x + 1  in GF(p^3) with poly x^3 - x - 1
        # x = (0, 1, 0); x^3 should be (1, 1, 0)  i.e. 1 + x
        x0, x1, x2 = np.uint64(0), np.uint64(1), np.uint64(0)
        x2_0, x2_1, x2_2 = _ff3_mul(x0, x1, x2, x0, x1, x2)   # x^2
        x3_0, x3_1, x3_2 = _ff3_mul(x2_0, x2_1, x2_2, x0, x1, x2)  # x^3
        assert (int(x3_0), int(x3_1), int(x3_2)) == (1, 1, 0)

    def test_inv_basic(self):
        a0, a1, a2 = np.uint64(12345), np.uint64(67890), np.uint64(11111)
        i0, i1, i2 = _ff3_inv(a0, a1, a2)
        r0, r1, r2 = _ff3_mul(a0, a1, a2, i0, i1, i2)
        assert (int(r0), int(r1), int(r2)) == (1, 0, 0)

    def test_inv_one(self):
        i0, i1, i2 = _ff3_inv(np.uint64(1), np.uint64(0), np.uint64(0))
        assert (int(i0), int(i1), int(i2)) == (1, 0, 0)

    def test_inv_x(self):
        # Invert x = (0, 1, 0) in GF(p^3)
        i0, i1, i2 = _ff3_inv(np.uint64(0), np.uint64(1), np.uint64(0))
        r0, r1, r2 = _ff3_mul(np.uint64(0), np.uint64(1), np.uint64(0), i0, i1, i2)
        assert (int(r0), int(r1), int(r2)) == (1, 0, 0)


# ── FF3 batch inverse ─────────────────────────────────────────────────────────

class TestFF3BatchInverse:
    def test_single_element(self):
        c0s = np.array([12345], dtype=np.uint64)
        c1s = np.array([67890], dtype=np.uint64)
        c2s = np.array([11111], dtype=np.uint64)
        inv0, inv1, inv2 = ff3_batch_inverse(c0s, c1s, c2s)
        r0, r1, r2 = _ff3_mul(c0s[0], c1s[0], c2s[0], inv0[0], inv1[0], inv2[0])
        assert (int(r0), int(r1), int(r2)) == (1, 0, 0)

    def test_multiple_elements(self):
        n = 50
        c0s = np.arange(1, n + 1, dtype=np.uint64)
        c1s = np.arange(n + 1, 2 * n + 1, dtype=np.uint64)
        c2s = np.arange(2 * n + 1, 3 * n + 1, dtype=np.uint64)
        inv0, inv1, inv2 = ff3_batch_inverse(c0s, c1s, c2s)
        for i in range(n):
            r0, r1, r2 = _ff3_mul(c0s[i], c1s[i], c2s[i], inv0[i], inv1[i], inv2[i])
            assert (int(r0), int(r1), int(r2)) == (1, 0, 0), f"failed at i={i}"

    def test_large_batch(self):
        rng = np.random.default_rng(42)
        n = 1000
        # numpy random only supports up to int64 max; use uint64 view of random bytes
        raw = rng.bytes(n * 8 * 3)
        all_vals = np.frombuffer(raw, dtype=np.uint64) % P
        c0s = all_vals[:n]
        c1s = all_vals[n:2*n]
        c2s = all_vals[2*n:3*n]
        # Ensure c0s non-zero (each element needs to be a non-zero FF3 value)
        c0s = np.where(c0s == np.uint64(0), np.uint64(1), c0s)
        inv0, inv1, inv2 = ff3_batch_inverse(c0s, c1s, c2s)
        # Spot-check first and last
        for i in [0, n // 2, n - 1]:
            r0, r1, r2 = _ff3_mul(c0s[i], c1s[i], c2s[i], inv0[i], inv1[i], inv2[i])
            assert (int(r0), int(r1), int(r2)) == (1, 0, 0), f"failed at i={i}"
