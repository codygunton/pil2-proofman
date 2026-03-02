primitives.goldilocks_jit
=========================

.. py:module:: primitives.goldilocks_jit

.. autoapi-nested-parse::

   Fast Goldilocks field arithmetic via Numba JIT.

   Provides scalar and vectorized operations for GF(p) and GF(p³) that bypass
   galois library's python-calculate mode for significant performance gains.

   GF(p):  Goldilocks prime p = 2^64 - 2^32 + 1 = 0xFFFFFFFF00000001
   GF(p³): cubic extension with irreducible polynomial x³ - x - 1  (so x³ = x + 1)

   FF3 multiplication formula (derived from x³ = x + 1):
       Let t = a1*b2 + a2*b1
       c0 = a0*b0 + t
       c1 = a0*b1 + a1*b0 + t + a2*b2
       c2 = a0*b2 + a1*b1 + a2*b0 + a2*b2



Functions
---------

.. autoapisummary::

   primitives.goldilocks_jit.gl_add_vec
   primitives.goldilocks_jit.gl_sub_vec
   primitives.goldilocks_jit.gl_mul_vec
   primitives.goldilocks_jit.gl_inv_vec
   primitives.goldilocks_jit.ff3_batch_inverse


Module Contents
---------------

.. py:function:: gl_add_vec(a, b)

   Element-wise (a + b) mod p over uint64 arrays.


.. py:function:: gl_sub_vec(a, b)

   Element-wise (a - b) mod p over uint64 arrays.


.. py:function:: gl_mul_vec(a, b)

   Element-wise (a * b) mod p over uint64 arrays.


.. py:function:: gl_inv_vec(a)

   Element-wise a^(p-2) mod p over uint64 arrays.


.. py:function:: ff3_batch_inverse(c0s, c1s, c2s)

   Batch-invert N FF3 elements using Montgomery's trick.

   Cost: 2(N-1) FF3 multiplications + 1 FF3 inversion  (vs N inversions).
   Each of the three component arrays must have the same length N > 0.


