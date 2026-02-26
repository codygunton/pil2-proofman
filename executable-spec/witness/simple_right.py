"""SimpleRight AIR witness generation.

SimpleRight proves two bus operations against values that SimpleLeft assumes:

- permutation_proves(2, [a, b]): [a, b] is a permutation of SimpleLeft's [e, f]
  (SimpleLeft assumes bus 2 with [e,f]; SimpleRight proves it by providing the
  same multiset in a potentially different order)

- lookup_proves(3, [c, d], mul): [c, d] are the distinct lookup table entries
  for bus 3; mul counts how many times each row's [c,d] appears in SimpleLeft's
  [g, h] column pair.

Stage-2 intermediates and grand sums are handled by the bytecode adapter.
"""

from collections import Counter

import numpy as np

from constraints.base import ConstraintContext
from primitives.field import GOLDILOCKS_PRIME, FF3Poly

from .base import WitnessModule


class SimpleRightWitness(WitnessModule):
    """Stage-1 witness generator for SimpleRight AIR.

    SimpleRight proves the permutation and lookup operations that SimpleLeft
    assumes. Given SimpleLeft's witness columns, this derives consistent
    SimpleRight values for use in purely-Python round-trip tests.

    For byte-identical C++ comparison tests, Stage-1 trace is loaded directly
    from C++ test vectors and this module is not invoked.
    """

    @staticmethod
    def compute_trace(
        simple_left_e: np.ndarray,
        simple_left_f: np.ndarray,
        simple_left_g: np.ndarray,
        simple_left_h: np.ndarray,
        N: int = 8,
    ) -> np.ndarray:
        """Compute SimpleRight's cm1 trace from SimpleLeft's Stage-1 columns.

        Args:
            simple_left_e: SimpleLeft's e column (N field elements)
            simple_left_f: SimpleLeft's f column (N field elements)
            simple_left_g: SimpleLeft's g column (N field elements)
            simple_left_h: SimpleLeft's h column (N field elements)
            N: Trace size (8 rows)

        Returns:
            cm1 buffer (N * 5 field elements) interleaved as [a0,b0,c0,d0,mul0, ...]
            Columns: [a, b, c, d, mul]
        """
        p = GOLDILOCKS_PRIME

        # [a, b]: permutation of SimpleLeft's [e, f] — sort rows lexicographically
        ef_pairs = list(zip(simple_left_e.tolist(), simple_left_f.tolist()))
        ef_sorted = sorted(ef_pairs)
        a_col = np.array([x[0] for x in ef_sorted], dtype=np.uint64)
        b_col = np.array([x[1] for x in ef_sorted], dtype=np.uint64)

        # [c, d, mul]: distinct [g, h] pairs with multiplicity counts
        gh_pairs = list(zip(simple_left_g.tolist(), simple_left_h.tolist()))
        counts = Counter(gh_pairs)
        distinct_pairs = sorted(counts.keys())

        c_col = np.zeros(N, dtype=np.uint64)
        d_col = np.zeros(N, dtype=np.uint64)
        mul_col = np.zeros(N, dtype=np.uint64)
        for i, (g_val, h_val) in enumerate(distinct_pairs[:N]):
            c_col[i] = g_val
            d_col[i] = h_val
            mul_col[i] = counts[(g_val, h_val)] % p

        # Pack into interleaved cm1 buffer: [a0,b0,c0,d0,mul0, a1,b1,c1,d1,mul1, ...]
        trace = np.zeros(N * 5, dtype=np.uint64)
        for i in range(N):
            trace[i * 5 + 0] = a_col[i]
            trace[i * 5 + 1] = b_col[i]
            trace[i * 5 + 2] = c_col[i]
            trace[i * 5 + 3] = d_col[i]
            trace[i * 5 + 4] = mul_col[i]
        return trace

    def compute_intermediates(self, ctx: ConstraintContext) -> dict[str, dict[int, FF3Poly]]:
        """Delegated to bytecode adapter; this module only computes Stage 1."""
        return {}

    def compute_grand_sums(self, ctx: ConstraintContext) -> dict[str, FF3Poly]:
        """Delegated to bytecode adapter; this module only computes Stage 1."""
        return {}
