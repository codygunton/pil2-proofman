"""Lookup2_12 AIR constraint evaluation.

Lookup2_12 logup terms (from gsum_debug_data hints):
1. Lookup assumes, busid=4, sel=1, cols=[a1, b1]  -- used in gsum direct_denom
2. Lookup proves, busid=4, mul=1, cols=[c1, d1]   -- stored_num = +1
3. Lookup assumes, busid=5, sel=1, cols=[a2, b2]  -- stored_num = -1
4. Lookup assumes, busid=6, sel=sel1, cols=[a3, b3]  -- stored_num = -sel1
5. Lookup proves, busid=6, mul=mul, cols=[c2, d2]    -- stored_num = +mul
6. Lookup assumes, busid=7, sel=sel2, cols=[a4, b4]  -- stored_num = -sel2

Intermediate columns clustering (from expressionsinfo constraint lines):
- im_cluster[0]: busid=4 proves [c1,d1] + busid=5 assumes [a2,b2]
- im_cluster[1]: busid=6 assumes [a3,b3] + busid=6 proves [c2,d2]
- im_single: busid=7 assumes [a4,b4]

Convention: stored_num = -selector for assumes, +multiplicity for proves.
This is because im_single*denom = stored_num, and im represents the negated
contribution to the logup sum.

5 constraints combined with std_vc powers.
"""

from typing import Union

import numpy as np

from primitives.field import FF3, FF3Poly, GOLDILOCKS_PRIME
from .base import ConstraintModule, ConstraintContext, compress_2col


class Lookup2_12Constraints(ConstraintModule):
    """Constraint evaluation for Lookup2_12 AIR.

    Lookup2_12 has 4096 rows (nBits=12) and exercises FRI folding.

    The 5 constraints (from expressionsinfo):
    - C0: im_cluster[0] verification: im*D1*D2 - (D2 - D1) = 0
          D1 = compress(4, [c1, d1]), D2 = compress(5, [a2, b2])
    - C1: im_cluster[1] verification: im*D1*D2 - ((-sel1)*D2 + mul*D1) = 0
          D1 = compress(6, [a3, b3]), D2 = compress(6, [c2, d2])
    - C2: im_single verification: im*D - (-sel2) = 0
          D = compress(7, [a4, b4])
    - C3: gsum recurrence: (gsum - gsum'*(1-L1) - sum_ims) * direct_den + 1 = 0
          direct_den = compress(4, [a1, b1])
    - C4: boundary constraint: L1' * (gsum_result - gsum) = 0
    """

    def constraint_polynomial(self, ctx: ConstraintContext) -> Union[FF3Poly, FF3]:
        """Evaluate combined constraint polynomial."""
        # Get challenges
        alpha = ctx.challenge('std_alpha')
        gamma = ctx.challenge('std_gamma')
        vc = ctx.challenge('std_vc')

        # Get witness columns - need conversion for prover/verifier compat
        a1 = ctx.col('a1')
        b1 = ctx.col('b1')
        a2 = ctx.col('a2')
        b2 = ctx.col('b2')
        a3 = ctx.col('a3')
        b3 = ctx.col('b3')
        a4 = ctx.col('a4')
        b4 = ctx.col('b4')
        c1 = ctx.col('c1')
        d1 = ctx.col('d1')
        c2 = ctx.col('c2')
        d2 = ctx.col('d2')
        sel1 = ctx.col('sel1')
        sel2 = ctx.col('sel2')
        mul = ctx.col('mul')

        # Get intermediate columns (already FF3)
        gsum = ctx.col('gsum')
        prev_gsum = ctx.prev_col('gsum')
        im_cluster_0 = ctx.col('im_cluster', 0)
        im_cluster_1 = ctx.col('im_cluster', 1)
        im_single = ctx.col('im_single')

        # Get constant L1 - convert from FF to FF3
        L1 = ctx.const('__L1__')
        next_L1 = ctx.next_const('__L1__')

        # Get airgroup value (gsum_result)
        gsum_result = ctx.airgroup_value(0)

        # Detect prover vs verifier mode
        try:
            n = len(a1)  # Prover mode: a1 is an array
        except TypeError:
            n = None  # Verifier mode: a1 is a scalar

        # Helper for creating scalar/array constants
        def const(value):
            if n is None:
                return FF3(value % GOLDILOCKS_PRIME)
            return FF3(np.full(n, value % GOLDILOCKS_PRIME, dtype=np.uint64))

        neg_one = const(-1)
        one = const(1)

        # Build constraint polynomials (unweighted)
        constraints = []

        # ===================================================================
        # Constraint 0: im_cluster[0] for busid=4 proves [c1,d1] + busid=5 assumes [a2,b2]
        # im * D1 * D2 - (D2 - D1) = 0
        # Where D1 = compress(4, [c1,d1]), D2 = compress(5, [a2,b2])
        # stored_nums: +1 for D1 (proves), -1 for D2 (assumes)
        # cross_sum = (+1)*D2 + (-1)*D1 = D2 - D1
        # ===================================================================
        D1 = compress_2col(4, c1, d1, alpha, gamma, n)
        D2 = compress_2col(5, a2, b2, alpha, gamma, n)
        constraint_0 = im_cluster_0 * D1 * D2 - (D2 + neg_one * D1)
        constraints.append(constraint_0)

        # ===================================================================
        # Constraint 1: im_cluster[1] for busid=6 assumes [a3,b3] + busid=6 proves [c2,d2]
        # im * D1 * D2 - ((-sel1)*D2 + mul*D1) = 0
        # Where D1 = compress(6, [a3,b3]), D2 = compress(6, [c2,d2])
        # stored_nums: -sel1 for D1 (assumes), +mul for D2 (proves)
        # cross_sum = (-sel1)*D2 + mul*D1
        # ===================================================================
        D1 = compress_2col(6, a3, b3, alpha, gamma, n)
        D2 = compress_2col(6, c2, d2, alpha, gamma, n)
        neg_sel1 = neg_one * sel1
        constraint_1 = im_cluster_1 * D1 * D2 - (neg_sel1 * D2 + mul * D1)
        constraints.append(constraint_1)

        # ===================================================================
        # Constraint 2: im_single for busid=7 assumes [a4,b4]
        # im * D - (-sel2) = 0
        # Where D = compress(7, [a4,b4])
        # stored_num = -sel2 (assumes)
        # ===================================================================
        D = compress_2col(7, a4, b4, alpha, gamma, n)
        neg_sel2 = neg_one * sel2
        constraint_2 = im_single * D - neg_sel2
        constraints.append(constraint_2)

        # ===================================================================
        # Constraint 3: gsum recurrence
        # (gsum - prev_gsum*(1-L1) - sum_ims) * direct_den + 1 = 0
        # direct_den = compress(4, [a1, b1])
        # ===================================================================
        sum_ims = im_cluster_0 + im_cluster_1 + im_single
        one_minus_L1 = one - L1
        direct_den = compress_2col(4, a1, b1, alpha, gamma, n)

        gsum_recurrence = (gsum - prev_gsum * one_minus_L1 - sum_ims) * direct_den + one
        constraints.append(gsum_recurrence)

        # ===================================================================
        # Constraint 4: boundary at last row
        # L1' * (gsum_result - gsum) = 0
        # ===================================================================
        boundary = next_L1 * (gsum_result - gsum)
        constraints.append(boundary)

        # Combine constraints using std_vc powers
        return self._combine_constraints(constraints, vc)
