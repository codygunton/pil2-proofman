"""Permutation1_6 AIR constraint evaluation.

Permutation1_6 uses both sum-based (logup) and product-based permutation arguments:

Sum-based logup terms (5 terms clustered into 2 im_cluster columns):
1. Permutation assumes, busid=1, sel=1, cols=[a1, b1]
2. Permutation proves, busid=1, sel=-1, cols=[c1, d1]
3. Permutation assumes, busid=2, sel=1, cols=[a2, b2]
4. Permutation assumes, busid=3, sel=sel1, cols=[a3, b3]
5. Permutation proves, busid=3, sel=-sel2, cols=[c2, d2]

Product-based permutation term (1 term using gprod):
6. Permutation assumes, busid=4, sel=sel3, cols=[a4, b4]

Clustering:
- im_cluster[0]: terms 1,2 (busid=1,2)  -- NOT 0,1!
- im_cluster[1]: terms 3,4,5 (busid=3)

6 constraints combined with std_vc powers.
"""


import numpy as np

from primitives.field import FF3, GOLDILOCKS_PRIME, FF3Poly

from .base import ConstraintContext, ConstraintModule, compress_2col


class Permutation1_6Constraints(ConstraintModule):
    """Constraint evaluation for Permutation1_6 AIR.

    Permutation1_6 has 64 rows (nBits=6) and uses both sum-based logup
    and product-based permutation arguments.

    The 6 constraints are:
    - C0: im_cluster[0] verification (busid=1,2)
    - C1: im_cluster[1] verification (busid=3)
    - C2: gsum recurrence
    - C3: gsum boundary constraint
    - C4: gprod recurrence
    - C5: gprod boundary constraint
    """

    def constraint_polynomial(self, ctx: ConstraintContext) -> FF3Poly | FF3:
        """Evaluate combined constraint polynomial."""
        # Get challenges
        alpha = ctx.challenge('std_alpha')
        gamma = ctx.challenge('std_gamma')
        vc = ctx.challenge('std_vc')

        # Get witness columns - stage 1
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
        sel3 = ctx.col('sel3')

        # Get intermediate columns - stage 2 (already FF3)
        gsum = ctx.col('gsum')
        prev_gsum = ctx.prev_col('gsum')
        im_cluster_0 = ctx.col('im_cluster', 0)
        im_cluster_1 = ctx.col('im_cluster', 1)
        gprod = ctx.col('gprod')
        prev_gprod = ctx.prev_col('gprod')

        # Get constant L1 - convert from FF to FF3
        L1 = ctx.const('__L1__')
        next_L1 = ctx.next_const('__L1__')

        # Get airgroup values (accumulated results)
        gsum_result = ctx.airgroup_value(0)
        gprod_result = ctx.airgroup_value(1)

        # Detect prover vs verifier mode
        try:
            n = len(a1)  # Prover mode: a1 is an array
        except TypeError:
            n = None  # Verifier mode: a1 is a scalar

        # Helper for creating scalar/array constants
        def const(value: int) -> FF3:
            if n is None:
                return FF3(value % GOLDILOCKS_PRIME)
            return FF3(np.full(n, value % GOLDILOCKS_PRIME, dtype=np.uint64))

        neg_one = const(-1)
        one = const(1)

        constraints = []

        # ===================================================================
        # Constraint 0: im_cluster[0] verification
        # Formula from expressionsinfo.json (std_sum.pil:587):
        # (im_cluster*D1*D2) - (D2 + (-1)*D1) = 0
        # D1 = compress(1, [c1, d1])
        # D2 = compress(2, [a2, b2])
        # ===================================================================
        D1 = compress_2col(1, c1, d1, alpha, gamma, n)
        D2 = compress_2col(2, a2, b2, alpha, gamma, n)
        constraint_0 = im_cluster_0 * D1 * D2 - (D2 + neg_one * D1)
        constraints.append(constraint_0)

        # ===================================================================
        # Constraint 1: im_cluster[1] verification
        # Formula from expressionsinfo.json (std_sum.pil:587):
        # (im_cluster*D1*D2) - ((-sel1)*D2 + sel2*D1) = 0
        # D1 = compress(3, [a3, b3])
        # D2 = compress(3, [c2, d2])
        # Note: (0 - sel1) = -sel1
        # ===================================================================
        D1 = compress_2col(3, a3, b3, alpha, gamma, n)
        D2 = compress_2col(3, c2, d2, alpha, gamma, n)
        neg_sel1 = neg_one * sel1
        constraint_1 = im_cluster_1 * D1 * D2 - (neg_sel1 * D2 + sel2 * D1)
        constraints.append(constraint_1)

        # ===================================================================
        # Constraint 2: gsum recurrence
        # Formula from expressionsinfo.json (std_sum.pil:596):
        # (gsum - prev_gsum*(1-L1) - (im_cluster[0] + im_cluster[1]) * compress(1,[a1,b1]) + 1 = 0
        # ===================================================================
        one_minus_L1 = one - L1
        sum_im = im_cluster_0 + im_cluster_1
        direct_den = compress_2col(1, a1, b1, alpha, gamma, n)
        gsum_recurrence = (gsum - prev_gsum * one_minus_L1 - sum_im) * direct_den + one
        constraints.append(gsum_recurrence)

        # ===================================================================
        # Constraint 3: gsum boundary at last row
        # Formula from expressionsinfo.json (std_sum.pil:693):
        # L1' * (gsum_result - gsum) = 0
        # ===================================================================
        gsum_boundary = next_L1 * (gsum_result - gsum)
        constraints.append(gsum_boundary)

        # ===================================================================
        # Constraint 4: gprod recurrence
        # Formula from expressionsinfo.json (std_prod.pil:817):
        # (gprod * denom) - (prev_gprod*(1-L1) + L1) = 0
        # denom = sel3 * (compress(4,[a4,b4]) + gamma - 1) + 1
        # Note: The expression shows: (gprod*((sel3*(e+gamma-1)+1) - ('gprod*(1-L1)+L1)
        # where e = compress(4,[a4,b4]) without gamma
        # ===================================================================
        # e = ((b4*alpha + a4)*alpha + 4) -- compress without gamma
        e = (b4 * alpha + a4) * alpha + const(4)
        gprod_denom = sel3 * (e + gamma - one) + one
        gprod_recurrence = gprod * gprod_denom - (prev_gprod * one_minus_L1 + L1)
        constraints.append(gprod_recurrence)

        # ===================================================================
        # Constraint 5: gprod boundary at last row
        # Formula from expressionsinfo.json (std_prod.pil:858):
        # L1' * (gprod_result - gprod) = 0
        # ===================================================================
        gprod_boundary = next_L1 * (gprod_result - gprod)
        constraints.append(gprod_boundary)

        # Combine constraints using std_vc powers
        return self._combine_constraints(constraints, vc)
