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

from primitives.field import FF3, FF3Poly, ff3, GOLDILOCKS_PRIME
from .base import ConstraintModule, ConstraintContext


def _ff3_scalar(scalar: int, n: int = None) -> FF3:
    """Create FF3 scalar or array filled with scalar value (handles negatives).

    Args:
        scalar: Integer value to convert
        n: If None, create scalar. If int, create array of size n.
    """
    val = scalar % GOLDILOCKS_PRIME
    if n is None:
        return ff3([val, 0, 0])
    return FF3(np.full(n, val, dtype=np.uint64))


def _ff_to_ff3(arr) -> FF3:
    """Convert FF array to FF3 array (embed base field in extension field).

    Handles both prover context (FF arrays) and verifier context (FF3 scalars).
    """
    # If already FF3 (verifier context), return as-is
    if type(arr) == FF3:
        return arr
    # FF3 can be constructed from base field values directly
    return FF3(np.asarray(arr, dtype=np.uint64))


def _compress_2col(busid: int, col1, col2, alpha: FF3, gamma: FF3, n: int) -> FF3:
    """Compress 2-column expression: ((col2*α + col1)*α + busid) + γ."""
    return (col2 * alpha + col1) * alpha + _ff3_scalar(busid, n) + gamma


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

        # Get witness columns
        a1 = _ff_to_ff3(ctx.col('a1'))
        b1 = _ff_to_ff3(ctx.col('b1'))
        a2 = _ff_to_ff3(ctx.col('a2'))
        b2 = _ff_to_ff3(ctx.col('b2'))
        a3 = _ff_to_ff3(ctx.col('a3'))
        b3 = _ff_to_ff3(ctx.col('b3'))
        a4 = _ff_to_ff3(ctx.col('a4'))
        b4 = _ff_to_ff3(ctx.col('b4'))
        c1 = _ff_to_ff3(ctx.col('c1'))
        d1 = _ff_to_ff3(ctx.col('d1'))
        c2 = _ff_to_ff3(ctx.col('c2'))
        d2 = _ff_to_ff3(ctx.col('d2'))
        sel1 = _ff_to_ff3(ctx.col('sel1'))
        sel2 = _ff_to_ff3(ctx.col('sel2'))
        mul = _ff_to_ff3(ctx.col('mul'))

        # Get intermediate columns (already FF3)
        gsum = ctx.col('gsum')
        prev_gsum = ctx.prev_col('gsum')
        im_cluster_0 = ctx.col('im_cluster', 0)
        im_cluster_1 = ctx.col('im_cluster', 1)
        im_single = ctx.col('im_single')

        # Get constant L1 - convert from FF to FF3
        L1 = _ff_to_ff3(ctx.const('__L1__'))
        next_L1 = _ff_to_ff3(ctx.next_const('__L1__'))

        # Get airgroup value (gsum_result)
        gsum_result = ctx.airgroup_value(0)

        # Detect prover vs verifier mode
        try:
            n = len(a1)  # Prover mode: a1 is an array
        except TypeError:
            n = None  # Verifier mode: a1 is a scalar

        # Build constraint polynomials (unweighted)
        constraints = []

        # ===================================================================
        # Constraint 0: im_cluster[0] for busid=4 proves [c1,d1] + busid=5 assumes [a2,b2]
        # im * D1 * D2 - (D2 - D1) = 0
        # Where D1 = compress(4, [c1,d1]), D2 = compress(5, [a2,b2])
        # stored_nums: +1 for D1 (proves), -1 for D2 (assumes)
        # cross_sum = (+1)*D2 + (-1)*D1 = D2 - D1
        # ===================================================================
        D1 = _compress_2col(4, c1, d1, alpha, gamma, n)
        D2 = _compress_2col(5, a2, b2, alpha, gamma, n)
        constraint_0 = im_cluster_0 * D1 * D2 - (D2 + _ff3_scalar(-1, n) * D1)
        constraints.append(constraint_0)

        # ===================================================================
        # Constraint 1: im_cluster[1] for busid=6 assumes [a3,b3] + busid=6 proves [c2,d2]
        # im * D1 * D2 - ((-sel1)*D2 + mul*D1) = 0
        # Where D1 = compress(6, [a3,b3]), D2 = compress(6, [c2,d2])
        # stored_nums: -sel1 for D1 (assumes), +mul for D2 (proves)
        # cross_sum = (-sel1)*D2 + mul*D1
        # ===================================================================
        D1 = _compress_2col(6, a3, b3, alpha, gamma, n)
        D2 = _compress_2col(6, c2, d2, alpha, gamma, n)
        neg_sel1 = _ff3_scalar(-1, n) * sel1
        constraint_1 = im_cluster_1 * D1 * D2 - (neg_sel1 * D2 + mul * D1)
        constraints.append(constraint_1)

        # ===================================================================
        # Constraint 2: im_single for busid=7 assumes [a4,b4]
        # im * D - (-sel2) = 0
        # Where D = compress(7, [a4,b4])
        # stored_num = -sel2 (assumes)
        # ===================================================================
        D = _compress_2col(7, a4, b4, alpha, gamma, n)
        neg_sel2 = _ff3_scalar(-1, n) * sel2
        constraint_2 = im_single * D - neg_sel2
        constraints.append(constraint_2)

        # ===================================================================
        # Constraint 3: gsum recurrence
        # (gsum - prev_gsum*(1-L1) - sum_ims) * direct_den + 1 = 0
        # direct_den = compress(4, [a1, b1])
        # ===================================================================
        sum_ims = im_cluster_0 + im_cluster_1 + im_single
        one_minus_L1 = _ff3_scalar(1, n) - L1
        direct_den = _compress_2col(4, a1, b1, alpha, gamma, n)

        gsum_recurrence = (gsum - prev_gsum * one_minus_L1 - sum_ims) * direct_den + _ff3_scalar(1, n)
        constraints.append(gsum_recurrence)

        # ===================================================================
        # Constraint 4: boundary at last row
        # L1' * (gsum_result - gsum) = 0
        # ===================================================================
        boundary = next_L1 * (gsum_result - gsum)
        constraints.append(boundary)

        # Combine constraints using the expression binary's accumulation pattern:
        # acc = C0 * vc
        # acc = (acc + C1) * vc
        # ...
        # acc = (acc + C3) * vc
        # acc = acc + C4
        # Result: C0*vc^4 + C1*vc^3 + C2*vc^2 + C3*vc + C4
        acc = constraints[0] * vc
        for i in range(1, len(constraints) - 1):  # Constraints 1 to 3
            acc = (acc + constraints[i]) * vc
        acc = acc + constraints[-1]  # Add constraint 4 without vc multiplication

        return acc
