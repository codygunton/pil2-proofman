"""Permutation1_6 AIR constraint evaluation.

Permutation1_6 uses both sum-based (logup) and product-based permutation arguments:

Sum-based logup terms (5 terms clustered into 2 im_cluster columns):
1. Permutation assumes, busid=1, sel=1, cols=[a1, b1]
2. Permutation proves, busid=1, sel=1, cols=[c1, d1]
3. Permutation assumes, busid=2, sel=1, cols=[a2, b2]
4. Permutation assumes, busid=3, sel=sel1, cols=[a3, b3]
5. Permutation proves, busid=3, sel=sel2, cols=[c2, d2]

Product-based permutation term (1 term using gprod):
6. Permutation assumes, busid=4, sel=sel3, cols=[a4, b4]

Clustering:
- im_cluster[0]: terms 0,1 (busid=1)
- im_cluster[1]: terms 2,3,4 (busid=2,3)

6 constraints combined with std_vc powers.
"""

from typing import Union, List
import numpy as np

from primitives.field import FF3, FF3Poly, ff3
from .base import ConstraintModule, ConstraintContext


def _ff3_scalar_to_array(scalar: int, n: int) -> FF3:
    """Create FF3 array of size n filled with scalar value (handles negatives)."""
    val = scalar % (2**64) if scalar >= 0 else (2**64 + scalar)
    return FF3(np.full(n, val, dtype=np.uint64))


def _ff_to_ff3(arr) -> FF3:
    """Convert FF array to FF3 array (embed base field in extension field)."""
    return FF3(np.asarray(arr, dtype=np.uint64))


def _compress_exprs(busid: int, cols: List, alpha: FF3, gamma: FF3, n: int) -> Union[FF3Poly, FF3]:
    """Compute denominator: busid + col1*α + col2*α² + ... + γ."""
    result = _ff3_scalar_to_array(busid, n)
    alpha_power = alpha
    for col in cols:
        result = result + col * alpha_power
        alpha_power = alpha_power * alpha
    return result + gamma


class Permutation1_6Constraints(ConstraintModule):
    """Constraint evaluation for Permutation1_6 AIR.

    Permutation1_6 has 64 rows (nBits=6) and uses both sum-based logup
    and product-based permutation arguments.

    The 6 constraints are:
    - C0: im_cluster[0] verification (busid=1 terms)
    - C1: im_cluster[1] verification (busid=2,3 terms)
    - C2: gsum recurrence
    - C3: gsum boundary constraint
    - C4: gprod recurrence
    - C5: gprod boundary constraint
    """

    def constraint_polynomial(self, ctx: ConstraintContext) -> Union[FF3Poly, FF3]:
        """Evaluate combined constraint polynomial."""
        # Get challenges
        alpha = ctx.challenge('std_alpha')
        gamma = ctx.challenge('std_gamma')
        vc = ctx.challenge('std_vc')

        # Get witness columns
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

        # Get intermediate columns
        gsum = ctx.col('gsum')
        prev_gsum = ctx.prev_col('gsum')
        im_cluster_0 = ctx.col('im_cluster', 0)
        im_cluster_1 = ctx.col('im_cluster', 1)
        gprod = ctx.col('gprod')
        prev_gprod = ctx.prev_col('gprod')

        # Get constant L1 - convert from FF to FF3
        L1 = _ff_to_ff3(ctx.const('__L1__'))
        next_L1 = _ff_to_ff3(ctx.next_const('__L1__'))

        # Get domain size from first column
        n = len(a1)

        # Define sum-based logup terms: (busid, cols, selector)
        # selector: positive for assumes, negative for proves
        sum_terms = [
            (1, [a1, b1], 1),        # assumes busid=1, sel=1
            (1, [c1, d1], -1),       # proves busid=1, sel=1 (negated)
            (2, [a2, b2], 1),        # assumes busid=2, sel=1
            (3, [a3, b3], sel1),     # assumes busid=3, sel=sel1
            (3, [c2, d2], -sel2),    # proves busid=3, sel=sel2 (negated)
        ]

        # Clustering for sum-based terms
        clusters = [
            ([0, 1], im_cluster_0),     # busid=1
            ([2, 3, 4], im_cluster_1),  # busid=2,3
        ]

        constraints = []
        vc_power = ff3([1, 0, 0])  # Scalar one

        # Build constraints for each sum-based cluster
        for term_indices, im_col in clusters:
            if len(term_indices) == 1:
                # Single term: im * denom = num
                busid, cols, sel = sum_terms[term_indices[0]]
                denom = _compress_exprs(busid, cols, alpha, gamma, n)
                # Convert selector to array (handle both int and column selectors)
                if isinstance(sel, int):
                    sel_arr = _ff3_scalar_to_array(sel, n)
                else:
                    sel_arr = sel
                constraint = im_col * denom - sel_arr
            else:
                # Multiple terms: im * prod(denoms) = sum(nums * other_denoms)
                denoms = []
                nums = []
                for idx in term_indices:
                    busid, cols, sel = sum_terms[idx]
                    denoms.append(_compress_exprs(busid, cols, alpha, gamma, n))
                    nums.append(sel)

                prod_denoms = denoms[0]
                for d in denoms[1:]:
                    prod_denoms = prod_denoms * d

                sum_cross = FF3(np.zeros(n, dtype=np.uint64))
                for i, num in enumerate(nums):
                    # Handle both int and column selectors
                    if isinstance(num, int):
                        cross_term = _ff3_scalar_to_array(num, n)
                    else:
                        cross_term = num
                    for j, d in enumerate(denoms):
                        if j != i:
                            cross_term = cross_term * d
                    sum_cross = sum_cross + cross_term

                constraint = im_col * prod_denoms - sum_cross

            constraints.append(constraint * vc_power)
            vc_power = vc_power * vc

        # Gsum recurrence: gsum - prev_gsum*(1-L1) - sum(ims) = 0
        sum_im = im_cluster_0 + im_cluster_1
        one_minus_L1 = _ff3_scalar_to_array(1, n) - L1
        gsum_constraint = gsum - prev_gsum * one_minus_L1 - sum_im
        constraints.append(gsum_constraint * vc_power)
        vc_power = vc_power * vc

        # Gsum boundary: next_L1 * gsum = 0 (balanced sum at last row)
        gsum_boundary = next_L1 * gsum
        constraints.append(gsum_boundary * vc_power)
        vc_power = vc_power * vc

        # Product-based permutation constraint for gprod
        # Formula from std_prod.pil:
        # gprod * denominator = ('gprod * (1-L1) + L1) * numerator
        #
        # For busid=4 assumes (type=0): denominator = sel3 * (compress + gamma - 1) + 1
        # (numerator = 1 since no proves in this AIR)
        compress_4 = _compress_exprs(4, [a4, b4], alpha, gamma, n)
        one_arr = _ff3_scalar_to_array(1, n)
        gprod_denominator = sel3 * (compress_4 + gamma - one_arr) + one_arr
        gprod_numerator = one_arr  # No proves for busid=4 in this AIR

        # Recurrence: gprod * denom = (prev_gprod * (1-L1) + L1) * num
        gprod_constraint = gprod * gprod_denominator - (prev_gprod * one_minus_L1 + L1) * gprod_numerator
        constraints.append(gprod_constraint * vc_power)
        vc_power = vc_power * vc

        # Gprod boundary: next_L1 * (result - gprod) = 0
        # For single-instance mode, result = 1 (product must balance to 1)
        gprod_boundary = next_L1 * (one_arr - gprod)
        constraints.append(gprod_boundary * vc_power)

        # Sum all constraints
        result = constraints[0]
        for c in constraints[1:]:
            result = result + c

        return result
