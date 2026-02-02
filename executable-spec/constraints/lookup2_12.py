"""Lookup2_12 AIR constraint evaluation.

Lookup2_12 logup terms (from gsum_debug_data hints):
1. Lookup assumes, busid=4, sel=1, cols=[a1, b1]
2. Lookup proves, busid=4, mul=1, cols=[c1, d1]
3. Lookup assumes, busid=5, sel=1, cols=[a2, b2]
4. Lookup assumes, busid=6, sel=sel1, cols=[a3, b3]
5. Lookup proves, busid=6, mul=mul, cols=[c2, d2]
6. Lookup assumes, busid=7, sel=sel2, cols=[a4, b4]

Intermediate columns:
- im_cluster[0]: clustered terms
- im_cluster[1]: clustered terms
- im_single: single term (not clustered)

5 constraints combined with std_vc powers.
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


class Lookup2_12Constraints(ConstraintModule):
    """Constraint evaluation for Lookup2_12 AIR.

    Lookup2_12 has 4096 rows (nBits=12) and exercises FRI folding.

    The 5 constraints are:
    - C0: im_cluster[0] verification (busid=4 terms)
    - C1: im_cluster[1] verification (busid=5,6 terms)
    - C2: im_single verification (busid=7 term)
    - C3: gsum recurrence
    - C4: boundary constraint
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
        mul = ctx.col('mul')

        # Get intermediate columns
        gsum = ctx.col('gsum')
        prev_gsum = ctx.prev_col('gsum')
        im_cluster_0 = ctx.col('im_cluster', 0)
        im_cluster_1 = ctx.col('im_cluster', 1)
        im_single = ctx.col('im_single')

        # Get constant L1 - convert from FF to FF3
        L1 = _ff_to_ff3(ctx.const('__L1__'))
        next_L1 = _ff_to_ff3(ctx.next_const('__L1__'))

        # Get domain size from first column
        n = len(a1)

        # Define all 6 logup terms: (busid, cols, selector)
        # selector: positive for assumes, negative for proves
        all_terms = [
            (4, [a1, b1], 1),        # assumes busid=4, sel=1
            (4, [c1, d1], -1),       # proves busid=4, mul=1 (negated)
            (5, [a2, b2], 1),        # assumes busid=5, sel=1
            (6, [a3, b3], sel1),     # assumes busid=6, sel=sel1
            (6, [c2, d2], -mul),     # proves busid=6, mul (negated)
            (7, [a4, b4], sel2),     # assumes busid=7, sel=sel2
        ]

        # Clustering based on compiler output:
        # - im_cluster[0]: terms 0,1 (busid=4: assumes + proves)
        # - im_cluster[1]: terms 2,3,4 (busid=5,6)
        # - im_single: term 5 (busid=7, single term)
        clusters = [
            ([0, 1], im_cluster_0),     # busid=4
            ([2, 3, 4], im_cluster_1),  # busid=5,6
            ([5], im_single),           # busid=7
        ]

        constraints = []
        vc_power = ff3([1, 0, 0])  # Scalar one

        # Build constraints for each cluster
        for term_indices, im_col in clusters:
            if len(term_indices) == 1:
                # Single term: im * denom = num
                busid, cols, sel = all_terms[term_indices[0]]
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
                    busid, cols, sel = all_terms[idx]
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
        sum_im = im_cluster_0 + im_cluster_1 + im_single
        one_minus_L1 = _ff3_scalar_to_array(1, n) - L1
        gsum_constraint = gsum - prev_gsum * one_minus_L1 - sum_im
        constraints.append(gsum_constraint * vc_power)
        vc_power = vc_power * vc

        # Boundary: next_L1 * gsum = 0 (balanced sum at last row)
        boundary_constraint = next_L1 * gsum
        constraints.append(boundary_constraint * vc_power)

        # Sum all constraints
        result = constraints[0]
        for c in constraints[1:]:
            result = result + c

        return result
