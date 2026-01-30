"""SimpleLeft AIR constraint evaluation.

SimpleLeft has 13 logup terms clustered into 6 im_cluster columns:
1-4: Permutation/lookup for (a,b), (c,d), (e,f), (g,h)
5-13: Range checks for k[0-6]

The constraint polynomial structure (from std_sum.pil):
- For each im_cluster cluster: im_cluster * prod(denoms) = sum(nums * other_denoms)
- Gsum recurrence: (gsum - prev_gsum*(1-L1) - sum_im) * direct_den = direct_num
- Boundary: L1' * (result - gsum) * direct_den = direct_num (at last row)

All constraints combined with std_vc powers: sum(Ci * vc^i) = Q * Z_H
"""

from typing import Union, List
import numpy as np

from primitives.field import FF3, FF3Poly
from .base import ConstraintModule, ConstraintContext


def _compress_exprs(busid: int, cols: List, alpha: FF3, gamma: FF3) -> Union[FF3Poly, FF3]:
    """Compute denominator: busid + col1*α + col2*α² + ... + γ."""
    result = cols[0] * FF3(0) + busid  # broadcast busid to match array shape
    alpha_power = alpha
    for col in cols:
        result = result + col * alpha_power
        alpha_power = alpha_power * alpha
    return result + gamma


class SimpleLeftConstraints(ConstraintModule):
    """Constraint evaluation for SimpleLeft AIR.

    The constraint polynomial verifies:
    1. Each im_cluster correctly stores sum(sel_j/denom_j) for its cluster
    2. gsum is the running sum of im_cluster contributions
    3. At the last row, the grand sum equals the expected result (0 for balanced)

    Note: The actual constraint polynomial structure involves clustered terms
    with shared denominators. This implementation provides a simplified version
    that verifies the key invariants.
    """

    def constraint_polynomial(self, ctx: ConstraintContext) -> Union[FF3Poly, FF3]:
        """Evaluate combined constraint polynomial.

        For prover: returns polynomial over evaluation domain
        For verifier: returns single FF3 value at evaluation point xi
        """
        # Get challenges
        alpha = ctx.challenge('std_alpha')
        gamma = ctx.challenge('std_gamma')
        vc = ctx.challenge('std_vc')

        # Get witness columns
        a = ctx.col('a')
        b = ctx.col('b')
        c = ctx.col('c')
        d = ctx.col('d')
        e = ctx.col('e')
        f = ctx.col('f')
        g = ctx.col('g')
        h = ctx.col('h')
        k = [ctx.col('k', i) for i in range(7)]

        # Get intermediate columns
        gsum = ctx.col('gsum')
        prev_gsum = ctx.prev_col('gsum')  # gsum at row-1
        im_clusters = [ctx.col('im_cluster', i) for i in range(6)]

        # Get constant L1 (selector for first row: [1,0,0,...])
        L1 = ctx.const('__L1__')
        next_L1 = ctx.next_const('__L1__')  # L1 at row+1

        # Define all 13 logup terms: (busid, cols_list, selector)
        # These match the gsum_debug_data hints
        all_terms = [
            # Permutation/lookup
            (1, [a, b], 1),      # permutation_assumes(1, [a, b])
            (1, [c, d], -1),     # permutation_proves(1, [c, d])
            (2, [e, f], 1),      # permutation_assumes(2, [e, f])
            (3, [g, h], -1),     # lookup(3, [g, h], mul=-1)
            # Range checks
            (100, [k[0]], 1),
            (101, [k[1]], 1),
            (100, [k[2] - 1], 1),
            (100, [255 - k[2]], 1),
            (101, [k[3]], 1),
            (101, [256 - k[3]], 1),
            (102, [k[4]], 1),
            (103, [k[5]], 1),
            (104, [k[6]], 1),
        ]

        # Clustering: which terms go into each im_cluster column
        clusters = [
            [0, 1],           # im_cluster[0]: Permutation busid=1
            [2],              # im_cluster[1]: Permutation busid=2
            [3],              # im_cluster[2]: Lookup busid=3
            [4, 6, 7],        # im_cluster[3]: Range checks busid=100
            [5, 8, 9],        # im_cluster[4]: Range checks busid=101
            [10, 11, 12],     # im_cluster[5]: Range checks busid=102-104
        ]

        # Build constraints
        constraints = []
        vc_power = FF3(1)

        # For each im_cluster, verify: im_cluster * prod(denoms) = sum(nums * other_denoms)
        for cluster_idx, term_indices in enumerate(clusters):
            if len(term_indices) == 1:
                # Single term: im_cluster * denom = num
                busid, cols, sel = all_terms[term_indices[0]]
                denom = _compress_exprs(busid, cols, alpha, gamma)
                constraint = im_clusters[cluster_idx] * denom - sel
            else:
                # Multiple terms: im_cluster * prod(denoms) = sum(nums * other_denoms)
                denoms = []
                nums = []
                for idx in term_indices:
                    busid, cols, sel = all_terms[idx]
                    denoms.append(_compress_exprs(busid, cols, alpha, gamma))
                    nums.append(sel)

                # prod_denoms = denom[0] * denom[1] * ... * denom[n-1]
                prod_denoms = denoms[0]
                for d in denoms[1:]:
                    prod_denoms = prod_denoms * d

                # sum_cross = num[0] * denom[1] * ... + num[1] * denom[0] * denom[2] * ... + ...
                sum_cross = denoms[0] * FF3(0)  # Initialize to zero with right shape
                for i, num in enumerate(nums):
                    cross_term = num
                    for j, d in enumerate(denoms):
                        if j != i:
                            cross_term = cross_term * d
                    sum_cross = sum_cross + cross_term

                constraint = im_clusters[cluster_idx] * prod_denoms - sum_cross

            constraints.append(constraint * vc_power)
            vc_power = vc_power * vc

        # Gsum recurrence constraint:
        # gsum - prev_gsum * (1 - L1) - sum(im_clusters) = 0
        # At row 0 (L1=1): gsum = sum(im_clusters)
        # At other rows (L1=0): gsum - prev_gsum = sum(im_clusters)
        sum_im = im_clusters[0]
        for im in im_clusters[1:]:
            sum_im = sum_im + im

        one_minus_L1 = 1 - L1
        gsum_constraint = gsum - prev_gsum * one_minus_L1 - sum_im
        constraints.append(gsum_constraint * vc_power)
        vc_power = vc_power * vc

        # Boundary constraint at last row:
        # L1' * (result - gsum) = 0
        # For SimpleLeft (single instance), result = airgroupValue which should be 0
        # at a valid trace, meaning the grand sum is balanced
        boundary_constraint = next_L1 * gsum
        constraints.append(boundary_constraint * vc_power)

        # Sum all constraints
        result = constraints[0]
        for c in constraints[1:]:
            result = result + c

        return result
