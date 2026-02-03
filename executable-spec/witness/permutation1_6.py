"""Permutation1_6 AIR witness generation.

Permutation1_6 uses both sum-based (logup) and product-based permutation:

Sum-based logup terms (5 terms, 0-indexed):
0. Permutation assumes, busid=1, sel=1, cols=[a1, b1] -> goes to gsum direct
1. Permutation proves, busid=1, sel=-1, cols=[c1, d1]
2. Permutation assumes, busid=2, sel=1, cols=[a2, b2]
3. Permutation assumes, busid=3, sel=sel1, cols=[a3, b3]
4. Permutation proves, busid=3, sel=-sel2, cols=[c2, d2]

Intermediate columns clustering (from constraint module):
- im_cluster[0]: terms 1,2 (proves busid=1 + assumes busid=2)
- im_cluster[1]: terms 3,4 (assumes busid=3 + proves busid=3)
- Term 0 goes directly to gsum, not into im_cluster

Product-based term (for gprod):
Permutation assumes, busid=4, sel=sel3, cols=[a4, b4]
"""

from typing import Dict, List, Tuple, Union

import numpy as np

from primitives.field import FF3, FF3Poly, batch_inverse, GOLDILOCKS_PRIME
from constraints.base import ConstraintContext
from .base import WitnessModule


class Permutation1_6Witness(WitnessModule):
    """Witness generation for Permutation1_6 AIR.

    Computes 2 im_cluster columns, 1 gsum column, and 1 gprod column.
    """

    def _get_sum_logup_terms(
        self, ctx: ConstraintContext
    ) -> List[Tuple[int, List[FF3Poly], Union[int, FF3Poly]]]:
        """Return sum-based logup terms as (busid, cols, selector) tuples."""
        # Get witness columns
        a1 = ctx.col('a1')
        b1 = ctx.col('b1')
        a2 = ctx.col('a2')
        b2 = ctx.col('b2')
        a3 = ctx.col('a3')
        b3 = ctx.col('b3')
        c1 = ctx.col('c1')
        d1 = ctx.col('d1')
        c2 = ctx.col('c2')
        d2 = ctx.col('d2')
        sel1 = ctx.col('sel1')
        sel2 = ctx.col('sel2')

        # Define all 5 sum-based logup terms
        # selector: +1 for assumes, -1 for proves (or the actual sel column negated)
        terms = [
            (1, [a1, b1], 1),        # assumes busid=1
            (1, [c1, d1], -1),       # proves busid=1 (negated)
            (2, [a2, b2], 1),        # assumes busid=2
            (3, [a3, b3], sel1),     # assumes busid=3, sel=sel1
            (3, [c2, d2], -sel2),    # proves busid=3, sel=sel2 (negated)
        ]
        return terms

    def compute_intermediates(self, ctx: ConstraintContext) -> Dict[str, Dict[int, FF3Poly]]:
        """Compute intermediate polynomials directly from constraint equations.

        From constraint module:
        - im_cluster[0]: (D2 - D1)/(D1*D2) where D1=compress(1,[c1,d1]), D2=compress(2,[a2,b2])
        - im_cluster[1]: ((-sel1)*D2 + sel2*D1)/(D1*D2) where D1=compress(3,[a3,b3]), D2=compress(3,[c2,d2])

        Returns:
            {
                'im_cluster': {0: im_cluster_0, 1: im_cluster_1}
            }
        """
        alpha = ctx.challenge('std_alpha')
        gamma = ctx.challenge('std_gamma')

        # Get all columns
        a2 = ctx.col('a2')
        b2 = ctx.col('b2')
        a3 = ctx.col('a3')
        b3 = ctx.col('b3')
        c1 = ctx.col('c1')
        d1 = ctx.col('d1')
        c2 = ctx.col('c2')
        d2 = ctx.col('d2')
        sel1 = ctx.col('sel1')
        sel2 = ctx.col('sel2')

        n = len(a2)

        def const(value):
            return FF3(np.full(n, value % GOLDILOCKS_PRIME, dtype=np.uint64))

        neg_one = const(-1)

        def compress_2(busid, col1, col2):
            return (col2 * alpha + col1) * alpha + const(busid) + gamma

        im_cluster = {}

        # im_cluster[0]: (D2 - D1)/(D1*D2) where D1=compress(1,[c1,d1]), D2=compress(2,[a2,b2])
        D1 = compress_2(1, c1, d1)
        D2 = compress_2(2, a2, b2)
        numerator = D2 + neg_one * D1  # D2 - D1
        denominator = D1 * D2
        im_cluster[0] = numerator * batch_inverse(denominator)

        # im_cluster[1]: ((-sel1)*D2 + sel2*D1)/(D1*D2) where D1=compress(3,[a3,b3]), D2=compress(3,[c2,d2])
        D1 = compress_2(3, a3, b3)
        D2 = compress_2(3, c2, d2)
        neg_sel1 = neg_one * sel1
        numerator = neg_sel1 * D2 + sel2 * D1
        denominator = D1 * D2
        im_cluster[1] = numerator * batch_inverse(denominator)

        return {'im_cluster': im_cluster}

    def compute_grand_sums(self, ctx: ConstraintContext) -> Dict[str, FF3Poly]:
        """Compute gsum and gprod polynomials.

        From constraint 2: gsum recurrence
        (gsum - prev_gsum*(1-L1) - sum_im) * direct_den + 1 = 0
        So gsum[i] = gsum[i-1] + sum_im[i] - 1/direct_den[i]
        where direct_den = compress(1,[a1,b1])

        From constraint 4: gprod recurrence
        gprod * denom = prev_gprod * (1-L1) + L1
        where denom = sel3 * (e + gamma - 1) + 1, e = (b4*alpha + a4)*alpha + 4
        For i>0: gprod[i] = gprod[i-1] / denom[i]
        For i=0: gprod[0] = 1 / denom[0]

        Returns:
            {'gsum': gsum_polynomial, 'gprod': gprod_polynomial}
        """
        alpha = ctx.challenge('std_alpha')
        gamma = ctx.challenge('std_gamma')

        # Get columns
        a1 = ctx.col('a1')
        b1 = ctx.col('b1')
        a4 = ctx.col('a4')
        b4 = ctx.col('b4')
        sel3 = ctx.col('sel3')

        intermediates = self.compute_intermediates(ctx)
        im_clusters = intermediates['im_cluster']

        n = len(im_clusters[0])

        def const(value):
            return FF3(np.full(n, value % GOLDILOCKS_PRIME, dtype=np.uint64))

        one = const(1)

        # ---- GSUM ----
        # direct_den = compress(1, [a1, b1])
        direct_den = (b1 * alpha + a1) * alpha + one + gamma

        # term0 contribution = -1 / direct_den
        term0 = const(-1) * batch_inverse(direct_den)

        # Sum all contributions for gsum: im_clusters + term0
        sum_im = im_clusters[0] + im_clusters[1]
        row_sum = sum_im + term0

        # Compute gsum cumulative sum
        gsum = self._compute_cumulative_sum(row_sum)

        # ---- GPROD ----
        # e = (b4*alpha + a4)*alpha + 4 (compress without gamma)
        e = (b4 * alpha + a4) * alpha + const(4)
        # denom = sel3 * (e + gamma - 1) + 1
        denom = sel3 * (e + gamma - one) + one

        # gprod[i] = prod(1/denom[j] for j in 0..i)
        inv_denom = batch_inverse(denom)
        gprod = self._compute_cumulative_product(inv_denom)

        return {'gsum': gsum, 'gprod': gprod}
