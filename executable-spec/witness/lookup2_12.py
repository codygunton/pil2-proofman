"""Lookup2_12 AIR witness generation.

Lookup2_12 logup terms (from gsum_debug_data hints):
0. Lookup assumes, busid=4, sel=1, cols=[a1, b1]  -- direct term in gsum
1. Lookup proves, busid=4, mul=1, cols=[c1, d1]   -- stored_num = +1
2. Lookup assumes, busid=5, sel=1, cols=[a2, b2]  -- stored_num = -1
3. Lookup assumes, busid=6, sel=sel1, cols=[a3, b3]  -- stored_num = -sel1
4. Lookup proves, busid=6, mul=mul, cols=[c2, d2]    -- stored_num = +mul
5. Lookup assumes, busid=7, sel=sel2, cols=[a4, b4]  -- stored_num = -sel2

Intermediate columns clustering (from expressionsinfo constraint lines):
- im_cluster[0]: busid=4 proves [c1,d1] + busid=5 assumes [a2,b2] = terms 1,2
- im_cluster[1]: busid=6 assumes [a3,b3] + busid=6 proves [c2,d2] = terms 3,4
- im_single: busid=7 assumes [a4,b4] = term 5

Convention: stored_num = -selector for assumes, +multiplicity for proves.
Term 0 (busid=4 assumes) is used directly in gsum, not in intermediate columns.
"""

from typing import Dict, List, Tuple, Union

import numpy as np

from primitives.field import FF3, FF3Poly, batch_inverse, GOLDILOCKS_PRIME
from constraints.base import ConstraintContext
from .base import WitnessModule


class Lookup2_12Witness(WitnessModule):
    """Witness generation for Lookup2_12 AIR.

    Computes 2 im_cluster columns, 1 im_single column, and 1 gsum column.
    """

    def _get_all_logup_terms(
        self, ctx: ConstraintContext
    ) -> List[Tuple[int, List[FF3Poly], Union[int, FF3Poly]]]:
        """Return all logup terms as (busid, cols, selector) tuples."""
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

        # Define all 6 logup terms with stored_num convention:
        # stored_num = -selector for assumes, +multiplicity for proves
        terms = [
            (4, [a1, b1], 1),        # term 0: assumes busid=4, used direct (selector=+1)
            (4, [c1, d1], 1),        # term 1: proves busid=4, stored_num = +1
            (5, [a2, b2], -1),       # term 2: assumes busid=5, stored_num = -1
            (6, [a3, b3], -sel1),    # term 3: assumes busid=6, stored_num = -sel1
            (6, [c2, d2], mul),      # term 4: proves busid=6, stored_num = +mul
            (7, [a4, b4], -sel2),    # term 5: assumes busid=7, stored_num = -sel2
        ]
        return terms

    def compute_intermediates(self, ctx: ConstraintContext) -> Dict[str, Dict[int, FF3Poly]]:
        """Compute intermediate polynomials directly from constraint equations.

        From constraint module:
        - im_cluster[0]: (D2 - D1)/(D1*D2) where D1=compress(4,[c1,d1]), D2=compress(5,[a2,b2])
        - im_cluster[1]: ((-sel1)*D2 + mul*D1)/(D1*D2) where D1=compress(6,[a3,b3]), D2=compress(6,[c2,d2])
        - im_single: (-sel2)/D where D=compress(7,[a4,b4])

        Returns:
            {
                'im_cluster': {0: im_cluster_0, 1: im_cluster_1},
                'im_single': {0: im_single}
            }
        """
        alpha = ctx.challenge('std_alpha')
        gamma = ctx.challenge('std_gamma')

        # Get all columns
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

        n = len(a2)

        def const(value):
            return FF3(np.full(n, value % GOLDILOCKS_PRIME, dtype=np.uint64))

        neg_one = const(-1)

        def compress_2(busid, col1, col2):
            return (col2 * alpha + col1) * alpha + const(busid) + gamma

        im_cluster = {}

        # im_cluster[0]: (D2 - D1)/(D1*D2) where D1=compress(4,[c1,d1]), D2=compress(5,[a2,b2])
        D1 = compress_2(4, c1, d1)
        D2 = compress_2(5, a2, b2)
        numerator = D2 + neg_one * D1  # D2 - D1
        denominator = D1 * D2
        im_cluster[0] = numerator * batch_inverse(denominator)

        # im_cluster[1]: ((-sel1)*D2 + mul*D1)/(D1*D2) where D1=compress(6,[a3,b3]), D2=compress(6,[c2,d2])
        D1 = compress_2(6, a3, b3)
        D2 = compress_2(6, c2, d2)
        neg_sel1 = neg_one * sel1
        numerator = neg_sel1 * D2 + mul * D1
        denominator = D1 * D2
        im_cluster[1] = numerator * batch_inverse(denominator)

        # im_single: (-sel2)/D where D=compress(7,[a4,b4])
        D = compress_2(7, a4, b4)
        neg_sel2 = neg_one * sel2
        im_single = {0: neg_sel2 * batch_inverse(D)}

        return {'im_cluster': im_cluster, 'im_single': im_single}

    def compute_grand_sums(self, ctx: ConstraintContext) -> Dict[str, FF3Poly]:
        """Compute gsum running sum polynomial.

        From constraint 3:
        (gsum - prev_gsum*(1-L1) - sum_ims) * direct_den + 1 = 0

        This means:
        gsum[i] = prev_gsum[i] * (1-L1[i]) + sum_ims[i] - 1/direct_den[i]

        Where direct_den = compress(4, [a1, b1]).

        Returns:
            {'gsum': gsum_polynomial}
        """
        alpha = ctx.challenge('std_alpha')
        gamma = ctx.challenge('std_gamma')

        # Get columns for direct_den
        a1 = ctx.col('a1')
        b1 = ctx.col('b1')

        intermediates = self.compute_intermediates(ctx)
        im_clusters = intermediates['im_cluster']
        im_single = intermediates['im_single']

        n = len(im_clusters[0])

        def const(value):
            return FF3(np.full(n, value % GOLDILOCKS_PRIME, dtype=np.uint64))

        # Compute direct_den = compress(4, [a1, b1])
        direct_den = (b1 * alpha + a1) * alpha + const(4) + gamma

        # term0 contribution = -1 / direct_den
        term0 = const(-1) * batch_inverse(direct_den)

        # Sum all contributions: im_clusters + im_single + term0
        sum_ims = im_clusters[0] + im_clusters[1] + im_single[0]
        row_sum = sum_ims + term0

        # Compute cumulative sum
        gsum = self._compute_cumulative_sum(row_sum)

        return {'gsum': gsum}
