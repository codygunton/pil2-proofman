"""SimpleLeft AIR witness generation.

SimpleLeft logup terms (from constraint module analysis):

Term 0: busid=1, [a,b] - assumes, selector=-1 (goes directly to gsum)
Term 1: busid=1, [c,d] - proves, selector=+1
Term 2: busid=2, [e,f] - assumes, selector=-1
Term 3: busid=3, [g,h] - lookup, selector=-1
Term 4: busid=100, k[0] - range, selector=-1
Term 5: busid=101, k[1] - range, selector=-1
Term 6: busid=100, k[2]-1 - range, selector=-1
Term 7: busid=100, 255-k[2] - range, selector=-1
Term 8: busid=101, k[3] - range, selector=-1
Term 9: busid=101, 256-k[3] - range, selector=-1
Term 10: busid=102, k[4] - range, selector=-1
Term 11: busid=103, k[5] - range, selector=-1
Term 12: busid=104, k[6] - range, selector=-1

Intermediate columns clustering (from constraint equations):
- im_cluster[0]: term1 + term2 (proves busid=1 + assumes busid=2)
- im_cluster[1]: term3 + term4 (lookup busid=3 + range busid=100,k[0])
- im_cluster[2]: term5 + term6 (range busid=101,k[1] + range busid=100,k[2]-1)
- im_cluster[3]: term7 + term8 (range busid=100,255-k[2] + range busid=101,k[3])
- im_cluster[4]: term9 + term10 (range busid=101,256-k[3] + range busid=102,k[4])
- im_cluster[5]: term11 + term12 (range busid=103,k[5] + range busid=104,k[6])

Term 0 is added directly to gsum, not via intermediate columns.
"""


import numpy as np

from constraints.base import ConstraintContext
from primitives.field import FF3, GOLDILOCKS_PRIME, FF3Poly, batch_inverse

from .base import WitnessModule


class SimpleLeftWitness(WitnessModule):
    """Witness generation for SimpleLeft AIR.

    Computes 6 im_cluster columns and 1 gsum column for the logup protocol.
    The exact clustering depends on compiler optimization, but the sum
    of all im_cluster columns equals the sum of all individual logup terms.
    """

    def _get_all_logup_terms(
        self, ctx: ConstraintContext
    ) -> list[tuple[int, list[FF3Poly], int]]:
        """Return all logup terms as (busid, cols, selector) tuples.

        Selector convention (from constraint analysis):
        - "proves" terms: selector = +1
        - "assumes" terms: selector = -1
        """
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

        # Define all 13 logup terms with constraint-derived selectors
        # Term 0: goes directly to gsum (not in intermediate columns)
        # Terms 1-12: grouped into 6 im_cluster columns
        one = FF3(1)
        v255 = FF3(255)
        v256 = FF3(256)
        terms = [
            # Term 0: permutation assumes (direct to gsum)
            (1, [a, b], -1),
            # Term 1: permutation proves
            (1, [c, d], 1),
            # Term 2: permutation assumes
            (2, [e, f], -1),
            # Term 3: lookup
            (3, [g, h], -1),
            # Terms 4-12: range checks (all assumes, so selector=-1)
            (100, [k[0]], -1),
            (101, [k[1]], -1),
            (100, [k[2] - one], -1),
            (100, [v255 - k[2]], -1),
            (101, [k[3]], -1),
            (101, [v256 - k[3]], -1),
            (102, [k[4]], -1),
            (103, [k[5]], -1),
            (104, [k[6]], -1),
        ]
        return terms

    def compute_intermediates(self, ctx: ConstraintContext) -> dict[str, dict[int, FF3Poly]]:
        """Compute im_cluster polynomials directly from constraint equations.

        Each im_cluster satisfies: im[i] * D1 * D2 = (coeff2*D2 + coeff1*D1)
        So: im[i] = (coeff2*D2 + coeff1*D1) / (D1 * D2)

        From constraint module:
        - im[0]: D1=compress(1,[c,d]), D2=compress(2,[e,f]), coeffs=(+1,-1) -> (D2-D1)/(D1*D2)
        - im[1]: D1=compress(3,[g,h]), D2=compress(100,k[0]), coeffs=(-1,-1) -> -(D1+D2)/(D1*D2)
        - im[2]: D1=compress(101,k[1]), D2=compress(100,k[2]-1), coeffs=(-1,-1)
        - im[3]: D1=compress(100,255-k[2]), D2=compress(101,k[3]), coeffs=(-1,-1)
        - im[4]: D1=compress(101,256-k[3]), D2=compress(102,k[4]), coeffs=(-1,-1)
        - im[5]: D1=compress(103,k[5]), D2=compress(104,k[6]), coeffs=(-1,-1)

        Returns:
            {'im_cluster': {0: poly0, 1: poly1, ..., 5: poly5}}
        """
        alpha = ctx.challenge('std_alpha')
        gamma = ctx.challenge('std_gamma')

        # Get all columns
        c = ctx.col('c')
        d = ctx.col('d')
        e = ctx.col('e')
        f = ctx.col('f')
        g = ctx.col('g')
        h = ctx.col('h')
        k = [ctx.col('k', i) for i in range(7)]

        n = len(c)

        def const(value: int) -> FF3:
            return FF3(np.full(n, value % GOLDILOCKS_PRIME, dtype=np.uint64))

        def compress_1(busid: int, col: FF3) -> FF3:
            return col * alpha + const(busid) + gamma

        def compress_2(busid: int, col1: FF3, col2: FF3) -> FF3:
            return (col2 * alpha + col1) * alpha + const(busid) + gamma

        neg_one = const(-1)
        one = const(1)
        v255 = const(255)
        v256 = const(256)

        im_cluster = {}

        # im_cluster[0]: (D2 - D1) / (D1 * D2) where D1=compress(1,[c,d]), D2=compress(2,[e,f])
        D1 = compress_2(1, c, d)
        D2 = compress_2(2, e, f)
        numerator = D2 + neg_one * D1  # D2 - D1
        denominator = D1 * D2
        im_cluster[0] = numerator * batch_inverse(denominator)

        # im_cluster[1]: -(D1 + D2) / (D1 * D2) where D1=compress(3,[g,h]), D2=compress(100,k[0])
        D1 = compress_2(3, g, h)
        D2 = compress_1(100, k[0])
        numerator = neg_one * D2 + neg_one * D1  # -D1 - D2
        denominator = D1 * D2
        im_cluster[1] = numerator * batch_inverse(denominator)

        # im_cluster[2]: -(D1 + D2) / (D1 * D2) where D1=compress(101,k[1]), D2=compress(100,k[2]-1)
        D1 = compress_1(101, k[1])
        D2 = compress_1(100, k[2] - one)
        numerator = neg_one * D2 + neg_one * D1
        denominator = D1 * D2
        im_cluster[2] = numerator * batch_inverse(denominator)

        # im_cluster[3]: -(D1 + D2) / (D1 * D2) where D1=compress(100,255-k[2]), D2=compress(101,k[3])
        D1 = compress_1(100, v255 - k[2])
        D2 = compress_1(101, k[3])
        numerator = neg_one * D2 + neg_one * D1
        denominator = D1 * D2
        im_cluster[3] = numerator * batch_inverse(denominator)

        # im_cluster[4]: -(D1 + D2) / (D1 * D2) where D1=compress(101,256-k[3]), D2=compress(102,k[4])
        D1 = compress_1(101, v256 - k[3])
        D2 = compress_1(102, k[4])
        numerator = neg_one * D2 + neg_one * D1
        denominator = D1 * D2
        im_cluster[4] = numerator * batch_inverse(denominator)

        # im_cluster[5]: -(D1 + D2) / (D1 * D2) where D1=compress(103,k[5]), D2=compress(104,k[6])
        D1 = compress_1(103, k[5])
        D2 = compress_1(104, k[6])
        numerator = neg_one * D2 + neg_one * D1
        denominator = D1 * D2
        im_cluster[5] = numerator * batch_inverse(denominator)

        return {'im_cluster': im_cluster}

    def compute_grand_sums(self, ctx: ConstraintContext) -> dict[str, FF3Poly]:
        """Compute gsum running sum polynomial.

        From constraint 6:
        (gsum - prev_gsum*(1-L1) - sum_ims) * direct_den + 1 = 0

        This means:
        gsum[i] = prev_gsum[i] * (1-L1[i]) + sum_ims[i] - 1/direct_den[i]

        Where direct_den = compress(1, [a, b]).

        Returns:
            {'gsum': gsum_polynomial}
        """
        alpha = ctx.challenge('std_alpha')
        gamma = ctx.challenge('std_gamma')

        # Get columns for term0
        a = ctx.col('a')
        b = ctx.col('b')

        # Compute intermediates
        intermediates = self.compute_intermediates(ctx)
        im_clusters = intermediates['im_cluster']

        n = len(list(im_clusters.values())[0])

        def const(value: int) -> FF3:
            return FF3(np.full(n, value % GOLDILOCKS_PRIME, dtype=np.uint64))

        # Compute direct_den = compress(1, [a, b]) = (b*α + a)*α + 1 + γ
        direct_den = (b * alpha + a) * alpha + const(1) + gamma

        # term0 contribution = -1 / direct_den
        term0 = const(-1) * batch_inverse(direct_den)

        # Sum all contributions: im_clusters + term0
        row_sum = im_clusters[0]
        for i in range(1, 6):
            row_sum = row_sum + im_clusters[i]
        row_sum = row_sum + term0

        # Compute cumulative sum
        gsum = self._compute_cumulative_sum(row_sum)

        return {'gsum': gsum}
