"""Permutation1_6 AIR witness generation.

Permutation1_6 uses both sum-based (logup) and product-based permutation:

Sum-based logup terms (5 terms):
1. Permutation assumes, busid=1, sel=1, cols=[a1, b1]
2. Permutation proves, busid=1, mul=1, cols=[c1, d1]
3. Permutation assumes, busid=2, sel=1, cols=[a2, b2]
4. Permutation assumes, busid=3, sel=sel1, cols=[a3, b3]
5. Permutation proves, busid=3, mul=sel2, cols=[c2, d2]

Clustered into:
- im_cluster[0]: terms 0,1 (busid=1)
- im_cluster[1]: terms 2,3,4 (busid=2,3)

Product-based term (1 term):
6. Permutation assumes, busid=4, sel=sel3, cols=[a4, b4]
"""

from typing import Dict, List, Tuple, Union
import numpy as np

from primitives.field import FF3, FF3Poly, batch_inverse
from constraints.base import ConstraintContext
from .base import WitnessModule


def _compress_exprs(busid: int, cols: List[FF3Poly], alpha: FF3, gamma: FF3) -> FF3Poly:
    """Compute denominator: busid + col1*α + col2*α² + ... + γ."""
    n = len(cols[0])
    result = FF3(np.full(n, busid, dtype=np.uint64))
    alpha_power = alpha
    for col in cols:
        result = result + col * alpha_power
        alpha_power = alpha_power * alpha
    return result + gamma


def _compute_logup_term(
    busid: int,
    cols: List[FF3Poly],
    selector: Union[int, FF3Poly],
    alpha: FF3,
    gamma: FF3
) -> FF3Poly:
    """Compute a single logup term: selector / (compressed_exprs + γ)."""
    denominator = _compress_exprs(busid, cols, alpha, gamma)
    n = len(cols[0])

    if isinstance(selector, int):
        # Scalar selector - handle negative values
        sel_val = selector % (2**64) if selector >= 0 else (2**64 + selector) % (2**64)
        numerator = FF3(np.full(n, sel_val, dtype=np.uint64))
    else:
        # Column selector
        numerator = selector

    return numerator * batch_inverse(denominator)


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
        """Compute intermediate polynomials for logup terms.

        Returns:
            {
                'im_cluster': {0: im_cluster_0, 1: im_cluster_1}
            }
        """
        alpha = ctx.challenge('std_alpha')
        gamma = ctx.challenge('std_gamma')

        terms = self._get_sum_logup_terms(ctx)
        n = len(terms[0][1][0])

        # Compute all 5 individual logup terms
        all_terms = []
        for busid, cols, sel in terms:
            term = _compute_logup_term(busid, cols, sel, alpha, gamma)
            all_terms.append(term)

        # Cluster into intermediate columns
        # - im_cluster[0]: terms 0,1 (busid=1)
        # - im_cluster[1]: terms 2,3,4 (busid=2,3)
        clusters = [
            [0, 1],      # busid=1
            [2, 3, 4],   # busid=2,3
        ]

        im_cluster = {}
        for i, cluster in enumerate(clusters):
            cluster_sum = FF3(np.zeros(n, dtype=np.uint64))
            for term_idx in cluster:
                cluster_sum = cluster_sum + all_terms[term_idx]
            im_cluster[i] = cluster_sum

        return {'im_cluster': im_cluster}

    def compute_grand_sums(self, ctx: ConstraintContext) -> Dict[str, FF3Poly]:
        """Compute gsum and gprod polynomials.

        gsum[i] = gsum[i-1] + sum(im_cluster columns at row i)
        gprod[i] = gprod[i-1] * (sel * (compress + gamma - 1) + 1)

        Returns:
            {'gsum': gsum_polynomial, 'gprod': gprod_polynomial}
        """
        alpha = ctx.challenge('std_alpha')
        gamma = ctx.challenge('std_gamma')

        # Get columns for gprod
        a4 = ctx.col('a4')
        b4 = ctx.col('b4')
        sel3 = ctx.col('sel3')

        intermediates = self.compute_intermediates(ctx)
        im_clusters = intermediates['im_cluster']

        # Sum all intermediate contributions for gsum
        n = len(im_clusters[0])
        row_sum = im_clusters[0] + im_clusters[1]

        # Compute gsum cumulative sum
        from primitives.field import ff3_from_interleaved_numpy

        row_vecs = row_sum.vector()  # (n, 3) in descending order [c2, c1, c0]
        gsum_values = np.zeros((n, 3), dtype=np.uint64)
        running_sum = FF3([0, 0, 0])

        for i in range(n):
            c0, c1, c2 = int(row_vecs[i, 2]), int(row_vecs[i, 1]), int(row_vecs[i, 0])
            current = FF3([c0, c1, c2])
            running_sum = running_sum + current

            r_vec = running_sum.vector()[0]
            gsum_values[i] = [int(r_vec[2]), int(r_vec[1]), int(r_vec[0])]

        gsum_interleaved = gsum_values.flatten()
        gsum = ff3_from_interleaved_numpy(gsum_interleaved, n)

        # Compute gprod running product
        # Formula: gprod[i] = gprod[i-1] * factor[i]
        # where factor = sel3 * (compress + gamma - 1) + 1
        # At row 0: gprod[0] = 1 * factor[0]

        compress_4 = _compress_exprs(4, [a4, b4], alpha, gamma)
        # factor = sel3 * (compress_4 + gamma - 1) + 1
        factor = sel3 * (compress_4 + gamma - 1) + 1

        factor_vecs = factor.vector()  # (n, 3) in descending order [c2, c1, c0]
        gprod_values = np.zeros((n, 3), dtype=np.uint64)
        running_prod = FF3([1, 0, 0])  # Start with 1

        for i in range(n):
            c0, c1, c2 = int(factor_vecs[i, 2]), int(factor_vecs[i, 1]), int(factor_vecs[i, 0])
            current_factor = FF3([c0, c1, c2])
            running_prod = running_prod * current_factor

            r_vec = running_prod.vector()[0]
            gprod_values[i] = [int(r_vec[2]), int(r_vec[1]), int(r_vec[0])]

        gprod_interleaved = gprod_values.flatten()
        gprod = ff3_from_interleaved_numpy(gprod_interleaved, n)

        return {'gsum': gsum, 'gprod': gprod}
