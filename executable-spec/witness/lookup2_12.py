"""Lookup2_12 AIR witness generation.

Lookup2_12 logup terms (from gsum_debug_data hints):
1. Lookup assumes, busid=4, sel=1, cols=[a1, b1]
2. Lookup proves, busid=4, mul=1, cols=[c1, d1]
3. Lookup assumes, busid=5, sel=1, cols=[a2, b2]
4. Lookup assumes, busid=6, sel=sel1, cols=[a3, b3]
5. Lookup proves, busid=6, mul=mul, cols=[c2, d2]
6. Lookup assumes, busid=7, sel=sel2, cols=[a4, b4]

Clustered into:
- im_cluster[0]: terms 0,1 (busid=4)
- im_cluster[1]: terms 2,3,4 (busid=5,6)
- im_single: term 5 (busid=7)
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

        # Define all 6 logup terms
        # selector: +1 for assumes, -1 for proves (or the actual mul column negated)
        terms = [
            (4, [a1, b1], 1),        # assumes busid=4
            (4, [c1, d1], -1),       # proves busid=4 (negated)
            (5, [a2, b2], 1),        # assumes busid=5
            (6, [a3, b3], sel1),     # assumes busid=6, sel=sel1
            (6, [c2, d2], -mul),     # proves busid=6, mul negated
            (7, [a4, b4], sel2),     # assumes busid=7, sel=sel2
        ]
        return terms

    def compute_intermediates(self, ctx: ConstraintContext) -> Dict[str, Dict[int, FF3Poly]]:
        """Compute intermediate polynomials for logup terms.

        Returns:
            {
                'im_cluster': {0: im_cluster_0, 1: im_cluster_1},
                'im_single': {0: im_single}
            }
        """
        alpha = ctx.challenge('std_alpha')
        gamma = ctx.challenge('std_gamma')

        terms = self._get_all_logup_terms(ctx)
        n = len(terms[0][1][0])

        # Compute all 6 individual logup terms
        all_terms = []
        for busid, cols, sel in terms:
            term = _compute_logup_term(busid, cols, sel, alpha, gamma)
            all_terms.append(term)

        # Cluster into intermediate columns
        # - im_cluster[0]: terms 0,1 (busid=4)
        # - im_cluster[1]: terms 2,3,4 (busid=5,6)
        # - im_single: term 5 (busid=7)
        clusters = [
            [0, 1],      # busid=4
            [2, 3, 4],   # busid=5,6
        ]

        im_cluster = {}
        for i, cluster in enumerate(clusters):
            cluster_sum = FF3(np.zeros(n, dtype=np.uint64))
            for term_idx in cluster:
                cluster_sum = cluster_sum + all_terms[term_idx]
            im_cluster[i] = cluster_sum

        # im_single is just term 5
        im_single = {0: all_terms[5]}

        return {'im_cluster': im_cluster, 'im_single': im_single}

    def compute_grand_sums(self, ctx: ConstraintContext) -> Dict[str, FF3Poly]:
        """Compute gsum running sum polynomial.

        gsum[i] = gsum[i-1] + sum(intermediate columns at row i)

        Returns:
            {'gsum': gsum_polynomial}
        """
        intermediates = self.compute_intermediates(ctx)
        im_clusters = intermediates['im_cluster']
        im_single = intermediates['im_single']

        # Sum all intermediate contributions
        n = len(im_clusters[0])
        row_sum = im_clusters[0] + im_clusters[1] + im_single[0]

        # Compute cumulative sum
        from primitives.field import ff3_from_interleaved_numpy

        row_vecs = row_sum.vector()  # (n, 3) in descending order [c2, c1, c0]
        gsum_values = np.zeros((n, 3), dtype=np.uint64)
        running = FF3([0, 0, 0])

        for i in range(n):
            c0, c1, c2 = int(row_vecs[i, 2]), int(row_vecs[i, 1]), int(row_vecs[i, 0])
            current = FF3([c0, c1, c2])
            running = running + current

            r_vec = running.vector()[0]
            gsum_values[i] = [int(r_vec[2]), int(r_vec[1]), int(r_vec[0])]

        gsum_interleaved = gsum_values.flatten()
        gsum = ff3_from_interleaved_numpy(gsum_interleaved, n)

        return {'gsum': gsum}
