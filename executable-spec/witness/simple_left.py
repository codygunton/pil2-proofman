"""SimpleLeft AIR witness generation.

SimpleLeft logup terms (from gsum_debug_data hints):
1. Permutation assumes (busid=1, [a,b]) - selector=+1
2. Permutation proves (busid=1, [c,d]) - selector=-1
3. Permutation assumes (busid=2, [e,f]) - selector=+1
4. Lookup free (busid=3, [g,h], mul=-1) - selector=-1
5. Range Check (busid=100, k[0]) - selector=+1
6. Range Check (busid=101, k[1]) - selector=+1
7. Range Check (busid=100, k[2]-1) - selector=+1
8. Range Check (busid=100, 255-k[2]) - selector=+1
9. Range Check (busid=101, k[3]) - selector=+1
10. Range Check (busid=101, 256-k[3]) - selector=+1
11. Range Check (busid=102, k[4]) - selector=+1
12. Range Check (busid=103, k[5]) - selector=+1
13. Range Check (busid=104, k[6]) - selector=+1

These 13 terms are clustered into 6 im_cluster columns for constraint
degree optimization. The clustering is determined by the compiler.
"""

from typing import Dict, List, Tuple
import numpy as np

from primitives.field import FF, FF3, FF3Poly, batch_inverse, ff3
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
    selector: int,
    alpha: FF3,
    gamma: FF3
) -> FF3Poly:
    """Compute a single logup term: selector / (compressed_exprs + γ)."""
    denominator = _compress_exprs(busid, cols, alpha, gamma)
    n = len(cols[0])
    numerator = FF3(np.full(n, selector % (2**64), dtype=np.uint64))  # Handle -1
    return numerator * batch_inverse(denominator)


class SimpleLeftWitness(WitnessModule):
    """Witness generation for SimpleLeft AIR.

    Computes 6 im_cluster columns and 1 gsum column for the logup protocol.
    The exact clustering depends on compiler optimization, but the sum
    of all im_cluster columns equals the sum of all individual logup terms.
    """

    def _get_all_logup_terms(
        self, ctx: ConstraintContext
    ) -> List[Tuple[int, List[FF3Poly], int]]:
        """Return all logup terms as (busid, cols, selector) tuples."""
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

        # Define all 13 logup terms from gsum_debug_data hints
        # (busid, cols_list, selector)
        terms = [
            # Permutation/lookup constraints
            (1, [a, b], 1),      # permutation_assumes(1, [a, b])
            (1, [c, d], -1),     # permutation_proves(1, [c, d])
            (2, [e, f], 1),      # permutation_assumes(2, [e, f])
            (3, [g, h], -1),     # lookup(3, [g, h], mul=-1)
            # Range check constraints
            # Note: FF3 arithmetic requires field element operands
            (100, [k[0]], 1),                                # range_check(k[0], 0, 255)
            (101, [k[1]], 1),                                # range_check(k[1], 0, 65535)
            (100, [k[2] - ff3([1, 0, 0])], 1),              # range_check(k[2]-1, 0, 254)
            (100, [ff3([255, 0, 0]) - k[2]], 1),            # range_check(255-k[2], 0, 254)
            (101, [k[3]], 1),                                # range_check(k[3], 0, 256)
            (101, [ff3([256, 0, 0]) - k[3]], 1),            # range_check(256-k[3], 0, 256)
            (102, [k[4]], 1),                                # range_check(k[4], 0, 255, predefined=0)
            (103, [k[5]], 1),                                # range_check(k[5], -128, -1)
            (104, [k[6]], 1),                                # range_check(k[6], -129, 127)
        ]
        return terms

    def compute_intermediates(self, ctx: ConstraintContext) -> Dict[str, Dict[int, FF3Poly]]:
        """Compute im_cluster polynomials for logup terms.

        The compiler clusters 13 terms into 6 im_cluster columns.
        Each im_cluster is a sum of sel_j / denom_j for its cluster.

        Note: This is a simplified implementation that computes individual
        terms. The actual compiler clusters multiple terms into each
        im_cluster column. For exact matching with C++, we would need
        to replicate the clustering algorithm or read from the hints.

        Returns:
            {'im_cluster': {0: poly0, 1: poly1, ..., 5: poly5}}
        """
        alpha = ctx.challenge('std_alpha')
        gamma = ctx.challenge('std_gamma')

        terms = self._get_all_logup_terms(ctx)
        n = len(terms[0][1][0])  # Number of rows

        # Compute all 13 individual terms
        all_terms = []
        for busid, cols, sel in terms:
            term = _compute_logup_term(busid, cols, sel, alpha, gamma)
            all_terms.append(term)

        # Cluster into 6 im_cluster columns
        # The clustering matches the compiler's degree optimization
        # For SimpleLeft, the clustering is roughly:
        # - im_cluster[0]: terms 0,1 (permutation for busid=1)
        # - im_cluster[1]: terms 2 (permutation for busid=2)
        # - im_cluster[2]: term 3 (lookup for busid=3)
        # - im_cluster[3]: terms 4,6,7 (range checks busid=100)
        # - im_cluster[4]: terms 5,8,9 (range checks busid=101)
        # - im_cluster[5]: terms 10,11,12 (range checks busids 102-104)

        im_cluster = {}
        clusters = [
            [0, 1],           # Permutation busid=1: assumes + proves
            [2],              # Permutation busid=2
            [3],              # Lookup busid=3
            [4, 6, 7],        # Range checks busid=100
            [5, 8, 9],        # Range checks busid=101
            [10, 11, 12],     # Range checks busids 102-104
        ]

        for i, cluster in enumerate(clusters):
            cluster_sum = FF3(np.zeros(n, dtype=np.uint64))
            for term_idx in cluster:
                cluster_sum = cluster_sum + all_terms[term_idx]
            im_cluster[i] = cluster_sum

        return {'im_cluster': im_cluster}

    def compute_grand_sums(self, ctx: ConstraintContext) -> Dict[str, FF3Poly]:
        """Compute gsum running sum polynomial.

        gsum[i] = gsum[i-1] + sum(im_cluster[row i])
        with gsum[-1] = 0 (boundary condition)

        Returns:
            {'gsum': gsum_polynomial}
        """
        # First compute intermediates
        intermediates = self.compute_intermediates(ctx)
        im_clusters = intermediates['im_cluster']

        # Sum all im_cluster contributions at each row
        n = len(list(im_clusters.values())[0])
        row_sum = im_clusters[0]
        for i in range(1, 6):
            row_sum = row_sum + im_clusters[i]

        # Compute cumulative sum using FF3 arithmetic
        # gsum[0] = row_sum[0]
        # gsum[i] = gsum[i-1] + row_sum[i]
        from primitives.field import ff3_to_interleaved_numpy, ff3_from_interleaved_numpy

        # Extract row_sum values
        row_vecs = row_sum.vector()  # (n, 3) in descending order [c2, c1, c0]

        # Build gsum with cumulative sum
        gsum_values = np.zeros((n, 3), dtype=np.uint64)
        running = FF3([0, 0, 0])

        for i in range(n):
            # Current row contribution
            c0, c1, c2 = int(row_vecs[i, 2]), int(row_vecs[i, 1]), int(row_vecs[i, 0])
            current = FF3([c0, c1, c2])

            # Add to running sum
            running = running + current

            # Extract coefficients for this row
            r_vec = running.vector()[0]  # scalar extraction
            gsum_values[i] = [int(r_vec[2]), int(r_vec[1]), int(r_vec[0])]

        # Convert to FF3Poly
        gsum_interleaved = gsum_values.flatten()
        gsum = ff3_from_interleaved_numpy(gsum_interleaved, n)

        return {'gsum': gsum}
