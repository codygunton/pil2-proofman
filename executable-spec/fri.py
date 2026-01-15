"""FRI folding protocol core operations."""

from typing import List
import math
import galois
from field import (
    GF, GOLDILOCKS_PRIME, Fe, Fe3,
    pow_mod, inv_mod, get_shift, get_shift_inv, get_omega, get_omega_inv,
    fe3_mul, fe3_add, fe3_scalar_mul,
)
from merkle_tree import MerkleTree, MerkleRoot

# --- Type Aliases ---

EvalPoly = List[Fe]
FriLayer = EvalPoly

# --- Constants ---

FIELD_EXTENSION = 3


# --- FRI Protocol ---

class FRI:
    """FRI protocol: folding, commitment, and verification."""

    @staticmethod
    def fold(
        step: int,
        pol: EvalPoly,
        challenge: Fe3,
        n_bits_ext: int,
        prev_bits: int,
        current_bits: int
    ) -> EvalPoly:
        """Fold polynomial using random challenge."""
        p = GOLDILOCKS_PRIME

        # Compute shift^(-1) raised to appropriate power
        pol_shift_inv = get_shift_inv()
        if step > 0:
            for _ in range(n_bits_ext - prev_bits):
                pol_shift_inv = (pol_shift_inv * pol_shift_inv) % p

        pol_2n = 1 << current_bits
        n_x = (1 << prev_bits) // pol_2n
        w_inv = get_omega_inv(prev_bits)

        result = [0] * (pol_2n * FIELD_EXTENSION)

        for g in range(pol_2n):
            # Extract n_x consecutive cubic extension values
            coeffs = []
            for i in range(n_x):
                idx = (g + i * pol_2n) * FIELD_EXTENSION
                coeffs.append([pol[idx], pol[idx + 1], pol[idx + 2]])

            # INTT to convert from evaluations to coefficients
            if n_x > 1:
                n_x_bits = int(math.log2(n_x))
                w_inv_small = get_omega_inv(n_x_bits)
                coeffs = FRI._intt_cubic(coeffs, n_x, w_inv_small)

            # polMulAxi: scale by (shift_inv * w_inv^g)^i
            sinv = (pol_shift_inv * pow_mod(w_inv, g, p)) % p
            acc = 1
            for i in range(n_x):
                coeffs[i] = fe3_scalar_mul(coeffs[i], acc)
                acc = (acc * sinv) % p

            # Horner evaluation at challenge
            res = coeffs[n_x - 1] if n_x > 0 else [0, 0, 0]
            for i in range(n_x - 2, -1, -1):
                res = fe3_mul(res, challenge)
                res = fe3_add(res, coeffs[i])

            result[g * FIELD_EXTENSION] = res[0]
            result[g * FIELD_EXTENSION + 1] = res[1]
            result[g * FIELD_EXTENSION + 2] = res[2]

        return result

    @staticmethod
    def merkelize(
        step: int,
        pol: EvalPoly,
        tree: MerkleTree,
        current_bits: int,
        next_bits: int
    ) -> MerkleRoot:
        """Commit to FRI layer via Merkle tree."""
        transposed = FRI._transpose(pol, 1 << current_bits, next_bits)
        height = 1 << next_bits
        width = (1 << (current_bits - next_bits)) * FIELD_EXTENSION
        tree.merkelize(transposed, height, width)
        return tree.get_root()

    @staticmethod
    def verify_fold(
        value: Fe3,
        step: int,
        n_bits_ext: int,
        current_bits: int,
        prev_bits: int,
        challenge: Fe3,
        idx: int,
        siblings: List[Fe3]
    ) -> Fe3:
        """Verify fold step (verifier algorithm)."""
        p = GOLDILOCKS_PRIME

        shift = get_shift()
        if step > 0:
            for _ in range(n_bits_ext - prev_bits):
                shift = (shift * shift) % p

        w = get_omega(prev_bits)
        w_inv = get_omega_inv(prev_bits)
        n_x = 1 << (prev_bits - current_bits)

        coeffs = list(siblings)
        if n_x > 1:
            coeffs = FRI._intt_cubic(coeffs, n_x, w_inv)

        sinv = inv_mod((shift * pow_mod(w, idx, p)) % p)
        aux = fe3_mul(challenge, [sinv, 0, 0])

        return FRI._eval_poly(coeffs, n_x, aux)

    @staticmethod
    def prove_queries(
        queries: List[int],
        trees: List[MerkleTree],
        current_bits: int
    ) -> List[List[int]]:
        """Generate Merkle proofs for query indices."""
        proofs = []
        for query_idx in queries:
            idx = query_idx % (1 << current_bits)
            tree_proofs = [tree.get_group_proof(idx) for tree in trees]
            proofs.append(tree_proofs)
        return proofs

    # --- Internal Utilities ---

    @staticmethod
    def _intt_cubic(values: List[Fe3], n: int, w_inv: Fe) -> List[Fe3]:
        """INTT on cubic extension elements (component-wise)."""
        comp0 = GF([v[0] for v in values])
        comp1 = GF([v[1] for v in values])
        comp2 = GF([v[2] for v in values])

        r0 = galois.intt(comp0, omega=w_inv)
        r1 = galois.intt(comp1, omega=w_inv)
        r2 = galois.intt(comp2, omega=w_inv)

        return [[int(r0[i]), int(r1[i]), int(r2[i])] for i in range(n)]

    @staticmethod
    def _transpose(pol: EvalPoly, degree: int, transpose_bits: int) -> EvalPoly:
        """Transpose polynomial for Merkle commitment."""
        w = 1 << transpose_bits
        h = degree // w

        result = [0] * len(pol)
        for i in range(w):
            for j in range(h):
                for k in range(FIELD_EXTENSION):
                    fi = (j * w + i) * FIELD_EXTENSION + k
                    di = (i * h + j) * FIELD_EXTENSION + k
                    result[di] = pol[fi]

        return result

    @staticmethod
    def _eval_poly(pol: List[Fe3], degree: int, x: Fe3) -> Fe3:
        """Evaluate polynomial at point using Horner's method."""
        if degree == 0:
            return [0, 0, 0]

        result = list(pol[degree - 1])
        for i in range(degree - 2, -1, -1):
            result = fe3_mul(result, x)
            result = fe3_add(result, pol[i])

        return result
