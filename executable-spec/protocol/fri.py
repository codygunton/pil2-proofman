"""FRI folding protocol core operations."""

from typing import List
import math
import galois
from primitives.field import (
    FF, FF3, ff3, ff3_coeffs,
    SHIFT, SHIFT_INV, get_omega_inv,
)
from primitives.merkle_tree import MerkleTree, MerkleRoot, transpose_for_merkle

# --- Type Aliases ---

EvalPoly = List[int]
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
        challenge: List[int],
        n_bits_ext: int,
        prev_bits: int,
        current_bits: int
    ) -> EvalPoly:
        """Fold polynomial using random challenge."""
        challenge_ff3 = ff3(challenge)

        # Compute SHIFT^(-2^k) where k = n_bits_ext - prev_bits
        k = n_bits_ext - prev_bits if step > 0 else 0
        pol_shift_inv = SHIFT_INV ** (1 << k)

        pol_2n = 1 << current_bits
        n_x = (1 << prev_bits) // pol_2n
        w_inv = FF(get_omega_inv(prev_bits))

        result = [0] * (pol_2n * FIELD_EXTENSION)

        for g in range(pol_2n):
            # Extract n_x consecutive cubic extension values
            coeffs: List[FF3] = []
            for i in range(n_x):
                idx = (g + i * pol_2n) * FIELD_EXTENSION
                coeffs.append(ff3([pol[idx], pol[idx + 1], pol[idx + 2]]))

            # INTT to convert from evaluations to coefficients
            if n_x > 1:
                n_x_bits = int(math.log2(n_x))
                w_inv_small = get_omega_inv(n_x_bits)
                coeffs = FRI._intt_cubic(coeffs, n_x, w_inv_small)

            # polMulAxi: scale by (shift_inv * w_inv^g)^i
            sinv = pol_shift_inv * (w_inv ** g)
            acc = FF(1)
            for i in range(n_x):
                coeffs[i] = coeffs[i] * int(acc)
                acc = acc * sinv

            # Horner evaluation at challenge
            res = galois.Poly(coeffs[::-1], field=FF3)(challenge_ff3) if coeffs else FF3(0)

            res_coeffs = ff3_coeffs(res)
            result[g * FIELD_EXTENSION] = res_coeffs[0]
            result[g * FIELD_EXTENSION + 1] = res_coeffs[1]
            result[g * FIELD_EXTENSION + 2] = res_coeffs[2]

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
        height = 1 << next_bits
        width = (1 << (current_bits - next_bits)) * FIELD_EXTENSION
        transposed = transpose_for_merkle(pol, 1 << current_bits, height, FIELD_EXTENSION)
        tree.merkelize(transposed, height, width)
        return tree.get_root()

    @staticmethod
    def verify_fold(
        value: List[int],
        step: int,
        n_bits_ext: int,
        current_bits: int,
        prev_bits: int,
        challenge: List[int],
        idx: int,
        siblings: List[List[int]]
    ) -> List[int]:
        """Verify fold step (verifier algorithm)."""
        challenge_ff3 = ff3(challenge)

        # Compute SHIFT^(2^k) where k = n_bits_ext - prev_bits
        k = n_bits_ext - prev_bits if step > 0 else 0
        shift = SHIFT ** (1 << k)

        w_inv = FF(get_omega_inv(prev_bits))
        n_x = 1 << (prev_bits - current_bits)

        coeffs = [ff3(s) for s in siblings]
        if n_x > 1:
            coeffs = FRI._intt_cubic(coeffs, n_x, get_omega_inv(prev_bits - current_bits + 1))

        sinv = (shift * (w_inv ** (-idx))) ** -1
        aux = challenge_ff3 * int(sinv)

        result = galois.Poly(coeffs[::-1], field=FF3)(aux) if coeffs else FF3(0)
        return ff3_coeffs(result)

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
    def _intt_cubic(values: List[FF3], n: int, w_inv: int) -> List[FF3]:
        """INTT on cubic extension elements (component-wise)."""
        coeffs = [ff3_coeffs(v) for v in values]
        comp0 = FF([c[0] for c in coeffs])
        comp1 = FF([c[1] for c in coeffs])
        comp2 = FF([c[2] for c in coeffs])

        r0 = galois.intt(comp0, omega=w_inv)
        r1 = galois.intt(comp1, omega=w_inv)
        r2 = galois.intt(comp2, omega=w_inv)

        return [ff3([int(r0[i]), int(r1[i]), int(r2[i])]) for i in range(n)]
