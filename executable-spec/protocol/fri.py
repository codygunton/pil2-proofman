"""FRI folding protocol."""

from typing import List

import galois

from primitives.field import FF, FF3, ff3, ff3_coeffs, ff3_array, SHIFT, SHIFT_INV, get_omega_inv
from primitives.merkle_tree import MerkleTree, MerkleRoot, transpose_for_merkle

# --- Type Aliases ---

EvalPoly = List[int]  # Polynomial in evaluation form (flattened FF3 coefficients)


# --- Internal Helpers ---

def _list_to_ff3_array(pol: EvalPoly) -> FF3:
    """Convert flattened coefficient list to FF3 galois array."""
    n = len(pol) // 3
    c0 = [pol[i * 3] for i in range(n)]
    c1 = [pol[i * 3 + 1] for i in range(n)]
    c2 = [pol[i * 3 + 2] for i in range(n)]
    return ff3_array(c0, c1, c2)


def _ff3_array_to_list(arr: FF3) -> EvalPoly:
    """Convert FF3 galois array to flattened coefficient list."""
    result = []
    for elem in arr:
        result.extend(ff3_coeffs(elem))
    return result


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
        current_bits: int,
    ) -> EvalPoly:
        """Fold polynomial by factor 2^(prev_bits - current_bits) using challenge."""
        challenge_ff3 = ff3(challenge)

        # Coset shift: SHIFT^(-2^k) where k depends on accumulated folding
        k = n_bits_ext - prev_bits if step > 0 else 0
        shift_inv_pow = SHIFT_INV ** (1 << k)

        n_out = 1 << current_bits  # Output size (number of groups)
        fold_factor = (1 << prev_bits) // n_out  # Points per group
        w_inv = FF(get_omega_inv(prev_bits))

        # Convert input to FF3 array
        pol_ff3 = _list_to_ff3_array(pol)

        result_elems = []
        for g in range(n_out):
            # Gather fold_factor evaluations for this group
            indices = [g + i * n_out for i in range(fold_factor)]
            evals = [pol_ff3[idx] for idx in indices]

            # INTT: evaluations -> coefficients
            if fold_factor > 1:
                fold_bits = prev_bits - current_bits
                evals = FRI._intt_cubic(evals, fold_factor, get_omega_inv(fold_bits))

            # Scale coefficients by (shift_inv * w_inv^g)^i (coset adjustment)
            scale = shift_inv_pow * (w_inv ** g)
            acc = FF(1)
            for i in range(fold_factor):
                evals[i] = evals[i] * int(acc)
                acc *= scale

            # Evaluate at challenge point (Horner)
            folded = galois.Poly(evals[::-1], field=FF3)(challenge_ff3) if evals else FF3(0)
            result_elems.append(folded)

        # Convert back to flattened list
        result = []
        for elem in result_elems:
            result.extend(ff3_coeffs(elem))
        return result

    @staticmethod
    def merkelize(
        step: int,  # noqa: ARG004 - kept for API consistency
        pol: EvalPoly,
        tree: MerkleTree,
        current_bits: int,
        next_bits: int,
    ) -> MerkleRoot:
        """Commit to FRI layer via Merkle tree."""
        dim = 3  # FF3 dimension
        height = 1 << next_bits
        n_groups = 1 << (current_bits - next_bits)
        width = n_groups * dim
        transposed = transpose_for_merkle(pol, 1 << current_bits, height, dim)
        tree.merkelize(transposed, height, width, n_cols=n_groups)
        return tree.get_root()

    @staticmethod
    def verify_fold(
        value: List[int],  # noqa: ARG004 - unused but part of protocol API
        step: int,
        n_bits_ext: int,
        current_bits: int,
        prev_bits: int,
        challenge: List[int],
        idx: int,
        siblings: List[List[int]],
    ) -> List[int]:
        """Verify fold step: recompute expected value from siblings and challenge."""
        challenge_ff3 = ff3(challenge)

        # Coset shift for verification (forward direction)
        k = n_bits_ext - prev_bits if step > 0 else 0
        shift_pow = SHIFT ** (1 << k)

        w_inv = FF(get_omega_inv(prev_bits))
        fold_factor = 1 << (prev_bits - current_bits)

        # Convert siblings to FF3 coefficients
        coeffs = [ff3(s) for s in siblings]
        if fold_factor > 1:
            fold_bits = prev_bits - current_bits
            coeffs = FRI._intt_cubic(coeffs, fold_factor, get_omega_inv(fold_bits))

        # Compute evaluation point: challenge * (shift * w^(-idx))^(-1)
        eval_point = challenge_ff3 * int((shift_pow * (w_inv ** (-idx))) ** -1)

        result = galois.Poly(coeffs[::-1], field=FF3)(eval_point) if coeffs else FF3(0)
        return ff3_coeffs(result)

    @staticmethod
    def prove_queries(
        queries: List[int],
        trees: List[MerkleTree],
        current_bits: int,
    ) -> List[List[int]]:
        """Generate Merkle proofs for query indices."""
        return [
            [tree.get_group_proof(q % (1 << current_bits)) for tree in trees]
            for q in queries
        ]

    # --- Internal ---

    @staticmethod
    def _intt_cubic(values: List[FF3], n: int, w_inv: int) -> List[FF3]:
        """INTT on cubic extension elements (component-wise over base field)."""
        coeffs = [ff3_coeffs(v) for v in values]

        # Separate components and apply INTT to each
        components = [FF([c[i] for c in coeffs]) for i in range(3)]
        results = [galois.intt(comp, omega=w_inv) for comp in components]

        return [ff3([int(r[i]) for r in results]) for i in range(n)]
