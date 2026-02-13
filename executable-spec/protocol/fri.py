"""FRI folding protocol."""


import galois

from primitives.field import (
    FF,
    FF3,
    FIELD_EXTENSION_DEGREE,
    SHIFT,
    SHIFT_INV,
    FF3Poly,
    ff3_to_flat_list,
    get_omega_inv,
)
from primitives.merkle_tree import MerkleRoot, MerkleTree, transpose_for_merkle
from primitives.polynomial import to_coefficients_cubic

# --- FRI Protocol ---

class FRI:
    """FRI protocol: folding, commitment, and verification."""

    @staticmethod
    def fold(
        fri_round: int,
        pol: FF3Poly,
        challenge: list[int],
        n_bits_ext: int,
        prev_bits: int,
        current_bits: int,
    ) -> FF3Poly:
        """Fold polynomial by factor 2^(prev_bits - current_bits) using challenge."""
        challenge_ff3 = FF3.Vector([challenge[2], challenge[1], challenge[0]])

        # Coset shift: SHIFT^(-2^k) where k depends on accumulated folding
        k = n_bits_ext - prev_bits if fri_round > 0 else 0
        shift_inv_pow = SHIFT_INV ** (1 << k)

        n_out = 1 << current_bits  # Output size (number of groups)
        fold_factor = (1 << prev_bits) // n_out  # Points per group
        w_inv = FF(get_omega_inv(prev_bits))

        result_elems = []
        for g in range(n_out):
            # Gather fold_factor evaluations for this group
            indices = [g + i * n_out for i in range(fold_factor)]
            evals = [pol[idx] for idx in indices]

            # Convert evaluations to coefficients (interpolation)
            if fold_factor > 1:
                evals = to_coefficients_cubic(evals, fold_factor)

            # Scale coefficients by (shift_inv * w_inv^g)^i (coset adjustment)
            scale = shift_inv_pow * (w_inv ** g)
            acc = FF(1)
            for i in range(fold_factor):
                evals[i] = evals[i] * int(acc)
                acc *= scale

            # Evaluate at challenge point (Horner)
            folded = galois.Poly(evals[::-1], field=FF3)(challenge_ff3) if evals else FF3(0)
            result_elems.append(folded)

        return FF3(result_elems)

    @staticmethod
    def merkelize(
        fri_round: int,  # noqa: ARG004 - kept for API consistency
        pol: FF3Poly,
        tree: MerkleTree,
        current_bits: int,
        next_bits: int,
    ) -> MerkleRoot:
        """Commit to FRI layer via Merkle tree."""
        dim = FIELD_EXTENSION_DEGREE
        height = 1 << next_bits
        n_groups = 1 << (current_bits - next_bits)
        width = n_groups * dim
        pol_flat = ff3_to_flat_list(pol)
        transposed = transpose_for_merkle(pol_flat, 1 << current_bits, height, dim)
        tree.merkelize(transposed, height, width, n_cols=n_groups)
        return tree.get_root()

    @staticmethod
    def verify_fold(
        value: list[int],  # noqa: ARG004 - unused but part of protocol API
        fri_round: int,
        n_bits_ext: int,
        current_bits: int,
        prev_bits: int,
        challenge: list[int],
        idx: int,
        siblings: list[list[int]],
    ) -> FF3:
        """Verify fold step: recompute expected value from siblings and challenge."""
        challenge_ff3 = FF3.Vector([challenge[2], challenge[1], challenge[0]])

        # Coset shift for verification (forward direction)
        k = n_bits_ext - prev_bits if fri_round > 0 else 0
        shift_pow = SHIFT ** (1 << k)

        w_inv = FF(get_omega_inv(prev_bits))
        fold_factor = 1 << (prev_bits - current_bits)

        # Convert siblings to FF3 coefficients (interpolation)
        coeffs = [FF3.Vector([s[2], s[1], s[0]]) for s in siblings]
        if fold_factor > 1:
            coeffs = to_coefficients_cubic(coeffs, fold_factor)

        # Compute evaluation point: challenge * (shift * w^(-idx))^(-1)
        eval_point = challenge_ff3 * int((shift_pow * (w_inv ** (-idx))) ** -1)

        return galois.Poly(coeffs[::-1], field=FF3)(eval_point) if coeffs else FF3(0)

    @staticmethod
    def prove_queries(
        queries: list[int],
        trees: list[MerkleTree],
        current_bits: int,
    ) -> list[list[int]]:
        """Generate Merkle proofs for query indices."""
        return [
            [tree.get_group_proof(q % (1 << current_bits)) for tree in trees]
            for q in queries
        ]

    # --- Internal ---
    # (All implementation details moved to primitives/polynomial.py)
