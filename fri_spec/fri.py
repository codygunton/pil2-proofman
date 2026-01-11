"""
FRI (Fast Reed-Solomon Interactive Oracle Proof of Proximity) core algorithms.

This module implements the core FRI folding and query algorithms.

C++ Reference: pil2-stark/src/starkpil/fri/fri.hpp
"""

from typing import List, Tuple, Optional
import math
from .field import GF, GF3, GOLDILOCKS_PRIME, ntt, intt, get_root_of_unity
from .merkle_tree import MerkleTree, HASH_SIZE


# Field extension degree (cubic)
FIELD_EXTENSION = 3


def _pow_mod(base: int, exp: int, mod: int = GOLDILOCKS_PRIME) -> int:
    """Modular exponentiation."""
    result = 1
    base = base % mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        exp >>= 1
        base = (base * base) % mod
    return result


def _inv_mod(x: int, mod: int = GOLDILOCKS_PRIME) -> int:
    """Modular inverse using Fermat's little theorem."""
    return _pow_mod(x, mod - 2, mod)


def _get_shift() -> int:
    """
    Get the shift constant (generator) for the Goldilocks field.

    This is the multiplicative generator used to shift the evaluation domain.

    C++ Reference: Goldilocks::shift()
    """
    # The shift is typically a small generator, using 7 as in many implementations
    return 7


# Precomputed roots of unity from C++ goldilocks_base_field.cpp
# W[i] is the primitive 2^i-th root of unity
_W = [
    1,                        # W[0]  = 1
    18446744069414584320,     # W[1]  = -1
    281474976710656,          # W[2]
    16777216,                 # W[3]
    4096,                     # W[4]
    64,                       # W[5]
    8,                        # W[6]
    2198989700608,            # W[7]
    4404853092538523347,      # W[8]
    6434636298004421797,      # W[9]
    4255134452441852017,      # W[10]
    9113133275150391358,      # W[11]
    4355325209153869931,      # W[12]
    4308460244895131701,      # W[13]
    7126024226993609386,      # W[14]
    1873558160482552414,      # W[15]
    8167150655112846419,      # W[16]
    5718075921287398682,      # W[17]
    3411401055030829696,      # W[18]
    8982441859486529725,      # W[19]
    1971462654193939361,      # W[20]
    6553637399136210105,      # W[21]
    8124823329697072476,      # W[22]
    5936499541590631774,      # W[23]
    2709866199236980323,      # W[24]
    8877499657461974390,      # W[25]
    3757607247483852735,      # W[26]
    4969973714567017225,      # W[27]
    2147253751702802259,      # W[28]
    2530564950562219707,      # W[29]
    1905180297017055339,      # W[30]
    3524815499551269279,      # W[31]
    7277203076849721926,      # W[32]
]


def _get_omega(n_bits: int) -> int:
    """
    Get primitive 2^n_bits-th root of unity.

    C++ Reference: Goldilocks::w(n_bits)

    Uses precomputed values matching the C++ implementation exactly.
    """
    if n_bits < 0 or n_bits >= len(_W):
        raise ValueError(f"n_bits must be in [0, {len(_W)-1}], got {n_bits}")
    return _W[n_bits]


def _mul_cubic(a: List[int], b: List[int]) -> List[int]:
    """
    Multiply two cubic extension field elements.

    Elements are represented as [a0, a1, a2] where the value is a0 + a1*x + a2*x^2
    and x^3 = x + 1 (irreducible polynomial).

    C++ Reference: Goldilocks3::mul
    """
    p = GOLDILOCKS_PRIME

    # Standard polynomial multiplication
    c0 = (a[0] * b[0]) % p
    c1 = (a[0] * b[1] + a[1] * b[0]) % p
    c2 = (a[0] * b[2] + a[1] * b[1] + a[2] * b[0]) % p
    c3 = (a[1] * b[2] + a[2] * b[1]) % p
    c4 = (a[2] * b[2]) % p

    # Reduce by x^3 = x + 1
    # c3*x^3 = c3*x + c3
    # c4*x^4 = c4*x^2 + c4*x
    r0 = (c0 + c3) % p
    r1 = (c1 + c3 + c4) % p
    r2 = (c2 + c4) % p

    return [r0, r1, r2]


def _add_cubic(a: List[int], b: List[int]) -> List[int]:
    """Add two cubic extension field elements."""
    p = GOLDILOCKS_PRIME
    return [(a[i] + b[i]) % p for i in range(3)]


def _scalar_mul_cubic(a: List[int], s: int) -> List[int]:
    """Multiply cubic extension element by scalar."""
    p = GOLDILOCKS_PRIME
    return [(a[i] * s) % p for i in range(3)]


class FRI:
    """
    FRI protocol implementation.

    This class provides static methods for FRI folding, merkleization,
    and query operations.
    """

    @staticmethod
    def fold(
        step: int,
        pol: List[int],
        challenge: List[int],
        n_bits_ext: int,
        prev_bits: int,
        current_bits: int
    ) -> List[int]:
        """
        Fold polynomial using random challenge.

        This reduces the polynomial size by combining evaluation points
        using the random challenge.

        Args:
            step: FRI step index (0 for first fold)
            pol: Polynomial in evaluation form (FIELD_EXTENSION elements per point)
            challenge: 3-element cubic extension challenge
            n_bits_ext: Original extended domain bits
            prev_bits: Previous step domain bits
            current_bits: Current step domain bits

        Returns:
            Folded polynomial (smaller by factor of 2^(prev_bits - current_bits))

        C++ Reference: FRI::fold
        """
        p = GOLDILOCKS_PRIME

        # Calculate shift inverse
        shift = _get_shift()
        shift_inv = _inv_mod(shift)

        # For step > 0, square shift_inv (n_bits_ext - prev_bits) times
        pol_shift_inv = shift_inv
        if step > 0:
            for _ in range(n_bits_ext - prev_bits):
                pol_shift_inv = (pol_shift_inv * pol_shift_inv) % p

        # Folding parameters
        pol_2n = 1 << current_bits  # Target domain size
        n_x = (1 << prev_bits) // pol_2n  # Folding ratio

        # Root of unity inverse
        w_inv = _inv_mod(_get_omega(prev_bits))

        # Prepare output
        result = [0] * (pol_2n * FIELD_EXTENSION)

        # Fold each group
        for g in range(pol_2n):
            # Extract n_x consecutive values (each is FIELD_EXTENSION elements)
            coeffs = []
            for i in range(n_x):
                idx = (g + i * pol_2n) * FIELD_EXTENSION
                coeffs.append([pol[idx], pol[idx + 1], pol[idx + 2]])

            # Apply INTT to convert to coefficients
            # For simplicity, we do a direct INTT implementation for small n_x
            if n_x > 1:
                # The small INTT needs omega for its own size, not the main domain
                n_x_bits = int(math.log2(n_x))
                w_inv_small = _inv_mod(_get_omega(n_x_bits))
                coeffs = FRI._intt_small(coeffs, n_x, w_inv_small)

            # Apply polMulAxi: multiply coefficient i by (shift_inv * w_inv^g)^i
            sinv = (pol_shift_inv * _pow_mod(w_inv, g, p)) % p
            acc = 1
            for i in range(n_x):
                coeffs[i] = _scalar_mul_cubic(coeffs[i], acc)
                acc = (acc * sinv) % p

            # Evaluate at challenge point using Horner's method
            res = coeffs[n_x - 1] if n_x > 0 else [0, 0, 0]
            for i in range(n_x - 2, -1, -1):
                res = _mul_cubic(res, challenge)
                res = _add_cubic(res, coeffs[i])

            # Store result
            result[g * FIELD_EXTENSION] = res[0]
            result[g * FIELD_EXTENSION + 1] = res[1]
            result[g * FIELD_EXTENSION + 2] = res[2]

        return result

    @staticmethod
    def _intt_small(values: List[List[int]], n: int, w_inv: int) -> List[List[int]]:
        """
        Small INTT for folding (works on cubic extension elements).

        This is a simplified INTT for small sizes used during folding.
        """
        p = GOLDILOCKS_PRIME

        # Bit-reversal permutation
        result = list(values)
        log_n = int(math.log2(n))

        for i in range(n):
            j = int('{:0{width}b}'.format(i, width=log_n)[::-1], 2)
            if i < j:
                result[i], result[j] = result[j], result[i]

        # Cooley-Tukey INTT
        m = 2
        while m <= n:
            wm = _pow_mod(w_inv, n // m, p)
            for k in range(0, n, m):
                w = 1
                for j in range(m // 2):
                    t = _scalar_mul_cubic(result[k + j + m // 2], w)
                    u = result[k + j]
                    result[k + j] = _add_cubic(u, t)
                    result[k + j + m // 2] = [
                        (u[0] - t[0]) % p,
                        (u[1] - t[1]) % p,
                        (u[2] - t[2]) % p
                    ]
                    w = (w * wm) % p
            m *= 2

        # Scale by 1/n
        n_inv = _inv_mod(n)
        for i in range(n):
            result[i] = _scalar_mul_cubic(result[i], n_inv)

        return result

    @staticmethod
    def merkelize(
        step: int,
        pol: List[int],
        tree: MerkleTree,
        current_bits: int,
        next_bits: int
    ) -> List[int]:
        """
        Build Merkle tree for FRI step polynomial.

        Args:
            step: FRI step index
            pol: Polynomial data
            tree: Merkle tree to populate
            current_bits: Current domain bits
            next_bits: Next domain bits (for transpose)

        Returns:
            Merkle root

        C++ Reference: FRI::merkelize
        """
        # Transpose polynomial for Merkle tree
        # C++ passes nextBits directly to getTransposed (not currentBits - nextBits)
        transposed = FRI.get_transposed(pol, 1 << current_bits, next_bits)

        # Build tree
        # After transpose: w = 1 << next_bits groups, h = (1 << current_bits) / w elements per group
        # Tree has w leaves (height), each with h * FIELD_EXTENSION values (width)
        height = 1 << next_bits  # number of leaves
        width = (1 << (current_bits - next_bits)) * FIELD_EXTENSION  # values per leaf
        tree.merkelize(transposed, height, width)

        return tree.get_root()

    @staticmethod
    def get_transposed(
        pol: List[int],
        degree: int,
        transpose_bits: int
    ) -> List[int]:
        """
        Transpose polynomial data for Merkle tree.

        C++ Reference: FRI::getTransposed
        """
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
    def prove_queries(
        queries: List[int],
        trees: List[MerkleTree],
        current_bits: int
    ) -> List[List[int]]:
        """
        Generate Merkle proofs for query indices.

        Args:
            queries: List of query indices
            trees: List of Merkle trees
            current_bits: Current domain bits

        Returns:
            List of proofs for each query

        C++ Reference: FRI::proveQueries
        """
        proofs = []
        for query_idx in queries:
            idx = query_idx % (1 << current_bits)
            tree_proofs = []
            for tree in trees:
                proof = tree.get_group_proof(idx)
                tree_proofs.append(proof)
            proofs.append(tree_proofs)
        return proofs

    @staticmethod
    def eval_pol(pol: List[List[int]], degree: int, x: List[int]) -> List[int]:
        """
        Evaluate polynomial at point using Horner's method.

        Args:
            pol: Polynomial coefficients (cubic extension elements)
            degree: Polynomial degree
            x: Evaluation point (cubic extension element)

        Returns:
            Result (cubic extension element)

        C++ Reference: FRI::evalPol
        """
        if degree == 0:
            return [0, 0, 0]

        result = list(pol[degree - 1])
        for i in range(degree - 2, -1, -1):
            result = _mul_cubic(result, x)
            result = _add_cubic(result, pol[i])

        return result

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
        """
        Verify a fold step (used by verifier).

        Args:
            value: Expected folded value
            step: FRI step index
            n_bits_ext: Extended domain bits
            current_bits: Current domain bits
            prev_bits: Previous domain bits
            challenge: Fold challenge
            idx: Query index
            siblings: Sibling values from proof

        Returns:
            Computed folded value

        C++ Reference: FRI::verify_fold
        """
        p = GOLDILOCKS_PRIME

        # Calculate shift
        shift = _get_shift()
        if step > 0:
            for _ in range(n_bits_ext - prev_bits):
                shift = (shift * shift) % p

        # Get omega for previous level
        w = _get_omega(prev_bits)

        # Reconstruct coefficients from siblings
        n_x = 1 << (prev_bits - current_bits)
        coeffs = list(siblings)

        # Apply INTT
        w_inv = _inv_mod(w)
        if n_x > 1:
            coeffs = FRI._intt_small(coeffs, n_x, w_inv)

        # Calculate shift inverse and omega power
        sinv = _inv_mod((shift * _pow_mod(w, idx, p)) % p)

        # Compute evaluation point
        aux = _mul_cubic(challenge, [sinv, 0, 0])

        # Evaluate polynomial at aux
        result = FRI.eval_pol(coeffs, n_x, aux)

        return result
