"""Number Theoretic Transform for Goldilocks field.

Faithful translation from pil2-stark/src/goldilocks/src/ntt_goldilocks.hpp/cpp

This module provides NTT (Number Theoretic Transform) operations for polynomials
over the Goldilocks field, including forward/inverse transforms and polynomial extension.
"""

import numpy as np
from typing import Optional
import galois
from primitives.field import FF, SHIFT, SHIFT_INV, get_omega, get_omega_inv, GOLDILOCKS_PRIME


# C++: pil2-stark/src/goldilocks/src/ntt_goldilocks.hpp::NTT_Goldilocks
class NTT:
    """Number Theoretic Transform for Goldilocks field.

    Provides NTT/INTT operations and polynomial extension for STARK proofs.

    Source: pil2-stark/src/goldilocks/src/ntt_goldilocks.hpp
    """

    # C++: NTT_Goldilocks::NTT_Goldilocks (ntt_goldilocks.cpp lines 66-162)
    def __init__(self, domain_size: int, extension: int = 1):
        """Initialize NTT engine for given domain size.

        Args:
            domain_size: Size of the NTT domain (must be power of 2)
            extension: Extension factor for LDE optimization (default 1)

        Source: NTT_Goldilocks::NTT_Goldilocks constructor (lines 66-162)
        """
        assert domain_size > 0, "Domain size must be positive"
        assert (domain_size & (domain_size - 1)) == 0, "Domain size must be power of 2"

        self.n = domain_size
        self.n_bits = self._log2(domain_size)
        self.extension = extension

        # Precompute twiddle factors (roots of unity)
        # C++: roots[k] = w^k where w is primitive 2^n_bits-th root of unity
        omega = get_omega(self.n_bits)
        self.roots = self._precompute_roots(omega, domain_size)

        # Precompute powers of 2^(-1) mod p
        # C++: powTwoInv[i] = 2^(-i) mod p
        self.pow_two_inv = self._precompute_pow_two_inv(self.n_bits)

        # r and r_ arrays for coset shifting (computed lazily)
        # C++: r[i] = SHIFT^i, r_[i] = r[i] * powTwoInv[domainPow]
        self.r: Optional[np.ndarray] = None
        self.r_: Optional[np.ndarray] = None

    # C++: No direct equivalent (inline in C++)
    @staticmethod
    def _log2(size: int) -> int:
        """Compute log2 of size (must be power of 2).

        Source: NTT_Goldilocks::log2 (lines 26-38)
        """
        assert size != 0
        res = 0
        while size != 1:
            size >>= 1
            res += 1
        return res

    # C++: NTT_Goldilocks constructor (precomputes roots, lines 66-162)
    def _precompute_roots(self, omega: int, n_roots: int) -> np.ndarray:
        """Precompute roots of unity: roots[k] = omega^k.

        Source: Constructor lines 144-150
        """
        # Create array in Goldilocks field
        roots = FF.Zeros(n_roots)
        roots[0] = FF(1)
        if n_roots > 1:
            omega_ff = FF(omega)
            for i in range(1, n_roots):
                roots[i] = roots[i - 1] * omega_ff
        return roots

    # C++: NTT_Goldilocks constructor (precomputes inverses, lines 66-162)
    def _precompute_pow_two_inv(self, max_bits: int) -> np.ndarray:
        """Precompute powers of 2^(-1): pow_two_inv[i] = 2^(-i) mod p.

        Source: Constructor lines 139-156
        """
        pow_two_inv = FF.Zeros(max_bits + 1)
        pow_two_inv[0] = FF(1)
        if max_bits > 0:
            # 2^(-1) mod p
            two_inv = FF(2) ** -1
            for i in range(1, max_bits + 1):
                pow_two_inv[i] = pow_two_inv[i - 1] * two_inv
        return pow_two_inv

    # C++: NTT_Goldilocks::computeR (ntt_goldilocks.cpp lines 48-60)
    def _compute_r(self, N: int) -> None:
        """Compute coset shift arrays r and r_.

        r[i] = SHIFT^i
        r_[i] = SHIFT^i (same as r, galois.intt already normalizes by 1/N)

        Note: C++ NTT computes r_[i] = SHIFT^i * powTwoInv but its INTT
        does NOT normalize. Python galois.intt DOES normalize, so we don't
        need the powTwoInv factor in r_.

        Source: NTT_Goldilocks::computeR (lines 48-60)
        """
        self.r = FF.Zeros(N)
        self.r_ = FF.Zeros(N)

        self.r[0] = FF(1)
        self.r_[0] = FF(1)

        shift_ff = FF(int(SHIFT))
        for i in range(1, N):
            self.r[i] = self.r[i - 1] * shift_ff
            self.r_[i] = self.r[i]  # Same as r since galois.intt normalizes

    # C++: NTT_Goldilocks::NTT (ntt_goldilocks.cpp lines 211-260)
    def ntt(self, coeffs: np.ndarray, n_cols: int = 1) -> np.ndarray:
        """Forward NTT: coefficients → evaluations.

        Args:
            coeffs: Input coefficients (N × n_cols array or flat array)
            n_cols: Number of polynomial columns

        Returns:
            Evaluations in bit-reversed order (same shape as input)

        Source: NTT_Goldilocks::NTT with inverse=False (lines 211-260)
        """
        if coeffs.size == 0:
            return coeffs

        # Track input shape to preserve it in output
        input_is_1d = coeffs.ndim == 1

        # Reshape to (N, n_cols) if needed
        coeffs_2d = self._reshape_input(coeffs, n_cols)
        N = coeffs_2d.shape[0]

        # Use galois library NTT on each column
        omega = int(get_omega(self._log2(N)))
        result = FF.Zeros((N, n_cols))

        for col in range(n_cols):
            # galois.ntt expects omega to be passed
            # Must convert to FF array so galois uses correct field
            coeffs_ff = FF(coeffs_2d[:, col])
            result[:, col] = galois.ntt(coeffs_ff, omega=omega)

        # Preserve input dimensionality
        return result.flatten() if input_is_1d else result

    # C++: NTT_Goldilocks::INTT (ntt_goldilocks.cpp lines 188-191)
    def intt(self, evals: np.ndarray, n_cols: int = 1, extend: bool = False) -> np.ndarray:
        """Inverse NTT: evaluations → coefficients.

        Args:
            evals: Input evaluations (N × n_cols array or flat array)
            n_cols: Number of polynomial columns
            extend: If True, multiply by r_ (coset shift for extension)

        Returns:
            Coefficients (or coset-shifted coefficients if extend=True, same shape as input)

        Source: NTT_Goldilocks::INTT (lines 188-191)
        """
        if evals.size == 0:
            return evals

        # Track input shape to preserve it in output
        input_is_1d = evals.ndim == 1

        # Reshape to (N, n_cols) if needed
        evals_2d = self._reshape_input(evals, n_cols)
        N = evals_2d.shape[0]

        # Compute r_ array if extending and not already computed
        if extend and self.r_ is None:
            self._compute_r(N)

        # Use galois library INTT on each column
        omega_inv = int(get_omega_inv(self._log2(N)))
        result = FF.Zeros((N, n_cols))

        for col in range(n_cols):
            # galois.intt expects omega to be the inverse root
            # Must convert to FF array so galois uses correct field
            evals_ff = FF(evals_2d[:, col])
            coeffs_col = galois.intt(evals_ff, omega=omega_inv)

            if extend:
                # Multiply by r_[i] for coset shifting (LDE optimization)
                # Source: NTT_iters lines 160-172
                for i in range(N):
                    result[i, col] = coeffs_col[i] * self.r_[i]
            else:
                result[:, col] = coeffs_col

        # Preserve input dimensionality
        return result.flatten() if input_is_1d else result

    # C++: NTT_Goldilocks::extendPol (ntt_goldilocks.cpp lines 369-404)
    def extend_pol(self,
                   src: np.ndarray,
                   n_extended: int,
                   n: int,
                   n_cols: int = 1) -> np.ndarray:
        """Extend polynomial from domain N to N_extended.

        Algorithm:
        1. INTT on source (N evaluations → N coefficients) with coset shift
        2. Implicit zero-padding to N_extended
        3. NTT on padded coefficients (N_extended coefficients → N_extended evaluations)

        Args:
            src: Source polynomial evaluations (N × n_cols)
            n_extended: Target extended domain size
            n: Source domain size
            n_cols: Number of polynomial columns

        Returns:
            Extended polynomial evaluations (N_extended × n_cols, same dimensionality as input)

        Source: NTT_Goldilocks::extendPol (lines 369-404)
        """
        if n == 0 or n_cols == 0:
            return src

        assert n_extended >= n, "Extended size must be >= original size"
        assert n_extended % n == 0, "Extended size must be multiple of original size"

        # Track input shape to preserve dimensionality
        input_is_1d = src.ndim == 1

        # Reshape to (N, n_cols) if needed
        src_2d = self._reshape_input(src, n_cols)

        # Create NTT engine for extended domain
        # C++: NTT_Goldilocks ntt_extension(N_Extended, nThreads, N_Extended / N);
        ntt_ext = NTT(n_extended, extension=n_extended // n)

        # Precompute r and r_ for coset shifting
        # C++: if (r == NULL) computeR(N);
        if self.r is None:
            self._compute_r(n)

        # Step 1: INTT with extend=True (multiplies by r_)
        # C++: INTT(output, input, N, ncols, tmp, nphase, nblock, true);
        # Force 2D output for processing
        coeffs = self.intt(src_2d, n_cols=n_cols, extend=True)
        coeffs_2d = self._reshape_input(coeffs, n_cols)

        # Step 2: Zero-pad to extended size (implicit in allocation)
        # Allocate extended output buffer and copy coefficients
        output = FF.Zeros((n_extended, n_cols))
        output[:n, :] = coeffs_2d
        # Remaining coefficients [n:n_extended] are zero (implicit)

        # Step 3: NTT on extended domain
        # C++: ntt_extension.NTT(output, output, N_Extended, ncols, tmp, nphase, nblock);
        # Force 2D processing
        result = ntt_ext.ntt(output, n_cols=n_cols)

        # Preserve input dimensionality
        return result.flatten() if input_is_1d else result

    # C++: No direct equivalent (handled inline in C++)
    def _reshape_input(self, arr: np.ndarray, n_cols: int) -> np.ndarray:
        """Reshape flat or 2D input to (N, n_cols) form."""
        if arr.ndim == 1:
            N = len(arr) // n_cols
            return arr.reshape(N, n_cols)
        elif arr.ndim == 2:
            assert arr.shape[1] == n_cols, f"Column count mismatch: {arr.shape[1]} != {n_cols}"
            return arr
        else:
            raise ValueError(f"Expected 1D or 2D array, got {arr.ndim}D")
