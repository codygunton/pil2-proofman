"""Number Theoretic Transform for Goldilocks field."""


import galois
import numpy as np

from primitives.field import FF, SHIFT, get_omega, get_omega_inv

# --- NTT Engine ---

class NTT:
    """NTT engine for polynomial operations over Goldilocks field."""

    def __init__(self, domain_size: int, extension: int = 1) -> None:
        """Initialize NTT engine for given domain size."""
        assert domain_size > 0, "Domain size must be positive"
        assert (domain_size & (domain_size - 1)) == 0, "Domain size must be power of 2"

        self.n = domain_size
        self.n_bits = _log2(domain_size)
        self.extension = extension

        # Precompute twiddle factors
        omega = get_omega(self.n_bits)
        self.roots = _precompute_roots(omega, domain_size)

        # Precompute powers of 2^(-1) mod p
        self.pow_two_inv = _precompute_pow_two_inv(self.n_bits)

        # Coset shift arrays (computed lazily)
        self.r: np.ndarray | None = None
        self.r_: np.ndarray | None = None

    def _compute_r(self, N: int) -> None:
        """Compute coset shift arrays r and r_.

        Note: r_ equals r since galois.intt already normalizes by 1/N.
        """
        self.r = FF.Zeros(N)
        self.r_= FF.Zeros(N)

        self.r[0] = FF(1)
        self.r_[0] = FF(1)

        shift_ff = FF(int(SHIFT))
        for i in range(1, N):
            self.r[i] = self.r[i - 1] * shift_ff
            self.r_[i] = self.r[i]

    def ntt(self, coeffs: np.ndarray, n_cols: int = 1) -> np.ndarray:
        """Forward NTT: coefficients -> evaluations."""
        if coeffs.size == 0:
            return coeffs

        input_is_1d = coeffs.ndim == 1
        coeffs_2d = _reshape_input(coeffs, n_cols)
        N = coeffs_2d.shape[0]

        omega = int(get_omega(_log2(N)))
        result = FF.Zeros((N, n_cols))

        for col in range(n_cols):
            coeffs_ff = FF(coeffs_2d[:, col])
            result[:, col] = galois.ntt(coeffs_ff, omega=omega)

        return result.flatten() if input_is_1d else result

    def intt(self, evals: np.ndarray, n_cols: int = 1, extend: bool = False) -> np.ndarray:
        """Inverse NTT: evaluations -> coefficients."""
        if evals.size == 0:
            return evals

        input_is_1d = evals.ndim == 1
        evals_2d = _reshape_input(evals, n_cols)
        N = evals_2d.shape[0]

        if extend and self.r_ is None:
            self._compute_r(N)

        omega_inv = int(get_omega_inv(_log2(N)))
        result = FF.Zeros((N, n_cols))

        for col in range(n_cols):
            evals_ff = FF(evals_2d[:, col])
            coeffs_col = galois.intt(evals_ff, omega=omega_inv)

            if extend:
                # Coset shift for LDE
                result[:, col] = coeffs_col * self.r_
            else:
                result[:, col] = coeffs_col

        return result.flatten() if input_is_1d else result

    def extend_pol(
        self,
        src: np.ndarray,
        n_extended: int,
        n: int,
        n_cols: int = 1,
    ) -> np.ndarray:
        """Extend polynomial from domain N to N_extended via zero-padding."""
        if n == 0 or n_cols == 0:
            return src

        assert n_extended >= n, "Extended size must be >= original size"
        assert n_extended % n == 0, "Extended size must be multiple of original size"

        input_is_1d = src.ndim == 1
        src_2d = _reshape_input(src, n_cols)

        ntt_ext = NTT(n_extended, extension=n_extended // n)

        if self.r is None:
            self._compute_r(n)

        # INTT with coset shift
        coeffs = self.intt(src_2d, n_cols=n_cols, extend=True)
        coeffs_2d = _reshape_input(coeffs, n_cols)

        # Zero-pad to extended size
        output = FF.Zeros((n_extended, n_cols))
        output[:n, :] = coeffs_2d

        # NTT on extended domain
        result = ntt_ext.ntt(output, n_cols=n_cols)

        return result.flatten() if input_is_1d else result


# --- Helpers ---

def _log2(size: int) -> int:
    """Compute log2 of size (must be power of 2)."""
    assert size != 0
    res = 0
    while size != 1:
        size >>= 1
        res += 1
    return res


def _precompute_roots(omega: int, n_roots: int) -> np.ndarray:
    """Precompute roots of unity: roots[k] = omega^k."""
    roots = FF.Zeros(n_roots)
    roots[0] = FF(1)
    if n_roots > 1:
        omega_ff = FF(omega)
        for i in range(1, n_roots):
            roots[i] = roots[i - 1] * omega_ff
    return roots


def _precompute_pow_two_inv(max_bits: int) -> np.ndarray:
    """Precompute powers of 2^(-1): pow_two_inv[i] = 2^(-i) mod p."""
    pow_two_inv = FF.Zeros(max_bits + 1)
    pow_two_inv[0] = FF(1)
    if max_bits > 0:
        two_inv = FF(2) ** -1
        for i in range(1, max_bits + 1):
            pow_two_inv[i] = pow_two_inv[i - 1] * two_inv
    return pow_two_inv


def _reshape_input(arr: np.ndarray, n_cols: int) -> np.ndarray:
    """Reshape flat or 2D input to (N, n_cols) form."""
    if arr.ndim == 1:
        N = len(arr) // n_cols
        return arr.reshape(N, n_cols)
    elif arr.ndim == 2:
        assert arr.shape[1] == n_cols, f"Column count mismatch: {arr.shape[1]} != {n_cols}"
        return arr
    else:
        raise ValueError(f"Expected 1D or 2D array, got {arr.ndim}D")
