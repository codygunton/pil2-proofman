"""Setup context and precomputed prover helpers."""

from typing import TYPE_CHECKING, Optional, List
import numpy as np

from primitives.field import FF, ff3, ff3_coeffs, get_omega, SHIFT

if TYPE_CHECKING:
    from protocol.stark_info import StarkInfo, Boundary
    from protocol.expressions_bin import ExpressionsBin


FIELD_EXTENSION = 3  # Goldilocks cubic extension


# --- Prover Helpers ---

class ProverHelpers:
    """Precomputed zerofiers and evaluation points.

    - zi: Zerofier evaluations 1/Z_H(x) for each boundary
    - x: Coset points shift * w^i for i in [0, N_ext)
    - x_n: Powers of x for PIL1 compatibility
    """

    def __init__(self):
        self.zi: Optional[np.ndarray] = None
        self.x: Optional[np.ndarray] = None
        self.x_n: Optional[np.ndarray] = None

    @classmethod
    def from_stark_info(cls, stark_info: 'StarkInfo', pil1: bool = False) -> 'ProverHelpers':
        """Initialize from StarkInfo for prover mode."""
        helpers = cls()
        n_bits = stark_info.starkStruct.nBits
        n_bits_ext = stark_info.starkStruct.nBitsExt
        boundaries = stark_info.boundaries

        helpers.compute_x(n_bits, n_bits_ext, pil1)
        helpers.compute_zerofier(n_bits, n_bits_ext, boundaries)

        return helpers

    @classmethod
    def from_challenge(cls, stark_info: 'StarkInfo', z: np.ndarray) -> 'ProverHelpers':
        """Initialize from challenge point z for verifier mode."""
        helpers = cls()
        n_bits = stark_info.starkStruct.nBits
        boundaries = stark_info.boundaries
        N = 1 << n_bits

        helpers.zi = np.zeros(len(boundaries) * FIELD_EXTENSION, dtype=np.uint64)

        z_ff3 = ff3([int(z[0]), int(z[1]), int(z[2])])
        one_ff3 = ff3([1, 0, 0])

        # z^N
        x_n_ff3 = one_ff3
        for _ in range(N):
            x_n_ff3 = x_n_ff3 * z_ff3

        # Z_H(z) = z^N - 1
        z_n_minus_one = x_n_ff3 - one_ff3
        z_n_inv = z_n_minus_one ** -1

        # First boundary: 1/(z^N - 1)
        helpers.zi[0:3] = ff3_coeffs(z_n_inv)

        # Other boundary zerofiers
        for i in range(1, len(boundaries)):
            boundary = boundaries[i]

            if boundary.name == "firstRow":
                # (z - 1)^(-1) * (z^N - 1)
                zi_temp = (z_ff3 - one_ff3) ** -1 * z_n_minus_one
                helpers.zi[i*FIELD_EXTENSION:(i+1)*FIELD_EXTENSION] = ff3_coeffs(zi_temp)

            elif boundary.name == "lastRow":
                # (z - w^(N-1))^(-1) * (z^N - 1)
                w = FF(get_omega(n_bits))
                root = w ** (N - 1)
                root_ff3 = ff3([int(root), 0, 0])
                zi_temp = (z_ff3 - root_ff3) ** -1 * z_n_minus_one
                helpers.zi[i*FIELD_EXTENSION:(i+1)*FIELD_EXTENSION] = ff3_coeffs(zi_temp)

            elif boundary.name == "everyRow":
                # Product of (z - w^k) for excluded rows
                w = FF(get_omega(n_bits))
                zi_temp = one_ff3

                # Rows [0, offsetMin)
                for k in range(boundary.offsetMin):
                    root_ff3 = ff3([int(w ** k), 0, 0])
                    zi_temp = zi_temp * (z_ff3 - root_ff3)

                # Rows [N - offsetMax, N)
                for k in range(boundary.offsetMax):
                    root_ff3 = ff3([int(w ** (N - k - 1)), 0, 0])
                    zi_temp = zi_temp * (z_ff3 - root_ff3)

                helpers.zi[i*FIELD_EXTENSION:(i+1)*FIELD_EXTENSION] = ff3_coeffs(zi_temp)

        helpers.x_n = np.array([z[0], z[1], z[2]], dtype=np.uint64)
        return helpers

    def compute_x(self, n_bits: int, n_bits_ext: int, pil1: bool):
        """Compute coset points x[i] = shift * w^i."""
        N_extended = 1 << n_bits_ext
        N = 1 << n_bits

        self.x = np.zeros(N_extended, dtype=np.uint64)
        if pil1:
            self.x_n = np.zeros(N, dtype=np.uint64)

        w_ext = FF(get_omega(n_bits_ext))
        w_n = FF(get_omega(n_bits))
        shift = SHIFT

        # Process in blocks of 4096 (matches C++ cache-friendly layout)
        for k in range(0, N_extended, 4096):
            if pil1 and k < N:
                self.x_n[k] = int(w_n ** k)
            self.x[k] = int(shift * (w_ext ** k))

            # Incremental within block (galois needs Python int, not numpy uint64)
            end = min(k + 4096, N_extended)
            for j in range(k + 1, end):
                if pil1 and j < N:
                    self.x_n[j] = int(FF(int(self.x_n[j-1])) * w_n)
                self.x[j] = int(FF(int(self.x[j-1])) * w_ext)

    def compute_zerofier(self, n_bits: int, n_bits_ext: int, boundaries: List['Boundary']):
        """Compute zerofier inverses 1/Z_H(x) for all boundaries."""
        N = 1 << n_bits
        N_extended = 1 << n_bits_ext

        self.zi = np.zeros(len(boundaries) * N_extended, dtype=np.uint64)

        for i, boundary in enumerate(boundaries):
            if boundary.name == "everyRow":
                self.build_zh_inv(n_bits, n_bits_ext)
            elif boundary.name == "firstRow":
                self.build_one_row_zerofier_inv(n_bits, n_bits_ext, i, 0)
            elif boundary.name == "lastRow":
                self.build_one_row_zerofier_inv(n_bits, n_bits_ext, i, N)
            elif boundary.name == "everyFrame":
                self.build_frame_zerofier_inv(n_bits, n_bits_ext, i,
                                              boundary.offsetMin, boundary.offsetMax)

    def build_zh_inv(self, n_bits: int, n_bits_ext: int):
        """Build 1/(x^N - 1) for all coset points. Writes to zi[0:N_ext]."""
        N_extended = 1 << n_bits_ext
        extend_bits = n_bits_ext - n_bits
        extend = 1 << extend_bits

        shift_n = SHIFT ** (1 << n_bits)
        w_ext = FF(get_omega(extend_bits))

        # Compute unique values: zi[i] = 1/(shift^N * w^i - 1)
        w = FF(1)
        for i in range(extend):
            self.zi[i] = int((shift_n * w - FF(1)) ** -1)
            w = w * w_ext

        # Repeat pattern (exploits periodicity of x^N on extended domain)
        for i in range(extend, N_extended):
            self.zi[i] = self.zi[i % extend]

    def build_one_row_zerofier_inv(self, n_bits: int, n_bits_ext: int,
                                   offset: int, row_index: int):
        """Build 1/((x - w^row) * Z_H(x)). Reads Z_H^(-1) from zi[0:N_ext]."""
        N_extended = 1 << n_bits_ext
        w = FF(get_omega(n_bits))
        root = w ** row_index

        for i in range(N_extended):
            x_i = FF(int(self.x[i]))
            zh_inv = FF(int(self.zi[i]))
            self.zi[offset * N_extended + i] = int(((x_i - root) * zh_inv) ** -1)

    def build_frame_zerofier_inv(self, n_bits: int, n_bits_ext: int, offset: int,
                                 offset_min: int, offset_max: int):
        """Build frame zerofier (NOT inverted): product of (x - w^k) for excluded rows."""
        N = 1 << n_bits
        N_extended = 1 << n_bits_ext
        w = FF(get_omega(n_bits))

        # Excluded roots: [0, offset_min) and [N - offset_max, N)
        roots = [w ** k for k in range(offset_min)]
        roots += [w ** (N - k - 1) for k in range(offset_max)]

        for i in range(N_extended):
            x_i = FF(int(self.x[i]))
            zi_val = FF(1)
            for root in roots:
                zi_val = zi_val * (x_i - root)
            self.zi[offset * N_extended + i] = int(zi_val)


# --- Setup Context ---

class SetupCtx:
    """Configuration bundle: StarkInfo + ExpressionsBin."""

    def __init__(self, stark_info: 'StarkInfo', expressions_bin: 'ExpressionsBin'):
        self.stark_info = stark_info
        self.expressions_bin = expressions_bin

    @classmethod
    def from_files(cls, starkinfo_path: str, expressions_bin_path: str) -> 'SetupCtx':
        """Load from starkinfo.json and expressions.bin files."""
        from protocol.stark_info import StarkInfo
        from protocol.expressions_bin import ExpressionsBin

        stark_info = StarkInfo.from_json(starkinfo_path)
        expressions_bin = ExpressionsBin.from_file(expressions_bin_path)

        return cls(stark_info, expressions_bin)
