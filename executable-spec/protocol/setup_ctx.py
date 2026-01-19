"""Setup context with precomputed prover helpers.

Faithful translation from pil2-stark/src/starkpil/setup_ctx.hpp.
Contains ProverHelpers (zerofiers, x powers) and SetupCtx (configuration bundle).

NAMING CONVENTION NOTE:
This module uses Python snake_case naming (e.g., offset_min, n_bits, stark_info).
The C++ source uses camelCase (e.g., offsetMin, nBits, starkInfo).
This follows Python conventions as specified in the translation principles.
The stark_info module (Task #1) should also use snake_case for consistency.
"""

from typing import TYPE_CHECKING, Optional, List
import numpy as np

from primitives.field import FF, FF3, ff3, ff3_coeffs, get_omega, SHIFT, SHIFT_INV

if TYPE_CHECKING:
    from protocol.stark_info import StarkInfo, Boundary
    from protocol.expressions_bin import ExpressionsBin


FIELD_EXTENSION = 3  # Goldilocks3 has 3 components


class ProverHelpers:
    """Precomputed values for constraint evaluation.

    This class computes and stores helper values used during proof generation:
    - zi: Zerofier evaluations (inverse vanishing polynomial values)
    - x: Coset evaluation points (shift * w^i for i in [0, N_ext))
    - x_n: Powers of x at domain size N (for PIL1 compatibility)

    Two modes of initialization:
    1. Prover mode: Computes zi, x, x_n from domain parameters
    2. Verifier mode: Computes zi, x_n from challenge point z
    """

    def __init__(self):
        """Default constructor - creates empty helpers."""
        self.zi: Optional[np.ndarray] = None
        self.x: Optional[np.ndarray] = None
        self.x_n: Optional[np.ndarray] = None

    @classmethod
    def from_stark_info(cls, stark_info: 'StarkInfo', pil1: bool = False) -> 'ProverHelpers':
        """Initialize prover helpers from StarkInfo.

        Args:
            stark_info: STARK configuration containing domain size and boundaries
            pil1: If True, compute x_n for PIL1 compatibility

        Returns:
            ProverHelpers with precomputed zi, x, and optionally x_n
        """
        helpers = cls()
        n_bits = stark_info.starkStruct.nBits
        n_bits_ext = stark_info.starkStruct.nBitsExt
        boundaries = stark_info.boundaries

        helpers.compute_x(n_bits, n_bits_ext, pil1)
        helpers.compute_zerofier(n_bits, n_bits_ext, boundaries)

        return helpers

    @classmethod
    def from_challenge(cls, stark_info: 'StarkInfo', z: np.ndarray) -> 'ProverHelpers':
        """Initialize verifier helpers from evaluation challenge.

        Used by the verifier to compute zerofier values at the challenge point z.

        Args:
            stark_info: STARK configuration
            z: Challenge point (3 elements for Goldilocks3)

        Returns:
            ProverHelpers with zi and x_n computed at challenge point
        """
        helpers = cls()
        n_bits = stark_info.starkStruct.nBits
        boundaries = stark_info.boundaries

        # Allocate zi for all boundaries
        helpers.zi = np.zeros(len(boundaries) * FIELD_EXTENSION, dtype=np.uint64)

        # Convert z to FF3
        z_ff3 = ff3([int(z[0]), int(z[1]), int(z[2])])

        # Compute x^N (z^N)
        one_ff3 = ff3([1, 0, 0])
        x_n_ff3 = one_ff3
        N = 1 << n_bits
        for _ in range(N):
            x_n_ff3 = x_n_ff3 * z_ff3

        # Compute z^N - 1
        z_n_minus_one = x_n_ff3 - one_ff3
        z_n_inv = z_n_minus_one ** -1

        # Store first boundary zerofier (z^N - 1)^(-1)
        zi_coeffs = ff3_coeffs(z_n_inv)
        helpers.zi[0:3] = zi_coeffs

        # Compute other boundary zerofiers
        for i in range(1, len(boundaries)):
            boundary = boundaries[i]

            if boundary.name == "firstRow":
                # zi = (z - 1)^(-1) * (z^N - 1)
                zi_temp = (z_ff3 - one_ff3) ** -1
                zi_temp = zi_temp * z_n_minus_one
                zi_coeffs = ff3_coeffs(zi_temp)
                helpers.zi[i*FIELD_EXTENSION:(i+1)*FIELD_EXTENSION] = zi_coeffs

            elif boundary.name == "lastRow":
                # Compute w^(N-1) where w is the N-th root of unity
                w = FF(get_omega(n_bits))
                root = FF(1)
                for _ in range(N - 1):
                    root = root * w

                # zi = (z - w^(N-1))^(-1) * (z^N - 1)
                root_ff3 = ff3([int(root), 0, 0])
                zi_temp = (z_ff3 - root_ff3) ** -1
                zi_temp = zi_temp * z_n_minus_one
                zi_coeffs = ff3_coeffs(zi_temp)
                helpers.zi[i*FIELD_EXTENSION:(i+1)*FIELD_EXTENSION] = zi_coeffs

            elif boundary.name == "everyRow":
                # Product over multiple roots
                n_roots = boundary.offsetMin + boundary.offsetMax
                w = FF(get_omega(n_bits))

                zi_temp = one_ff3

                # Roots at the beginning [0, offsetMin)
                for k in range(boundary.offsetMin):
                    root = FF(1)
                    for _ in range(k):
                        root = root * w
                    root_ff3 = ff3([int(root), 0, 0])
                    zi_temp = zi_temp * (z_ff3 - root_ff3)

                # Roots at the end [N - offsetMax, N)
                for k in range(boundary.offsetMax):
                    root = FF(1)
                    for _ in range(N - k - 1):
                        root = root * w
                    root_ff3 = ff3([int(root), 0, 0])
                    zi_temp = zi_temp * (z_ff3 - root_ff3)

                zi_coeffs = ff3_coeffs(zi_temp)
                helpers.zi[i*FIELD_EXTENSION:(i+1)*FIELD_EXTENSION] = zi_coeffs

        # Store x_n = z
        helpers.x_n = np.array([z[0], z[1], z[2]], dtype=np.uint64)

        return helpers

    def compute_x(self, n_bits: int, n_bits_ext: int, pil1: bool):
        """Compute coset evaluation points x = shift * w^i.

        Args:
            n_bits: Log2 of original domain size N
            n_bits_ext: Log2 of extended domain size N_ext
            pil1: If True, also compute x_n for original domain
        """
        N_extended = 1 << n_bits_ext
        N = 1 << n_bits

        self.x = np.zeros(N_extended, dtype=np.uint64)
        if pil1:
            self.x_n = np.zeros(N, dtype=np.uint64)

        w_ext = FF(get_omega(n_bits_ext))
        w_n = FF(get_omega(n_bits))
        shift = SHIFT

        # Compute in blocks of 4096 to preserve C++ structure
        # (C++ uses this for cache efficiency with OpenMP)
        for k in range(0, N_extended, 4096):
            # Compute starting values
            if pil1 and k < N:
                self.x_n[k] = int(w_n ** k)

            self.x[k] = int(shift * (w_ext ** k))

            # Compute subsequent values incrementally
            # Note: Must convert numpy uint64 to Python int before creating FF,
            # as galois library has issues with numpy integer types in multiplication
            end = min(k + 4096, N_extended)
            for j in range(k + 1, end):
                if pil1 and j < N:
                    self.x_n[j] = int(FF(int(self.x_n[j-1])) * w_n)
                self.x[j] = int(FF(int(self.x[j-1])) * w_ext)

    def compute_zerofier(self, n_bits: int, n_bits_ext: int, boundaries: List['Boundary']):
        """Compute zerofier inverse values for all boundaries.

        The zerofier is the vanishing polynomial for the boundary constraints.
        This method computes 1/Z_H(x) for various boundary types.

        Args:
            n_bits: Log2 of original domain size N
            n_bits_ext: Log2 of extended domain size N_ext
            boundaries: List of boundary constraint specifications
        """
        N = 1 << n_bits
        N_extended = 1 << n_bits_ext

        # Allocate storage for all boundary zerofiers
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
        """Build inverse zerofier for all rows: 1/(x^N - 1).

        This is the standard vanishing polynomial for the full execution trace.
        Always writes to the beginning of zi array (zi[0:N_extended]).

        Args:
            n_bits: Log2 of original domain size N
            n_bits_ext: Log2 of extended domain size N_ext
        """
        N_extended = 1 << n_bits_ext
        extend_bits = n_bits_ext - n_bits
        extend = 1 << extend_bits

        # Compute shift^N
        shift_n = SHIFT ** (1 << n_bits)

        w_ext = FF(get_omega(extend_bits))
        w = FF(1)

        # Compute zi[0:extend] = 1 / (shift^N * w^i - 1)
        for i in range(extend):
            self.zi[i] = int((shift_n * w - FF(1)) ** -1)
            w = w * w_ext

        # Repeat pattern across full extended domain (exploits periodicity)
        for i in range(extend, N_extended):
            self.zi[i] = self.zi[i % extend]

    def build_one_row_zerofier_inv(self, n_bits: int, n_bits_ext: int,
                                   offset: int, row_index: int):
        """Build inverse zerofier for a single row: 1/((x - root) * Z_H(x)).

        Used for constraints that apply only at a specific row.
        Reads Z_H inverse from zi[0:N_extended] (computed by build_zh_inv).

        Args:
            n_bits: Log2 of original domain size N
            n_bits_ext: Log2 of extended domain size N_ext
            offset: Boundary index in zi array (writes to offset*N_extended)
            row_index: Index of the constrained row (0 for first, N for last)
        """
        N_extended = 1 << n_bits_ext
        w = FF(get_omega(n_bits))

        # Compute root = w^row_index
        root = FF(1)
        for _ in range(row_index):
            root = root * w

        # zi[offset*N_ext + i] = 1 / ((x[i] - root) * zi[i])
        # Note: zi[i] contains Z_H(x[i])^(-1) from build_zh_inv (everyRow)
        # Note: Must convert numpy uint64 to Python int before creating FF
        for i in range(N_extended):
            x_i = FF(int(self.x[i]))
            zh_inv = FF(int(self.zi[i]))  # Read from offset 0 (everyRow boundary)
            self.zi[offset * N_extended + i] = int(((x_i - root) * zh_inv) ** -1)

    def build_frame_zerofier_inv(self, n_bits: int, n_bits_ext: int, offset: int,
                                 offset_min: int, offset_max: int):
        """Build zerofier for frame boundaries (not inverted in C++ version).

        Frame boundaries constrain specific rows at the start and end of the trace.
        Unlike other zerofiers, this computes Z(x) rather than 1/Z(x).

        Args:
            n_bits: Log2 of original domain size N
            n_bits_ext: Log2 of extended domain size N_ext
            offset: Boundary index in zi array
            offset_min: Number of constrained rows at start
            offset_max: Number of constrained rows at end
        """
        N = 1 << n_bits
        N_extended = 1 << n_bits_ext
        n_roots = offset_min + offset_max

        w = FF(get_omega(n_bits))

        # Compute roots at the beginning [0, offset_min)
        roots_begin = []
        for i in range(offset_min):
            root = FF(1)
            for _ in range(i):
                root = root * w
            roots_begin.append(root)

        # Compute roots at the end [N - offset_max, N)
        roots_end = []
        for i in range(offset_max):
            root = FF(1)
            for _ in range(N - i - 1):
                root = root * w
            roots_end.append(root)

        roots = roots_begin + roots_end

        # Compute product: zi[i] = prod_j (x[i] - roots[j])
        # Note: Must convert numpy uint64 to Python int before creating FF
        for i in range(N_extended):
            x_i = FF(int(self.x[i]))
            zi_val = FF(1)
            for root in roots:
                zi_val = zi_val * (x_i - root)
            self.zi[offset * N_extended + i] = int(zi_val)


class SetupCtx:
    """Setup context combining StarkInfo and helpers.

    This is the main configuration object passed to all prover/verifier functions.
    It bundles together:
    - StarkInfo: STARK configuration (domain sizes, stages, polynomials)
    - ExpressionsBin: Compiled constraint expressions

    Note: ProverHelpers are created separately and not stored here (unlike some
    C++ variants that embed them).
    """

    def __init__(self, stark_info: 'StarkInfo', expressions_bin: 'ExpressionsBin'):
        """Initialize setup context.

        Args:
            stark_info: STARK configuration
            expressions_bin: Compiled expression database
        """
        self.stark_info = stark_info
        self.expressions_bin = expressions_bin

    @classmethod
    def from_files(cls, starkinfo_path: str, expressions_bin_path: str) -> 'SetupCtx':
        """Load setup context from files.

        Args:
            starkinfo_path: Path to starkinfo.json
            expressions_bin_path: Path to expressions.bin

        Returns:
            Initialized SetupCtx
        """
        # Import here to avoid circular dependency
        from protocol.stark_info import StarkInfo
        from protocol.expressions_bin import ExpressionsBin

        stark_info = StarkInfo.from_json(starkinfo_path)
        expressions_bin = ExpressionsBin.from_file(expressions_bin_path)

        return cls(stark_info, expressions_bin)
