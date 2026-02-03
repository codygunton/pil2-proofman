"""AIR configuration and precomputed prover data.

This module provides the configuration bundle for STARK proving/verification:

- AirConfig: Bundles StarkInfo (AIR specification) and optional GlobalInfo
  (cross-AIR coordination).
- ProverHelpers: Precomputed zerofiers and evaluation points needed by both
  prover and verifier for constraint evaluation.

The 'AIR' (Algebraic Intermediate Representation) defines the constraint system
that the STARK proves. AirConfig packages everything needed to evaluate those
constraints.

Example:
    config = AirConfig.from_starkinfo("path/to/starkinfo.json")
    proof = gen_proof(config, params)
"""

from typing import TYPE_CHECKING, Optional, List, Union
import numpy as np

from primitives.field import (
    FF, FF3, ff3_to_numpy_coeffs, get_omega, SHIFT, batch_inverse,
    FIELD_EXTENSION_DEGREE,
)

if TYPE_CHECKING:
    from protocol.stark_info import StarkInfo, Boundary
    from protocol.global_info import GlobalInfo


# --- Prover Helpers ---

class ProverHelpers:
    """Precomputed zerofiers and evaluation points for constraint evaluation.

    The prover and verifier both need to evaluate constraints at various points.
    This class precomputes values that would otherwise be redundantly calculated:

    Attributes:
        zi: Zerofier evaluations 1/Z_H(x) for each boundary constraint.
            Z_H(x) = x^N - 1 is the vanishing polynomial on the trace domain.
            Different boundaries (firstRow, lastRow, everyRow) have different
            zerofiers, all stored in this array.
        x: Coset evaluation points shift * w^i for i in [0, N_ext).
            These are the points where polynomials are evaluated on the
            extended domain (coset of the trace domain).
        x_n: Powers of x for PIL1 compatibility (legacy support).

    Usage:
        # For prover: precompute from domain parameters
        helpers = ProverHelpers.from_stark_info(stark_info)

        # For verifier: compute at challenge point z
        helpers = ProverHelpers.from_challenge(stark_info, z)
    """

    def __init__(self):
        self.zi: Optional[Union[FF, np.ndarray]] = None
        self.x: Optional[FF] = None
        self.x_n: Optional[Union[FF, np.ndarray]] = None

    @classmethod
    def from_stark_info(cls, stark_info: 'StarkInfo', pil1: bool = False) -> 'ProverHelpers':
        """Initialize from StarkInfo for prover mode.

        Precomputes zerofiers and evaluation points for the extended domain.

        Args:
            stark_info: AIR specification with domain sizes and boundaries
            pil1: Enable PIL1 compatibility mode (computes x_n powers)

        Returns:
            ProverHelpers with precomputed values for prover
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
        """Initialize from challenge point z for verifier mode.

        Computes zerofiers at the random challenge point z (in extension field).

        Args:
            stark_info: AIR specification with domain sizes and boundaries
            z: Challenge point as numpy array [z0, z1, z2] (FF3 coefficients)

        Returns:
            ProverHelpers with zerofiers computed at challenge point
        """
        helpers = cls()
        n_bits = stark_info.starkStruct.nBits
        boundaries = stark_info.boundaries
        N = 1 << n_bits

        helpers.zi = np.zeros(len(boundaries) * FIELD_EXTENSION_DEGREE, dtype=np.uint64)

        z_ff3 = FF3.Vector([int(z[2]), int(z[1]), int(z[0])])
        one_ff3 = FF3(1)

        # z^N
        x_n_ff3 = one_ff3
        for _ in range(N):
            x_n_ff3 = x_n_ff3 * z_ff3

        # Z_H(z) = z^N - 1
        z_n_minus_one = x_n_ff3 - one_ff3
        z_n_inv = z_n_minus_one ** -1

        # First boundary: 1/(z^N - 1)
        helpers.zi[0:3] = ff3_to_numpy_coeffs(z_n_inv)

        # Other boundary zerofiers
        for i in range(1, len(boundaries)):
            boundary = boundaries[i]

            if boundary.name == "firstRow":
                # (z - 1)^(-1) * (z^N - 1)
                zi_temp = (z_ff3 - one_ff3) ** -1 * z_n_minus_one
                helpers.zi[i*FIELD_EXTENSION_DEGREE:(i+1)*FIELD_EXTENSION_DEGREE] = ff3_to_numpy_coeffs(zi_temp)

            elif boundary.name == "lastRow":
                # (z - w^(N-1))^(-1) * (z^N - 1)
                w = FF(get_omega(n_bits))
                root = w ** (N - 1)
                root_ff3 = FF3(int(root))
                zi_temp = (z_ff3 - root_ff3) ** -1 * z_n_minus_one
                helpers.zi[i*FIELD_EXTENSION_DEGREE:(i+1)*FIELD_EXTENSION_DEGREE] = ff3_to_numpy_coeffs(zi_temp)

            elif boundary.name == "everyRow":
                # Product of (z - w^k) for excluded rows
                w = FF(get_omega(n_bits))
                zi_temp = one_ff3

                # Rows [0, offsetMin)
                for k in range(boundary.offsetMin):
                    root_ff3 = FF3(int(w ** k))
                    zi_temp = zi_temp * (z_ff3 - root_ff3)

                # Rows [N - offsetMax, N)
                for k in range(boundary.offsetMax):
                    root_ff3 = FF3(int(w ** (N - k - 1)))
                    zi_temp = zi_temp * (z_ff3 - root_ff3)

                helpers.zi[i*FIELD_EXTENSION_DEGREE:(i+1)*FIELD_EXTENSION_DEGREE] = ff3_to_numpy_coeffs(zi_temp)

        helpers.x_n = np.array([z[0], z[1], z[2]], dtype=np.uint64)
        return helpers

    def compute_x(self, n_bits: int, n_bits_ext: int, pil1: bool):
        """Compute coset points x[i] = shift * w^i using cumulative product."""
        N_extended = 1 << n_bits_ext
        N = 1 << n_bits

        w_ext = FF(get_omega(n_bits_ext))

        # Build array [1, w, w, w, ...] then cumprod gives [1, w, w^2, w^3, ...]
        ones = FF.Ones(N_extended)
        ones[1:] = w_ext
        powers = np.cumprod(ones)  # [1, w, w^2, ..., w^(N_ext-1)]
        self.x = SHIFT * powers

        if pil1:
            w_n = FF(get_omega(n_bits))
            ones_n = FF.Ones(N)
            ones_n[1:] = w_n
            self.x_n = np.cumprod(ones_n)  # [1, w, w^2, ..., w^(N-1)]

    def compute_zerofier(self, n_bits: int, n_bits_ext: int, boundaries: List['Boundary']):
        """Compute zerofier inverses 1/Z_H(x) for all boundaries."""
        N = 1 << n_bits
        N_extended = 1 << n_bits_ext

        self.zi = FF.Zeros(len(boundaries) * N_extended)

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

        # Build [1, w, w, ...] for cumprod
        ones = FF.Ones(extend)
        ones[1:] = w_ext
        powers = np.cumprod(ones)  # [1, w, w^2, ..., w^(extend-1)]

        # zi[i] = 1/(shift^N * w^i - 1)
        unique_vals = batch_inverse(shift_n * powers - FF(1))

        # Fill first extend values
        self.zi[:extend] = unique_vals

        # Repeat pattern (exploits periodicity of x^N on extended domain)
        for i in range(extend, N_extended):
            self.zi[i] = self.zi[i % extend]

    def build_one_row_zerofier_inv(self, n_bits: int, n_bits_ext: int,
                                   offset: int, row_index: int):
        """Build 1/((x - w^row) * Z_H(x)). Reads Z_H^(-1) from zi[0:N_ext]."""
        N_extended = 1 << n_bits_ext
        w = FF(get_omega(n_bits))
        root = w ** row_index

        # (x - root) * zh_inv, then invert
        diffs = self.x - root
        zh_inv = self.zi[:N_extended]
        self.zi[offset * N_extended:(offset + 1) * N_extended] = batch_inverse(diffs * zh_inv)

    def build_frame_zerofier_inv(self, n_bits: int, n_bits_ext: int, offset: int,
                                 offset_min: int, offset_max: int):
        """Build frame zerofier (NOT inverted): product of (x - w^k) for excluded rows."""
        N = 1 << n_bits
        N_extended = 1 << n_bits_ext
        w = FF(get_omega(n_bits))

        # Excluded roots: [0, offset_min) and [N - offset_max, N)
        roots = [w ** k for k in range(offset_min)]
        roots += [w ** (N - k - 1) for k in range(offset_max)]

        # Start with ones
        result = FF.Ones(N_extended)

        for root in roots:
            result = result * (self.x - root)

        self.zi[offset * N_extended:(offset + 1) * N_extended] = result


# --- AIR Configuration ---

class AirConfig:
    """Configuration bundle for STARK proving and verification.

    AirConfig packages all read-only configuration needed to generate or verify
    a STARK proof for a specific AIR (Algebraic Intermediate Representation):

    Attributes:
        stark_info: The AIR specification containing domain sizes, stage counts,
            constraint definitions, polynomial mappings, and FRI parameters.
        global_info: Optional cross-AIR coordination data for VADCOP (Virtual
            Algebraic Distributed Computation Over Provers) mode.

    Usage:
        config = AirConfig.from_starkinfo("path/to/starkinfo.json")
        proof = gen_proof(config, params)
    """

    def __init__(
        self,
        stark_info: 'StarkInfo',
        global_info: Optional['GlobalInfo'] = None
    ):
        self.stark_info = stark_info
        self.global_info = global_info

    @classmethod
    def from_starkinfo(cls, starkinfo_path: str, global_info_path: Optional[str] = None) -> 'AirConfig':
        """Load AIR configuration from starkinfo.json.

        Args:
            starkinfo_path: Path to starkinfo.json (AIR specification)
            global_info_path: Optional path to pilout.globalInfo.json (VADCOP)

        Returns:
            AirConfig instance with loaded configuration
        """
        from protocol.stark_info import StarkInfo
        from protocol.global_info import GlobalInfo

        stark_info = StarkInfo.from_json(starkinfo_path)

        global_info = None
        if global_info_path:
            global_info = GlobalInfo.from_json(global_info_path)

        return cls(stark_info, global_info)


# Backward compatibility alias
SetupCtx = AirConfig

# Re-export FIELD_EXTENSION_DEGREE for modules that import it from here
__all__ = ['AirConfig', 'SetupCtx', 'ProverHelpers', 'FIELD_EXTENSION_DEGREE']
