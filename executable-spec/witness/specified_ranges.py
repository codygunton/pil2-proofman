"""SpecifiedRanges AIR witness generation.

SpecifiedRanges proves custom (non-predefined) range lookups used by SimpleLeft.
The table has 64 rows and 11 multiplicity columns covering three custom ranges:

SimpleLeft's columns subject to custom range checks:
  k[4]: range_check(k[4], 0, 255)     → bus 102, 256 values
  k[5]: range_check(k[5], -128, -1)   → bus 103, 128 values (negative range)
  k[6]: range_check(k[6], -129, 127)  → bus 104, 257 values

The constant polynomial columns (RANGE[0..10]) define what value each (row, col)
cell covers. Multiplicity mul[j] at row i = number of occurrences of RANGE[j][i]
in the corresponding SimpleLeft k column.

Stage-2 intermediates and grand sums are handled by the bytecode adapter.
"""

from collections import Counter

import numpy as np

from constraints.base import ConstraintContext
from primitives.field import GOLDILOCKS_PRIME, FF3Poly

from .base import WitnessModule


class SpecifiedRangesWitness(WitnessModule):
    """Stage-1 witness generator for SpecifiedRanges AIR.

    Computes 11 multiplicity columns for the three custom range-check buses
    derived from SimpleLeft's k[4], k[5], k[6] columns.

    The const_pols RANGE columns define what value each (row, mul_idx) cell
    covers, so we use them directly to avoid hardcoding the layout.

    For byte-identical C++ comparison tests, Stage-1 trace is loaded directly
    from C++ test vectors and this module is not invoked.
    """

    @staticmethod
    def compute_trace(
        simple_left_k456: np.ndarray,
        const_pols: np.ndarray,
        N: int = 64,
        n_constants: int = 12,
    ) -> np.ndarray:
        """Compute SpecifiedRanges cm1 trace using const_pols RANGE layout.

        Args:
            simple_left_k456: Array of shape (8, 3) with SimpleLeft's k[4], k[5], k[6]
                columns. k[4] uses bus 102, k[5] uses bus 103, k[6] uses bus 104.
            const_pols: SpecifiedRanges constant polynomials (N * n_constants elements).
                Columns 0..10 are RANGE values defining coverage per (row, col).
                Column 11 is __L1__ (selector).
            N: Trace size = 64 rows
            n_constants: Number of constant polynomial columns (default 12)

        Returns:
            cm1 buffer (64 * 11 field elements) interleaved as [mul0_0, mul1_0, ...]
            mul[j] at row i = count of value const_pols[j][i] in the corresponding k column.
        """
        p = GOLDILOCKS_PRIME

        # Reshape const_pols into (N, n_constants) for easy access
        # const_pols is stored as N*n_constants elements in interleaved format:
        # [col0_row0, col1_row0, ..., col11_row0, col0_row1, ...]
        const_matrix = const_pols[:N * n_constants].reshape(N, n_constants)

        # Count occurrences of each value in SimpleLeft's k[4], k[5], k[6]
        # k[4]: bus 102 (custom range 0..255)
        # k[5]: bus 103 (custom range −128..−1, stored as Goldilocks values)
        # k[6]: bus 104 (custom range −129..127, stored as Goldilocks values)
        k4_counts = Counter(int(v) % p for v in simple_left_k456[:, 0])
        k5_counts = Counter(int(v) % p for v in simple_left_k456[:, 1])
        k6_counts = Counter(int(v) % p for v in simple_left_k456[:, 2])

        # Determine which const_pol columns correspond to which k columns.
        # The 11 RANGE columns are ordered by bus: first k[4] range, then k[5], then k[6].
        # With 256 values for k[4] and 64 rows, that's 4 columns per bus for k[4] (4*64=256).
        # Similarly, k[5] has 128 values → 2 columns (2*64=128).
        # k[6] has 257 values → 5 columns (5*64=320, padded or truncated to 257).
        # Total: 4+2+5 = 11 columns.
        k4_cols = list(range(0, 4))    # RANGE columns for k[4] (bus 102)
        k5_cols = list(range(4, 6))    # RANGE columns for k[5] (bus 103)
        k6_cols = list(range(6, 11))   # RANGE columns for k[6] (bus 104)

        source_counts = (
            [(col_idx, k4_counts) for col_idx in k4_cols]
            + [(col_idx, k5_counts) for col_idx in k5_cols]
            + [(col_idx, k6_counts) for col_idx in k6_cols]
        )

        # Build multiplicity trace
        trace = np.zeros(N * 11, dtype=np.uint64)
        for mul_idx, (col_idx, counts) in enumerate(source_counts):
            for row in range(N):
                range_value = int(const_matrix[row, col_idx]) % p
                trace[row * 11 + mul_idx] = counts.get(range_value, 0)
        return trace

    def compute_intermediates(self, ctx: ConstraintContext) -> dict[str, dict[int, FF3Poly]]:
        """Delegated to bytecode adapter; this module only computes Stage 1."""
        return {}

    def compute_grand_sums(self, ctx: ConstraintContext) -> dict[str, FF3Poly]:
        """Delegated to bytecode adapter; this module only computes Stage 1."""
        return {}
