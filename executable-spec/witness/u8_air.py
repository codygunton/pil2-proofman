"""U8Air AIR witness generation.

U8Air proves U8 range lookups used by SimpleLeft. The table covers all 256 U8
values (0–255) packed two per row across 128 rows:

  Row i covers values: [2i, 2i+1]
  Column mul[0] at row i: count of value 2i
  Column mul[1] at row i: count of value 2i+1

SimpleLeft's columns subject to U8 range checks (bus ids 100):
  k[0]: range_check(k[0], 0, 255)
  k[2]: range_check(k[2]-1, 0, 254) — i.e. k[2] in 1..255
  k[3]: range_check(k[3], 0, 255) and range_check(256-k[3], 1, 256)

Stage-2 intermediates and grand sums are handled by the bytecode adapter.
"""

from collections import Counter

import numpy as np

from constraints.base import ConstraintContext
from primitives.field import GOLDILOCKS_PRIME, FF3Poly

from .base import WitnessModule


class U8AirWitness(WitnessModule):
    """Stage-1 witness generator for U8Air AIR.

    Computes multiplicity columns mul[0], mul[1] by counting how many times
    each U8 value (0–255) appears across SimpleLeft's U8 range-check columns.

    For byte-identical C++ comparison tests, Stage-1 trace is loaded directly
    from C++ test vectors and this module is not invoked.
    """

    @staticmethod
    def compute_trace(
        simple_left_k0: np.ndarray,
        simple_left_k2: np.ndarray,
        simple_left_k3: np.ndarray,
        N: int = 128,
    ) -> np.ndarray:
        """Compute U8Air's cm1 trace from SimpleLeft's U8 range-check columns.

        Args:
            simple_left_k0: SimpleLeft's k[0] column (8 elements, values 0..255)
            simple_left_k2: SimpleLeft's k[2] column (8 elements, values 1..255)
            simple_left_k3: SimpleLeft's k[3] column (8 elements, values 0..255)
            N: Trace size = 128 rows

        Returns:
            cm1 buffer (128 * 2 field elements) interleaved as [mul0_0, mul1_0, ...]
            mul[j] at row i = count of value (2*i + j) across k[0], k[2]-1, k[3]
        """
        # Collect all values that contribute to U8 range checks
        # k[0] contributes values as-is (0..255)
        # k[2] contributes k[2]-1 (1..255 → 0..254)
        # k[3] contributes k[3] (0..255) and 256-k[3] (1..256, but capped at 255)
        # 256-k[3] only lands in 0..255 when k[3]=256, which is impossible for U8.
        # So only k[0], k[2]-1, and k[3] contribute to U8Air's table; the 256-k[3]
        # values are covered by U16Air (bus 101).
        p = GOLDILOCKS_PRIME

        all_values = []
        all_values.extend(int(v) % p for v in simple_left_k0)
        all_values.extend((int(v) - 1) % p for v in simple_left_k2)
        all_values.extend(int(v) % p for v in simple_left_k3)

        # Count occurrences of each U8 value
        counts = Counter(v for v in all_values if 0 <= v <= 255)

        # Pack into 128-row × 2-column table
        trace = np.zeros(N * 2, dtype=np.uint64)
        for i in range(N):
            trace[i * 2 + 0] = counts.get(2 * i, 0)
            trace[i * 2 + 1] = counts.get(2 * i + 1, 0)
        return trace

    def compute_intermediates(self, ctx: ConstraintContext) -> dict[str, dict[int, FF3Poly]]:
        """Delegated to bytecode adapter; this module only computes Stage 1."""
        return {}

    def compute_grand_sums(self, ctx: ConstraintContext) -> dict[str, FF3Poly]:
        """Delegated to bytecode adapter; this module only computes Stage 1."""
        return {}
