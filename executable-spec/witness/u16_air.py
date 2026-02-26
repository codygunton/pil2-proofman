"""U16Air AIR witness generation.

U16Air proves U16 range lookups used by SimpleLeft. The table covers all 65536 U16
values (0–65535) packed four per row across 16384 rows:

  Row i covers values: [4i, 4i+1, 4i+2, 4i+3]
  Column mul[j] at row i: count of value 4i+j

SimpleLeft's column subject to U16 range check (bus id 101):
  k[1]: range_check(k[1], 0, 65535)
  Also: k[3] range check via 256-k[3] contributes to U16 space

Stage-2 intermediates and grand sums are handled by the bytecode adapter.
"""

from collections import Counter

import numpy as np

from constraints.base import ConstraintContext
from primitives.field import GOLDILOCKS_PRIME, FF3Poly

from .base import WitnessModule


class U16AirWitness(WitnessModule):
    """Stage-1 witness generator for U16Air AIR.

    Computes multiplicity columns mul[0..3] by counting how many times each U16
    value (0–65535) appears in SimpleLeft's k[1] column (and related columns).

    For byte-identical C++ comparison tests, Stage-1 trace is loaded directly
    from C++ test vectors and this module is not invoked.
    """

    @staticmethod
    def compute_trace(
        simple_left_k1: np.ndarray,
        simple_left_k3: np.ndarray,
        N: int = 16384,
    ) -> np.ndarray:
        """Compute U16Air's cm1 trace from SimpleLeft's U16 range-check columns.

        Args:
            simple_left_k1: SimpleLeft's k[1] column (8 elements, values 0..65535)
            simple_left_k3: SimpleLeft's k[3] column (8 elements); contributes
                256-k[3] to U16 range (values 1..256)
            N: Trace size = 16384 rows

        Returns:
            cm1 buffer (16384 * 4 field elements) interleaved as [mul0_0, ..., mul3_0, ...]
            mul[j] at row i = count of value (4*i + j) across all U16 sources
        """
        p = GOLDILOCKS_PRIME

        # k[1] contributes values 0..65535 directly
        # 256-k[3] contributes values 1..256 (U16 range check via bus 101)
        all_values = []
        all_values.extend(int(v) % p for v in simple_left_k1)
        all_values.extend((256 - int(v)) % p for v in simple_left_k3)

        # Count occurrences of each U16 value
        counts = Counter(v for v in all_values if 0 <= v <= 65535)

        # Pack into 16384-row × 4-column table
        trace = np.zeros(N * 4, dtype=np.uint64)
        for i in range(N):
            for j in range(4):
                trace[i * 4 + j] = counts.get(4 * i + j, 0)
        return trace

    def compute_intermediates(self, ctx: ConstraintContext) -> dict[str, dict[int, FF3Poly]]:
        """Delegated to bytecode adapter; this module only computes Stage 1."""
        return {}

    def compute_grand_sums(self, ctx: ConstraintContext) -> dict[str, FF3Poly]:
        """Delegated to bytecode adapter; this module only computes Stage 1."""
        return {}
