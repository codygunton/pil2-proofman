"""Base class for witness generation."""

from abc import ABC, abstractmethod

from constraints.base import ConstraintContext
from primitives.field import FF3Poly


class WitnessModule(ABC):
    """Per-AIR witness generation. Used by prover only.

    Each AIR (Algebraic Intermediate Representation) may have its own witness
    module that computes intermediate polynomials and grand sums needed for
    lookups and permutations. Unlike ConstraintModule, this is only used by
    the prover - the verifier checks constraints but doesn't generate witnesses.
    """

    @abstractmethod
    def compute_intermediates(self, ctx: ConstraintContext) -> dict[str, dict[int, FF3Poly]]:
        """Compute im_cluster polynomials.

        Args:
            ctx: ConstraintContext providing access to columns, constants, challenges

        Returns:
            Dictionary mapping cluster names to their indexed polynomials.
            Example: {'im_cluster': {0: poly0, 1: poly1, ...}}
        """
        pass

    @abstractmethod
    def compute_grand_sums(self, ctx: ConstraintContext) -> dict[str, FF3Poly]:
        """Compute gsum/gprod running sum polynomials.

        Args:
            ctx: ConstraintContext providing access to columns, constants, challenges

        Returns:
            Dictionary mapping polynomial names to their values.
            Example: {'gsum': gsum_poly}
        """
        pass

    def _compute_cumulative_sum(self, row_values: FF3Poly) -> FF3Poly:
        """Compute cumulative sum: result[i] = sum(row_values[0:i+1])."""
        result = row_values.copy()
        for i in range(1, len(row_values)):
            result[i] = result[i - 1] + row_values[i]
        return result

    def _compute_cumulative_product(self, row_values: FF3Poly) -> FF3Poly:
        """Compute cumulative product: result[i] = prod(row_values[0:i+1])."""
        result = row_values.copy()
        for i in range(1, len(row_values)):
            result[i] = result[i - 1] * row_values[i]
        return result
