"""SimpleLeft AIR witness generation."""

from typing import Dict

from primitives.field import FF3Poly
from constraints.base import ConstraintContext
from .base import WitnessModule


class SimpleLeftWitness(WitnessModule):
    """Witness generation for SimpleLeft AIR."""

    def compute_intermediates(self, ctx: ConstraintContext) -> Dict[str, Dict[int, FF3Poly]]:
        """Compute im_cluster polynomials (batch inverses for logup)."""
        raise NotImplementedError("SimpleLeft intermediates not yet implemented")

    def compute_grand_sums(self, ctx: ConstraintContext) -> Dict[str, FF3Poly]:
        """Compute gsum running sum polynomial."""
        raise NotImplementedError("SimpleLeft grand sums not yet implemented")
