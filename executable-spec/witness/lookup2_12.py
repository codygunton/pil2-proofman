"""Lookup2_12 AIR witness generation."""

from typing import Dict

from primitives.field import FF3Poly
from constraints.base import ConstraintContext
from .base import WitnessModule


class Lookup2_12Witness(WitnessModule):
    """Witness generation for Lookup2_12 AIR."""

    def compute_intermediates(self, ctx: ConstraintContext) -> Dict[str, Dict[int, FF3Poly]]:
        """Compute im_cluster polynomials for lookup operations."""
        raise NotImplementedError("Lookup2_12 intermediates not yet implemented")

    def compute_grand_sums(self, ctx: ConstraintContext) -> Dict[str, FF3Poly]:
        """Compute gsum running sum polynomial."""
        raise NotImplementedError("Lookup2_12 grand sums not yet implemented")
