"""Permutation1_6 AIR witness generation."""

from typing import Dict

from primitives.field import FF3Poly
from constraints.base import ConstraintContext
from .base import WitnessModule


class Permutation1_6Witness(WitnessModule):
    """Witness generation for Permutation1_6 AIR."""

    def compute_intermediates(self, ctx: ConstraintContext) -> Dict[str, Dict[int, FF3Poly]]:
        """Compute im_cluster polynomials for permutation checks."""
        raise NotImplementedError("Permutation1_6 intermediates not yet implemented")

    def compute_grand_sums(self, ctx: ConstraintContext) -> Dict[str, FF3Poly]:
        """Compute gprod running product polynomial."""
        raise NotImplementedError("Permutation1_6 grand sums not yet implemented")
