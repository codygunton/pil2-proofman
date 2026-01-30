"""Lookup2_12 AIR constraint evaluation."""

from typing import Union

from primitives.field import FF3
from .base import ConstraintModule, ConstraintContext

FF3Poly = FF3


class Lookup2_12Constraints(ConstraintModule):
    """Constraint evaluation for Lookup2_12 AIR.

    Lookup2_12 has 4096 rows and uses complex lookup operations.
    This is a larger AIR that exercises FRI folding.
    """

    def constraint_polynomial(self, ctx: ConstraintContext) -> Union[FF3Poly, FF3]:
        """Evaluate combined constraint polynomial.

        TODO: Implement actual constraints after studying expression binary output.
        """
        raise NotImplementedError("Lookup2_12 constraints not yet implemented")
