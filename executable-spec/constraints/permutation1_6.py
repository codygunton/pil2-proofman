"""Permutation1_6 AIR constraint evaluation."""

from typing import Union

from primitives.field import FF3
from .base import ConstraintModule, ConstraintContext

FF3Poly = FF3


class Permutation1_6Constraints(ConstraintModule):
    """Constraint evaluation for Permutation1_6 AIR.

    Permutation1_6 has 64 rows and uses permutation constraints.
    This AIR tests the permutation argument protocol.
    """

    def constraint_polynomial(self, ctx: ConstraintContext) -> Union[FF3Poly, FF3]:
        """Evaluate combined constraint polynomial.

        TODO: Implement actual constraints after studying expression binary output.
        """
        raise NotImplementedError("Permutation1_6 constraints not yet implemented")
