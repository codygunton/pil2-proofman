"""SimpleLeft AIR constraint evaluation."""

from typing import Union

from primitives.field import FF3
from .base import ConstraintModule, ConstraintContext

FF3Poly = FF3


class SimpleLeftConstraints(ConstraintModule):
    """Constraint evaluation for SimpleLeft AIR.

    SimpleLeft has 8 rows and uses the logup protocol for lookups.
    Constraints:
    - Grand sum recurrence: gsum' = gsum + sum(im_cluster[i])
    - Boundary: gsum[0] = 0
    """

    def constraint_polynomial(self, ctx: ConstraintContext) -> Union[FF3Poly, FF3]:
        """Evaluate combined constraint polynomial.

        TODO: Implement actual constraints after studying expression binary output.
        """
        raise NotImplementedError("SimpleLeft constraints not yet implemented")
