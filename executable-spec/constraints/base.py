"""Base classes for constraint evaluation.

ConstraintContext provides a uniform interface for constraint evaluation that works
for both prover (returns arrays) and verifier (returns scalars). The same constraint
code can be used in both contexts thanks to galois broadcasting.

Example:
    def eval_constraint(ctx: ConstraintContext):
        a = ctx.col('a')
        b = ctx.col('b')
        return a * b - ctx.challenge('alpha')

    # Works for prover (arrays)
    prover_result = eval_constraint(ProverConstraintContext(prover_data))

    # Works for verifier (scalars)
    verifier_result = eval_constraint(VerifierConstraintContext(verifier_data))
"""

from abc import ABC, abstractmethod
from typing import Union

import numpy as np

from primitives.field import FF, FF3, GOLDILOCKS_PRIME
from protocol.data import ProverData, VerifierData

# Type aliases for clarity
FF3Poly = FF3  # Array of extension field elements
FFPoly = FF    # Array of base field elements


def compress_2col(busid: int, col1, col2, alpha, gamma, n: int = None):
    """Compress 2-column expression: ((col2*α + col1)*α + busid) + γ."""
    if n is None:
        busid_val = FF3(busid % GOLDILOCKS_PRIME)
    else:
        busid_val = FF3(np.full(n, busid % GOLDILOCKS_PRIME, dtype=np.uint64))
    return (col2 * alpha + col1) * alpha + busid_val + gamma


class ConstraintContext(ABC):
    """Uniform interface for constraint evaluation - works for prover and verifier."""

    @abstractmethod
    def col(self, name: str, index: int = 0) -> Union[FF3Poly, FF3]:
        """Get column at current row.

        Args:
            name: Column name
            index: Column index for multi-column polynomials (default 0)

        Returns:
            Prover: array of values at all domain points
            Verifier: scalar evaluation at xi
        """
        pass

    @abstractmethod
    def next_col(self, name: str, index: int = 0) -> Union[FF3Poly, FF3]:
        """Get column at next row (offset +1).

        Args:
            name: Column name
            index: Column index for multi-column polynomials (default 0)

        Returns:
            Prover: array shifted by -1 (circular)
            Verifier: evaluation at xi * omega
        """
        pass

    @abstractmethod
    def prev_col(self, name: str, index: int = 0) -> Union[FF3Poly, FF3]:
        """Get column at previous row (offset -1).

        Args:
            name: Column name
            index: Column index for multi-column polynomials (default 0)

        Returns:
            Prover: array shifted by +1 (circular)
            Verifier: evaluation at xi * omega^(-1)
        """
        pass

    @abstractmethod
    def const(self, name: str) -> Union[FF3Poly, FF3]:
        """Get constant polynomial at current row (converted to extension field).

        Args:
            name: Constant name (e.g., '__L1__' for Lagrange polynomial)

        Returns:
            Prover: array of constant values (as FF3 for arithmetic compatibility)
            Verifier: scalar evaluation at xi
        """
        pass

    @abstractmethod
    def next_const(self, name: str) -> Union[FF3Poly, FF3]:
        """Get constant polynomial at next row (offset +1).

        Args:
            name: Constant name

        Returns:
            Prover: array shifted by -1 (circular)
            Verifier: evaluation at xi * omega
        """
        pass

    @abstractmethod
    def prev_const(self, name: str) -> Union[FF3Poly, FF3]:
        """Get constant polynomial at previous row (offset -1).

        Args:
            name: Constant name

        Returns:
            Prover: array shifted by +1 (circular)
            Verifier: evaluation at xi * omega^(-1)
        """
        pass

    @abstractmethod
    def challenge(self, name: str) -> FF3:
        """Get Fiat-Shamir challenge (always scalar).

        Args:
            name: Challenge name (e.g., 'std_alpha')

        Returns:
            Scalar challenge value
        """
        pass

    @abstractmethod
    def airgroup_value(self, index: int) -> FF3:
        """Get airgroup value (accumulated result across AIR instances).

        Args:
            index: Airgroup value index

        Returns:
            Scalar airgroup value (FF3)
        """
        pass


class ProverConstraintContext(ConstraintContext):
    """Prover implementation - returns polynomial arrays.

    The prover evaluates constraints at all domain points simultaneously,
    producing arrays of constraint evaluations.
    """

    def __init__(self, data: ProverData):
        self._data = data

    def col(self, name: str, index: int = 0) -> FF3Poly:
        key = (name, index)
        return self._data.columns[key]

    def next_col(self, name: str, index: int = 0) -> FF3Poly:
        # On extended domain, row offset is multiplied by extend factor
        extend = self._data.extend
        return np.roll(self.col(name, index), -extend)

    def prev_col(self, name: str, index: int = 0) -> FF3Poly:
        # On extended domain, row offset is multiplied by extend factor
        extend = self._data.extend
        return np.roll(self.col(name, index), extend)

    def const(self, name: str) -> FF3Poly:
        # Convert base field constant to extension field for arithmetic compatibility
        return FF3(np.asarray(self._data.constants[name], dtype=np.uint64))

    def next_const(self, name: str) -> FF3Poly:
        # On extended domain, row offset is multiplied by extend factor
        extend = self._data.extend
        return np.roll(self.const(name), -extend)

    def prev_const(self, name: str) -> FF3Poly:
        # On extended domain, row offset is multiplied by extend factor
        extend = self._data.extend
        return np.roll(self.const(name), extend)

    def challenge(self, name: str) -> FF3:
        return self._data.challenges[name]

    def airgroup_value(self, index: int) -> FF3:
        return self._data.airgroup_values.get(index, FF3(0))


class VerifierConstraintContext(ConstraintContext):
    """Verifier implementation - returns scalar evaluations.

    The verifier evaluates constraints at a single random point xi,
    checking that the constraint polynomial evaluates to zero.
    """

    def __init__(self, data: VerifierData):
        self._data = data

    def col(self, name: str, index: int = 0) -> FF3:
        # offset=0 means evaluation at xi
        return self._data.evals[(name, index, 0)]

    def next_col(self, name: str, index: int = 0) -> FF3:
        # offset=1 means evaluation at xi * omega
        return self._data.evals[(name, index, 1)]

    def prev_col(self, name: str, index: int = 0) -> FF3:
        # offset=-1 means evaluation at xi * omega^(-1)
        return self._data.evals[(name, index, -1)]

    def const(self, name: str) -> FF3:
        # Constants stored in evals with index=0, offset=0
        return self._data.evals[(name, 0, 0)]

    def next_const(self, name: str) -> FF3:
        # Constants at next row (offset=1)
        return self._data.evals[(name, 0, 1)]

    def prev_const(self, name: str) -> FF3:
        # Constants at previous row (offset=-1)
        return self._data.evals[(name, 0, -1)]

    def challenge(self, name: str) -> FF3:
        return self._data.challenges[name]

    def airgroup_value(self, index: int) -> FF3:
        return self._data.airgroup_values.get(index, FF3(0))


class ConstraintModule(ABC):
    """Per-AIR constraint evaluation. Used by both prover and verifier.

    Each AIR (Algebraic Intermediate Representation) has its own constraint
    module that defines how constraints are evaluated. The same module works
    for both prover and verifier contexts.
    """

    @abstractmethod
    def constraint_polynomial(self, ctx: ConstraintContext) -> Union[FF3Poly, FF3]:
        """Evaluate all constraints combined into single polynomial.

        Args:
            ctx: ConstraintContext providing access to columns, constants, challenges

        Returns:
            Prover: array of constraint evaluations at all domain points
            Verifier: single constraint evaluation at xi
        """
        pass

    def _combine_constraints(self, constraints, vc):
        """Combine constraint list using standard accumulation pattern.

        Computes: ((constraints[0] * vc + constraints[1]) * vc + ...) + constraints[-1]
        """
        acc = constraints[0] * vc
        for i in range(1, len(constraints) - 1):
            acc = (acc + constraints[i]) * vc
        acc = acc + constraints[-1]
        return acc
