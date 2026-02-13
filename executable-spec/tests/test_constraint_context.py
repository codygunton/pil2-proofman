"""Tests for ConstraintContext ABC and implementations."""

import numpy as np
import pytest

from primitives.field import FF, FF3


def test_prover_context_col_returns_array() -> None:
    """ProverConstraintContext.col returns full array of values."""
    from constraints.base import ProverConstraintContext
    from protocol.data import ProverData

    # Create test data with 8 rows
    a_values = FF3.Random(8)
    columns = {('a', 0): a_values}
    challenges = {'std_alpha': FF3.Random(1)[0]}

    data = ProverData(columns=columns, challenges=challenges)
    ctx = ProverConstraintContext(data)

    result = ctx.col('a')
    assert len(result) == 8
    assert np.array_equal(result, a_values)


def test_prover_context_col_with_index() -> None:
    """ProverConstraintContext.col supports index parameter for multi-column polynomials."""
    from constraints.base import ProverConstraintContext
    from protocol.data import ProverData

    a0_values = FF3.Random(8)
    a1_values = FF3.Random(8)
    columns = {('a', 0): a0_values, ('a', 1): a1_values}

    data = ProverData(columns=columns, challenges={})
    ctx = ProverConstraintContext(data)

    assert np.array_equal(ctx.col('a', 0), a0_values)
    assert np.array_equal(ctx.col('a', 1), a1_values)


def test_prover_context_next_col_shifts() -> None:
    """ProverConstraintContext.next_col shifts values by -1 (circular)."""
    from constraints.base import ProverConstraintContext
    from protocol.data import ProverData

    # Create sequential values for easy verification
    a_values = FF3([1, 2, 3, 4, 5, 6, 7, 8])
    columns = {('a', 0): a_values}

    data = ProverData(columns=columns, challenges={})
    ctx = ProverConstraintContext(data)

    result = ctx.next_col('a')
    # next_col shifts by -1, so [1,2,3,4,5,6,7,8] -> [2,3,4,5,6,7,8,1]
    expected = FF3([2, 3, 4, 5, 6, 7, 8, 1])
    assert np.array_equal(result, expected)


def test_prover_context_prev_col_shifts() -> None:
    """ProverConstraintContext.prev_col shifts values by +1 (circular)."""
    from constraints.base import ProverConstraintContext
    from protocol.data import ProverData

    a_values = FF3([1, 2, 3, 4, 5, 6, 7, 8])
    columns = {('a', 0): a_values}

    data = ProverData(columns=columns, challenges={})
    ctx = ProverConstraintContext(data)

    result = ctx.prev_col('a')
    # prev_col shifts by +1, so [1,2,3,4,5,6,7,8] -> [8,1,2,3,4,5,6,7]
    expected = FF3([8, 1, 2, 3, 4, 5, 6, 7])
    assert np.array_equal(result, expected)


def test_prover_context_challenge_returns_scalar() -> None:
    """ProverConstraintContext.challenge returns scalar challenge value."""
    from constraints.base import ProverConstraintContext
    from protocol.data import ProverData

    alpha = FF3.Random(1)[0]
    data = ProverData(columns={}, challenges={'std_alpha': alpha})
    ctx = ProverConstraintContext(data)

    result = ctx.challenge('std_alpha')
    assert result == alpha


def test_prover_context_const_returns_array() -> None:
    """ProverConstraintContext.const returns full constant polynomial array."""
    from constraints.base import ProverConstraintContext
    from protocol.data import ProverData

    const_values = FF.Random(8)
    data = ProverData(columns={}, challenges={}, constants={'L1': const_values})
    ctx = ProverConstraintContext(data)

    result = ctx.const('L1')
    assert np.array_equal(result, const_values)


def test_verifier_context_col_returns_scalar() -> None:
    """VerifierConstraintContext.col returns scalar evaluation at xi."""
    from constraints.base import VerifierConstraintContext
    from protocol.data import VerifierData

    eval_val = FF3.Random(1)[0]
    evals = {('a', 0, 0): eval_val}

    data = VerifierData(evals=evals, challenges={})
    ctx = VerifierConstraintContext(data)

    result = ctx.col('a')
    assert result == eval_val


def test_verifier_context_next_col_returns_shifted_eval() -> None:
    """VerifierConstraintContext.next_col returns evaluation at xi*omega."""
    from constraints.base import VerifierConstraintContext
    from protocol.data import VerifierData

    next_eval = FF3.Random(1)[0]
    evals = {('a', 0, 1): next_eval}  # offset=1 means next

    data = VerifierData(evals=evals, challenges={})
    ctx = VerifierConstraintContext(data)

    result = ctx.next_col('a')
    assert result == next_eval


def test_verifier_context_prev_col_returns_shifted_eval() -> None:
    """VerifierConstraintContext.prev_col returns evaluation at xi*omega^(-1)."""
    from constraints.base import VerifierConstraintContext
    from protocol.data import VerifierData

    prev_eval = FF3.Random(1)[0]
    evals = {('a', 0, -1): prev_eval}  # offset=-1 means prev

    data = VerifierData(evals=evals, challenges={})
    ctx = VerifierConstraintContext(data)

    result = ctx.prev_col('a')
    assert result == prev_eval


def test_verifier_context_challenge_returns_scalar() -> None:
    """VerifierConstraintContext.challenge returns scalar challenge value."""
    from constraints.base import VerifierConstraintContext
    from protocol.data import VerifierData

    alpha = FF3.Random(1)[0]
    data = VerifierData(evals={}, challenges={'std_alpha': alpha})
    ctx = VerifierConstraintContext(data)

    result = ctx.challenge('std_alpha')
    assert result == alpha


def test_constraint_module_abc() -> None:
    """ConstraintModule is an abstract base class requiring constraint_polynomial."""
    from constraints.base import ConstraintModule

    # Cannot instantiate ConstraintModule directly
    with pytest.raises(TypeError):
        ConstraintModule()


def test_uniform_constraint_evaluation() -> None:
    """Same constraint code works for both prover and verifier contexts."""
    from constraints.base import (
        ConstraintContext,
        ProverConstraintContext,
        VerifierConstraintContext,
    )
    from protocol.data import ProverData, VerifierData

    # Simple constraint: a * b - c = 0

    def eval_constraint(ctx: ConstraintContext) -> FF3:
        a = ctx.col('a')
        b = ctx.col('b')
        c = ctx.col('c')
        return a * b - c

    # Prover context: arrays
    a_vals = FF3([2, 3, 4, 5])
    b_vals = FF3([3, 4, 5, 6])
    c_vals = a_vals * b_vals  # constraint satisfied

    prover_data = ProverData(
        columns={('a', 0): a_vals, ('b', 0): b_vals, ('c', 0): c_vals},
        challenges={},
    )
    prover_ctx = ProverConstraintContext(prover_data)
    prover_result = eval_constraint(prover_ctx)
    assert all(prover_result == FF3([0, 0, 0, 0]))

    # Verifier context: scalars
    # Evaluate at xi where a(xi)=2, b(xi)=3, c(xi)=6
    verifier_data = VerifierData(
        evals={('a', 0, 0): FF3(2), ('b', 0, 0): FF3(3), ('c', 0, 0): FF3(6)},
        challenges={},
    )
    verifier_ctx = VerifierConstraintContext(verifier_data)
    verifier_result = eval_constraint(verifier_ctx)
    assert verifier_result == FF3(0)
