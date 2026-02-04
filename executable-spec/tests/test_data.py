"""Unit tests for ProverData and VerifierData dataclasses."""

from primitives.field import FF3


def test_prover_data_stores_columns() -> None:
    from protocol.data import ProverData

    # Create simple test data with (name, index) tuple keys
    columns = {('a', 0): FF3.Random(8), ('b', 0): FF3.Random(8)}
    challenges = {'std_alpha': FF3.Random(1)[0]}

    data = ProverData(columns=columns, challenges=challenges)

    assert ('a', 0) in data.columns
    assert 'std_alpha' in data.challenges


def test_verifier_data_stores_evals() -> None:
    from protocol.data import VerifierData

    evals = {('a', 0, 0): FF3.Random(1)[0], ('a', 0, 1): FF3.Random(1)[0]}
    challenges = {'std_alpha': FF3.Random(1)[0]}

    data = VerifierData(evals=evals, challenges=challenges)

    assert ('a', 0, 0) in data.evals
    assert 'std_alpha' in data.challenges
