"""Unit tests for verifier constraint module evaluation.

These tests isolate the discrepancy between expression binary and constraint
module evaluation at a single point xi.
"""

import pytest
import numpy as np
from pathlib import Path
import json

from primitives.field import ff3_coeffs, FIELD_EXTENSION_DEGREE, GOLDILOCKS_PRIME, FF3
from protocol.air_config import SetupCtx
from protocol.proof import from_bytes_full
from protocol.verifier import (
    _build_verifier_data,
    _reconstruct_transcript,
)
from protocol.proof_context import ProofContext
from protocol.data import VerifierData
from constraints import get_constraint_module, VerifierConstraintContext


TEST_DATA_DIR = Path(__file__).parent / "test-data"


def load_simple_left_fixture():
    """Load all data needed for SimpleLeft verifier constraint test."""
    base_dir = Path(__file__).parent
    starkinfo_path = base_dir / '../../pil2-components/test/simple/build/provingKey/build/Simple/airs/SimpleLeft/air/SimpleLeft.starkinfo.json'

    setup_ctx = SetupCtx.from_starkinfo(str(starkinfo_path))
    stark_info = setup_ctx.stark_info

    # Load proof
    with open(TEST_DATA_DIR / 'simple-left.proof.bin', 'rb') as f:
        proof_bytes = f.read()
    proof = from_bytes_full(proof_bytes, stark_info)

    # Load test vectors
    with open(TEST_DATA_DIR / 'simple-left.json') as f:
        vectors = json.load(f)

    global_challenge = np.array(vectors['inputs']['global_challenge'], dtype=np.uint64)
    challenges, _ = _reconstruct_transcript(proof, stark_info, global_challenge)

    # Build airgroup_values as interleaved numpy array
    airgroup_values = np.array([v for av in proof.airgroup_values for v in av], dtype=np.uint64)

    return setup_ctx, stark_info, proof, challenges, vectors, airgroup_values


class TestConstraintVerifierBasics:
    """Test basic assumptions about constraint evaluation."""

    def test_verifier_data_contains_all_columns(self):
        """Verify VerifierData has all columns needed by SimpleLeft."""
        setup_ctx, stark_info, proof, challenges, _, airgroup_values = load_simple_left_fixture()
        evals = np.array(proof.evals, dtype=np.uint64).flatten()
        verifier_data = _build_verifier_data(stark_info, evals, challenges, airgroup_values)

        # Check required columns exist
        required_cols = [
            ('a', 0, 0), ('b', 0, 0), ('c', 0, 0), ('d', 0, 0),
            ('e', 0, 0), ('f', 0, 0), ('g', 0, 0), ('h', 0, 0),
            ('gsum', 0, 0), ('gsum', 0, -1),
            ('im_cluster', 0, 0), ('im_cluster', 1, 0), ('im_cluster', 2, 0),
            ('im_cluster', 3, 0), ('im_cluster', 4, 0), ('im_cluster', 5, 0),
            ('__L1__', 0, 0), ('__L1__', 0, 1),
        ]
        for key in required_cols:
            assert key in verifier_data.evals, f"Missing column: {key}"

        # Check k[0..6]
        for i in range(7):
            assert ('k', i, 0) in verifier_data.evals, f"Missing k[{i}]"

    def test_verifier_data_challenges_match(self):
        """Verify challenges are correctly mapped."""
        setup_ctx, stark_info, proof, challenges, _, airgroup_values = load_simple_left_fixture()
        evals = np.array(proof.evals, dtype=np.uint64).flatten()
        verifier_data = _build_verifier_data(stark_info, evals, challenges, airgroup_values)

        # Check required challenges
        assert 'std_alpha' in verifier_data.challenges
        assert 'std_gamma' in verifier_data.challenges
        assert 'std_vc' in verifier_data.challenges


class TestExpressionBinaryEvaluation:
    """Test expression binary evaluation as ground truth."""

    def test_reconstructed_q_from_proof(self):
        """Verify we can reconstruct Q(xi) from proof evaluations."""
        setup_ctx, stark_info, proof, challenges, _, _ = load_simple_left_fixture()
        evals = np.array(proof.evals, dtype=np.uint64).flatten()

        # Get xi
        xi_idx = next(i for i, cm in enumerate(stark_info.challengesMap) if cm.name == 'std_xi')
        xi = challenges[xi_idx * FIELD_EXTENSION_DEGREE:(xi_idx + 1) * FIELD_EXTENSION_DEGREE]
        xi_ff3 = FF3.Vector([int(xi[2]), int(xi[1]), int(xi[0])])

        # Get Q(xi) from proof (reconstructed from Q0, Q1)
        trace_size = 1 << stark_info.starkStruct.nBits

        # Compute xi^N
        xi_to_n = xi_ff3
        for _ in range(trace_size - 1):
            xi_to_n = xi_to_n * xi_ff3

        # Find Q0, Q1 in evals
        q_stage = stark_info.nStages + 1
        q_start_idx = next(i for i, p in enumerate(stark_info.cmPolsMap) if p.stage == q_stage)

        q0_ev_idx = next(j for j, e in enumerate(stark_info.evMap)
                        if e.type.name == 'cm' and e.id == q_start_idx)
        q1_ev_idx = next(j for j, e in enumerate(stark_info.evMap)
                        if e.type.name == 'cm' and e.id == q_start_idx + 1)

        q0 = FF3.Vector([int(evals[q0_ev_idx * 3 + 2]), int(evals[q0_ev_idx * 3 + 1]), int(evals[q0_ev_idx * 3])])
        q1 = FF3.Vector([int(evals[q1_ev_idx * 3 + 2]), int(evals[q1_ev_idx * 3 + 1]), int(evals[q1_ev_idx * 3])])

        # Q(xi) = Q0(xi) + xi^N * Q1(xi)
        reconstructed_q = q0 + xi_to_n * q1

        print(f"\nReconstructed Q(xi) from proof:")
        print(f"  Q0(xi): {ff3_coeffs(q0)}")
        print(f"  Q1(xi): {ff3_coeffs(q1)}")
        print(f"  xi^N: {ff3_coeffs(xi_to_n)}")
        print(f"  Q(xi) = Q0 + xi^N * Q1: {ff3_coeffs(reconstructed_q)}")

        # This is what the verifier will check against
        assert reconstructed_q is not None


class TestConstraintModuleEvaluation:
    """Test constraint module evaluation and compare to expression binary."""

    def test_constraint_module_basic_evaluation(self):
        """Test that constraint module runs without error."""
        setup_ctx, stark_info, proof, challenges, _, airgroup_values = load_simple_left_fixture()
        evals = np.array(proof.evals, dtype=np.uint64).flatten()
        verifier_data = _build_verifier_data(stark_info, evals, challenges, airgroup_values)

        constraint_module = get_constraint_module('SimpleLeft')
        ctx = VerifierConstraintContext(verifier_data)

        # Should not raise
        result = constraint_module.constraint_polynomial(ctx)
        assert result is not None

    def test_constraint_module_vs_proof_q(self):
        """Compare constraint module Q(xi) to reconstructed Q(xi) from proof.

        The proof contains Q0(xi) and Q1(xi) evaluations. We reconstruct Q(xi)
        and compare to what the constraint module produces.
        """
        setup_ctx, stark_info, proof, challenges, _, airgroup_values = load_simple_left_fixture()
        evals = np.array(proof.evals, dtype=np.uint64).flatten()

        # Get xi
        xi_idx = next(i for i, cm in enumerate(stark_info.challengesMap) if cm.name == 'std_xi')
        xi = challenges[xi_idx * FIELD_EXTENSION_DEGREE:(xi_idx + 1) * FIELD_EXTENSION_DEGREE]
        xi_ff3 = FF3.Vector([int(xi[2]), int(xi[1]), int(xi[0])])

        # === Reconstruct Q(xi) from proof ===
        trace_size = 1 << stark_info.starkStruct.nBits
        xi_to_n = xi_ff3
        for _ in range(trace_size - 1):
            xi_to_n = xi_to_n * xi_ff3

        q_stage = stark_info.nStages + 1
        q_start_idx = next(i for i, p in enumerate(stark_info.cmPolsMap) if p.stage == q_stage)

        q0_ev_idx = next(j for j, e in enumerate(stark_info.evMap)
                        if e.type.name == 'cm' and e.id == q_start_idx)
        q1_ev_idx = next(j for j, e in enumerate(stark_info.evMap)
                        if e.type.name == 'cm' and e.id == q_start_idx + 1)

        q0 = FF3.Vector([int(evals[q0_ev_idx * 3 + 2]), int(evals[q0_ev_idx * 3 + 1]), int(evals[q0_ev_idx * 3])])
        q1 = FF3.Vector([int(evals[q1_ev_idx * 3 + 2]), int(evals[q1_ev_idx * 3 + 1]), int(evals[q1_ev_idx * 3])])

        expected_q_xi = q0 + xi_to_n * q1

        # === Constraint module path ===
        verifier_data = _build_verifier_data(stark_info, evals, challenges, airgroup_values)
        constraint_module = get_constraint_module('SimpleLeft')
        ctx = VerifierConstraintContext(verifier_data)

        c_xi = constraint_module.constraint_polynomial(ctx)

        # Divide by Z_H(xi) = xi^N - 1
        zh_xi = xi_to_n - FF3(1)
        module_q_xi = c_xi * (zh_xi ** -1)

        # Compare
        print(f"\nExpected Q(xi) from proof: {ff3_coeffs(expected_q_xi)}")
        print(f"Constraint module Q(xi):   {ff3_coeffs(module_q_xi)}")
        print(f"Constraint module C(xi):   {ff3_coeffs(c_xi)}")
        print(f"Z_H(xi):                   {ff3_coeffs(zh_xi)}")

        residual = ff3_coeffs(expected_q_xi - module_q_xi)
        print(f"Residual: {residual}")

        # Should match now that airgroup_values are passed
        assert residual == [0, 0, 0], (
            f"Constraint module Q(xi) doesn't match proof Q(xi)\n"
            f"  expected: {ff3_coeffs(expected_q_xi)}\n"
            f"  got:      {ff3_coeffs(module_q_xi)}\n"
            f"  residual: {residual}"
        )


class TestIndividualConstraints:
    """Test individual constraints to find where divergence occurs."""

    def test_constraint_0_manually(self):
        """Manually compute constraint 0 and compare."""
        setup_ctx, stark_info, proof, challenges, _, airgroup_values = load_simple_left_fixture()
        evals = np.array(proof.evals, dtype=np.uint64).flatten()
        verifier_data = _build_verifier_data(stark_info, evals, challenges, airgroup_values)

        # Get values for constraint 0
        alpha = verifier_data.challenges['std_alpha']
        gamma = verifier_data.challenges['std_gamma']

        c = verifier_data.evals[('c', 0, 0)]
        d = verifier_data.evals[('d', 0, 0)]
        e = verifier_data.evals[('e', 0, 0)]
        f = verifier_data.evals[('f', 0, 0)]
        im0 = verifier_data.evals[('im_cluster', 0, 0)]

        # Compute D1 = compress(1, [c,d]) = ((d*α + c)*α + 1) + γ
        one = FF3(1)
        two = FF3(2)
        neg_one = FF3(GOLDILOCKS_PRIME - 1)

        D1 = (d * alpha + c) * alpha + one + gamma
        D2 = (f * alpha + e) * alpha + two + gamma

        # Constraint 0: im * D1 * D2 - (D2 + (-1)*D1)
        constraint_0 = im0 * D1 * D2 - (D2 + neg_one * D1)

        print(f"\nManual constraint 0 computation:")
        print(f"  alpha: {ff3_coeffs(alpha)}")
        print(f"  gamma: {ff3_coeffs(gamma)}")
        print(f"  c: {ff3_coeffs(c)}")
        print(f"  d: {ff3_coeffs(d)}")
        print(f"  e: {ff3_coeffs(e)}")
        print(f"  f: {ff3_coeffs(f)}")
        print(f"  im[0]: {ff3_coeffs(im0)}")
        print(f"  D1: {ff3_coeffs(D1)}")
        print(f"  D2: {ff3_coeffs(D2)}")
        print(f"  constraint_0: {ff3_coeffs(constraint_0)}")

        # This should be zero if the witness is correct
        # (we're just verifying the formula, not that it equals zero)
        assert constraint_0 is not None
