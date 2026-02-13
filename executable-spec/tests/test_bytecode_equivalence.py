"""Tests that bytecode constraint modules produce identical results to hand-written modules.

Validates the BytecodeConstraintModule adapter by feeding identical VerifierData
to both the hand-written and bytecode modules and comparing constraint polynomial
evaluations at a single point xi.
"""

import json
from pathlib import Path

import numpy as np
import pytest

from constraints import VerifierConstraintContext, get_constraint_module
from constraints.bytecode_adapter import BytecodeConstraintModule
from primitives.field import ff3_coeffs
from protocol.air_config import AirConfig
from protocol.proof import from_bytes_full
from protocol.verifier import _build_verifier_data, _reconstruct_transcript

TEST_DATA_DIR = Path(__file__).parent / "test-data"
BASE_DIR = Path(__file__).parent

# Test AIR configurations: name -> (starkinfo_path, bin_path, test_vector, proof_bin)
AIR_CONFIGS = {
    'SimpleLeft': {
        'starkinfo': '../../pil2-components/test/simple/build/provingKey/build/Simple/airs/SimpleLeft/air/SimpleLeft.starkinfo.json',
        'bin': '../../pil2-components/test/simple/build/provingKey/build/Simple/airs/SimpleLeft/air/SimpleLeft.bin',
        'test_vector': 'simple-left.json',
        'proof_bin': 'simple-left.proof.bin',
    },
    'Lookup2_12': {
        'starkinfo': '../../pil2-components/test/lookup/build/provingKey/lookup/Lookup/airs/Lookup2_12/air/Lookup2_12.starkinfo.json',
        'bin': '../../pil2-components/test/lookup/build/provingKey/lookup/Lookup/airs/Lookup2_12/air/Lookup2_12.bin',
        'test_vector': 'lookup2-12.json',
        'proof_bin': 'lookup2-12.proof.bin',
    },
    'Permutation1_6': {
        'starkinfo': '../../pil2-components/test/permutation/build/provingKey/permutation/Permutation/airs/Permutation1_6/air/Permutation1_6.starkinfo.json',
        'bin': '../../pil2-components/test/permutation/build/provingKey/permutation/Permutation/airs/Permutation1_6/air/Permutation1_6.bin',
        'test_vector': 'permutation1-6.json',
        'proof_bin': 'permutation1-6.proof.bin',
    },
}


def _load_verifier_fixture(air_name: str) -> tuple:
    """Load proof and build VerifierData for a test AIR.

    Returns:
        Tuple of (stark_info, verifier_data) ready for constraint evaluation
    """
    config = AIR_CONFIGS[air_name]
    starkinfo_path = BASE_DIR / config['starkinfo']
    air_config = AirConfig.from_starkinfo(str(starkinfo_path))
    stark_info = air_config.stark_info

    # Load proof
    with open(TEST_DATA_DIR / config['proof_bin'], 'rb') as f:
        proof_bytes = f.read()
    proof = from_bytes_full(proof_bytes, stark_info)

    # Load test vectors for global challenge
    with open(TEST_DATA_DIR / config['test_vector']) as f:
        vectors = json.load(f)

    global_challenge = np.array(vectors['inputs']['global_challenge'], dtype=np.uint64)
    challenges = _reconstruct_transcript(proof, stark_info, global_challenge)

    # Build airgroup_values as interleaved numpy array
    airgroup_values = np.array(
        [v for av in proof.airgroup_values for v in av], dtype=np.uint64
    )

    # Build VerifierData
    evals = np.array(proof.evals, dtype=np.uint64).flatten()
    verifier_data = _build_verifier_data(stark_info, evals, challenges, airgroup_values)

    return stark_info, verifier_data


class TestVerifierConstraintEquivalence:
    """Compare bytecode vs hand-written constraint evaluation in verifier mode."""

    @pytest.mark.parametrize("air_name", list(AIR_CONFIGS.keys()))
    def test_verifier_constraint_matches(self, air_name: str) -> None:
        """Bytecode and hand-written modules produce identical C(xi) for verifier."""
        config = AIR_CONFIGS[air_name]
        bin_path = str(BASE_DIR / config['bin'])

        # Skip if .bin file missing
        if not Path(bin_path).exists():
            pytest.skip(f"Missing {bin_path}")

        stark_info, verifier_data = _load_verifier_fixture(air_name)

        # Hand-written module
        hand_module = get_constraint_module(air_name)
        hand_ctx = VerifierConstraintContext(verifier_data)
        hand_result = hand_module.constraint_polynomial(hand_ctx)

        # Bytecode module
        bytecode_module = BytecodeConstraintModule(bin_path)
        bytecode_ctx = VerifierConstraintContext(verifier_data)
        bytecode_result = bytecode_module.constraint_polynomial(bytecode_ctx)

        # Compare FF3 scalars
        hand_coeffs = ff3_coeffs(hand_result)
        bytecode_coeffs = ff3_coeffs(bytecode_result)

        assert hand_coeffs == bytecode_coeffs, (
            f"Constraint mismatch for {air_name} verifier mode\n"
            f"  hand-written: {hand_coeffs}\n"
            f"  bytecode:     {bytecode_coeffs}\n"
            f"  residual:     {[h - b for h, b in zip(hand_coeffs, bytecode_coeffs)]}"
        )
