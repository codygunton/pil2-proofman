"""End-to-end tests for STARK proof generation.

These tests validate that the Python STARK prover produces identical output
to the C++ implementation by comparing against captured golden values.

The test vectors include complete Fiat-Shamir transcript state, enabling
deterministic replay that matches C++ exactly.
"""

import json
import pytest
import numpy as np
from pathlib import Path
from typing import Dict, Any, Optional

from tests.setup_ctx import SetupCtx
from tests.steps_params import StepsParams
from primitives.transcript import Transcript
from tests.gen_proof import gen_proof


TEST_DATA_DIR = Path(__file__).parent / "test-data"

# AIR configurations
AIR_CONFIGS = {
    'simple': {
        'test_vector': 'simple-left.json',
        'starkinfo': '../pil2-components/test/simple/build/provingKey/build/Simple/airs/SimpleLeft/air/SimpleLeft.starkinfo.json',
        'expressions_bin': '../pil2-components/test/simple/build/provingKey/build/Simple/airs/SimpleLeft/air/SimpleLeft.bin',
    },
    'lookup': {
        'test_vector': 'lookup2-12.json',
        'starkinfo': '../pil2-components/test/lookup/build/provingKey/lookup/Lookup/airs/Lookup2_12/air/Lookup2_12.starkinfo.json',
        'expressions_bin': '../pil2-components/test/lookup/build/provingKey/lookup/Lookup/airs/Lookup2_12/air/Lookup2_12.bin',
    },
    'permutation': {
        'test_vector': 'permutation1-6.json',
        'starkinfo': '../pil2-components/test/permutation/build/provingKey/permutation/Permutation/airs/Permutation1_6/air/Permutation1_6.starkinfo.json',
        'expressions_bin': '../pil2-components/test/permutation/build/provingKey/permutation/Permutation/airs/Permutation1_6/air/Permutation1_6.bin',
    },
}


def load_test_vectors(air_name: str) -> Optional[Dict[str, Any]]:
    """Load test vectors for an AIR."""
    config = AIR_CONFIGS.get(air_name)
    if not config:
        return None

    test_vector_path = TEST_DATA_DIR / config['test_vector']
    if not test_vector_path.exists():
        return None

    with open(test_vector_path) as f:
        return json.load(f)


def load_setup_ctx(air_name: str) -> Optional[SetupCtx]:
    """Load SetupCtx for an AIR."""
    config = AIR_CONFIGS.get(air_name)
    if not config:
        return None

    base_dir = Path(__file__).parent
    starkinfo_path = base_dir / config['starkinfo']
    expressions_bin_path = base_dir / config['expressions_bin']

    if not starkinfo_path.exists() or not expressions_bin_path.exists():
        return None

    return SetupCtx.from_files(str(starkinfo_path), str(expressions_bin_path))


def create_transcript_from_state(stark_info, state_dict: dict,
                                  pending_data: list = None) -> Transcript:
    """Create a Transcript initialized to the captured state.

    Args:
        stark_info: STARK configuration
        state_dict: Captured transcript state with state, out, cursors
        pending_data: Data in the pending buffer (e.g., global_challenge)
    """
    transcript = Transcript(
        arity=stark_info.starkStruct.transcriptArity,
        custom=stark_info.starkStruct.merkleTreeCustom
    )

    # Build pending buffer: pad pending_data to full size
    pending = [0] * transcript.transcript_out_size
    if pending_data:
        for i, v in enumerate(pending_data):
            if i < len(pending):
                pending[i] = v

    transcript.set_state(
        state=state_dict['state'],
        out=state_dict['out'],
        out_cursor=state_dict['out_cursor'],
        pending_cursor=state_dict['pending_cursor'],
        pending=pending
    )
    return transcript


def get_captured_roots(vectors: dict, exclude_root1: bool = False) -> dict:
    """Extract captured Merkle roots from test vectors.

    Args:
        vectors: Test vectors dict
        exclude_root1: If True, don't include root1. Use this when the transcript
                      state was captured AFTER root1 was absorbed.
    """
    intermediates = vectors.get('intermediates', {})
    roots = {}
    if 'root1' in intermediates and not exclude_root1:
        roots['root1'] = intermediates['root1']
    if 'root2' in intermediates:
        roots['root2'] = intermediates['root2']
    if 'rootQ' in intermediates:
        roots['rootQ'] = intermediates['rootQ']
    return roots


def create_params_from_vectors(stark_info, vectors: dict,
                                inject_challenges: bool = False) -> StepsParams:
    """Create StepsParams initialized from test vectors.

    Args:
        stark_info: STARK configuration
        vectors: Test vectors dict
        inject_challenges: If True, pre-populate challenges from test vectors
    """
    from ntt import NTT

    inputs = vectors['inputs']
    intermediates = vectors.get('intermediates', {})

    N = 1 << stark_info.starkStruct.nBits
    N_ext = 1 << stark_info.starkStruct.nBitsExt
    n_constants = inputs['n_constants']

    # Calculate total trace buffer size needed (cm1 + cm2 + cm3)
    # The trace buffer holds all witness stages in the base domain
    trace_size = 0
    for section in ['cm1', 'cm2', 'cm3']:
        if section in stark_info.mapSectionsN:
            offset = stark_info.mapOffsets.get((section, False), 0)
            size = N * stark_info.mapSectionsN[section]
            trace_size = max(trace_size, offset + size)

    # Allocate full trace buffer and copy witness trace into cm1 portion
    witness_trace_data = np.array(inputs['witness_trace'], dtype=np.uint64)
    trace = np.zeros(trace_size, dtype=np.uint64)
    trace[:len(witness_trace_data)] = witness_trace_data

    # Convert constant polynomials (already in evaluation form at base domain coset)
    # const_pols contains evaluations at SHIFT * w^i for i in [0, N)
    # These are typically selector polynomials like [1, 0, 0, ...] for first row
    const_pols = np.array(inputs['const_pols'], dtype=np.uint64)

    # Extend constant polynomials from N to N_ext
    ntt = NTT(N)
    const_pols_extended = ntt.extend_pol(const_pols, N_ext, N, n_constants)

    # Allocate challenges buffer
    challenges = np.zeros(len(stark_info.challengesMap) * 3, dtype=np.uint64)

    # Optionally inject captured challenges
    if inject_challenges:
        # Stage 2 challenges
        stage2_challenges = intermediates.get('challenges_stage2', [])
        for i, cm in enumerate(stark_info.challengesMap):
            if cm.stage == 2 and cm.stageId < len(stage2_challenges):
                for j, v in enumerate(stage2_challenges[cm.stageId]):
                    challenges[i * 3 + j] = v

        # Stage Q challenges
        stageQ_challenges = intermediates.get('challenges_stageQ', [])
        for i, cm in enumerate(stark_info.challengesMap):
            if cm.stage == stark_info.nStages + 1 and cm.stageId < len(stageQ_challenges):
                for j, v in enumerate(stageQ_challenges[cm.stageId]):
                    challenges[i * 3 + j] = v

        # Xi challenge (stage nStages + 2)
        xi_challenge = intermediates.get('xi_challenge', [])
        if xi_challenge:
            for i, cm in enumerate(stark_info.challengesMap):
                if cm.stage == stark_info.nStages + 2 and cm.stageId == 0:
                    for j, v in enumerate(xi_challenge):
                        challenges[i * 3 + j] = v

        # FRI challenges (stage nStages + 3)
        fri_challenges = intermediates.get('challenges_fri', [])
        for i, cm in enumerate(stark_info.challengesMap):
            if cm.stage == stark_info.nStages + 3 and cm.stageId < len(fri_challenges):
                for j, v in enumerate(fri_challenges[cm.stageId]):
                    challenges[i * 3 + j] = v

    # Allocate buffers
    params = StepsParams(
        trace=trace,
        auxTrace=np.zeros(stark_info.mapTotalN, dtype=np.uint64),
        publicInputs=np.zeros(max(1, stark_info.nPublics), dtype=np.uint64),
        challenges=challenges,
        evals=np.zeros(len(stark_info.evMap) * 3, dtype=np.uint64),
        airValues=np.zeros(max(1, stark_info.airValuesSize * 3), dtype=np.uint64),
        airgroupValues=np.zeros(max(1, stark_info.airgroupValuesSize * 3), dtype=np.uint64),
        constPols=const_pols,
        constPolsExtended=const_pols_extended,
    )

    return params


def flatten_evals(evals_nested):
    """Flatten nested evals [[a,b,c], [d,e,f], ...] to [a,b,c,d,e,f,...]."""
    if evals_nested and isinstance(evals_nested[0], list):
        return [v for triplet in evals_nested for v in triplet]
    return evals_nested


class TestStarkE2E:
    """End-to-end STARK proof tests with transcript replay."""

    @pytest.mark.parametrize("air_name", ['simple'])
    def test_challenges_match(self, air_name):
        """Test that Fiat-Shamir challenges match C++ golden values."""
        vectors = load_test_vectors(air_name)
        if vectors is None:
            pytest.skip(f"Test vectors not found for {air_name}")

        setup_ctx = load_setup_ctx(air_name)
        if setup_ctx is None:
            pytest.skip(f"Setup files not found for {air_name}")

        stark_info = setup_ctx.stark_info

        # Create transcript with captured state
        transcript_state = vectors['inputs'].get('transcript_state_step0')
        if transcript_state is None:
            pytest.skip(f"transcript_state_step0 not in test vectors for {air_name}")

        global_challenge = vectors['inputs'].get('global_challenge', [])
        transcript = create_transcript_from_state(stark_info, transcript_state, global_challenge)

        # Create params
        params = create_params_from_vectors(stark_info, vectors)

        # Run gen_proof with initialized transcript
        # Note: transcript_state_step0 is captured AFTER root1 was absorbed,
        # so we exclude root1 from captured_roots to avoid adding it twice
        captured_roots = get_captured_roots(vectors, exclude_root1=True)
        proof = gen_proof(setup_ctx, params, transcript=transcript, captured_roots=captured_roots)

        # Check challenges
        intermediates = vectors['intermediates']

        # Check stage 2 challenges
        expected_stage2 = intermediates.get('challenges_stage2', [])
        if expected_stage2:
            expected_flat = flatten_evals(expected_stage2)
            actual = []
            for i, cm in enumerate(stark_info.challengesMap):
                if cm.stage == 2:
                    actual.extend(list(params.challenges[i*3:(i+1)*3]))

            assert actual == expected_flat, f"Stage 2 challenges mismatch"

        # Check stage Q challenges
        expected_stageQ = intermediates.get('challenges_stageQ', [])
        if expected_stageQ:
            expected_flat = flatten_evals(expected_stageQ)
            actual = []
            for i, cm in enumerate(stark_info.challengesMap):
                if cm.stage == stark_info.nStages + 1:
                    actual.extend(list(params.challenges[i*3:(i+1)*3]))

            assert actual == expected_flat, f"Stage Q challenges mismatch"

    @pytest.mark.parametrize("air_name", ['simple'])
    def test_evals_match(self, air_name):
        """Test that polynomial evaluations match C++ golden values."""
        vectors = load_test_vectors(air_name)
        if vectors is None:
            pytest.skip(f"Test vectors not found for {air_name}")

        setup_ctx = load_setup_ctx(air_name)
        if setup_ctx is None:
            pytest.skip(f"Setup files not found for {air_name}")

        stark_info = setup_ctx.stark_info

        # Create transcript with captured state
        transcript_state = vectors['inputs'].get('transcript_state_step0')
        if transcript_state is None:
            pytest.skip(f"transcript_state_step0 not in test vectors for {air_name}")

        global_challenge = vectors['inputs'].get('global_challenge', [])
        transcript = create_transcript_from_state(stark_info, transcript_state, global_challenge)
        params = create_params_from_vectors(stark_info, vectors)

        # Run gen_proof
        # Note: transcript_state_step0 is captured AFTER root1 was absorbed
        captured_roots = get_captured_roots(vectors, exclude_root1=True)
        proof = gen_proof(setup_ctx, params, transcript=transcript, captured_roots=captured_roots)

        # Check evals
        expected_evals = vectors['intermediates'].get('evals', [])
        expected_flat = flatten_evals(expected_evals)

        n_evals = len(stark_info.evMap) * 3
        actual_evals = [int(v) for v in params.evals[:n_evals]]

        # Count matches
        n_match = sum(1 for i in range(len(expected_flat)) if expected_flat[i] == actual_evals[i])

        assert actual_evals == expected_flat, (
            f"Evals mismatch: {n_match}/{len(expected_flat)} matching. "
            f"First expected: {expected_flat[:6]}, First actual: {actual_evals[:6]}"
        )

    @pytest.mark.parametrize("air_name", ['simple'])
    def test_fri_output_matches(self, air_name):
        """Test that FRI output matches C++ golden values."""
        vectors = load_test_vectors(air_name)
        if vectors is None:
            pytest.skip(f"Test vectors not found for {air_name}")

        setup_ctx = load_setup_ctx(air_name)
        if setup_ctx is None:
            pytest.skip(f"Setup files not found for {air_name}")

        stark_info = setup_ctx.stark_info

        # Create transcript with captured state
        transcript_state = vectors['inputs'].get('transcript_state_step0')
        if transcript_state is None:
            pytest.skip(f"transcript_state_step0 not in test vectors for {air_name}")

        global_challenge = vectors['inputs'].get('global_challenge', [])
        transcript = create_transcript_from_state(stark_info, transcript_state, global_challenge)
        params = create_params_from_vectors(stark_info, vectors)

        # Run gen_proof
        # Note: transcript_state_step0 is captured AFTER root1 was absorbed
        captured_roots = get_captured_roots(vectors, exclude_root1=True)
        proof = gen_proof(setup_ctx, params, transcript=transcript, captured_roots=captured_roots)

        # Check nonce
        expected_nonce = vectors['expected']['nonce']
        actual_nonce = proof['nonce']
        assert actual_nonce == expected_nonce, f"Nonce mismatch: expected {expected_nonce}, got {actual_nonce}"

        # Check final polynomial
        expected_final_pol = vectors['expected']['final_pol']
        actual_final_pol = [int(v) for v in proof['fri_proof'].final_pol]

        assert actual_final_pol == expected_final_pol, (
            f"Final polynomial mismatch. "
            f"First 6 expected: {expected_final_pol[:6]}, First 6 actual: {actual_final_pol[:6]}"
        )


class TestStarkWithInjectedChallenges:
    """Test polynomial computations with challenges injected from test vectors.

    This bypasses the transcript timing complexity (captured state is before roots
    are added) to verify the polynomial computation logic is correct given
    the expected challenges.
    """

    @pytest.mark.parametrize("air_name", ['simple'])
    def test_evals_with_injected_challenges(self, air_name):
        """Test that evals match when using injected challenges."""
        vectors = load_test_vectors(air_name)
        if vectors is None:
            pytest.skip(f"Test vectors not found for {air_name}")

        setup_ctx = load_setup_ctx(air_name)
        if setup_ctx is None:
            pytest.skip(f"Setup files not found for {air_name}")

        stark_info = setup_ctx.stark_info

        # Create params with injected challenges - bypass transcript entirely
        params = create_params_from_vectors(stark_info, vectors, inject_challenges=True)

        # Create transcript (won't be used for challenges, just for FRI)
        transcript_state = vectors['inputs'].get('transcript_state_step0')
        global_challenge = vectors['inputs'].get('global_challenge', [])
        transcript = create_transcript_from_state(stark_info, transcript_state, global_challenge)

        # Run gen_proof - challenges are pre-populated, skip transcript challenge derivation
        captured_roots = get_captured_roots(vectors)
        proof = gen_proof(setup_ctx, params, transcript=transcript, captured_roots=captured_roots,
                         skip_challenge_derivation=True)

        # Check that stage 2 challenges match (they were injected)
        intermediates = vectors['intermediates']
        expected_stage2 = flatten_evals(intermediates.get('challenges_stage2', []))
        if expected_stage2:
            actual = []
            for i, cm in enumerate(stark_info.challengesMap):
                if cm.stage == 2:
                    actual.extend([int(v) for v in params.challenges[i*3:(i+1)*3]])
            assert actual == expected_stage2, f"Stage 2 challenges injection failed"

        # Check evals
        expected_evals = flatten_evals(intermediates.get('evals', []))
        n_evals = len(stark_info.evMap) * 3
        actual_evals = [int(v) for v in params.evals[:n_evals]]

        n_match = sum(1 for i in range(len(expected_evals)) if expected_evals[i] == actual_evals[i])
        assert actual_evals == expected_evals, (
            f"Evals mismatch: {n_match}/{len(expected_evals)} matching. "
            f"First expected: {expected_evals[:6]}, First actual: {actual_evals[:6]}"
        )


class TestStarkPartialEvals:
    """Test evaluations that don't require witness STD computation.

    Stage 2 (gsum) polynomials require witness STD calculation which
    isn't implemented in Python. This test verifies cm1 and const
    polynomial evaluations which can be computed from available data.
    """

    @pytest.mark.parametrize("air_name", ['simple'])
    def test_cm1_and_const_evals(self, air_name):
        """Test that cm1 and constant polynomial evaluations match."""
        vectors = load_test_vectors(air_name)
        if vectors is None:
            pytest.skip(f"Test vectors not found for {air_name}")

        setup_ctx = load_setup_ctx(air_name)
        if setup_ctx is None:
            pytest.skip(f"Setup files not found for {air_name}")

        stark_info = setup_ctx.stark_info

        # Create params with injected challenges
        params = create_params_from_vectors(stark_info, vectors, inject_challenges=True)

        # Create transcript (not used for challenges)
        transcript_state = vectors['inputs'].get('transcript_state_step0')
        global_challenge = vectors['inputs'].get('global_challenge', [])
        transcript = create_transcript_from_state(stark_info, transcript_state, global_challenge)

        # Run gen_proof with challenge derivation skipped
        captured_roots = get_captured_roots(vectors)
        proof = gen_proof(setup_ctx, params, transcript=transcript, captured_roots=captured_roots,
                         skip_challenge_derivation=True)

        # Identify testable evaluations (cm1 and const only)
        testable_eval_indices = []
        for i, ev in enumerate(stark_info.evMap):
            if ev.type.name == 'cm':
                pol = stark_info.cmPolsMap[ev.id]
                if pol.stage == 1:
                    testable_eval_indices.append(i)
            elif ev.type.name == 'const_':
                testable_eval_indices.append(i)

        # Get expected evals
        expected_evals = vectors['intermediates'].get('evals', [])
        expected_flat = flatten_evals(expected_evals)

        # Check only testable evaluations
        mismatches = []
        matches = 0
        for idx in testable_eval_indices:
            actual_triplet = [int(params.evals[idx * 3 + j]) for j in range(3)]
            expected_triplet = expected_flat[idx * 3:(idx + 1) * 3]
            if actual_triplet == expected_triplet:
                matches += 1
            else:
                ev = stark_info.evMap[idx]
                mismatches.append(f"eval[{idx}] ({ev.type.name}): expected {expected_triplet}, got {actual_triplet}")

        assert matches == len(testable_eval_indices), (
            f"cm1/const evals: {matches}/{len(testable_eval_indices)} matching.\n"
            f"Mismatches:\n" + "\n".join(mismatches[:5])
        )


class TestStarkE2EComplete:
    """Complete end-to-end test running full proof and comparing all outputs."""

    @pytest.mark.parametrize("air_name", ['simple'])
    def test_full_proof_matches(self, air_name):
        """Test complete proof generation matches C++ golden values."""
        vectors = load_test_vectors(air_name)
        if vectors is None:
            pytest.skip(f"Test vectors not found for {air_name}")

        setup_ctx = load_setup_ctx(air_name)
        if setup_ctx is None:
            pytest.skip(f"Setup files not found for {air_name}")

        stark_info = setup_ctx.stark_info

        # Create transcript with captured state
        transcript_state = vectors['inputs'].get('transcript_state_step0')
        if transcript_state is None:
            pytest.skip(f"transcript_state_step0 not in test vectors for {air_name}")

        global_challenge = vectors['inputs'].get('global_challenge', [])
        transcript = create_transcript_from_state(stark_info, transcript_state, global_challenge)
        params = create_params_from_vectors(stark_info, vectors)

        # Run gen_proof
        # Note: transcript_state_step0 is captured AFTER root1 was absorbed
        captured_roots = get_captured_roots(vectors, exclude_root1=True)
        proof = gen_proof(setup_ctx, params, transcript=transcript, captured_roots=captured_roots)

        # Collect all mismatches
        mismatches = []

        # Check challenges
        intermediates = vectors['intermediates']

        expected_stage2 = flatten_evals(intermediates.get('challenges_stage2', []))
        if expected_stage2:
            actual = []
            for i, cm in enumerate(stark_info.challengesMap):
                if cm.stage == 2:
                    actual.extend([int(v) for v in params.challenges[i*3:(i+1)*3]])
            if actual != expected_stage2:
                mismatches.append(f"challenges_stage2: expected {expected_stage2[:6]}..., got {actual[:6]}...")

        # Check evals
        expected_evals = flatten_evals(intermediates.get('evals', []))
        actual_evals = [int(v) for v in params.evals[:len(expected_evals)]]
        if actual_evals != expected_evals:
            n_match = sum(1 for i in range(len(expected_evals)) if expected_evals[i] == actual_evals[i])
            mismatches.append(f"evals: {n_match}/{len(expected_evals)} matching")

        # Check nonce
        expected_nonce = vectors['expected']['nonce']
        if proof['nonce'] != expected_nonce:
            mismatches.append(f"nonce: expected {expected_nonce}, got {proof['nonce']}")

        # Check final polynomial
        expected_final_pol = vectors['expected']['final_pol']
        actual_final_pol = [int(v) for v in proof['fri_proof'].final_pol]
        if actual_final_pol != expected_final_pol:
            n_match = sum(1 for i in range(len(expected_final_pol)) if expected_final_pol[i] == actual_final_pol[i])
            mismatches.append(f"final_pol: {n_match}/{len(expected_final_pol)} matching")

        assert not mismatches, f"Proof mismatches:\n" + "\n".join(f"  - {m}" for m in mismatches)
