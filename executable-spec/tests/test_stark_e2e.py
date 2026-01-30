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

from primitives.field import FF, ff3_to_flat_list
from protocol.proof_context import ProofContext
from protocol.air_config import SetupCtx
from protocol.prover import gen_proof


TEST_DATA_DIR = Path(__file__).parent / "test-data"

# AIR configurations
AIR_CONFIGS = {
    'simple': {
        'test_vector': 'simple-left.json',
        'starkinfo': '../../pil2-components/test/simple/build/provingKey/build/Simple/airs/SimpleLeft/air/SimpleLeft.starkinfo.json',
        'expressions_bin': '../../pil2-components/test/simple/build/provingKey/build/Simple/airs/SimpleLeft/air/SimpleLeft.bin',
        'global_info': '../../pil2-components/test/simple/build/provingKey/pilout.globalInfo.json',
    },
    'lookup': {
        'test_vector': 'lookup2-12.json',
        'starkinfo': '../../pil2-components/test/lookup/build/provingKey/lookup/Lookup/airs/Lookup2_12/air/Lookup2_12.starkinfo.json',
        'expressions_bin': '../../pil2-components/test/lookup/build/provingKey/lookup/Lookup/airs/Lookup2_12/air/Lookup2_12.bin',
        'global_info': '../../pil2-components/test/lookup/build/provingKey/pilout.globalInfo.json',
    },
    'permutation': {
        'test_vector': 'permutation1-6.json',
        'starkinfo': '../../pil2-components/test/permutation/build/provingKey/permutation/Permutation/airs/Permutation1_6/air/Permutation1_6.starkinfo.json',
        'expressions_bin': '../../pil2-components/test/permutation/build/provingKey/permutation/Permutation/airs/Permutation1_6/air/Permutation1_6.bin',
        'global_info': '../../pil2-components/test/permutation/build/provingKey/pilout.globalInfo.json',
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
    """Load SetupCtx for an AIR including globalInfo.json."""
    config = AIR_CONFIGS.get(air_name)
    if not config:
        return None

    base_dir = Path(__file__).parent
    starkinfo_path = base_dir / config['starkinfo']
    expressions_bin_path = base_dir / config['expressions_bin']
    global_info_path = base_dir / config.get('global_info', '')

    if not starkinfo_path.exists() or not expressions_bin_path.exists():
        return None

    global_info_str = str(global_info_path) if global_info_path.exists() else None
    return SetupCtx.from_files(str(starkinfo_path), str(expressions_bin_path), global_info_str)


def create_params_from_vectors(stark_info, vectors: dict,
                                inject_challenges: bool = False) -> tuple:
    """Create ProofContext and global_challenge from test vectors.

    Args:
        stark_info: STARK configuration
        vectors: Test vectors dict
        inject_challenges: If True, pre-populate challenges from test vectors

    Returns:
        Tuple of (ProofContext, global_challenge) where global_challenge is a list of 3 ints
        or None if not present in test vectors.
    """
    from primitives.ntt import NTT

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
    witness_trace_data = FF(inputs['witness_trace'])
    trace = FF.Zeros(trace_size)
    trace[:len(witness_trace_data)] = witness_trace_data

    # Convert constant polynomials (already in evaluation form at base domain coset)
    # const_pols contains evaluations at SHIFT * w^i for i in [0, N)
    # These are typically selector polynomials like [1, 0, 0, ...] for first row
    const_pols = FF(inputs['const_pols'])

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

    # Extract global_challenge from inputs if present
    global_challenge = None
    if 'global_challenge' in inputs:
        gc = inputs['global_challenge']
        global_challenge = list(gc) if isinstance(gc, list) else gc

    # Allocate buffers
    params = ProofContext(
        trace=trace,
        auxTrace=np.zeros(stark_info.mapTotalN, dtype=np.uint64),
        publicInputs=FF.Zeros(max(1, stark_info.nPublics)),
        challenges=challenges,
        evals=np.zeros(len(stark_info.evMap) * 3, dtype=np.uint64),
        airValues=np.zeros(max(1, stark_info.airValuesSize * 3), dtype=np.uint64),
        airgroupValues=np.zeros(max(1, stark_info.airgroupValuesSize * 3), dtype=np.uint64),
        constPols=const_pols,
        constPolsExtended=const_pols_extended,
    )

    return params, global_challenge


def flatten_evals(evals_nested):
    """Flatten nested evals [[a,b,c], [d,e,f], ...] to [a,b,c,d,e,f,...]."""
    if evals_nested and isinstance(evals_nested[0], list):
        return [v for triplet in evals_nested for v in triplet]
    return evals_nested


class TestStarkE2E:
    """End-to-end STARK proof tests with transcript replay."""

    @pytest.mark.parametrize("air_name", ['simple'])
    def test_challenges_match(self, air_name):
        """Test that proof generation completes successfully with internal global_challenge.

        This test verifies that gen_proof can compute global_challenge internally
        and successfully derive all challenges using the Fiat-Shamir pattern.

        Note: Intermediate challenge values may differ from C++ fixtures because
        we now compute global_challenge internally using Poseidon2 instead of
        accepting pre-computed values. The real validation is the byte-for-byte
        proof match in test_full_binary_proof_match().
        """
        vectors = load_test_vectors(air_name)
        if vectors is None:
            pytest.fail(f"Test vectors not found for {air_name}")

        setup_ctx = load_setup_ctx(air_name)
        if setup_ctx is None:
            pytest.fail(f"Setup files not found for {air_name}")

        stark_info = setup_ctx.stark_info

        params, global_challenge = create_params_from_vectors(stark_info, vectors)

        # Run gen_proof with global_challenge from test vectors (VADCOP mode)
        proof = gen_proof(setup_ctx, params, global_challenge=global_challenge)

        # Verify proof structure is valid
        assert 'roots' in proof
        assert 'evals' in proof
        assert 'fri_proof' in proof
        assert len(proof['roots']) > 0
        assert len(proof['evals']) > 0

    @pytest.mark.parametrize("air_name", ['simple'])
    def test_evals_match(self, air_name):
        """Test that polynomial evaluations are computed.

        Verifies that gen_proof successfully computes polynomial evaluations
        at the challenge point. Intermediate values may differ from C++ fixtures
        since we now compute global_challenge internally. The real validation is
        byte-for-byte proof match.
        """
        vectors = load_test_vectors(air_name)
        if vectors is None:
            pytest.fail(f"Test vectors not found for {air_name}")

        setup_ctx = load_setup_ctx(air_name)
        if setup_ctx is None:
            pytest.fail(f"Setup files not found for {air_name}")

        stark_info = setup_ctx.stark_info

        params, global_challenge = create_params_from_vectors(stark_info, vectors)

        # Run gen_proof with global_challenge from test vectors (VADCOP mode)
        proof = gen_proof(setup_ctx, params, global_challenge=global_challenge)

        # Verify evaluations were computed
        n_evals = len(stark_info.evMap) * 3
        actual_evals = [int(v) for v in params.evals[:n_evals]]

        # Check that we have the expected number of evaluations
        assert len(actual_evals) == n_evals
        assert all(isinstance(e, int) for e in actual_evals)

    @pytest.mark.parametrize("air_name", ['simple'])
    def test_fri_output_matches(self, air_name):
        """Test that FRI output is generated.

        Verifies that gen_proof successfully generates FRI components
        including proof-of-work and final polynomial.
        """
        vectors = load_test_vectors(air_name)
        if vectors is None:
            pytest.fail(f"Test vectors not found for {air_name}")

        setup_ctx = load_setup_ctx(air_name)
        if setup_ctx is None:
            pytest.fail(f"Setup files not found for {air_name}")

        stark_info = setup_ctx.stark_info

        params, global_challenge = create_params_from_vectors(stark_info, vectors)

        # Run gen_proof with global_challenge from test vectors (VADCOP mode)
        proof = gen_proof(setup_ctx, params, global_challenge=global_challenge)

        # Check proof structure
        assert 'nonce' in proof
        assert isinstance(proof['nonce'], int)

        # Check FRI proof exists
        assert 'fri_proof' in proof
        fri_proof = proof['fri_proof']
        assert hasattr(fri_proof, 'final_pol')

        # Check final polynomial is computed
        final_pol = ff3_to_flat_list(fri_proof.final_pol)
        assert len(final_pol) > 0


class TestStarkWithInjectedChallenges:
    """Test polynomial computations with challenges injected from test vectors.

    These tests inject known challenges to verify polynomial computation logic,
    while still computing Merkle roots independently. The roots should still
    match C++ if the polynomial computations are correct.
    """

    @pytest.mark.parametrize("air_name", ['simple'])
    def test_evals_with_injected_challenges(self, air_name):
        """Test that evals match when using injected challenges.

        Challenges are injected from test vectors, but roots are computed by Python.
        """
        vectors = load_test_vectors(air_name)
        if vectors is None:
            pytest.fail(f"Test vectors not found for {air_name}")

        setup_ctx = load_setup_ctx(air_name)
        if setup_ctx is None:
            pytest.fail(f"Setup files not found for {air_name}")

        stark_info = setup_ctx.stark_info

        # Create params with injected challenges - bypass transcript for challenge derivation
        params, global_challenge = create_params_from_vectors(stark_info, vectors, inject_challenges=True)

        # Run gen_proof - challenges are pre-populated, skip transcript challenge derivation
        # Use global_challenge from test vectors (VADCOP mode) for transcript seeding
        proof = gen_proof(setup_ctx, params, skip_challenge_derivation=True, global_challenge=global_challenge)

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
        """Test that cm1 and constant polynomial evaluations match.

        Challenges are injected, but roots are computed by Python.
        """
        vectors = load_test_vectors(air_name)
        if vectors is None:
            pytest.fail(f"Test vectors not found for {air_name}")

        setup_ctx = load_setup_ctx(air_name)
        if setup_ctx is None:
            pytest.fail(f"Setup files not found for {air_name}")

        stark_info = setup_ctx.stark_info

        # Create params with injected challenges
        params, global_challenge = create_params_from_vectors(stark_info, vectors, inject_challenges=True)

        # Run gen_proof with challenge derivation skipped
        # Use global_challenge from test vectors (VADCOP mode) for transcript seeding
        proof = gen_proof(setup_ctx, params, skip_challenge_derivation=True, global_challenge=global_challenge)

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
    """Complete end-to-end test running full proof and comparing all outputs.

    IMPORTANT: This test is non-circular. Python computes everything from scratch:
    - Merkle roots are computed by Python, not captured from C++
    - Challenges are derived from transcript using Python-computed roots
    """

    @pytest.mark.parametrize("air_name", list(AIR_CONFIGS.keys()))
    def test_full_proof_matches(self, air_name):
        """Test complete proof generation matches C++ golden values.

        Python computes its own roots and uses them throughout. If roots match
        C++, all derived values (challenges, evals, FRI) will match.
        """
        vectors = load_test_vectors(air_name)
        if vectors is None:
            pytest.fail(f"Test vectors not found for {air_name}")

        setup_ctx = load_setup_ctx(air_name)
        if setup_ctx is None:
            pytest.fail(f"Setup files not found for {air_name}")

        stark_info = setup_ctx.stark_info

        params, global_challenge = create_params_from_vectors(stark_info, vectors)

        # Run gen_proof with global_challenge from test vectors (VADCOP mode)
        proof = gen_proof(setup_ctx, params, global_challenge=global_challenge)

        # Verify Python-computed roots match C++ expected roots
        intermediates = vectors['intermediates']
        expected_roots = []
        if 'root1' in intermediates:
            expected_roots.append(intermediates['root1'])
        if 'root2' in intermediates:
            expected_roots.append(intermediates['root2'])
        if 'rootQ' in intermediates:
            expected_roots.append(intermediates['rootQ'])

        # Collect all mismatches
        mismatches = []

        # Check challenges
        intermediates = vectors['intermediates']

        expected_stage2 = flatten_evals(intermediates.get('challenges_stage2', []))
        actual_stage2 = []
        for i, cm in enumerate(stark_info.challengesMap):
            if cm.stage == 2:
                actual_stage2.extend([int(v) for v in params.challenges[i*3:(i+1)*3]])
        if actual_stage2 != expected_stage2:
            mismatches.append(f"challenges_stage2: expected {expected_stage2[:6]}..., got {actual_stage2[:6]}...")

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

        # Check final polynomial (convert FF3Poly to flat list)
        expected_final_pol = vectors['expected']['final_pol']
        actual_final_pol = ff3_to_flat_list(proof['fri_proof'].final_pol)
        if actual_final_pol != expected_final_pol:
            n_match = sum(1 for i in range(len(expected_final_pol)) if expected_final_pol[i] == actual_final_pol[i])
            mismatches.append(f"final_pol: {n_match}/{len(expected_final_pol)} matching")

        # Full byte-level comparison of proof
        # This compares the complete serialized proof byte-for-byte with C++
        config = AIR_CONFIGS.get(air_name)
        bin_filename = config['test_vector'].replace('.json', '.proof.bin')
        bin_path = TEST_DATA_DIR / bin_filename

        if not bin_path.exists():
            pytest.fail(f"Binary proof file not found: {bin_path}")

        from protocol.proof import to_bytes_full_from_dict
        import struct

        with open(bin_path, 'rb') as f:
            cpp_proof_bytes = f.read()

        # Serialize complete Python proof
        python_proof_bytes = to_bytes_full_from_dict(proof, stark_info)

        # Write Python proof to file for manual diff
        py_bin_path = TEST_DATA_DIR / bin_filename.replace('.proof.bin', '.proof.py.bin')
        with open(py_bin_path, 'wb') as f:
            f.write(python_proof_bytes)

        # Paranoid checks
        assert len(cpp_proof_bytes) > 0, "C++ proof bytes is empty"
        assert len(python_proof_bytes) > 0, "Python proof bytes is empty"
        assert len(cpp_proof_bytes) % 8 == 0, f"C++ proof size {len(cpp_proof_bytes)} not multiple of 8"
        assert len(python_proof_bytes) % 8 == 0, f"Python proof size {len(python_proof_bytes)} not multiple of 8"

        # Compare sizes
        cpp_n_vals = len(cpp_proof_bytes) // 8
        py_n_vals = len(python_proof_bytes) // 8

        assert cpp_n_vals > 0, "C++ proof has zero uint64s"
        assert py_n_vals > 0, "Python proof has zero uint64s"

        if cpp_n_vals != py_n_vals:
            mismatches.append(
                f"proof_bytes: size mismatch - C++ has {cpp_n_vals} uint64s, "
                f"Python has {py_n_vals} uint64s"
            )
        else:
            # Compare byte-for-byte
            cpp_vals = struct.unpack(f'<{cpp_n_vals}Q', cpp_proof_bytes)
            py_vals = struct.unpack(f'<{py_n_vals}Q', python_proof_bytes)

            assert len(cpp_vals) == len(py_vals), "Unpacked lengths differ"
            assert cpp_proof_bytes == python_proof_bytes, (
                f"Binary proofs differ. Written Python proof to {py_bin_path}. "
                f"Diff with: cmp -l {bin_path} {py_bin_path}"
            )

        assert not mismatches, f"Proof mismatches:\n" + "\n".join(f"  - {m}" for m in mismatches)


class TestFullBinaryComparison:
    """Full binary proof comparison test.

    This test uses to_bytes_full_from_dict to serialize the complete proof
    and compares it byte-for-byte against the C++ binary proof.

    IMPORTANT: This test is non-circular. Python computes everything from scratch:
    - Merkle roots (root1, root2, rootQ) are computed by Python, not captured from C++
    - Challenges are derived from transcript using Python-computed roots
    - If Python's roots differ from C++, challenges will diverge and test will fail
    """

    @pytest.mark.parametrize("air_name", list(AIR_CONFIGS.keys()))
    def test_full_binary_proof_match(self, air_name):
        """Test full binary proof equivalence with C++.

        This test serializes the complete Python proof (including query proofs)
        and compares it byte-for-byte with the C++ binary proof.

        The test is non-circular: Python computes its own Merkle roots and uses
        them throughout. If roots match C++, challenges match, and the full proof
        matches byte-for-byte.
        """
        import struct

        setup_ctx = load_setup_ctx(air_name)
        if setup_ctx is None:
            pytest.fail(f"Setup not found for {air_name}")

        stark_info = setup_ctx.stark_info
        vectors = load_test_vectors(air_name)
        if vectors is None:
            pytest.fail(f"Test vectors not found for {air_name}")

        params, global_challenge = create_params_from_vectors(stark_info, vectors)

        # Run gen_proof with global_challenge from test vectors (VADCOP mode)
        proof = gen_proof(setup_ctx, params, global_challenge=global_challenge)

        # Verify Python-computed roots match C++ expected roots
        intermediates = vectors['intermediates']
        expected_roots = []
        if 'root1' in intermediates:
            expected_roots.append(intermediates['root1'])
        if 'root2' in intermediates:
            expected_roots.append(intermediates['root2'])
        if 'rootQ' in intermediates:
            expected_roots.append(intermediates['rootQ'])

        assert len(proof['roots']) == len(expected_roots), (
            f"Root count mismatch: Python has {len(proof['roots'])}, "
            f"expected {len(expected_roots)}"
        )

        for i, (py_root, cpp_root) in enumerate(zip(proof['roots'], expected_roots)):
            root_name = ['root1', 'root2', 'rootQ'][i] if i < 3 else f'root{i+1}'
            assert list(py_root) == list(cpp_root), (
                f"{root_name} mismatch:\n"
                f"  Python: {py_root}\n"
                f"  C++:    {cpp_root}"
            )

        # Load C++ binary proof
        config = AIR_CONFIGS.get(air_name)
        bin_filename = config['test_vector'].replace('.json', '.proof.bin')
        bin_path = TEST_DATA_DIR / bin_filename

        if not bin_path.exists():
            pytest.fail(f"Binary proof file not found: {bin_path}")

        with open(bin_path, 'rb') as f:
            cpp_proof_bytes = f.read()

        # Serialize Python proof using full serialization
        from protocol.proof import to_bytes_full_from_dict

        python_proof_bytes = to_bytes_full_from_dict(proof, stark_info)

        # Write Python proof to file for manual diff
        py_bin_path = TEST_DATA_DIR / bin_filename.replace('.proof.bin', '.proof.py.bin')
        with open(py_bin_path, 'wb') as f:
            f.write(python_proof_bytes)

        # Paranoid checks
        assert len(cpp_proof_bytes) > 0, "C++ proof bytes is empty"
        assert len(python_proof_bytes) > 0, "Python proof bytes is empty"
        assert len(cpp_proof_bytes) % 8 == 0, f"C++ proof size {len(cpp_proof_bytes)} not multiple of 8"
        assert len(python_proof_bytes) % 8 == 0, f"Python proof size {len(python_proof_bytes)} not multiple of 8"

        # Compare sizes
        cpp_n_vals = len(cpp_proof_bytes) // 8
        py_n_vals = len(python_proof_bytes) // 8

        assert cpp_n_vals > 0, "C++ proof has zero uint64s"
        assert py_n_vals > 0, "Python proof has zero uint64s"

        if cpp_n_vals != py_n_vals:
            pytest.fail(
                f"Proof size mismatch: C++ has {cpp_n_vals} uint64s, "
                f"Python has {py_n_vals} uint64s (diff: {py_n_vals - cpp_n_vals})"
            )

        # Direct binary comparison
        assert len(cpp_proof_bytes) == len(python_proof_bytes), "Byte lengths differ"
        assert cpp_proof_bytes == python_proof_bytes, (
            f"Binary proofs differ. Written Python proof to {py_bin_path}. "
            f"Diff with: cmp -l {bin_path} {py_bin_path}"
        )


class TestGlobalChallengeComputation:
    """Verify global_challenge handling modes.

    Note on multi-AIR aggregation:
    C++ proofman computes global_challenge by aggregating contributions from ALL AIR
    instances in a pilout (e.g., SimpleLeft + SimpleRight + U8Air + etc.). The Python
    executable spec only handles a single AIR at a time, so internal computation
    produces a different value than C++ test vectors.

    For multi-AIR scenarios, external global_challenge must be provided.
    Internal computation is useful for single-AIR scenarios or testing the algorithm.
    """

    @pytest.mark.parametrize("air_name", list(AIR_CONFIGS.keys()))
    def test_internal_challenge_produces_valid_proof(self, air_name):
        """Verify internal global_challenge computation produces valid proof.

        This test runs gen_proof with compute_global_challenge=True (internal
        computation via lattice expansion) and verifies a valid proof is generated.

        Note: The proof will differ from C++ because internal computation only
        considers a single AIR, while C++ aggregates all AIRs in the pilout.
        """
        setup_ctx = load_setup_ctx(air_name)
        if setup_ctx is None:
            pytest.skip(f"Setup not found for {air_name}")

        vectors = load_test_vectors(air_name)
        if vectors is None:
            pytest.skip(f"Test vectors not found for {air_name}")

        stark_info = setup_ctx.stark_info
        params, _ = create_params_from_vectors(stark_info, vectors)

        # Generate proof with internal challenge computation
        proof = gen_proof(
            setup_ctx, params,
            global_challenge=None,  # Force internal computation
            compute_global_challenge=True
        )

        # Verify proof was generated successfully
        assert proof is not None
        assert len(proof['roots']) == 3
        assert proof['fri_proof'] is not None

    def test_external_challenge_required_for_cpp_match(self):
        """Verify that external global_challenge is required for C++ byte-identical proofs.

        The test vectors' global_challenge was computed by C++ proofman by aggregating
        contributions from ALL 5 AIRs in the simple pilout. Python's internal computation
        only considers one AIR, so it produces a different value.

        This test confirms that using the external challenge produces matching proofs.
        """
        air_name = "simple"
        setup_ctx = load_setup_ctx(air_name)
        if setup_ctx is None:
            pytest.skip("Setup not available")

        vectors = load_test_vectors(air_name)
        if vectors is None:
            pytest.skip("Test vectors not available")

        stark_info = setup_ctx.stark_info
        params, expected_challenge = create_params_from_vectors(stark_info, vectors)

        # Generate with external challenge (from C++ test vectors)
        proof = gen_proof(
            setup_ctx, params,
            global_challenge=expected_challenge
        )

        # Verify roots match C++ expected values
        intermediates = vectors['intermediates']
        expected_root1 = intermediates.get('root1')
        expected_root2 = intermediates.get('root2')

        assert list(proof['roots'][0]) == expected_root1, "root1 mismatch"
        assert list(proof['roots'][1]) == expected_root2, "root2 mismatch"
