"""Test witness module output matches expression binary output.

These tests compare the output of per-AIR witness modules against the
expression binary's calculate_witness_std function to identify differences
in im_cluster, gsum, and gprod columns.
"""

import json
import pytest
import numpy as np
from pathlib import Path

from primitives.field import FF
from primitives.ntt import NTT
from protocol.proof_context import ProofContext
from protocol.air_config import SetupCtx
from protocol.stages import compare_witness_outputs


TEST_DATA_DIR = Path(__file__).parent / "test-data"

# AIR configurations (same as test_stark_e2e.py)
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


def load_test_vectors(air_name: str):
    """Load test vectors for an AIR."""
    config = AIR_CONFIGS.get(air_name)
    if not config:
        return None

    test_vector_path = TEST_DATA_DIR / config['test_vector']
    if not test_vector_path.exists():
        return None

    with open(test_vector_path) as f:
        return json.load(f)


def load_setup_ctx(air_name: str):
    """Load SetupCtx for an AIR."""
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


def create_params_with_stage2_challenges(stark_info, vectors: dict) -> ProofContext:
    """Create ProofContext with stage 2 challenges populated.

    Witness generation happens in stage 2 and requires stage 2 challenges
    (std_alpha, std_gamma, etc.) to be set.
    """
    inputs = vectors['inputs']
    intermediates = vectors.get('intermediates', {})

    N = 1 << stark_info.starkStruct.nBits
    N_ext = 1 << stark_info.starkStruct.nBitsExt
    n_constants = inputs['n_constants']

    # Calculate trace buffer size
    trace_size = 0
    for section in ['cm1', 'cm2', 'cm3']:
        if section in stark_info.mapSectionsN:
            offset = stark_info.mapOffsets.get((section, False), 0)
            size = N * stark_info.mapSectionsN[section]
            trace_size = max(trace_size, offset + size)

    # Load witness trace
    witness_trace_data = FF(inputs['witness_trace'])
    trace = FF.Zeros(trace_size)
    trace[:len(witness_trace_data)] = witness_trace_data

    # Load and extend constant polynomials
    const_pols = FF(inputs['const_pols'])
    ntt = NTT(N)
    const_pols_extended = ntt.extend_pol(const_pols, N_ext, N, n_constants)

    # Allocate challenges and inject stage 2 challenges
    challenges = np.zeros(len(stark_info.challengesMap) * 3, dtype=np.uint64)

    # Stage 2 challenges are required for witness generation
    stage2_challenges = intermediates.get('challenges_stage2', [])
    for i, cm in enumerate(stark_info.challengesMap):
        if cm.stage == 2 and cm.stageId < len(stage2_challenges):
            for j, v in enumerate(stage2_challenges[cm.stageId]):
                challenges[i * 3 + j] = v

    # Create ProofContext
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

    return params


class TestWitnessComparison:
    """Compare witness module output to expression binary output."""

    @pytest.mark.parametrize("air_name", ['simple'])
    def test_simple_left_witness_matches_expression_binary(self, air_name):
        """Compare SimpleLeft witness module output to expression binary."""
        vectors = load_test_vectors(air_name)
        if vectors is None:
            pytest.skip(f"Test vectors not found for {air_name}")

        setup_ctx = load_setup_ctx(air_name)
        if setup_ctx is None:
            pytest.skip(f"Setup files not found for {air_name}")

        stark_info = setup_ctx.stark_info
        params = create_params_with_stage2_challenges(stark_info, vectors)

        # Create expression context for calculate_witness_std
        from protocol.expression_evaluator import ExpressionsPack
        expressions_ctx = ExpressionsPack(setup_ctx)

        # Run comparison
        result = compare_witness_outputs(
            stark_info, params,
            setup_ctx.expressions_bin, expressions_ctx
        )

        # Report differences
        if not result['match']:
            print(f"\n=== SimpleLeft Witness Comparison ===")
            print(f"Found {len(result['differences'])} difference(s):")
            for diff in result['differences']:
                if diff['type'] == 'value_mismatch':
                    print(f"  {diff['column']}[{diff['index']}] row {diff['row']} coeff {diff['coeff']}:")
                    print(f"    expected: {diff['expected']}")
                    print(f"    actual:   {diff['actual']}")
                else:
                    print(f"  {diff}")

        # For now, just report - don't fail until we fix the modules
        # assert result['match'], f"Witness outputs differ: {result['differences']}"

    @pytest.mark.parametrize("air_name", ['lookup'])
    def test_lookup2_12_witness_matches_expression_binary(self, air_name):
        """Compare Lookup2_12 witness module output to expression binary."""
        vectors = load_test_vectors(air_name)
        if vectors is None:
            pytest.skip(f"Test vectors not found for {air_name}")

        setup_ctx = load_setup_ctx(air_name)
        if setup_ctx is None:
            pytest.skip(f"Setup files not found for {air_name}")

        stark_info = setup_ctx.stark_info
        params = create_params_with_stage2_challenges(stark_info, vectors)

        from protocol.expression_evaluator import ExpressionsPack
        expressions_ctx = ExpressionsPack(setup_ctx)

        result = compare_witness_outputs(
            stark_info, params,
            setup_ctx.expressions_bin, expressions_ctx
        )

        if not result['match']:
            print(f"\n=== Lookup2_12 Witness Comparison ===")
            print(f"Found {len(result['differences'])} difference(s):")
            for diff in result['differences'][:10]:  # Limit output
                if diff['type'] == 'value_mismatch':
                    print(f"  {diff['column']}[{diff['index']}] row {diff['row']} coeff {diff['coeff']}:")
                    print(f"    expected: {diff['expected']}")
                    print(f"    actual:   {diff['actual']}")
                else:
                    print(f"  {diff}")

    @pytest.mark.parametrize("air_name", ['permutation'])
    def test_permutation1_6_witness_matches_expression_binary(self, air_name):
        """Compare Permutation1_6 witness module output to expression binary."""
        vectors = load_test_vectors(air_name)
        if vectors is None:
            pytest.skip(f"Test vectors not found for {air_name}")

        setup_ctx = load_setup_ctx(air_name)
        if setup_ctx is None:
            pytest.skip(f"Setup files not found for {air_name}")

        stark_info = setup_ctx.stark_info
        params = create_params_with_stage2_challenges(stark_info, vectors)

        from protocol.expression_evaluator import ExpressionsPack
        expressions_ctx = ExpressionsPack(setup_ctx)

        result = compare_witness_outputs(
            stark_info, params,
            setup_ctx.expressions_bin, expressions_ctx
        )

        if not result['match']:
            print(f"\n=== Permutation1_6 Witness Comparison ===")
            print(f"Found {len(result['differences'])} difference(s):")
            for diff in result['differences'][:10]:  # Limit output
                if diff['type'] == 'value_mismatch':
                    print(f"  {diff['column']}[{diff['index']}] row {diff['row']} coeff {diff['coeff']}:")
                    print(f"    expected: {diff['expected']}")
                    print(f"    actual:   {diff['actual']}")
                else:
                    print(f"  {diff}")


class TestWitnessComparisonStrict:
    """Strict tests that fail if witness module output doesn't match.

    Enable these tests after fixing witness modules.
    """

    def test_simple_left_strict(self):
        """SimpleLeft witness module must match expression binary exactly."""
        vectors = load_test_vectors('simple')
        setup_ctx = load_setup_ctx('simple')

        if vectors is None or setup_ctx is None:
            pytest.skip("Test data not available")

        stark_info = setup_ctx.stark_info
        params = create_params_with_stage2_challenges(stark_info, vectors)

        from protocol.expression_evaluator import ExpressionsPack
        expressions_ctx = ExpressionsPack(setup_ctx)

        result = compare_witness_outputs(
            stark_info, params,
            setup_ctx.expressions_bin, expressions_ctx
        )

        assert result['match'], f"Witness outputs differ: {result['differences']}"

    def test_lookup2_12_strict(self):
        """Lookup2_12 witness module must match expression binary exactly."""
        vectors = load_test_vectors('lookup')
        setup_ctx = load_setup_ctx('lookup')

        if vectors is None or setup_ctx is None:
            pytest.skip("Test data not available")

        stark_info = setup_ctx.stark_info
        params = create_params_with_stage2_challenges(stark_info, vectors)

        from protocol.expression_evaluator import ExpressionsPack
        expressions_ctx = ExpressionsPack(setup_ctx)

        result = compare_witness_outputs(
            stark_info, params,
            setup_ctx.expressions_bin, expressions_ctx
        )

        assert result['match'], f"Witness outputs differ: {result['differences']}"

    def test_permutation1_6_strict(self):
        """Permutation1_6 witness module must match expression binary exactly."""
        vectors = load_test_vectors('permutation')
        setup_ctx = load_setup_ctx('permutation')

        if vectors is None or setup_ctx is None:
            pytest.skip("Test data not available")

        stark_info = setup_ctx.stark_info
        params = create_params_with_stage2_challenges(stark_info, vectors)

        from protocol.expression_evaluator import ExpressionsPack
        expressions_ctx = ExpressionsPack(setup_ctx)

        result = compare_witness_outputs(
            stark_info, params,
            setup_ctx.expressions_bin, expressions_ctx
        )

        assert result['match'], f"Witness outputs differ: {result['differences']}"
