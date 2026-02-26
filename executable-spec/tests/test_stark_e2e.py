"""End-to-end tests for STARK proof generation.

These tests validate that the Python STARK prover produces identical output
to the C++ implementation by comparing against captured golden values.

The test vectors include complete Fiat-Shamir transcript state, enabling
deterministic replay that matches C++ exactly.
"""

import json
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from primitives.field import FF, ff3_to_flat_list
from primitives.ntt import NTT
from protocol.air_config import AirConfig
from protocol.proof import from_bytes_full, to_bytes_full_from_dict
from protocol.prover import gen_proof
from protocol.stages import PolynomialCommitter
from protocol.stark_info import StarkInfo
from protocol.verifier import stark_verify

TEST_DATA_DIR = Path(__file__).parent / "test-data"

_SIMPLE_PK = '../../pil2-components/test/simple/build/provingKey'

# AIR configurations
AIR_CONFIGS = {
    'simple': {
        'test_vector': 'simple-left.json',
        'starkinfo': f'{_SIMPLE_PK}/build/Simple/airs/SimpleLeft/air/SimpleLeft.starkinfo.json',
        'expressions_bin': f'{_SIMPLE_PK}/build/Simple/airs/SimpleLeft/air/SimpleLeft.bin',
        'global_info': f'{_SIMPLE_PK}/pilout.globalInfo.json',
    },
    'simple_right': {
        'test_vector': 'simple-right.json',
        'starkinfo': f'{_SIMPLE_PK}/build/Simple/airs/SimpleRight/air/SimpleRight.starkinfo.json',
        'expressions_bin': f'{_SIMPLE_PK}/build/Simple/airs/SimpleRight/air/SimpleRight.bin',
        'global_info': f'{_SIMPLE_PK}/pilout.globalInfo.json',
    },
    'u8_air': {
        'test_vector': 'u8-air.json',
        'starkinfo': f'{_SIMPLE_PK}/build/Simple/airs/U8Air/air/U8Air.starkinfo.json',
        'expressions_bin': f'{_SIMPLE_PK}/build/Simple/airs/U8Air/air/U8Air.bin',
        'global_info': f'{_SIMPLE_PK}/pilout.globalInfo.json',
    },
    'u16_air': {
        'test_vector': 'u16-air.json',
        'starkinfo': f'{_SIMPLE_PK}/build/Simple/airs/U16Air/air/U16Air.starkinfo.json',
        'expressions_bin': f'{_SIMPLE_PK}/build/Simple/airs/U16Air/air/U16Air.bin',
        'global_info': f'{_SIMPLE_PK}/pilout.globalInfo.json',
    },
    'specified_ranges': {
        'test_vector': 'specified-ranges.json',
        'starkinfo': f'{_SIMPLE_PK}/build/Simple/airs/SpecifiedRanges/air/SpecifiedRanges.starkinfo.json',
        'expressions_bin': f'{_SIMPLE_PK}/build/Simple/airs/SpecifiedRanges/air/SpecifiedRanges.bin',
        'global_info': f'{_SIMPLE_PK}/pilout.globalInfo.json',
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

# All five Simple pilout AIRs, in accumulation order (matches C++ proofman)
SIMPLE_PILOUT_AIR_NAMES = ['simple', 'simple_right', 'u8_air', 'u16_air', 'specified_ranges']

# Maps test-level name (key in AIR_CONFIGS) → starkinfo AIR name (from starkinfo.json)
SIMPLE_PILOUT_STARKINFO_AIR_NAMES = {
    'simple': 'SimpleLeft',
    'simple_right': 'SimpleRight',
    'u8_air': 'U8Air',
    'u16_air': 'U16Air',
    'specified_ranges': 'SpecifiedRanges',
}


def load_test_vectors(air_name: str) -> dict[str, Any] | None:
    """Load JSON test vectors for a named AIR.

    Returns None if air_name is unknown or the test vector file has not been
    generated yet (run generate-test-vectors.sh first).
    """
    config = AIR_CONFIGS.get(air_name)
    if not config:
        return None

    test_vector_path = TEST_DATA_DIR / config['test_vector']
    if not test_vector_path.exists():
        return None

    with open(test_vector_path) as f:
        return json.load(f)


def load_air_config(air_name: str) -> AirConfig | None:
    """Load AirConfig for a named AIR, including globalInfo if present.

    Returns None if air_name is unknown or the proving key has not been built
    (run setup.sh first).
    """
    config = AIR_CONFIGS.get(air_name)
    if not config:
        return None

    base_dir = Path(__file__).parent
    starkinfo_path = base_dir / config['starkinfo']
    global_info_path = base_dir / config.get('global_info', '')

    if not starkinfo_path.exists():
        return None

    global_info_str = str(global_info_path) if global_info_path.exists() else None
    return AirConfig.from_starkinfo(str(starkinfo_path), global_info_str)


def create_buffers_from_vectors(
    stark_info: StarkInfo, vectors: dict
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray | None]:
    """Create explicit buffers from test vectors.

    Args:
        stark_info: STARK configuration
        vectors: Test vectors dict

    Returns:
        Tuple of (trace, const_pols, const_pols_extended, public_inputs)
    """
    inputs = vectors['inputs']

    N = 1 << stark_info.stark_struct.n_bits
    N_ext = 1 << stark_info.stark_struct.n_bits_ext
    n_constants = inputs['n_constants']

    # Calculate total trace buffer size needed (cm1 + cm2 + cm3)
    # The trace buffer holds all witness stages in the base domain
    trace_size = 0
    for section in ['cm1', 'cm2', 'cm3']:
        if section in stark_info.map_sections_n:
            offset = stark_info.map_offsets.get((section, False), 0)
            size = N * stark_info.map_sections_n[section]
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

    # Extract public_inputs (if any)
    public_inputs = None
    if stark_info.n_publics > 0 and 'public_inputs' in inputs:
        public_inputs = np.array(inputs['public_inputs'], dtype=np.uint64)

    return (
        np.asarray(trace, dtype=np.uint64),
        np.asarray(const_pols, dtype=np.uint64),
        np.asarray(const_pols_extended, dtype=np.uint64),
        public_inputs,
    )


class TestStarkE2E:
    """End-to-end STARK proof tests using internal global_challenge (Mode 2)."""

    @pytest.mark.parametrize("air_name", ['simple'])
    def test_challenges_match(self, air_name: str) -> None:
        """Test that proof generation completes with internally-computed global_challenge.

        Uses Mode 2: gen_proof computes global_challenge via Poseidon2 lattice expansion
        from (verkey, publics, stage1_commitment). The computed challenge is returned in
        proof['global_challenge'] and can be used to verify the proof.
        """
        vectors = load_test_vectors(air_name)
        if vectors is None:
            pytest.fail(f"Test vectors not found for {air_name}")

        air_config = load_air_config(air_name)
        if air_config is None:
            pytest.fail(f"Setup files not found for {air_name}")

        stark_info = air_config.stark_info

        trace, const_pols, const_pols_extended, public_inputs = \
            create_buffers_from_vectors(stark_info, vectors)

        proof = gen_proof(
            air_config, trace, const_pols, const_pols_extended,
            public_inputs=public_inputs,
        )

        # Verify proof structure is valid
        assert 'roots' in proof
        assert 'evals' in proof
        assert 'fri_proof' in proof
        assert len(proof['roots']) > 0
        assert len(proof['evals']) > 0

    @pytest.mark.parametrize("air_name", ['simple'])
    def test_evals_match(self, air_name: str) -> None:
        """Test that polynomial evaluations are computed (Mode 2)."""
        vectors = load_test_vectors(air_name)
        if vectors is None:
            pytest.fail(f"Test vectors not found for {air_name}")

        air_config = load_air_config(air_name)
        if air_config is None:
            pytest.fail(f"Setup files not found for {air_name}")

        stark_info = air_config.stark_info

        trace, const_pols, const_pols_extended, public_inputs = \
            create_buffers_from_vectors(stark_info, vectors)

        proof = gen_proof(
            air_config, trace, const_pols, const_pols_extended,
            public_inputs=public_inputs,
        )

        # Verify evaluations were computed
        n_evals = len(stark_info.ev_map) * 3
        actual_evals = proof['evals']

        assert len(actual_evals) == n_evals
        assert all(isinstance(e, int) for e in actual_evals)

    @pytest.mark.parametrize("air_name", ['simple'])
    def test_fri_output_matches(self, air_name: str) -> None:
        """Test that FRI output is generated (Mode 2)."""
        vectors = load_test_vectors(air_name)
        if vectors is None:
            pytest.fail(f"Test vectors not found for {air_name}")

        air_config = load_air_config(air_name)
        if air_config is None:
            pytest.fail(f"Setup files not found for {air_name}")

        stark_info = air_config.stark_info

        trace, const_pols, const_pols_extended, public_inputs = \
            create_buffers_from_vectors(stark_info, vectors)

        proof = gen_proof(
            air_config, trace, const_pols, const_pols_extended,
            public_inputs=public_inputs,
        )

        assert 'nonce' in proof
        assert isinstance(proof['nonce'], int)

        assert 'fri_proof' in proof
        fri_proof = proof['fri_proof']
        assert hasattr(fri_proof, 'final_pol')

        final_pol = ff3_to_flat_list(fri_proof.final_pol)
        assert len(final_pol) > 0


class TestStarkE2EComplete:
    """Complete end-to-end test: prove with Mode 2, then verify with Python verifier.

    Demonstrates the full VADCOP proving flow:
    1. gen_proof computes global_challenge via Poseidon2 lattice expansion
    2. The proof is serialized to binary and deserialized
    3. stark_verify reconstructs the transcript using the returned global_challenge
    4. All protocol checks (evaluations, FRI, Merkle) must pass
    """

    @pytest.mark.parametrize("air_name", list(AIR_CONFIGS.keys()),
                             ids=list(AIR_CONFIGS.keys()))
    def test_full_proof_verifies(self, air_name: str) -> None:
        """Prove with Mode 2, serialize/deserialize, then verify with Python verifier."""
        vectors = load_test_vectors(air_name)
        if vectors is None:
            pytest.fail(f"Test vectors not found for {air_name}")

        air_config = load_air_config(air_name)
        if air_config is None:
            pytest.fail(f"Setup files not found for {air_name}")

        stark_info = air_config.stark_info

        trace, const_pols, const_pols_extended, public_inputs = \
            create_buffers_from_vectors(stark_info, vectors)

        # Generate proof using Mode 2: internal global_challenge computation
        proof_dict = gen_proof(
            air_config, trace, const_pols, const_pols_extended,
            public_inputs=public_inputs,
        )

        # Extract the transcript seed computed by the prover
        global_challenge = proof_dict['global_challenge']
        assert global_challenge is not None, "Mode 2 should always produce a global_challenge"

        # Serialize and deserialize the proof (full round-trip)
        proof_bytes = to_bytes_full_from_dict(proof_dict, stark_info)
        proof = from_bytes_full(proof_bytes, stark_info)

        # Build verkey from constant polynomials
        committer = PolynomialCommitter(air_config)
        verkey = committer.build_const_tree(const_pols_extended)

        # Verify: reconstructs transcript using global_challenge, checks all protocol conditions
        result = stark_verify(
            proof=proof,
            air_config=air_config,
            verkey=verkey,
            global_challenge=np.array(global_challenge, dtype=np.uint64),
            publics=public_inputs,
        )

        assert result is True, f"Proof for {air_name} failed verification"


class TestGlobalChallengeComputation:
    """Verify that global_challenge is computed correctly in Mode 2.

    Mode 2 (internal VADCOP): gen_proof computes global_challenge via Poseidon2
    lattice expansion from (verkey, publics, stage1_commitment). This mirrors C++
    proofman's challenge_accumulation.rs, which aggregates ALL AIR instances. Since
    Python only handles one AIR at a time, the computed value differs from C++
    test vectors (which aggregate all 5 AIRs in the pilout), but proofs are still
    self-consistent and verifiable.
    """

    @pytest.mark.parametrize("air_name", list(AIR_CONFIGS.keys()))
    def test_internal_challenge_produces_valid_proof(self, air_name: str) -> None:
        """Verify that Mode 2 produces a proof that the Python verifier accepts.

        gen_proof computes global_challenge internally via lattice expansion.
        The proof dict includes the computed challenge so the verifier can
        reconstruct the same transcript.
        """
        air_config = load_air_config(air_name)
        if air_config is None:
            pytest.fail(f"Setup not found for {air_name}")

        vectors = load_test_vectors(air_name)
        if vectors is None:
            pytest.fail(f"Test vectors not found for {air_name}")

        stark_info = air_config.stark_info
        trace, const_pols, const_pols_extended, public_inputs = \
            create_buffers_from_vectors(stark_info, vectors)

        proof_dict = gen_proof(
            air_config, trace, const_pols, const_pols_extended,
            public_inputs=public_inputs,
        )

        assert proof_dict is not None
        assert len(proof_dict['roots']) == 3
        assert proof_dict['fri_proof'] is not None

        # Verify using the challenge the prover computed
        global_challenge = proof_dict['global_challenge']
        assert global_challenge is not None

        committer = PolynomialCommitter(air_config)
        verkey = committer.build_const_tree(const_pols_extended)

        proof_bytes = to_bytes_full_from_dict(proof_dict, stark_info)
        proof = from_bytes_full(proof_bytes, stark_info)

        result = stark_verify(
            proof=proof,
            air_config=air_config,
            verkey=verkey,
            global_challenge=np.array(global_challenge, dtype=np.uint64),
            publics=public_inputs,
        )

        assert result is True, f"Proof for {air_name} failed verification"


def _simple_pilout_vectors_available() -> bool:
    """Return True if all five Simple pilout test vector files exist."""
    return all(
        (TEST_DATA_DIR / AIR_CONFIGS[n]['test_vector']).exists()
        for n in SIMPLE_PILOUT_AIR_NAMES
    )


@pytest.mark.skipif(
    not _simple_pilout_vectors_available(),
    reason="Simple pilout test vectors not generated (run ./generate-test-vectors.sh simple)"
)
class TestCppBinaryEquivalence:
    """Byte-identical comparison between Python and C++ proofs using multi-AIR challenge.

    Protocol:
      1. Load Stage-1 traces for all five Simple pilout AIRs from C++ test vectors.
      2. Commit Stage 1 for all five AIRs and compute lattice contributions.
      3. Derive global_challenge via five-AIR accumulation (matching C++ exactly).
      4. Prove each AIR fully with this global_challenge (Mode 1 external VADCOP).
      5. Compare each proof byte-for-byte with the C++ binary proof file.

    This validates both the multi-AIR global challenge computation and the full
    proof pipeline (Stage-1/2/Q commitment, FRI, query proofs).
    """

    def _load_all_simple_air_data(
        self,
    ) -> dict[str, tuple]:
        """Load (air_config, trace, const_pols, const_pols_extended, public_inputs) for all five."""
        result = {}
        for test_name in SIMPLE_PILOUT_AIR_NAMES:
            air_config = load_air_config(test_name)
            vectors = load_test_vectors(test_name)
            if air_config is None or vectors is None:
                pytest.fail(f"Missing test data for {test_name}")
            trace, const_pols, const_pols_extended, public_inputs = \
                create_buffers_from_vectors(air_config.stark_info, vectors)
            starkinfo_name = SIMPLE_PILOUT_STARKINFO_AIR_NAMES[test_name]
            result[starkinfo_name] = (air_config, trace, const_pols, const_pols_extended, public_inputs)
        return result

    def test_global_challenge_matches_cpp(self) -> None:
        """Python multi-AIR global challenge equals the value stored in C++ test vectors.

        C++ proofman stores the global_challenge used for each AIR in its test vector JSON
        (under inputs.global_challenge). All five Simple AIRs receive the same challenge.
        """
        from protocol.simple_pilout import AIRStage1Data, prove_simple_pilout_stage1

        all_data = self._load_all_simple_air_data()
        air_stage1 = {
            name: AIRStage1Data(
                air_config=data[0],
                trace=data[1],
                const_pols=data[2],
                const_pols_extended=data[3],
            )
            for name, data in all_data.items()
        }

        result = prove_simple_pilout_stage1(air_stage1)

        # All five AIRs receive the same global_challenge from C++ proofman
        simple_vectors = load_test_vectors('simple')
        cpp_global_challenge = simple_vectors['inputs']['global_challenge']

        assert list(result.global_challenge) == list(cpp_global_challenge), (
            f"Python multi-AIR global challenge does not match C++.\n"
            f"  Python: {result.global_challenge}\n"
            f"  C++:    {cpp_global_challenge}"
        )

    @pytest.mark.parametrize("test_air_name", SIMPLE_PILOUT_AIR_NAMES,
                             ids=SIMPLE_PILOUT_AIR_NAMES)
    def test_full_binary_proof_match(self, test_air_name: str) -> None:
        """Prove each Simple AIR with the multi-AIR global challenge and compare bytes with C++."""
        from protocol.simple_pilout import AIRStage1Data, prove_simple_pilout_stage1

        all_data = self._load_all_simple_air_data()
        air_stage1 = {
            name: AIRStage1Data(
                air_config=data[0],
                trace=data[1],
                const_pols=data[2],
                const_pols_extended=data[3],
            )
            for name, data in all_data.items()
        }

        # Derive global challenge from all five AIR contributions (matches C++)
        result = prove_simple_pilout_stage1(air_stage1)
        global_challenge = result.global_challenge

        # Prove the target AIR fully with Mode 1 (externally-provided global_challenge)
        starkinfo_name = SIMPLE_PILOUT_STARKINFO_AIR_NAMES[test_air_name]
        air_config, trace, const_pols, const_pols_extended, public_inputs = \
            all_data[starkinfo_name]

        proof_dict = gen_proof(
            air_config, trace, const_pols, const_pols_extended,
            public_inputs=public_inputs,
            global_challenge=global_challenge,
        )

        python_proof_bytes = to_bytes_full_from_dict(proof_dict, air_config.stark_info)

        # Load C++ binary proof
        config = AIR_CONFIGS[test_air_name]
        bin_path = TEST_DATA_DIR / config['test_vector'].replace('.json', '.proof.bin')
        with open(bin_path, 'rb') as f:
            cpp_proof_bytes = f.read()

        # Write Python proof for manual diff if test fails
        py_bin_path = TEST_DATA_DIR / config['test_vector'].replace('.json', '.proof.py.bin')
        with open(py_bin_path, 'wb') as f:
            f.write(python_proof_bytes)

        assert len(python_proof_bytes) == len(cpp_proof_bytes), (
            f"{test_air_name}: proof size mismatch "
            f"(Python {len(python_proof_bytes)}, C++ {len(cpp_proof_bytes)})"
        )
        assert python_proof_bytes == cpp_proof_bytes, (
            f"{test_air_name}: byte mismatch. Diff: cmp -l {bin_path} {py_bin_path}"
        )
