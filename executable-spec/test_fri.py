# FRI tests - validates Python FRI matches C++ exactly.
# Run with: python -m pytest executable-spec/test_fri.py -v
"""
FRI pinning and end-to-end tests.

These tests validate that the Python FRI implementation produces
byte-identical outputs to the C++ implementation by comparing
Python-computed values against C++ captured golden values.
"""

import pytest

from merkle_tree import MerkleTree
from transcript import Transcript
from fri import FRI
from fri_pcs import FriPcs, FriPcsConfig
from poseidon2_ffi import linear_hash

from test_vectors import (
    get_config,
    get_expected_final_pol,
    get_expected_hash,
    get_expected_nonce,
    get_fri_challenges,
    get_grinding_challenge,
    get_fri_steps,
    get_n_bits_ext,
    get_fri_queries,
    get_fri_input_polynomial,
    get_fri_input_hash,
    get_poly_hashes_after_fold,
    get_merkle_roots,
    get_query_proof_siblings,
    get_transcript_state,
)

# =============================================================================
# End-to-end prove tests (lookup only - simple has no folding)
# =============================================================================

class TestProveEndToEnd:
    """
    End-to-end prove test for Lookup2_12.

    This test validates that calling FriPcs.prove() with captured
    transcript state and input polynomial produces byte-identical
    output to C++.
    """

    @pytest.fixture(autouse=True)
    def setup(self):
        """Load all Lookup2_12 test vectors."""
        self.config = get_config('lookup')
        self.input_pol = get_fri_input_polynomial('lookup')
        self.fri_challenges = get_fri_challenges('lookup')
        self.expected_final_pol = get_expected_final_pol('lookup')
        self.expected_nonce = get_expected_nonce('lookup')
        self.merkle_roots = get_merkle_roots('lookup')
        self.transcript_state = get_transcript_state('lookup')
        self.fri_steps = get_fri_steps('lookup')
        self.n_bits_ext = get_n_bits_ext('lookup')

    def _create_fri_pcs(self):
        """Create FriPcs with config."""
        return FriPcs(FriPcsConfig(
            n_bits_ext=self.n_bits_ext,
            fri_steps=self.fri_steps,
            n_queries=self.config['n_queries'],
            merkle_arity=self.config['merkle_arity'],
            pow_bits=self.config['pow_bits'],
            transcript_arity=self.config['transcript_arity'],
            hash_commits=self.config['hash_commits'],
        ))

    def _create_primed_transcript(self):
        """Create transcript primed with captured state."""
        transcript = Transcript(arity=self.config['transcript_arity'])
        transcript.state = list(self.transcript_state['state'])
        transcript.out = list(self.transcript_state['out'])
        transcript.out_cursor = self.transcript_state['out_cursor']
        transcript.pending_cursor = self.transcript_state['pending_cursor']
        transcript.pending = [0] * transcript.transcript_out_size
        return transcript

    def test_prove_complete_match(self):
        """
        COMPLETE END-TO-END TEST.

        Validates ALL outputs from prove() match C++ exactly:
        - fri_roots (weakest - just hashes)
        - nonce (medium - depends on grinding challenge)
        - final_pol (strongest - depends on all prior steps)

        If this test passes, Python FRI is byte-identical to C++ FRI.
        """
        fri_pcs = self._create_fri_pcs()
        transcript = self._create_primed_transcript()
        proof = fri_pcs.prove(self.input_pol, transcript)

        # Assert from weakest to strongest
        assert len(proof.fri_roots) == len(self.merkle_roots)
        for i in range(len(proof.fri_roots)):
            assert proof.fri_roots[i] == self.merkle_roots[i], f"FRI root {i} mismatch"

        assert proof.nonce == self.expected_nonce

        assert proof.final_pol == self.expected_final_pol

    def test_prove_challenges_match(self):
        """
        Test that transcript generates the same challenges as C++.

        C++ FRI flow:
        1. put(root[0]), get_field() -> c0, fold, merkelize -> root1
        2. put(root[1]), get_field() -> c1, fold, merkelize -> root2
        3. put(root[2]), get_field() -> c2, fold (final)
        4. put(hash(final_pol)), get_state(3) -> grinding_challenge
        """
        transcript = self._create_primed_transcript()

        generated_challenges = []

        # Steps 0, 1, 2: put root, get challenge
        for i in range(len(self.merkle_roots)):
            transcript.put(self.merkle_roots[i])
            challenge = transcript.get_field()
            generated_challenges.append(challenge)

        # Step 3 (final): put final_pol hash, then get_state for grinding
        sponge_width = self.config['transcript_arity'] * 4  # HASH_SIZE = 4
        final_hash = linear_hash(self.expected_final_pol, sponge_width)
        transcript.put(final_hash)
        grinding_challenge = transcript.get_state(3)
        generated_challenges.append(grinding_challenge)

        # Compare to expected challenges
        for i, (generated, expected) in enumerate(zip(generated_challenges, self.fri_challenges)):
            assert generated == expected, f"Challenge {i} mismatch"


# Run with: python -m pytest executable-spec/test_fri.py -v

# =============================================================================
# Parameterized unit tests (simple + lookup)
# =============================================================================

@pytest.mark.parametrize("air_name", ["simple", "lookup", "permutation"])
def test_final_polynomial_hash(air_name):
    """Test that linear_hash(final_pol) matches C++ captured hash."""
    expected_pol = get_expected_final_pol(air_name)
    expected_hash = get_expected_hash(air_name)
    computed_hash = linear_hash(expected_pol, width=16)
    assert computed_hash == expected_hash


@pytest.mark.parametrize("air_name", ["simple", "lookup", "permutation"])
def test_query_indices_derivation(air_name):
    """Test query index derivation matches C++ exactly."""
    expected_queries = get_fri_queries(air_name)
    config = get_config(air_name)
    grinding_challenge = get_grinding_challenge(air_name)
    nonce = get_expected_nonce(air_name)

    query_transcript = Transcript(arity=config['transcript_arity'])
    query_transcript.put(grinding_challenge)
    query_transcript.put([nonce])

    actual_queries = query_transcript.get_permutations(
        config['n_queries'], config['fri_steps'][0]
    )

    assert actual_queries == expected_queries


# =============================================================================
# FRI folding tests (lookup only - simple has no folding)
# =============================================================================

class TestFRIFolding:
    """
    FRI folding validation tests for Lookup2_12.

    Lookup2_12 performs actual FRI folding: 2^13 -> 2^10 -> 2^7 -> 2^5.
    These tests validate Python FRI.fold() produces identical output to C++.
    """

    @pytest.fixture(autouse=True)
    def setup(self):
        """Load Lookup2_12 vectors from JSON."""
        self.input_pol = get_fri_input_polynomial('lookup')
        self.input_hash = get_fri_input_hash('lookup')
        self.challenges = get_fri_challenges('lookup')
        self.fri_steps = get_fri_steps('lookup')
        self.n_bits_ext = get_n_bits_ext('lookup')

    def _compute_final_polynomial(self):
        """Compute final polynomial through all FRI folds."""
        current_pol = list(self.input_pol)
        for fold_idx in range(len(self.fri_steps) - 1):
            current_pol = FRI.fold(
                step=fold_idx,
                pol=current_pol,
                challenge=self.challenges[fold_idx],
                n_bits_ext=self.n_bits_ext,
                prev_bits=self.fri_steps[fold_idx],
                current_bits=self.fri_steps[fold_idx + 1]
            )
        return current_pol

    def test_input_polynomial_hash_matches(self):
        """Verify input polynomial hash matches C++ captured value."""
        computed_hash = linear_hash(self.input_pol, width=16)
        assert computed_hash == self.input_hash

    def test_final_polynomial_matches_expected(self):
        """CRITICAL TEST: Verify final folded polynomial matches C++ golden values."""
        computed = self._compute_final_polynomial()
        expected = get_expected_final_pol('lookup')
        assert computed == expected

    def test_final_polynomial_hash_matches(self):
        """Verify hash of folded polynomial matches expected hash."""
        computed_hash = linear_hash(self._compute_final_polynomial(), width=16)
        expected_hash = get_expected_hash('lookup')
        assert computed_hash == expected_hash

    def test_intermediate_polynomial_hashes(self):
        """Verify polynomial hash after EACH fold step matches C++ captured values."""
        expected_hashes = get_poly_hashes_after_fold('lookup')
        assert expected_hashes, "Intermediate polynomial hashes not captured"
        assert expected_hashes[0] == self.input_hash

        current_pol = list(self.input_pol)
        for fold_idx in range(len(self.fri_steps) - 1):
            current_pol = FRI.fold(
                step=fold_idx + 1,
                pol=current_pol,
                challenge=self.challenges[fold_idx],
                n_bits_ext=self.n_bits_ext,
                prev_bits=self.fri_steps[fold_idx],
                current_bits=self.fri_steps[fold_idx + 1]
            )

            cpp_step_idx = fold_idx + 1
            if cpp_step_idx < len(expected_hashes):
                computed_hash = linear_hash(current_pol, width=16)
                assert computed_hash == expected_hashes[cpp_step_idx]

    def test_merkle_roots_match_cpp(self):
        """Verify Python Merkle tree roots match C++ captured values."""
        expected_roots = get_merkle_roots('lookup')
        assert expected_roots, "Merkle roots not captured"

        current_pol = list(self.input_pol)
        for step_idx in range(len(self.fri_steps) - 1):
            tree = MerkleTree(arity=4)
            computed_root = FRI.merkelize(
                step=step_idx,
                pol=current_pol,
                tree=tree,
                current_bits=self.fri_steps[step_idx],
                next_bits=self.fri_steps[step_idx + 1]
            )

            if step_idx < len(expected_roots):
                assert computed_root == expected_roots[step_idx]

            current_pol = FRI.fold(
                step=step_idx,
                pol=current_pol,
                challenge=self.challenges[step_idx],
                n_bits_ext=self.n_bits_ext,
                prev_bits=self.fri_steps[step_idx],
                current_bits=self.fri_steps[step_idx + 1]
            )

    def test_query_proof_siblings_match_cpp(self):
        """Verify Python Merkle proof extraction matches C++ exactly.

        This validates that MerkleTree.get_group_proof() produces
        byte-identical sibling hashes to C++ MerkleTreeGL::getGroupProof().
        """
        expected_siblings = get_query_proof_siblings('lookup')
        if not expected_siblings:
            pytest.skip("Query proof siblings not captured in test vectors")

        queries = get_fri_queries('lookup')
        assert queries, "FRI queries not available"

        config = get_config('lookup')

        # Build step 0 tree with correct configuration
        tree = MerkleTree(
            arity=config.get('merkle_arity', 4),
            last_level_verification=config.get('last_level_verification', 0),
            custom=config.get('merkle_tree_custom', False)
        )
        current_bits = self.fri_steps[0]
        next_bits = self.fri_steps[1]

        FRI.merkelize(
            step=0,
            pol=self.input_pol,
            tree=tree,
            current_bits=current_bits,
            next_bits=next_bits
        )

        # Get proof for first query (same index C++ uses)
        query_idx = queries[0]
        proof_idx = query_idx % (1 << next_bits)
        computed_siblings = tree.get_group_proof(proof_idx)

        assert computed_siblings == expected_siblings, (
            f"Query proof siblings mismatch at idx={proof_idx}"
        )
