"""
FRI Polynomial Commitment Tests
===============================

Run: uv run python -m pytest test_fri.py -v

Tests the FRI (Fast Reed-Solomon IOP) layer of the STARK prover.
Validates Python FRI produces byte-identical outputs to C++.

What these tests cover:
    - FriPcs.prove(): Merkle commitment, folding, grinding, query generation
    - FRI.fold(): Polynomial folding with random challenges
    - MerkleTree: Tree construction and proof generation
    - Transcript: Fiat-Shamir challenge derivation

What these tests do NOT cover:
    - Witness polynomial extension (stage 1)
    - Intermediate polynomial computation (stage 2)
    - Quotient polynomial computation (stage Q)
    - Full gen_proof() flow from witness to proof

The tests use fri_input_polynomial captured from C++ as input. This polynomial
is the OUTPUT of the earlier STARK stages. To test the full STARK prover,
a separate test starting from raw witness_trace would be needed.

AIRs Tested:
    - simple (SimpleLeft): 8 rows, no FRI folding
    - lookup (Lookup2_12): 4096 rows, 4 FRI folding steps
    - permutation (Permutation1_6): 64 rows, 2 FRI folding steps
"""

import pytest

from primitives.field import ff3_from_flat_list, ff3_to_flat_list
from primitives.merkle_tree import MerkleTree
from primitives.transcript import Transcript
from protocol.fri import FRI
from protocol.pcs import FriPcs, FriPcsConfig
from poseidon2_ffi import linear_hash

from tests.fri_vectors import (
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
# FRI End-to-End Tests - Runs FriPcs.prove(), compares against C++ golden values
# =============================================================================

@pytest.mark.parametrize("air_name", ["simple", "lookup", "permutation"])
class TestProveEndToEnd:
    """
    FRI prover end-to-end test.

    For each AIR:
        1. Loads fri_input_polynomial captured from C++ (output of earlier STARK stages)
        2. Primes transcript with C++ captured state
        3. Runs FriPcs.prove() - the Python FRI prover
        4. Compares ALL FRI outputs against C++ golden values:
           - fri_roots (Merkle commitments at each fold step)
           - final_pol (polynomial after all FRI folds)
           - nonce (proof-of-work grinding result)

    If this test passes, Python FRI is byte-identical to C++ FRI.
    """

    @pytest.fixture(autouse=True)
    def setup(self, air_name):
        """Load test vectors for the AIR."""
        self.air_name = air_name
        self.config = get_config(air_name)
        # Convert input polynomial from flat list to FF3Poly (FriPcs.prove expects FF3Poly)
        input_pol_flat = get_fri_input_polynomial(air_name)
        self.input_pol = ff3_from_flat_list(input_pol_flat)
        self.fri_challenges = get_fri_challenges(air_name)
        # Keep expected as flat list for comparison
        self.expected_final_pol = get_expected_final_pol(air_name)
        self.expected_nonce = get_expected_nonce(air_name)
        self.merkle_roots = get_merkle_roots(air_name)
        self.transcript_state = get_transcript_state(air_name)
        self.fri_steps = get_fri_steps(air_name)
        self.n_bits_ext = get_n_bits_ext(air_name)

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

    def test_prove_complete_match(self, air_name):
        """
        COMPLETE END-TO-END TEST.

        Validates ALL outputs from prove() match C++ exactly:
        - fri_roots (weakest - just hashes, empty for simple AIR)
        - nonce (medium - depends on grinding challenge)
        - final_pol (strongest - depends on all prior steps)

        If this test passes, Python FRI is byte-identical to C++ FRI.
        """
        fri_pcs = self._create_fri_pcs()
        transcript = self._create_primed_transcript()
        proof = fri_pcs.prove(self.input_pol, transcript)

        # Assert from weakest to strongest
        # For simple AIR, merkle_roots is empty (no folding steps)
        assert len(proof.fri_roots) == len(self.merkle_roots), \
            f"Expected {len(self.merkle_roots)} FRI roots, got {len(proof.fri_roots)}"
        for i in range(len(proof.fri_roots)):
            assert proof.fri_roots[i] == self.merkle_roots[i], f"FRI root {i} mismatch"

        assert proof.nonce == self.expected_nonce, \
            f"Nonce mismatch: expected {self.expected_nonce}, got {proof.nonce}"

        # Convert FF3Poly to flat list for comparison
        actual_final_pol = ff3_to_flat_list(proof.final_pol)
        assert actual_final_pol == self.expected_final_pol, \
            f"Final polynomial mismatch (length: expected {len(self.expected_final_pol)}, got {len(actual_final_pol)})"

    def test_prove_challenges_match(self, air_name):
        """
        Test that transcript generates the same challenges as C++.

        C++ FRI flow:
        1. put(root[i]), get_field() -> challenge[i], fold, merkelize -> root[i+1]
        2. ... repeat for each fold step
        3. put(hash(final_pol)), get_state(3) -> grinding_challenge
        """
        transcript = self._create_primed_transcript()

        generated_challenges = []

        # Put each root, get challenge
        for i in range(len(self.merkle_roots)):
            transcript.put(self.merkle_roots[i])
            challenge = transcript.get_field()
            generated_challenges.append(challenge)

        # Final: put final_pol hash, then get_state for grinding
        sponge_width = self.config['transcript_arity'] * 4  # HASH_SIZE = 4
        final_hash = linear_hash(self.expected_final_pol, sponge_width)
        transcript.put(final_hash)
        grinding_challenge = transcript.get_state(3)
        generated_challenges.append(grinding_challenge)

        # Compare to expected challenges
        for i, (generated, expected) in enumerate(zip(generated_challenges, self.fri_challenges)):
            assert generated == expected, f"Challenge {i} mismatch"


# =============================================================================
# Component validation tests - Hash and transcript functions
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
# Detailed FRI folding tests - Validates intermediate steps (lookup, permutation only)
# =============================================================================

@pytest.mark.parametrize("air_name", ["lookup", "permutation"])
class TestFRIFolding:
    """
    Detailed FRI folding validation - tests individual operations.

    These tests validate intermediate steps of the FRI protocol:
    - Input polynomial hashing
    - Step-by-step folding
    - Merkle tree construction at each step
    - Query proof generation

    Only runs on AIRs with FRI folding (lookup, permutation).
    Simple AIR has no folding so is covered by TestProveEndToEnd only.
    """

    @pytest.fixture(autouse=True)
    def setup(self, air_name):
        """Load vectors from JSON."""
        self.air_name = air_name
        self.input_pol = get_fri_input_polynomial(air_name)
        self.input_hash = get_fri_input_hash(air_name)
        self.challenges = get_fri_challenges(air_name)
        self.fri_steps = get_fri_steps(air_name)
        self.n_bits_ext = get_n_bits_ext(air_name)
        self.config = get_config(air_name)

    def _compute_final_polynomial(self):
        """Compute final polynomial through all FRI folds."""
        current_pol = ff3_from_flat_list(self.input_pol)
        for fold_idx in range(len(self.fri_steps) - 1):
            current_pol = FRI.fold(
                step=fold_idx,
                pol=current_pol,
                challenge=self.challenges[fold_idx],
                n_bits_ext=self.n_bits_ext,
                prev_bits=self.fri_steps[fold_idx],
                current_bits=self.fri_steps[fold_idx + 1]
            )
        return ff3_to_flat_list(current_pol)

    def test_input_polynomial_hash_matches(self, air_name):
        """Verify input polynomial hash matches C++ captured value."""
        computed_hash = linear_hash(self.input_pol, width=16)
        assert computed_hash == self.input_hash

    def test_final_polynomial_matches_expected(self, air_name):
        """CRITICAL TEST: Verify final folded polynomial matches C++ golden values."""
        computed = self._compute_final_polynomial()
        expected = get_expected_final_pol(air_name)
        assert computed == expected

    def test_final_polynomial_hash_matches(self, air_name):
        """Verify hash of folded polynomial matches expected hash."""
        computed_hash = linear_hash(self._compute_final_polynomial(), width=16)
        expected_hash = get_expected_hash(air_name)
        assert computed_hash == expected_hash

    def test_intermediate_polynomial_hashes(self, air_name):
        """Verify polynomial hash after EACH fold step matches C++ captured values."""
        expected_hashes = get_poly_hashes_after_fold(air_name)
        if not expected_hashes:
            pytest.fail(f"Intermediate polynomial hashes not captured for {air_name}")

        assert expected_hashes[0] == self.input_hash

        current_pol = ff3_from_flat_list(self.input_pol)
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
                computed_hash = linear_hash(ff3_to_flat_list(current_pol), width=16)
                assert computed_hash == expected_hashes[cpp_step_idx]

    def test_merkle_roots_match_cpp(self, air_name):
        """Verify Python Merkle tree roots match C++ captured values."""
        expected_roots = get_merkle_roots(air_name)
        if not expected_roots:
            pytest.fail(f"Merkle roots not captured for {air_name}")

        current_pol = ff3_from_flat_list(self.input_pol)
        for step_idx in range(len(self.fri_steps) - 1):
            tree = MerkleTree(arity=self.config.get('merkle_arity', 4))
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

    def test_query_proof_siblings_match_cpp(self, air_name):
        """Verify Python Merkle proof extraction matches C++ exactly.

        This validates that MerkleTree.get_group_proof() produces
        byte-identical sibling hashes to C++ MerkleTreeGL::getGroupProof().
        """
        expected_siblings = get_query_proof_siblings(air_name)
        if not expected_siblings:
            pytest.fail(f"Query proof siblings not captured for {air_name}")

        queries = get_fri_queries(air_name)
        assert queries, "FRI queries not available"

        # Build step 0 tree with correct configuration
        tree = MerkleTree(
            arity=self.config.get('merkle_arity', 4),
            last_level_verification=self.config.get('last_level_verification', 0),
            custom=self.config.get('merkle_tree_custom', False)
        )
        current_bits = self.fri_steps[0]
        next_bits = self.fri_steps[1]

        FRI.merkelize(
            step=0,
            pol=ff3_from_flat_list(self.input_pol),
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
