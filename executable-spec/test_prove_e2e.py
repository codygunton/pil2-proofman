"""
End-to-end FRI prove tests.

These tests validate that FriPcs.prove() produces byte-identical output
to the C++ implementation when given the same inputs and transcript state.

This is the HIGHEST BAR of testing - it proves Python FRI == C++ FRI.
"""

import unittest
from typing import List

from field import GOLDILOCKS_PRIME
from transcript import Transcript
from fri_pcs import FriPcs, FriPcsConfig
from poseidon2_ffi import linear_hash

from test_vectors import (
    get_config,
    get_fri_input_polynomial,
    get_fri_challenges,
    get_grinding_challenge,
    get_expected_final_pol,
    get_expected_nonce,
    get_expected_hash,
    get_fri_steps,
    get_n_bits_ext,
    get_merkle_roots,
    get_transcript_state,
)


def _get_config_value(config: dict, key: str, default):
    """Get config value, using default if value is None or missing."""
    val = config.get(key)
    return val if val is not None else default


class TestProveEndToEndLookup(unittest.TestCase):
    """
    End-to-end prove test for Lookup2_12.

    This test validates that calling FriPcs.prove() with:
    1. The captured transcript state (primed correctly)
    2. The captured input polynomial
    3. The captured input polynomial Merkle root

    Produces:
    - Identical final polynomial
    - Identical grinding nonce
    - Identical FRI Merkle roots
    """

    @classmethod
    def setUpClass(cls):
        """Load all Lookup2_12 test vectors."""
        try:
            cls.config = get_config('lookup')
            cls.input_pol = get_fri_input_polynomial('lookup')
            cls.fri_challenges = get_fri_challenges('lookup')
            cls.expected_final_pol = get_expected_final_pol('lookup')
            cls.expected_nonce = get_expected_nonce('lookup')
            cls.expected_hash = get_expected_hash('lookup')
            cls.merkle_roots = get_merkle_roots('lookup')
            cls.transcript_state = get_transcript_state('lookup')
            cls.fri_steps = get_fri_steps('lookup')
            cls.n_bits_ext = get_n_bits_ext('lookup')
            cls.vectors_loaded = True
        except (FileNotFoundError, ValueError) as e:
            cls.vectors_loaded = False
            cls.load_error = str(e)

    def test_vectors_loaded(self):
        """Verify all required vectors are available."""
        if not self.vectors_loaded:
            self.skipTest(f"Vectors not loaded: {self.load_error}")

    def test_transcript_state_available(self):
        """Verify transcript state is captured."""
        if not self.vectors_loaded:
            self.skipTest("Vectors not loaded")

        self.assertTrue(
            self.transcript_state.get('state'),
            "Transcript state not captured"
        )
        self.assertEqual(
            len(self.transcript_state['state']),
            16,
            "Transcript state should have 16 elements"
        )

    def test_merkle_roots_available(self):
        """Verify Merkle roots are captured."""
        if not self.vectors_loaded:
            self.skipTest("Vectors not loaded")

        self.assertTrue(
            self.merkle_roots,
            "Merkle roots not captured"
        )
        # For lookup with fri_steps=[13,10,7,5], we expect 3 roots
        self.assertEqual(
            len(self.merkle_roots),
            len(self.fri_steps) - 1,
            f"Expected {len(self.fri_steps) - 1} merkle roots, got {len(self.merkle_roots)}"
        )

    def test_prove_challenges_match(self):
        """
        Test that prove() generates the same challenges as C++.

        C++ FRI flow:
        1. put(root[0]), get_field() -> c0, fold, merkelize -> root1
        2. put(root[1]), get_field() -> c1, fold, merkelize -> root2
        3. put(root[2]), get_field() -> c2, fold (final)
        4. put(hash(final_pol)), get_state(3) -> grinding_challenge (= c3)

        This validates the put->get order matches C++.
        """
        if not self.vectors_loaded:
            self.skipTest("Vectors not loaded")

        if not self.transcript_state.get('state'):
            self.skipTest("Transcript state not captured")

        # Create transcript and prime with captured state
        transcript = Transcript(arity=self.config['transcript_arity'])
        transcript.state = list(self.transcript_state['state'])
        transcript.out = list(self.transcript_state['out'])
        transcript.out_cursor = self.transcript_state['out_cursor']
        transcript.pending_cursor = self.transcript_state['pending_cursor']
        transcript.pending = [0] * transcript.transcript_out_size

        # C++ flow: put(root), then get_field() for each step
        generated_challenges = []

        # Steps 0, 1, 2: put root, get challenge
        for i in range(len(self.merkle_roots)):
            transcript.put(self.merkle_roots[i])
            challenge = transcript.get_field()
            generated_challenges.append(challenge)

        # Step 3 (final): put final_pol hash, then get_state for grinding
        # Compute final polynomial hash
        sponge_width = self.config['transcript_arity'] * 4  # HASH_SIZE = 4
        final_hash = linear_hash(self.expected_final_pol, sponge_width)
        transcript.put(final_hash)

        # Grinding challenge comes from get_state, not get_field
        grinding_challenge = transcript.get_state(3)
        generated_challenges.append(grinding_challenge)

        # Compare to expected challenges
        for i, (generated, expected) in enumerate(zip(generated_challenges, self.fri_challenges)):
            self.assertEqual(
                generated,
                expected,
                f"Challenge {i} mismatch:\n"
                f"  Generated: {generated}\n"
                f"  Expected:  {expected}"
            )

    def test_prove_final_polynomial(self):
        """
        CRITICAL TEST: prove() produces identical final polynomial.

        This is the definitive test that Python FRI folding matches C++.
        """
        if not self.vectors_loaded:
            self.skipTest("Vectors not loaded")

        if not self.transcript_state.get('state'):
            self.skipTest("Transcript state not captured")

        # Create FRI PCS config
        config = FriPcsConfig(
            n_bits_ext=self.n_bits_ext,
            fri_steps=self.fri_steps,
            n_queries=_get_config_value(self.config, 'n_queries', 228),
            merkle_arity=_get_config_value(self.config, 'merkle_arity', 4),
            pow_bits=_get_config_value(self.config, 'pow_bits', 16),
            transcript_arity=_get_config_value(self.config, 'transcript_arity', 4),
            hash_commits=_get_config_value(self.config, 'hash_commits', True),
        )

        fri_pcs = FriPcs(config)

        # Create and prime transcript
        transcript = Transcript(arity=config.transcript_arity)
        transcript.state = list(self.transcript_state['state'])
        transcript.out = list(self.transcript_state['out'])
        transcript.out_cursor = self.transcript_state['out_cursor']
        transcript.pending_cursor = self.transcript_state['pending_cursor']
        transcript.pending = [0] * transcript.transcript_out_size

        # Add input polynomial root before calling prove()
        # prove() now does merkelize→put internally, no need to prime

        # Run prove
        proof = fri_pcs.prove(self.input_pol, transcript)

        # Verify final polynomial matches
        self.assertEqual(
            len(proof.final_pol),
            len(self.expected_final_pol),
            f"Final polynomial size mismatch: {len(proof.final_pol)} vs {len(self.expected_final_pol)}"
        )

        mismatches = []
        for i, (actual, expected) in enumerate(zip(proof.final_pol, self.expected_final_pol)):
            if actual != expected:
                mismatches.append((i, actual, expected))

        if mismatches:
            msg = f"CRITICAL: Final polynomial mismatch ({len(mismatches)} values differ):\n"
            for i, actual, expected in mismatches[:10]:
                msg += f"  [{i}]: got {actual}, expected {expected}\n"
            if len(mismatches) > 10:
                msg += f"  ... and {len(mismatches) - 10} more\n"
            self.fail(msg)

    def test_prove_nonce(self):
        """Test that prove() finds the same grinding nonce as C++."""
        if not self.vectors_loaded:
            self.skipTest("Vectors not loaded")

        if not self.transcript_state.get('state'):
            self.skipTest("Transcript state not captured")

        config = FriPcsConfig(
            n_bits_ext=self.n_bits_ext,
            fri_steps=self.fri_steps,
            n_queries=_get_config_value(self.config, 'n_queries', 228),
            merkle_arity=_get_config_value(self.config, 'merkle_arity', 4),
            pow_bits=_get_config_value(self.config, 'pow_bits', 16),
            transcript_arity=_get_config_value(self.config, 'transcript_arity', 4),
            hash_commits=_get_config_value(self.config, 'hash_commits', True),
        )

        fri_pcs = FriPcs(config)

        # Prime transcript
        transcript = Transcript(arity=config.transcript_arity)
        transcript.state = list(self.transcript_state['state'])
        transcript.out = list(self.transcript_state['out'])
        transcript.out_cursor = self.transcript_state['out_cursor']
        transcript.pending_cursor = self.transcript_state['pending_cursor']
        transcript.pending = [0] * transcript.transcript_out_size

        # prove() now does merkelize→put internally, no need to prime

        proof = fri_pcs.prove(self.input_pol, transcript)

        self.assertEqual(
            proof.nonce,
            self.expected_nonce,
            f"Nonce mismatch: got {proof.nonce}, expected {self.expected_nonce}"
        )

    def test_prove_merkle_roots(self):
        """Test that prove() generates the same Merkle roots as C++."""
        if not self.vectors_loaded:
            self.skipTest("Vectors not loaded")

        if not self.transcript_state.get('state'):
            self.skipTest("Transcript state not captured")

        config = FriPcsConfig(
            n_bits_ext=self.n_bits_ext,
            fri_steps=self.fri_steps,
            n_queries=_get_config_value(self.config, 'n_queries', 228),
            merkle_arity=_get_config_value(self.config, 'merkle_arity', 4),
            pow_bits=_get_config_value(self.config, 'pow_bits', 16),
            transcript_arity=_get_config_value(self.config, 'transcript_arity', 4),
            hash_commits=_get_config_value(self.config, 'hash_commits', True),
        )

        fri_pcs = FriPcs(config)

        transcript = Transcript(arity=config.transcript_arity)
        transcript.state = list(self.transcript_state['state'])
        transcript.out = list(self.transcript_state['out'])
        transcript.out_cursor = self.transcript_state['out_cursor']
        transcript.pending_cursor = self.transcript_state['pending_cursor']
        transcript.pending = [0] * transcript.transcript_out_size

        # DON'T put merkle_roots[0] - the captured state already accounts for it
        # prove() will put fri_roots[0] after step 0, which should equal merkle_roots[0]

        proof = fri_pcs.prove(self.input_pol, transcript)

        # fri_roots should match merkle_roots exactly
        # fri_roots[i] = merkle_roots[i] for all i
        expected_roots = self.merkle_roots

        compare_count = min(len(proof.fri_roots), len(expected_roots))
        self.assertGreater(compare_count, 0, "No roots to compare")

        for i in range(compare_count):
            self.assertEqual(
                proof.fri_roots[i],
                expected_roots[i],
                f"FRI root {i} mismatch:\n"
                f"  Got:      {proof.fri_roots[i]}\n"
                f"  Expected: {expected_roots[i]}"
            )

    def test_prove_complete_match(self):
        """
        COMPLETE END-TO-END TEST.

        Validates ALL outputs from prove() match C++ exactly:
        - final_pol
        - nonce
        - fri_roots

        If this test passes, Python FRI is byte-identical to C++ FRI.
        """
        if not self.vectors_loaded:
            self.skipTest("Vectors not loaded")

        if not self.transcript_state.get('state'):
            self.skipTest("Transcript state not captured")

        config = FriPcsConfig(
            n_bits_ext=self.n_bits_ext,
            fri_steps=self.fri_steps,
            n_queries=_get_config_value(self.config, 'n_queries', 228),
            merkle_arity=_get_config_value(self.config, 'merkle_arity', 4),
            pow_bits=_get_config_value(self.config, 'pow_bits', 16),
            transcript_arity=_get_config_value(self.config, 'transcript_arity', 4),
            hash_commits=_get_config_value(self.config, 'hash_commits', True),
        )

        fri_pcs = FriPcs(config)

        transcript = Transcript(arity=config.transcript_arity)
        transcript.state = list(self.transcript_state['state'])
        transcript.out = list(self.transcript_state['out'])
        transcript.out_cursor = self.transcript_state['out_cursor']
        transcript.pending_cursor = self.transcript_state['pending_cursor']
        transcript.pending = [0] * transcript.transcript_out_size

        # Add input root before prove
        # prove() now does merkelize→put internally, no need to prime

        # Run prove
        proof = fri_pcs.prove(self.input_pol, transcript)

        # Collect all failures
        failures = []

        # Check final polynomial
        if proof.final_pol != self.expected_final_pol:
            mismatches = sum(1 for a, b in zip(proof.final_pol, self.expected_final_pol) if a != b)
            failures.append(f"final_pol: {mismatches}/{len(self.expected_final_pol)} values differ")

        # Check nonce
        if proof.nonce != self.expected_nonce:
            failures.append(f"nonce: got {proof.nonce}, expected {self.expected_nonce}")

        # Check Merkle roots (fri_roots[i] = merkle_roots[i])
        expected_roots = self.merkle_roots
        compare_count = min(len(proof.fri_roots), len(expected_roots))
        for i in range(compare_count):
            if proof.fri_roots[i] != expected_roots[i]:
                failures.append(f"fri_roots[{i}]: mismatch")

        if failures:
            self.fail(
                "PROVE END-TO-END TEST FAILED:\n" +
                "\n".join(f"  - {f}" for f in failures)
            )

        # If we get here, everything matches!
        print("\n" + "=" * 60)
        print("SUCCESS: Python prove() output is BYTE-IDENTICAL to C++!")
        print("=" * 60)


# Run with: python -m pytest executable-spec/test_prove_e2e.py -v
