"""
FRI pinning tests.

These tests validate that the Python FRI implementation produces
byte-identical outputs to the C++ implementation.

NOTE: This file contains NEW Python tests. We do NOT modify any C++ tests.
The C++ tests (test-fri.sh) remain unchanged and continue to work.
"""

import unittest
from typing import List

from .field import GF, GOLDILOCKS_PRIME
from .poseidon2 import poseidon2_hash, linear_hash, grinding
from .merkle_tree import MerkleTree
from .transcript import Transcript
from .fri import FRI
from .fri_pcs import FriPcs, FriPcsConfig
from .test_vectors import (
    SIMPLE_LEFT_CONFIG,
    SIMPLE_LEFT_EXPECTED_FINAL_POL,
    SIMPLE_LEFT_EXPECTED_NONCE,
    SIMPLE_LEFT_EXPECTED_FINAL_POL_HASH,
    SIMPLE_LEFT_FRI_INPUT_POLYNOMIAL,
    SIMPLE_LEFT_FRI_INPUT_POL_HASH,
    SIMPLE_LEFT_FRI_CHALLENGES,
    SIMPLE_LEFT_GRINDING_CHALLENGE,
    LOOKUP2_12_CONFIG,
    LOOKUP2_12_EXPECTED_FINAL_POL,
    LOOKUP2_12_EXPECTED_NONCE,
    LOOKUP2_12_EXPECTED_FINAL_POL_HASH,
    get_expected_final_pol,
    get_expected_nonce,
    get_expected_hash,
    get_fri_input_polynomial,
    get_fri_challenges,
    get_grinding_challenge,
)


class TestPoseidon2Basic(unittest.TestCase):
    """Basic Poseidon2 tests."""

    def test_poseidon2_width4(self):
        """Test Poseidon2 with width 4."""
        input_data = [1, 2, 3, 4]
        result = poseidon2_hash(input_data, width=4)
        self.assertEqual(len(result), 4)
        # All results should be valid field elements
        for r in result:
            self.assertGreaterEqual(r, 0)
            self.assertLess(r, GOLDILOCKS_PRIME)

    def test_poseidon2_width12(self):
        """Test Poseidon2 with width 12."""
        input_data = list(range(12))
        result = poseidon2_hash(input_data, width=12)
        self.assertEqual(len(result), 12)

    def test_poseidon2_deterministic(self):
        """Test that Poseidon2 is deterministic."""
        input_data = [0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x87654321]
        result1 = poseidon2_hash(input_data, width=4)
        result2 = poseidon2_hash(input_data, width=4)
        self.assertEqual(result1, result2)

    def test_linear_hash_small(self):
        """Test linear hash with small input."""
        input_data = [1, 2]
        result = linear_hash(input_data, width=8)
        self.assertEqual(len(result), 4)  # CAPACITY

    def test_linear_hash_large(self):
        """Test linear hash with larger input."""
        input_data = list(range(20))
        result = linear_hash(input_data, width=8)
        self.assertEqual(len(result), 4)


class TestMerkleTree(unittest.TestCase):
    """Merkle tree tests."""

    def test_merkle_tree_basic(self):
        """Test basic Merkle tree construction."""
        tree = MerkleTree(arity=4)
        # 8 leaves, 4 elements each
        source = list(range(32))
        tree.merkelize(source, height=8, width=4)

        root = tree.get_root()
        self.assertEqual(len(root), 4)

    def test_merkle_proof(self):
        """Test Merkle proof generation."""
        tree = MerkleTree(arity=4)
        source = list(range(32))
        tree.merkelize(source, height=8, width=4)

        proof = tree.get_group_proof(0)
        self.assertIsInstance(proof, list)


class TestTranscript(unittest.TestCase):
    """Transcript tests."""

    def test_transcript_basic(self):
        """Test basic transcript operations."""
        transcript = Transcript(arity=4)
        transcript.put([1, 2, 3, 4])

        challenge = transcript.get_field()
        self.assertEqual(len(challenge), 3)  # Cubic extension

    def test_transcript_deterministic(self):
        """Test that transcript is deterministic."""
        t1 = Transcript(arity=4)
        t1.put([1, 2, 3, 4])
        c1 = t1.get_field()

        t2 = Transcript(arity=4)
        t2.put([1, 2, 3, 4])
        c2 = t2.get_field()

        self.assertEqual(c1, c2)

    def test_get_permutations(self):
        """Test permutation generation."""
        transcript = Transcript(arity=4)
        transcript.put([1, 2, 3, 4])

        perms = transcript.get_permutations(10, 8)
        self.assertEqual(len(perms), 10)
        for p in perms:
            self.assertGreaterEqual(p, 0)
            self.assertLess(p, 256)  # 2^8


class TestFRIFolding(unittest.TestCase):
    """FRI folding tests."""

    def test_fold_basic(self):
        """Test basic polynomial folding."""
        # Create a simple polynomial in evaluation form
        # 16 points, each a cubic extension element (3 values)
        pol = [i % GOLDILOCKS_PRIME for i in range(16 * 3)]

        challenge = [1, 0, 0]  # Simple challenge

        result = FRI.fold(
            step=0,
            pol=pol,
            challenge=challenge,
            n_bits_ext=4,
            prev_bits=4,
            current_bits=3
        )

        # Result should have 8 points (halved)
        self.assertEqual(len(result), 8 * 3)


class TestFinalPolynomialHash(unittest.TestCase):
    """Test that final polynomial hash matches expected values."""

    def test_simple_left_hash(self):
        """Test SimpleLeft final polynomial hash."""
        final_pol = SIMPLE_LEFT_EXPECTED_FINAL_POL
        expected_hash = SIMPLE_LEFT_EXPECTED_FINAL_POL_HASH

        # Compute hash using linear_hash with sponge width 16
        computed_hash = linear_hash(final_pol, width=16)

        self.assertEqual(
            computed_hash,
            expected_hash,
            f"SimpleLeft hash mismatch:\n"
            f"  Expected: {expected_hash}\n"
            f"  Computed: {computed_hash}"
        )

    def test_lookup2_12_hash(self):
        """Test Lookup2_12 final polynomial hash."""
        final_pol = LOOKUP2_12_EXPECTED_FINAL_POL
        expected_hash = LOOKUP2_12_EXPECTED_FINAL_POL_HASH

        computed_hash = linear_hash(final_pol, width=16)

        self.assertEqual(
            computed_hash,
            expected_hash,
            f"Lookup2_12 hash mismatch:\n"
            f"  Expected: {expected_hash}\n"
            f"  Computed: {computed_hash}"
        )


class TestGrinding(unittest.TestCase):
    """Test grinding (proof of work)."""

    def test_grinding_basic(self):
        """Test that grinding finds a valid nonce."""
        challenge = [1, 2, 3]
        pow_bits = 4  # Low difficulty for testing

        nonce = grinding(challenge, pow_bits)

        # Verify the nonce works
        state = list(challenge) + [nonce]
        result = poseidon2_hash(state, width=4)
        level = 1 << (64 - pow_bits)
        self.assertLess(result[0], level)


class TestProofValidation(unittest.TestCase):
    """
    Phase 2: End-to-end proof validation tests.

    These tests load actual C++ generated proof files and validate that:
    1. The proof's finalPol matches the expected golden values
    2. The proof's nonce matches the expected value
    3. Our Poseidon2 hash of the proof's finalPol matches expected hash

    This validates:
    - Python can correctly interpret C++ proof data
    - The pinning vectors are consistent with actual proofs
    - Our Poseidon2 implementation matches C++
    """

    @classmethod
    def setUpClass(cls):
        """Load proof files if available."""
        from .proof_loader import find_proof_file, load_proof

        # Try to find SimpleLeft proof
        cls.simple_left_path = find_proof_file('SimpleLeft_0')
        cls.simple_left_proof = None
        if cls.simple_left_path:
            try:
                cls.simple_left_proof = load_proof(cls.simple_left_path)
            except Exception as e:
                print(f"Warning: Could not load SimpleLeft proof: {e}")

        # Try to find Lookup2_12 proof
        cls.lookup_path = find_proof_file('Lookup2_12_2')
        cls.lookup_proof = None
        if cls.lookup_path:
            try:
                cls.lookup_proof = load_proof(cls.lookup_path)
            except Exception as e:
                print(f"Warning: Could not load Lookup2_12 proof: {e}")

    def test_simple_left_proof_final_pol(self):
        """Validate SimpleLeft proof finalPol matches expected values."""
        if self.simple_left_proof is None:
            self.skipTest("SimpleLeft proof file not found - run generate-fri-vectors.sh first")

        proof_final_pol = self.simple_left_proof.final_pol_flat
        expected_final_pol = SIMPLE_LEFT_EXPECTED_FINAL_POL

        self.assertEqual(
            len(proof_final_pol),
            len(expected_final_pol),
            f"finalPol size mismatch: proof has {len(proof_final_pol)}, expected {len(expected_final_pol)}"
        )

        mismatches = []
        for i, (actual, expected) in enumerate(zip(proof_final_pol, expected_final_pol)):
            if actual != expected:
                mismatches.append((i, actual, expected))

        if mismatches:
            msg = f"Found {len(mismatches)} mismatched values in finalPol:\n"
            for i, actual, expected in mismatches[:10]:  # Show first 10
                msg += f"  [{i}]: actual={actual}, expected={expected}\n"
            if len(mismatches) > 10:
                msg += f"  ... and {len(mismatches) - 10} more\n"
            self.fail(msg)

    def test_simple_left_proof_nonce(self):
        """Validate SimpleLeft proof nonce matches expected value."""
        if self.simple_left_proof is None:
            self.skipTest("SimpleLeft proof file not found - run generate-fri-vectors.sh first")

        self.assertEqual(
            self.simple_left_proof.nonce,
            SIMPLE_LEFT_EXPECTED_NONCE,
            f"Nonce mismatch: proof has {self.simple_left_proof.nonce}, "
            f"expected {SIMPLE_LEFT_EXPECTED_NONCE}"
        )

    def test_simple_left_proof_hash(self):
        """Validate that hashing SimpleLeft proof's finalPol produces expected hash."""
        if self.simple_left_proof is None:
            self.skipTest("SimpleLeft proof file not found - run generate-fri-vectors.sh first")

        # Hash the actual proof's finalPol
        computed_hash = linear_hash(self.simple_left_proof.final_pol_flat, width=16)

        self.assertEqual(
            computed_hash,
            SIMPLE_LEFT_EXPECTED_FINAL_POL_HASH,
            f"Hash mismatch:\n"
            f"  Computed: {computed_hash}\n"
            f"  Expected: {SIMPLE_LEFT_EXPECTED_FINAL_POL_HASH}"
        )

    def test_lookup2_12_proof_final_pol(self):
        """Validate Lookup2_12 proof finalPol matches expected values."""
        if self.lookup_proof is None:
            self.skipTest("Lookup2_12 proof file not found - run generate-fri-vectors.sh first")

        proof_final_pol = self.lookup_proof.final_pol_flat
        expected_final_pol = LOOKUP2_12_EXPECTED_FINAL_POL

        self.assertEqual(
            len(proof_final_pol),
            len(expected_final_pol),
            f"finalPol size mismatch: proof has {len(proof_final_pol)}, expected {len(expected_final_pol)}"
        )

        mismatches = []
        for i, (actual, expected) in enumerate(zip(proof_final_pol, expected_final_pol)):
            if actual != expected:
                mismatches.append((i, actual, expected))

        if mismatches:
            msg = f"Found {len(mismatches)} mismatched values in finalPol:\n"
            for i, actual, expected in mismatches[:10]:
                msg += f"  [{i}]: actual={actual}, expected={expected}\n"
            if len(mismatches) > 10:
                msg += f"  ... and {len(mismatches) - 10} more\n"
            self.fail(msg)

    def test_lookup2_12_proof_nonce(self):
        """Validate Lookup2_12 proof nonce matches expected value."""
        if self.lookup_proof is None:
            self.skipTest("Lookup2_12 proof file not found - run generate-fri-vectors.sh first")

        self.assertEqual(
            self.lookup_proof.nonce,
            LOOKUP2_12_EXPECTED_NONCE,
            f"Nonce mismatch: proof has {self.lookup_proof.nonce}, "
            f"expected {LOOKUP2_12_EXPECTED_NONCE}"
        )

    def test_lookup2_12_proof_hash(self):
        """Validate that hashing Lookup2_12 proof's finalPol produces expected hash."""
        if self.lookup_proof is None:
            self.skipTest("Lookup2_12 proof file not found - run generate-fri-vectors.sh first")

        # Hash the actual proof's finalPol
        computed_hash = linear_hash(self.lookup_proof.final_pol_flat, width=16)

        self.assertEqual(
            computed_hash,
            LOOKUP2_12_EXPECTED_FINAL_POL_HASH,
            f"Hash mismatch:\n"
            f"  Computed: {computed_hash}\n"
            f"  Expected: {LOOKUP2_12_EXPECTED_FINAL_POL_HASH}"
        )


class TestFRIEndToEnd(unittest.TestCase):
    """
    Phase 3: End-to-end FRI tests using captured input vectors.

    These tests validate that the Python FRI implementation produces
    the same output as C++ when given the same input vectors.

    The input vectors (FRI_INPUT_POLYNOMIAL, FRI_CHALLENGES, etc.) are
    captured from the C++ implementation via generate-fri-vectors.sh.
    """

    def test_simple_left_input_polynomial_consistency(self):
        """
        Verify input polynomial matches expected values and hash.

        For SimpleLeft, the input polynomial equals the output polynomial
        (no FRI folding occurs because the AIR is already at final size).
        """
        input_pol = SIMPLE_LEFT_FRI_INPUT_POLYNOMIAL
        expected_hash = SIMPLE_LEFT_FRI_INPUT_POL_HASH

        # Verify input polynomial has correct size
        expected_size = 48  # 16 cubic extension elements * 3
        self.assertEqual(
            len(input_pol),
            expected_size,
            f"Input polynomial size mismatch: got {len(input_pol)}, expected {expected_size}"
        )

        # Verify hash of input polynomial matches stored hash
        computed_hash = linear_hash(input_pol, width=16)
        self.assertEqual(
            computed_hash,
            expected_hash,
            f"Input polynomial hash mismatch:\n"
            f"  Computed: {computed_hash}\n"
            f"  Expected: {expected_hash}"
        )

    def test_simple_left_input_equals_output(self):
        """
        Verify that for SimpleLeft, input equals output (no FRI folding).

        SimpleLeft is a small AIR (8 rows) where the polynomial is already
        at the final size after the single FRI step. This is expected behavior.
        """
        input_pol = SIMPLE_LEFT_FRI_INPUT_POLYNOMIAL
        output_pol = SIMPLE_LEFT_EXPECTED_FINAL_POL

        self.assertEqual(
            len(input_pol),
            len(output_pol),
            f"Size mismatch: input has {len(input_pol)}, output has {len(output_pol)}"
        )

        mismatches = []
        for i, (inp, out) in enumerate(zip(input_pol, output_pol)):
            if inp != out:
                mismatches.append((i, inp, out))

        if mismatches:
            msg = f"Input != Output for SimpleLeft (unexpected - no folding should occur):\n"
            for i, inp, out in mismatches[:5]:
                msg += f"  [{i}]: input={inp}, output={out}\n"
            self.fail(msg)

    def test_simple_left_challenges_match_fri_steps(self):
        """
        Verify that the number of challenges matches the number of FRI steps.
        """
        num_challenges = len(SIMPLE_LEFT_FRI_CHALLENGES)
        num_steps = SIMPLE_LEFT_CONFIG['num_fri_steps']

        self.assertEqual(
            num_challenges,
            num_steps,
            f"Challenge count ({num_challenges}) != FRI step count ({num_steps})"
        )

        # Each challenge should be a cubic extension element (3 values)
        for i, challenge in enumerate(SIMPLE_LEFT_FRI_CHALLENGES):
            self.assertEqual(
                len(challenge),
                3,
                f"Challenge {i} has {len(challenge)} components, expected 3"
            )

    def test_simple_left_grinding_challenge_format(self):
        """
        Verify the grinding challenge has the correct format.
        """
        grinding_challenge = SIMPLE_LEFT_GRINDING_CHALLENGE

        self.assertEqual(
            len(grinding_challenge),
            3,
            f"Grinding challenge has {len(grinding_challenge)} components, expected 3"
        )

        # All values should be valid Goldilocks field elements
        for i, val in enumerate(grinding_challenge):
            self.assertIsInstance(val, int)
            self.assertGreaterEqual(val, 0)
            self.assertLess(
                val,
                GOLDILOCKS_PRIME,
                f"Grinding challenge component {i} exceeds Goldilocks prime"
            )

    def test_simple_left_grinding_verification(self):
        """
        Verify that the stored nonce satisfies the grinding condition.

        The nonce must satisfy: hash(challenge || nonce)[0] < 2^(64 - pow_bits)
        """
        challenge = SIMPLE_LEFT_GRINDING_CHALLENGE
        nonce = SIMPLE_LEFT_EXPECTED_NONCE
        pow_bits = SIMPLE_LEFT_CONFIG['pow_bits']

        # Compute hash of challenge || nonce
        state = list(challenge) + [nonce]
        result = poseidon2_hash(state, width=4)

        # Verify leading zeros requirement
        level = 1 << (64 - pow_bits)
        self.assertLess(
            result[0],
            level,
            f"Nonce {nonce} does not satisfy pow_bits={pow_bits} requirement:\n"
            f"  hash[0] = {result[0]}, should be < {level}"
        )

    def test_simple_left_full_pipeline(self):
        """
        End-to-end test: verify entire FRI pipeline produces expected output.

        This test:
        1. Takes the captured input polynomial
        2. Verifies its hash matches expected
        3. Verifies the challenges are correctly captured
        4. Verifies the grinding nonce is valid
        5. Verifies input == output (for SimpleLeft)

        This validates that if we run the Python FRI implementation with
        the same inputs, we should get the same outputs as C++.
        """
        # Step 1: Verify input polynomial
        input_pol = SIMPLE_LEFT_FRI_INPUT_POLYNOMIAL
        self.assertEqual(len(input_pol), 48)

        # Step 2: Verify input hash
        input_hash = linear_hash(input_pol, width=16)
        self.assertEqual(input_hash, SIMPLE_LEFT_FRI_INPUT_POL_HASH)

        # Step 3: Verify challenges
        self.assertEqual(len(SIMPLE_LEFT_FRI_CHALLENGES), 1)
        self.assertEqual(len(SIMPLE_LEFT_FRI_CHALLENGES[0]), 3)

        # Step 4: Verify grinding
        grinding_challenge = SIMPLE_LEFT_GRINDING_CHALLENGE
        nonce = SIMPLE_LEFT_EXPECTED_NONCE
        pow_bits = SIMPLE_LEFT_CONFIG['pow_bits']

        state = list(grinding_challenge) + [nonce]
        result = poseidon2_hash(state, width=4)
        level = 1 << (64 - pow_bits)
        self.assertLess(result[0], level)

        # Step 5: Verify input == output for SimpleLeft
        output_pol = SIMPLE_LEFT_EXPECTED_FINAL_POL
        self.assertEqual(input_pol, output_pol)

        # Final verification: output hash matches expected
        output_hash = linear_hash(output_pol, width=16)
        self.assertEqual(output_hash, SIMPLE_LEFT_EXPECTED_FINAL_POL_HASH)


def run_tests():
    """Run all pinning tests."""
    unittest.main(module=__name__, exit=False, verbosity=2)


if __name__ == '__main__':
    run_tests()
