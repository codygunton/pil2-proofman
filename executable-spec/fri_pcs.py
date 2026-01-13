"""
FRI PCS (Polynomial Commitment Scheme) wrapper.

This module provides the high-level FRI proving interface.

C++ Reference: pil2-stark/src/starkpil/fri/fri_pcs.hpp
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from fri import FRI, FIELD_EXTENSION
from merkle_tree import MerkleTree, HASH_SIZE
from transcript import Transcript
from poseidon2_ffi import linear_hash, grinding


@dataclass
class FriPcsConfig:
    """
    FRI PCS configuration.

    C++ Reference: FriPcsConfig struct in fri_pcs_types.hpp
    """
    n_bits_ext: int  # Extended domain bits
    fri_steps: List[int]  # Domain bits for each step (decreasing)
    n_queries: int  # Number of query points
    merkle_arity: int = 4  # Tree branching factor
    pow_bits: int = 16  # Grinding difficulty
    last_level_verification: int = 0  # Merkle tree optimization
    hash_commits: bool = True  # Hash final polynomial?
    transcript_arity: int = 4  # Transcript hash arity
    merkle_tree_custom: bool = False  # Custom tree flag

# QUESTION: Does the structure of this class reflect the structure of another class in C++? ANS: Yes, loosely mirrors the proof JSON structure from proof_serializer.hpp, and the fields match what FriPcs::prove() populates in fri_pcs.hpp. The C++ doesn't have a single "FriProof" class - proof data is spread across StarksProof members. We consolidated into one dataclass for clarity. Field names (fri_roots, final_pol, nonce) match the JSON keys the C++ serializer outputs. Can simplify at cost of C++ divergence? Y - could use a plain dict instead of dataclass, but loses type safety and documentation.
@dataclass
class FriProof:
    """
    FRI proof structure.

    Contains all data needed to verify the FRI protocol.

    C++ Reference: FRIProof<ElementType> in proof_stark.hpp - NO CORRESPONDING FUNCTION
                   (C++ spreads proof data across StarksProof members; this consolidates for clarity)
    """
    # Merkle roots for each FRI step
    fri_roots: List[List[int]] = field(default_factory=list)

    # Final polynomial (cubic extension elements)
    final_pol: List[int] = field(default_factory=list)

    # Grinding nonce
    nonce: int = 0

    # Query proofs
    query_proofs: List[Any] = field(default_factory=list)


class FriPcs:
    """
    FRI Polynomial Commitment Scheme.

    This class orchestrates the full FRI proving flow.

    C++ Reference: FriPcs<MerkleTreeType> template class in fri_pcs.hpp
    """

    def __init__(self, config: FriPcsConfig):
        """
        Initialize FRI PCS with configuration.

        C++ Reference: FriPcs<MerkleTreeType>::FriPcs() constructor in fri_pcs.hpp:197

        Args:
            config: FRI configuration parameters
        """
        self.config = config
        self.fri_trees: List[MerkleTree] = []

        # Initialize FRI trees for each step (except final)
        for _ in range(len(config.fri_steps) - 1):
            tree = MerkleTree(
                arity=config.merkle_arity,
                last_level_verification=config.last_level_verification,
                custom=config.merkle_tree_custom
            )
            self.fri_trees.append(tree)

    def prove(
        self,
        polynomial: List[int],
        transcript: Transcript,
        stage_trees: Optional[List[MerkleTree]] = None
    ) -> FriProof:
        """
        Generate FRI proof for polynomial.

        This implements the full FRI proving flow:
        1. Iteratively fold polynomial with random challenges
        2. Build Merkle trees for each step
        3. Find grinding nonce (proof of work)
        4. Derive query indices
        5. Generate query proofs

        Args:
            polynomial: Polynomial in evaluation form (extended domain)
            transcript: Fiat-Shamir transcript
            stage_trees: Optional stage polynomial trees for queries

        Returns:
            Complete FRI proof

        C++ Reference: FriPcs<MerkleTreeType>::prove() in fri_pcs.hpp:65
        """
        proof = FriProof()
        config = self.config

        # Current polynomial (will be folded)
        current_pol = list(polynomial)

        # Previous domain bits
        prev_bits = config.n_bits_ext

        # Folding loop
        for step in range(len(config.fri_steps)):
            current_bits = config.fri_steps[step]

            # Get challenge from transcript
            challenge = transcript.get_field()

            # Fold polynomial
            current_pol = FRI.fold(
                step=step,
                pol=current_pol,
                challenge=challenge,
                n_bits_ext=config.n_bits_ext,
                prev_bits=prev_bits,
                current_bits=current_bits
            )

            # Build Merkle tree for this step (except final)
            if step < len(config.fri_steps) - 1:
                next_bits = config.fri_steps[step + 1]
                root = FRI.merkelize(
                    step=step,
                    pol=current_pol,
                    tree=self.fri_trees[step],
                    current_bits=current_bits,
                    next_bits=next_bits
                )
                proof.fri_roots.append(list(root))

                # Add root to transcript
                transcript.put(root)
            else:
                # Final step: add final polynomial to transcript
                if config.hash_commits:
                    # Hash the final polynomial
                    final_hash = linear_hash(current_pol, config.transcript_arity * HASH_SIZE)
                    transcript.put(final_hash)
                else:
                    # Add polynomial directly
                    transcript.put(current_pol)

            prev_bits = current_bits

        # Store final polynomial
        proof.final_pol = list(current_pol)

        # Get challenge for grinding
        grinding_challenge = transcript.get_state(3)

        # Compute grinding nonce (proof of work)
        proof.nonce = self.compute_grinding_nonce(grinding_challenge, config.pow_bits)

        # Derive query indices
        query_indices = self.derive_query_indices(
            grinding_challenge,
            proof.nonce,
            config.n_queries,
            config.fri_steps[0]
        )

        # Generate query proofs (inlined from _generate_query_proofs to match C++)
        proofs = []
        for idx in query_indices:
            query_proof = {
                'index': idx,
                'stage_proofs': [],
                'fri_proofs': []
            }

            # Stage tree proofs
            for tree in (stage_trees or []):
                tree_proof = tree.get_group_proof(idx % tree.height)
                query_proof['stage_proofs'].append(tree_proof)

            # FRI tree proofs
            current_idx = idx
            for step, tree in enumerate(self.fri_trees):
                current_bits = config.fri_steps[step]
                folded_idx = current_idx % (1 << current_bits)
                tree_proof = tree.get_group_proof(folded_idx)
                query_proof['fri_proofs'].append(tree_proof)
                current_idx = folded_idx

            proofs.append(query_proof)

        proof.query_proofs = proofs

        return proof

    def compute_grinding_nonce(self, challenge: List[int], pow_bits: int) -> int:
        """
        Find grinding nonce (proof of work).

        C++ Reference: FriPcs<MerkleTreeType>::compute_grinding_nonce() in fri_pcs.hpp:101

        Args:
            challenge: Current transcript state (3 elements)
            pow_bits: Difficulty in bits

        Returns:
            Nonce satisfying PoW requirement
        """
        return grinding(challenge, pow_bits)

    def derive_query_indices(
        self,
        challenge: List[int],
        nonce: int,
        n_queries: int,
        domain_bits: int
    ) -> List[int]:
        """
        Derive query indices from challenge and nonce.

        Creates a fresh transcript seeded with challenge+nonce
        and uses it to generate pseudorandom query positions.

        Args:
            challenge: Grinding challenge
            nonce: Grinding nonce
            n_queries: Number of queries to generate
            domain_bits: Domain size in bits

        Returns:
            List of query indices

        C++ Reference: FriPcs<MerkleTreeType>::derive_query_indices() in fri_pcs.hpp:136
        """
        # Create fresh transcript with challenge + nonce
        query_transcript = Transcript(arity=self.config.transcript_arity)
        query_transcript.put(challenge)
        query_transcript.put([nonce])

        # Generate permutation values
        return query_transcript.get_permutations(n_queries, domain_bits)

    def get_fri_tree(self, step: int) -> MerkleTree:
        """
        Get FRI tree for given step.

        C++ Reference: FriPcs<MerkleTreeType>::get_fri_tree() in fri_pcs.hpp:156
        """
        return self.fri_trees[step]


# QUESTION: what is the use of this? Should this be here? ANS: Yes, mirrors FriPcs::calculateHash in fri_pcs.hpp:116. Used during FRI proving to hash polynomials at each folding step (see fri_pcs.hpp:394,414). It creates a fresh transcript and absorbs buffer elements to produce a deterministic hash. Placed here as a module-level function (vs class method) for simplicity, but matches C++ static method. Can simplify at cost of C++ divergence? N - required for proof generation, not just structural.
def calculate_hash(
    buffer: List[int],
    n_elements: int,
    transcript_arity: int = 4
) -> List[int]:
    """
    Calculate hash of buffer elements.

    C++ Reference: FriPcs<MerkleTreeType>::calculateHash() in fri_pcs.hpp:116
    """
    sponge_width = transcript_arity * HASH_SIZE
    return linear_hash(buffer[:n_elements], sponge_width)
