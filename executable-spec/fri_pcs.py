"""
FRI PCS (Polynomial Commitment Scheme) wrapper.

This module provides the high-level FRI proving interface.

C++ Reference: pil2-stark/src/starkpil/fri/fri_pcs.hpp
"""

from typing import List, Any, Optional
from dataclasses import dataclass, field
from fri import FRI
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

        C++ FRI flow (merkelize BEFORE fold, put BEFORE get):
        1. merkelize(input) -> root0, put(root0), get_field() -> c0
        2. fold with c0 -> P1, merkelize(P1) -> root1, put(root1), get_field() -> c1
        3. fold with c1 -> P2, merkelize(P2) -> root2, put(root2), get_field() -> c2
        4. fold with c2 -> P3 (final)
        5. put(hash(P3)), get_state(3) -> grinding_challenge

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

        # Folding loop - C++ flow: merkelize, put, get challenge, fold
        # Uses fri_steps[i] as current poly size, fri_steps[i+1] as target
        for step in range(len(config.fri_steps) - 1):
            step_bits = config.fri_steps[step]
            next_bits = config.fri_steps[step + 1]

            # Merkelize current polynomial BEFORE folding
            root = FRI.merkelize(
                step=step,
                pol=current_pol,
                tree=self.fri_trees[step],
                current_bits=step_bits,
                next_bits=next_bits
            )
            proof.fri_roots.append(list(root))

            # Put root to transcript
            transcript.put(root)

            # Get challenge from transcript
            challenge = transcript.get_field()

            # Fold polynomial
            current_pol = FRI.fold(
                step=step,
                pol=current_pol,
                challenge=challenge,
                n_bits_ext=config.n_bits_ext,
                prev_bits=step_bits,
                current_bits=next_bits
            )

        # Final step: add final polynomial hash to transcript
        if config.hash_commits:
            final_hash = linear_hash(current_pol, config.transcript_arity * HASH_SIZE)
            transcript.put(final_hash)
        else:
            transcript.put(current_pol)

        # Store final polynomial
        proof.final_pol = list(current_pol)

        # Get challenge for grinding
        grinding_challenge = transcript.get_state(3)

        # Compute grinding nonce (proof of work)
        proof.nonce = self.compute_grinding_nonce(grinding_challenge, config.pow_bits)

        # Generate query proofs
        # Derive query indices from grinding challenge + nonce
        query_transcript = Transcript(arity=config.transcript_arity)
        query_transcript.put(grinding_challenge)
        query_transcript.put([proof.nonce])
        query_indices = query_transcript.get_permutations(
            config.n_queries, config.fri_steps[0]
        )

        # For each query, extract Merkle proofs from each FRI step tree
        for query_idx in query_indices:
            query_proof = {'fri_proofs': []}
            current_idx = query_idx

            for step in range(len(config.fri_steps) - 1):
                next_bits = config.fri_steps[step + 1]
                proof_idx = current_idx % (1 << next_bits)

                # Get Merkle proof siblings from this step's tree
                siblings = self.fri_trees[step].get_group_proof(proof_idx)
                query_proof['fri_proofs'].append(siblings)

                current_idx = proof_idx

            proof.query_proofs.append(query_proof)

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
