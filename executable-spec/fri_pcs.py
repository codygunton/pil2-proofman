"""FRI Polynomial Commitment Scheme (non-interactive via Fiat-Shamir)."""

from typing import List, Any, Optional
from dataclasses import dataclass, field

from fri import FRI, EvalPoly
from merkle_tree import MerkleTree, MerkleRoot, HASH_SIZE
from transcript import Transcript
from poseidon2_ffi import linear_hash, grinding
from field import Fe

# --- Type Aliases ---

Nonce = int
QueryIndex = int


# --- Configuration ---

@dataclass
class FriPcsConfig:
    """FRI PCS configuration parameters."""
    n_bits_ext: int
    fri_steps: List[int]
    n_queries: int
    merkle_arity: int = 4
    pow_bits: int = 16
    last_level_verification: int = 0
    hash_commits: bool = True
    transcript_arity: int = 4
    merkle_tree_custom: bool = False


@dataclass
class FriProof:
    """Complete FRI proof structure."""
    fri_roots: List[MerkleRoot] = field(default_factory=list)
    final_pol: EvalPoly = field(default_factory=list)
    nonce: Nonce = 0
    query_proofs: List[Any] = field(default_factory=list)


# --- FRI PCS ---

class FriPcs:
    """FRI Polynomial Commitment Scheme."""

    def __init__(self, config: FriPcsConfig):
        self.config = config
        self.fri_trees: List[MerkleTree] = []

        for _ in range(len(config.fri_steps) - 1):
            tree = MerkleTree(
                arity=config.merkle_arity,
                last_level_verification=config.last_level_verification,
                custom=config.merkle_tree_custom
            )
            self.fri_trees.append(tree)

    def prove(
        self,
        polynomial: EvalPoly,
        transcript: Transcript,
        stage_trees: Optional[List[MerkleTree]] = None
    ) -> FriProof:
        """Generate FRI proof for polynomial."""
        proof = FriProof()
        config = self.config
        current_pol = list(polynomial)

        # --- Commit-Fold Phase ---
        for step in range(len(config.fri_steps) - 1):
            step_bits = config.fri_steps[step]
            next_bits = config.fri_steps[step + 1]

            root = FRI.merkelize(
                step=step,
                pol=current_pol,
                tree=self.fri_trees[step],
                current_bits=step_bits,
                next_bits=next_bits
            )
            proof.fri_roots.append(list(root))

            transcript.put(root)
            challenge = transcript.get_field()

            current_pol = FRI.fold(
                step=step,
                pol=current_pol,
                challenge=challenge,
                n_bits_ext=config.n_bits_ext,
                prev_bits=step_bits,
                current_bits=next_bits
            )

        # --- Finalize ---
        if config.hash_commits:
            transcript.put(linear_hash(current_pol, config.transcript_arity * HASH_SIZE))
        else:
            transcript.put(current_pol)

        proof.final_pol = list(current_pol)

        # --- Grinding ---
        grinding_challenge = transcript.get_state(3)
        proof.nonce = self._compute_grinding_nonce(grinding_challenge, config.pow_bits)

        # --- Query Phase ---
        query_indices = self._derive_query_indices(
            grinding_challenge,
            proof.nonce,
            config.n_queries,
            config.fri_steps[0]
        )

        for query_idx in query_indices:
            query_proof = {'fri_proofs': []}
            current_idx = query_idx

            for step in range(len(config.fri_steps) - 1):
                next_bits = config.fri_steps[step + 1]
                proof_idx = current_idx % (1 << next_bits)

                siblings = self.fri_trees[step].get_group_proof(proof_idx)
                query_proof['fri_proofs'].append(siblings)

                current_idx = proof_idx

            proof.query_proofs.append(query_proof)

        return proof

    # --- Grinding ---

    def _compute_grinding_nonce(self, challenge: List[Fe], pow_bits: int) -> Nonce:
        """Find nonce satisfying proof-of-work requirement."""
        return grinding(challenge, pow_bits)

    def _derive_query_indices(
        self,
        challenge: List[Fe],
        nonce: Nonce,
        n_queries: int,
        domain_bits: int
    ) -> List[QueryIndex]:
        """Derive query indices from (challenge, nonce)."""
        query_transcript = Transcript(arity=self.config.transcript_arity)
        query_transcript.put(challenge)
        query_transcript.put([nonce])
        return query_transcript.get_permutations(n_queries, domain_bits)

    # --- Accessors ---

    def get_fri_tree(self, step: int) -> MerkleTree:
        """Get Merkle tree for given FRI step."""
        return self.fri_trees[step]
