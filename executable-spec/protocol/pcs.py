"""FRI Polynomial Commitment Scheme."""

from dataclasses import dataclass, field
from typing import List, Optional

from poseidon2_ffi import grinding, linear_hash
from primitives.field import FF3, FF3Poly, ff3_to_flat_list
from primitives.merkle_tree import HASH_SIZE, MerkleRoot, MerkleTree, QueryProof
from primitives.transcript import Transcript
from protocol.fri import FRI
from protocol.stark_info import FIELD_EXTENSION_DEGREE

# --- Type Aliases ---

EvalPoly = FF3Poly  # Polynomial in evaluation form (FF3 array)
Nonce = int
QueryIndex = int


# --- Configuration ---

@dataclass
class FriPcsConfig:
    """FRI PCS parameters."""
    n_bits_ext: int
    fri_round_log_sizes: List[int]
    n_queries: int
    merkle_arity: int = 4
    pow_bits: int = 16
    last_level_verification: int = 0
    hash_commits: bool = True
    transcript_arity: int = 4
    merkle_tree_custom: bool = False


@dataclass
class FriProof:
    """FRI proof: roots, final polynomial, grinding nonce, and query proofs."""
    fri_roots: List[MerkleRoot] = field(default_factory=list)
    final_pol: FF3Poly = field(default_factory=lambda: FF3([]))
    nonce: Nonce = 0
    query_proofs: List[List[QueryProof]] = field(default_factory=list)
    query_indices: List[QueryIndex] = field(default_factory=list)


# --- FRI PCS ---

class FriPcs:
    """FRI Polynomial Commitment Scheme."""

    def __init__(self, config: FriPcsConfig):
        self.config = config
        self.fri_trees = [
            MerkleTree(
                arity=config.merkle_arity,
                last_level_verification=config.last_level_verification,
                custom=config.merkle_tree_custom
            )
            for _ in range(len(config.fri_round_log_sizes) - 1)
        ]

    def prove(
        self,
        polynomial: EvalPoly,
        transcript: Transcript,
        stage_trees: Optional[List[MerkleTree]] = None,  # noqa: ARG002
    ) -> FriProof:
        """Generate FRI proof: commit-fold, finalize, grind, query."""
        cfg = self.config
        n_fri_rounds = len(cfg.fri_round_log_sizes) - 1

        # --- Commit-Fold Loop ---
        # Each iteration: merkelize -> commit root -> derive challenge -> fold
        fri_roots: List[MerkleRoot] = []
        current_pol = polynomial  # Already FF3Poly

        for fri_round in range(n_fri_rounds):
            prev_bits, curr_bits = cfg.fri_round_log_sizes[fri_round], cfg.fri_round_log_sizes[fri_round + 1]

            # Commit: build Merkle tree, add root to transcript
            root = FRI.merkelize(fri_round, current_pol, self.fri_trees[fri_round], prev_bits, curr_bits)
            fri_roots.append(list(root))
            transcript.put(root)

            # Fold: derive challenge, reduce polynomial
            challenge = transcript.get_field()
            current_pol = FRI.fold(fri_round, current_pol, challenge, cfg.n_bits_ext, prev_bits, curr_bits)

        # --- Finalize ---
        # Convert to flat list for transcript operations (serialization boundary)
        final_pol_flat = ff3_to_flat_list(current_pol)
        if cfg.hash_commits:
            transcript.put(linear_hash(final_pol_flat, cfg.transcript_arity * HASH_SIZE))
        else:
            transcript.put(final_pol_flat)

        # --- Grinding (proof-of-work) ---
        grinding_challenge = transcript.get_state(3)
        nonce = grinding(grinding_challenge, cfg.pow_bits)

        # --- Query Phase ---
        query_indices = self._derive_query_indices(grinding_challenge, nonce)
        query_proofs = self._generate_query_proofs(query_indices)

        return FriProof(
            fri_roots=fri_roots,
            final_pol=current_pol,  # Store as FF3Poly
            nonce=nonce,
            query_proofs=query_proofs,
            query_indices=query_indices,
        )

    def _derive_query_indices(self, challenge: List[int], nonce: Nonce) -> List[QueryIndex]:
        """Derive pseudorandom query indices from grinding output."""
        cfg = self.config
        query_transcript = Transcript(arity=cfg.transcript_arity)
        query_transcript.put(challenge)
        query_transcript.put([nonce])
        return query_transcript.get_permutations(cfg.n_queries, cfg.fri_round_log_sizes[0])

    def _generate_query_proofs(self, query_indices: List[QueryIndex]) -> List[List[QueryProof]]:
        """Generate Merkle proofs for all queries at each FRI layer."""
        cfg = self.config
        query_proofs: List[List[QueryProof]] = []

        for fri_round in range(len(cfg.fri_round_log_sizes) - 1):
            domain_bits = cfg.fri_round_log_sizes[fri_round + 1]
            step_proofs = [
                self.fri_trees[fri_round].get_query_proof(
                    self._fold_index(idx, fri_round) % (1 << domain_bits),
                    elem_size=FIELD_EXTENSION_DEGREE,
                )
                for idx in query_indices
            ]
            query_proofs.append(step_proofs)

        return query_proofs

    def _fold_index(self, query_idx: int, fri_round: int) -> int:
        """Map original query index to folded domain index at given FRI layer."""
        # Each fold step reduces domain size, so index wraps modulo new size
        idx = query_idx
        for s in range(fri_round):
            idx %= 1 << self.config.fri_round_log_sizes[s + 1]
        return idx

    def get_fri_tree(self, fri_round: int) -> MerkleTree:
        """Get Merkle tree for given FRI layer."""
        return self.fri_trees[fri_round]
