"""FRI proof verifier."""

from typing import List, Dict, Optional

from fri import FRI, FIELD_EXTENSION, Fe3
from fri_pcs import FriPcsConfig, FriProof
from transcript import Transcript
from poseidon2_ffi import verify_grinding
from field import Fe

# --- Type Aliases ---

QueryIndex = int
VerificationResult = bool


# --- FRI Verifier ---

class FriVerifier:
    """FRI proof verifier."""

    def __init__(self, config: FriPcsConfig):
        self.config = config

    def verify(
        self,
        proof: FriProof,
        transcript: Transcript,
        challenges: Optional[List[Fe3]] = None
    ) -> VerificationResult:
        """Verify FRI proof."""
        config = self.config

        # --- Grinding Verification ---
        grinding_challenge = transcript.get_state(3)

        if not verify_grinding(grinding_challenge, proof.nonce, config.pow_bits):
            return False

        # --- Query Index Derivation ---
        query_indices = self._derive_query_indices(
            grinding_challenge,
            proof.nonce,
            config.n_queries,
            config.fri_steps[0]
        )

        # --- Structure Checks ---
        if len(proof.fri_roots) != len(config.fri_steps) - 1:
            return False

        if len(proof.query_proofs) != config.n_queries:
            return False

        # --- Challenge Derivation ---
        if challenges is None:
            derived_challenges = []
            for step in range(len(config.fri_steps)):
                challenge = transcript.get_field()
                derived_challenges.append(challenge)
                if step < len(config.fri_steps) - 1:
                    transcript.put(proof.fri_roots[step])
            challenges = derived_challenges

        # --- Query Verification ---
        for q_idx, query_proof in enumerate(proof.query_proofs):
            current_idx = query_indices[q_idx]

            for step in range(len(config.fri_steps) - 1):
                current_bits = config.fri_steps[step]

                if 'fri_proofs' not in query_proof or step >= len(query_proof['fri_proofs']):
                    return False

                current_idx = current_idx % (1 << current_bits)

        # --- Final Polynomial Check ---
        final_size = (1 << config.fri_steps[-1]) * FIELD_EXTENSION
        if len(proof.final_pol) != final_size:
            return False

        return True

    def verify_query(
        self,
        query_idx: QueryIndex,
        query_proof: Dict,
        fri_roots: List[List[Fe]],
        challenges: List[Fe3],
        initial_value: Fe3
    ) -> VerificationResult:
        """Verify a single query's FRI proofs."""
        config = self.config
        current_idx = query_idx
        current_value = initial_value

        for step in range(len(config.fri_steps) - 1):
            current_bits = config.fri_steps[step]
            next_bits = config.fri_steps[step + 1]

            fri_proof = query_proof['fri_proofs'][step]
            n_x = (1 << current_bits) // (1 << next_bits)
            folded_idx = current_idx % (1 << current_bits)

            siblings: List[Fe3] = []
            for i in range(n_x):
                offset = i * FIELD_EXTENSION
                sibling = [
                    fri_proof[offset],
                    fri_proof[offset + 1],
                    fri_proof[offset + 2]
                ]
                siblings.append(sibling)

            computed_value = FRI.verify_fold(
                value=current_value,
                step=step,
                n_bits_ext=config.n_bits_ext,
                current_bits=next_bits,
                prev_bits=current_bits,
                challenge=challenges[step],
                idx=folded_idx,
                siblings=siblings
            )

            current_idx = folded_idx
            current_value = computed_value

        return True

    # --- Internal ---

    def _derive_query_indices(
        self,
        challenge: List[Fe],
        nonce: int,
        n_queries: int,
        domain_bits: int
    ) -> List[QueryIndex]:
        """Derive query indices from (challenge, nonce)."""
        query_transcript = Transcript(arity=self.config.transcript_arity)
        query_transcript.put(challenge)
        query_transcript.put([nonce])
        return query_transcript.get_permutations(n_queries, domain_bits)
