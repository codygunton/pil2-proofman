"""Merkle tree verification abstraction.

This module provides a clean interface for Merkle tree verification that hides
the complexity of the `last_level_verification` optimization internally.

The `last_level_verification` optimization allows skipping proof verification
for the top N levels of the tree by including pre-computed hashes at that level
directly in the proof. This reduces proof size for each query while adding a
small fixed overhead.
"""

import math
from dataclasses import dataclass
from typing import TYPE_CHECKING

from poseidon2_ffi import hash_seq, linear_hash

from primitives.merkle_tree import HASH_SIZE, MerkleTree

if TYPE_CHECKING:
    from protocol.proof import STARKProof
    from protocol.stark_info import StarkInfo

# --- Type Aliases ---
MerkleRoot = list[int]
SiblingHash = list[int]


# --- Configuration ---


@dataclass(frozen=True)
class MerkleConfig:
    """Merkle tree configuration for verification.

    Frozen dataclass that captures all tree parameters needed for verification.
    The sponge_width and n_siblings are computed properties.

    Attributes:
        arity: Tree branching factor (2, 3, or 4)
        domain_bits: Log2 of the number of leaves
        last_level_verification: Number of top levels to skip in per-query verification
    """

    arity: int
    domain_bits: int
    last_level_verification: int

    @property
    def sponge_width(self) -> int:
        """Poseidon2 sponge width for this arity."""
        return {2: 8, 3: 12, 4: 16}[self.arity]

    @property
    def n_siblings(self) -> int:
        """Number of sibling levels in each query proof."""
        return (
            int(math.ceil(self.domain_bits / math.log2(self.arity))) - self.last_level_verification
        )

    @property
    def siblings_per_level(self) -> int:
        """Number of sibling hash elements per level."""
        return (self.arity - 1) * HASH_SIZE


# --- Verifier Class ---


class MerkleVerifier:
    """Merkle tree verifier with encapsulated last_level_verification logic.

    This class provides a clean verify_query() interface that hides whether
    verification checks against the root directly or against pre-verified
    last-level nodes.

    Usage:
        verifier = MerkleVerifier.for_stage(proof, stark_info, root, stage=1)
        for query_idx in range(n_queries):
            if not verifier.verify_query(query_idx, leaf_values, siblings):
                return False
        return True
    """

    def __init__(
        self, root: MerkleRoot, config: MerkleConfig, last_level_nodes: list[int] | None = None
    ) -> None:
        """Initialize verifier with root and configuration.

        Args:
            root: Expected Merkle root (HASH_SIZE elements)
            config: Tree configuration
            last_level_nodes: Pre-verified nodes at the last-level boundary
                              (required if config.last_level_verification > 0)
        """
        self.root = root
        self.config = config
        self._last_level_verified = False
        self._last_level_nodes: list[int] = []

        if config.last_level_verification > 0:
            if last_level_nodes is None:
                raise ValueError("last_level_nodes required when last_level_verification > 0")
            self._last_level_nodes = last_level_nodes

    # --- Factory Methods ---

    @classmethod
    def for_stage(
        cls, proof: "STARKProof", stark_info: "StarkInfo", root: MerkleRoot, stage: int
    ) -> "MerkleVerifier":
        """Create verifier for a stage commitment tree.

        Args:
            proof: STARK proof containing last_levels
            stark_info: STARK configuration
            root: Expected root for this stage
            stage: Stage number (1-indexed)

        Returns:
            Configured MerkleVerifier for this stage
        """
        stark_struct = stark_info.stark_struct
        config = MerkleConfig(
            arity=stark_struct.merkle_tree_arity,
            domain_bits=stark_struct.fri_fold_steps[0].domain_bits,
            last_level_verification=stark_struct.last_level_verification,
        )

        last_level_nodes = None
        if config.last_level_verification > 0:
            tree_idx = stage - 1  # Stage 1 -> tree_idx 0
            if tree_idx < len(proof.last_levels):
                last_level_nodes = cls._flatten_last_levels(proof.last_levels[tree_idx])

        return cls(root, config, last_level_nodes)

    @classmethod
    def for_const(
        cls, proof: "STARKProof", stark_info: "StarkInfo", verkey: MerkleRoot
    ) -> "MerkleVerifier":
        """Create verifier for constant polynomial tree.

        Args:
            proof: STARK proof containing last_levels
            stark_info: STARK configuration
            verkey: Verification key (root of constant polynomial tree)

        Returns:
            Configured MerkleVerifier for constant tree
        """
        stark_struct = stark_info.stark_struct
        config = MerkleConfig(
            arity=stark_struct.merkle_tree_arity,
            domain_bits=stark_struct.fri_fold_steps[0].domain_bits,
            last_level_verification=stark_struct.last_level_verification,
        )

        last_level_nodes = None
        if config.last_level_verification > 0:
            const_tree_idx = stark_info.n_stages + 1
            if const_tree_idx < len(proof.last_levels):
                last_level_nodes = cls._flatten_last_levels(proof.last_levels[const_tree_idx])

        return cls(verkey, config, last_level_nodes)

    @classmethod
    def for_custom_commit(
        cls, proof: "STARKProof", stark_info: "StarkInfo", root: MerkleRoot, commit_idx: int
    ) -> "MerkleVerifier":
        """Create verifier for a custom commit tree.

        Custom commits are additional polynomial commitments beyond the standard
        stage trees (e.g., the Rom AIR commits its lookup table separately).
        Each custom commit has its own Merkle tree stored at a distinct index:
        tree_idx = n_stages + 2 + commit_idx (after stage trees and const tree).

        This is separate from for_stage/for_const because:
        - The tree index formula differs (stage uses stage-1, const uses n_stages+1)
        - The root comes from public inputs rather than the proof or verkey
        - Only certain AIRs have custom commits (e.g., Rom in Zisk)

        Args:
            proof: STARK proof containing last_levels
            stark_info: STARK configuration
            root: Expected root, reconstructed from publics[custom_commit.public_values]
            commit_idx: Index of the custom commit (0-based)

        Returns:
            Configured MerkleVerifier for this custom commit tree
        """
        stark_struct = stark_info.stark_struct
        config = MerkleConfig(
            arity=stark_struct.merkle_tree_arity,
            domain_bits=stark_struct.fri_fold_steps[0].domain_bits,
            last_level_verification=stark_struct.last_level_verification,
        )

        last_level_nodes = None
        if config.last_level_verification > 0:
            tree_idx = stark_info.n_stages + 2 + commit_idx
            if tree_idx < len(proof.last_levels):
                last_level_nodes = cls._flatten_last_levels(proof.last_levels[tree_idx])

        return cls(root, config, last_level_nodes)

    @classmethod
    def for_fri_step(
        cls, proof: "STARKProof", stark_info: "StarkInfo", step: int
    ) -> "MerkleVerifier":
        """Create verifier for a FRI folding step tree.

        Args:
            proof: STARK proof containing FRI trees
            stark_info: STARK configuration
            step: FRI step number (1-indexed, since step 0 is the initial domain)

        Returns:
            Configured MerkleVerifier for this FRI step
        """
        stark_struct = stark_info.stark_struct
        config = MerkleConfig(
            arity=stark_struct.merkle_tree_arity,
            domain_bits=stark_struct.fri_fold_steps[step].domain_bits,
            last_level_verification=stark_struct.last_level_verification,
        )

        root = proof.fri.trees_fri[step - 1].root

        last_level_nodes = None
        if config.last_level_verification > 0:
            fri_last_levels = proof.fri.trees_fri[step - 1].last_levels
            if fri_last_levels:
                last_level_nodes = cls._flatten_last_levels(fri_last_levels)

        return cls(root, config, last_level_nodes)

    # --- Verification ---

    def verify_query(
        self, query_index: int, leaf_values: list[int], siblings: list[list[int]]
    ) -> bool:
        """Verify a single query proof.

        This method hides the last_level_verification logic internally:
        - If last_level_verification == 0: verify up to root
        - Otherwise: verify up to last-level boundary, check against pre-verified nodes

        The last-level nodes are verified once (lazily) against the root on first query.

        Args:
            query_index: Index of the leaf being verified
            leaf_values: Leaf data to hash
            siblings: Sibling hashes per level (n_siblings levels)

        Returns:
            True if query proof is valid
        """
        # Lazy verification of last-level nodes against root
        if not self._verify_last_level_once():
            return False

        # Hash leaf data
        current_hash = linear_hash(leaf_values, self.config.sponge_width)
        current_idx = query_index

        # Walk up the tree through sibling levels
        for level_siblings in siblings:
            child_position = current_idx % self.config.arity
            current_idx = current_idx // self.config.arity

            hash_input = self._build_parent_hash_input(current_hash, level_siblings, child_position)
            current_hash = hash_seq(hash_input, self.config.sponge_width)

        # Check against target (root or last-level node)
        return self._check_against_target(current_hash, current_idx)

    # --- Private Helpers ---

    def _verify_last_level_once(self) -> bool:
        """Verify last-level nodes against root (once per verifier instance)."""
        if self._last_level_verified:
            return True

        if self.config.last_level_verification == 0:
            self._last_level_verified = True
            return True

        # Use MerkleTree's static verification method
        # Note: height is derived from domain_bits
        height = 1 << self.config.domain_bits
        result = MerkleTree.verify_merkle_root(
            self.root,
            self._last_level_nodes,
            height,
            self.config.last_level_verification,
            self.config.arity,
            self.config.sponge_width,
        )

        if result:
            self._last_level_verified = True

        return result

    def _build_parent_hash_input(
        self, child_hash: list[int], siblings: list[int], child_position: int
    ) -> list[int]:
        """Build hash input for parent node from child hash and siblings.

        In a Merkle tree with arity N, each parent hashes N children together.
        This function constructs that hash input by placing the child hash at
        its position and filling other positions with sibling hashes.
        """
        hash_input = [0] * self.config.sponge_width
        sibling_idx = 0

        for position in range(self.config.arity):
            for hash_element in range(HASH_SIZE):
                buffer_idx = position * HASH_SIZE + hash_element

                if buffer_idx < self.config.sponge_width:
                    if position == child_position:
                        hash_input[buffer_idx] = child_hash[hash_element]
                    else:
                        hash_input[buffer_idx] = siblings[sibling_idx * HASH_SIZE + hash_element]

            if position != child_position:
                sibling_idx += 1

        return hash_input

    def _check_against_target(self, computed_hash: list[int], node_idx: int) -> bool:
        """Check computed hash against target (root or last-level node)."""
        if self.config.last_level_verification == 0:
            return computed_hash[:HASH_SIZE] == self.root[:HASH_SIZE]
        else:
            expected = self._last_level_nodes[node_idx * HASH_SIZE : (node_idx + 1) * HASH_SIZE]
            return computed_hash[:HASH_SIZE] == expected

    @staticmethod
    def _flatten_last_levels(last_levels: list[list[int]]) -> list[int]:
        """Flatten nested last_levels structure to flat list."""
        if not last_levels:
            return []

        # Check if already flat
        if last_levels and isinstance(last_levels[0], int):
            return list(last_levels)

        # Flatten [[h0,h1,h2,h3], [h0,h1,h2,h3], ...]
        result = []
        for node in last_levels:
            result.extend(node)
        return result
