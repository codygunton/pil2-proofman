"""Merkle tree commitment abstraction for proof generation.

Mirrors MerkleVerifier: provides factory methods that construct properly-configured
Merkle trees from StarkInfo, hiding arity and last_level_verification details.
"""

from typing import TYPE_CHECKING

from primitives.merkle_tree import MerkleRoot, MerkleTree, QueryProof
from primitives.merkle_verifier import MerkleConfig

if TYPE_CHECKING:
    from protocol.stark_info import StarkInfo


class MerkleProver:
    """Merkle tree builder with encapsulated configuration.

    Usage:
        prover = MerkleProver.for_stage(stark_info)
        root = prover.commit(data, height, n_cols)
        proof = prover.get_query_proof(idx, elem_size=1)
    """

    def __init__(self, config: MerkleConfig, custom: bool = False) -> None:
        self.config = config
        self._tree = MerkleTree(
            arity=config.arity,
            last_level_verification=config.last_level_verification,
            custom=custom,
        )

    # --- Factory Methods ---

    @classmethod
    def for_stage(cls, stark_info: 'StarkInfo') -> 'MerkleProver':
        """Create prover for stage commitment trees (cm1, cm2, ..., cmQ)."""
        ss = stark_info.stark_struct
        config = MerkleConfig(
            arity=ss.merkle_tree_arity,
            domain_bits=ss.fri_fold_steps[0].domain_bits,
            last_level_verification=ss.last_level_verification,
        )
        return cls(config, custom=ss.merkle_tree_custom)

    @classmethod
    def for_const(cls, stark_info: 'StarkInfo') -> 'MerkleProver':
        """Create prover for constant polynomial tree."""
        ss = stark_info.stark_struct
        config = MerkleConfig(
            arity=ss.merkle_tree_arity,
            domain_bits=ss.fri_fold_steps[0].domain_bits,
            last_level_verification=ss.last_level_verification,
        )
        return cls(config, custom=ss.merkle_tree_custom)

    @classmethod
    def for_fri_step(cls, stark_info: 'StarkInfo') -> 'MerkleProver':
        """Create prover for FRI folding step trees."""
        ss = stark_info.stark_struct
        config = MerkleConfig(
            arity=ss.merkle_tree_arity,
            domain_bits=ss.fri_fold_steps[0].domain_bits,
            last_level_verification=ss.last_level_verification,
        )
        return cls(config, custom=ss.merkle_tree_custom)

    # --- Operations ---

    def commit(self, data: list[int], height: int, n_cols: int) -> MerkleRoot:
        """Build Merkle tree and return root.

        Args:
            data: Flattened leaf data (height * n_cols elements)
            height: Number of leaves
            n_cols: Number of columns per leaf

        Returns:
            Merkle root (HASH_SIZE elements)
        """
        self._tree.merkelize(data, height, n_cols, n_cols=n_cols)
        return self._tree.get_root()

    def get_query_proof(self, idx: int, elem_size: int = 1) -> QueryProof:
        """Get Merkle proof for a query index."""
        return self._tree.get_query_proof(idx, elem_size)

    def get_last_level_nodes(self) -> list[int]:
        """Get flattened last-level nodes for proof serialization."""
        if self.config.last_level_verification == 0:
            return []
        return self._tree.get_last_levels()

    @property
    def tree(self) -> MerkleTree:
        """Access the underlying MerkleTree (for backward compatibility)."""
        return self._tree
