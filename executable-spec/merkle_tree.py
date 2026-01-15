"""Merkle tree commitment using Poseidon2."""

from typing import List
import math
from poseidon2_ffi import linear_hash, hash_seq
from field import Fe

# --- Type Aliases ---

MerkleRoot = List[Fe]
MerkleProof = List[Fe]
LeafData = List[Fe]

# --- Constants ---

HASH_SIZE = 4


# --- Merkle Tree ---

class MerkleTree:
    """Variable-arity Merkle tree using Poseidon2 hashing."""

    def __init__(
        self,
        arity: int = 4,
        last_level_verification: int = 0,
        custom: bool = False
    ):
        if arity not in [2, 3, 4]:
            raise ValueError(f"arity must be 2, 3, or 4, got {arity}")

        self.arity = arity
        self.last_level_verification = last_level_verification
        self.custom = custom
        self.n_field_elements = HASH_SIZE
        self.sponge_width = {2: 8, 3: 12, 4: 16}[arity]

        self.height = 0
        self.width = 0
        self.nodes: List[Fe] = []
        self.num_nodes = 0

    # --- Core Operations ---

    def merkelize(self, source: LeafData, height: int, width: int) -> None:
        """Build Merkle tree from source data."""
        self.height = height
        self.width = width
        self.num_nodes = self._compute_num_nodes(height)
        self.nodes = [0] * self.num_nodes

        if height == 0:
            return

        # Hash each leaf row
        for i in range(height):
            row_start = i * width
            row_data = source[row_start:row_start + width]
            leaf_hash = linear_hash(row_data, self.sponge_width)
            for j in range(HASH_SIZE):
                self.nodes[i * HASH_SIZE + j] = leaf_hash[j]

        # Build internal nodes bottom-up
        pending = height
        next_index = 0

        while pending > 1:
            extra_zeros = (self.arity - (pending % self.arity)) % self.arity
            if extra_zeros > 0:
                for i in range(extra_zeros * HASH_SIZE):
                    self.nodes[next_index + pending * HASH_SIZE + i] = 0

            next_n = (pending + (self.arity - 1)) // self.arity

            for i in range(next_n):
                hash_input = [0] * self.sponge_width
                for a in range(self.arity):
                    child_idx = next_index + (i * self.arity + a) * HASH_SIZE
                    for j in range(HASH_SIZE):
                        if a * HASH_SIZE + j < self.sponge_width:
                            hash_input[a * HASH_SIZE + j] = self.nodes[child_idx + j]

                parent_hash = hash_seq(hash_input, self.sponge_width)
                parent_idx = next_index + (pending + extra_zeros + i) * HASH_SIZE
                for j in range(HASH_SIZE):
                    self.nodes[parent_idx + j] = parent_hash[j]

            next_index += (pending + extra_zeros) * HASH_SIZE
            pending = next_n

    def get_root(self) -> MerkleRoot:
        """Return the Merkle root commitment."""
        if self.num_nodes == 0:
            return [0] * HASH_SIZE
        return self.nodes[self.num_nodes - HASH_SIZE:self.num_nodes]

    def get_group_proof(self, idx: int) -> MerkleProof:
        """Generate Merkle proof for leaf at index."""
        proof: MerkleProof = []
        self._collect_proof_siblings(proof, idx, 0, self.height)
        return proof

    def verify_group_proof(
        self,
        root: MerkleRoot,
        proof: List[List[Fe]],
        idx: int,
        leaf_data: LeafData
    ) -> bool:
        """Verify Merkle proof for a leaf."""
        computed = linear_hash(leaf_data, self.sponge_width)

        for level_siblings in proof:
            curr_idx = idx % self.arity
            idx = idx // self.arity

            inputs = [0] * self.sponge_width
            p = 0
            for i in range(self.arity):
                if i != curr_idx:
                    for j in range(HASH_SIZE):
                        if i * HASH_SIZE + j < self.sponge_width:
                            inputs[i * HASH_SIZE + j] = level_siblings[p * HASH_SIZE + j]
                    p += 1
                else:
                    for j in range(HASH_SIZE):
                        if i * HASH_SIZE + j < self.sponge_width:
                            inputs[i * HASH_SIZE + j] = computed[j]

            computed = hash_seq(inputs, self.sponge_width)

        return computed == root[:HASH_SIZE]

    # --- Proof Size Utilities ---

    def get_merkle_proof_length(self) -> int:
        """Number of levels in a Merkle proof."""
        if self.height > 1:
            return math.ceil(math.log(self.height) / math.log(self.arity)) - self.last_level_verification
        return 0

    def get_num_siblings(self) -> int:
        """Number of sibling elements per proof level."""
        return (self.arity - 1) * self.n_field_elements

    def get_merkle_proof_size(self) -> int:
        """Total size of a Merkle proof in field elements."""
        return self.get_merkle_proof_length() * self.get_num_siblings()

    # --- Internal Helpers ---

    def _compute_num_nodes(self, height: int) -> int:
        """Calculate total storage needed for tree nodes."""
        num_nodes = height
        nodes_level = height

        while nodes_level > 1:
            extra_zeros = (self.arity - (nodes_level % self.arity)) % self.arity
            num_nodes += extra_zeros
            next_n = (nodes_level + (self.arity - 1)) // self.arity
            num_nodes += next_n
            nodes_level = next_n

        return num_nodes * self.n_field_elements

    def _collect_proof_siblings(
        self,
        proof: MerkleProof,
        idx: int,
        offset: int,
        n: int
    ) -> None:
        """Recursively collect sibling hashes for proof."""
        if n <= 1:
            return

        if self.last_level_verification > 0:
            if n <= self.arity ** self.last_level_verification:
                return

        curr_idx = idx % self.arity
        next_idx = idx // self.arity
        si = idx - curr_idx

        for i in range(self.arity):
            if i != curr_idx:
                node_offset = offset + (si + i) * HASH_SIZE
                for j in range(HASH_SIZE):
                    proof.append(self.nodes[node_offset + j])

        extra_zeros = (self.arity - (n % self.arity)) % self.arity
        next_n = (n + (self.arity - 1)) // self.arity
        next_offset = offset + (n + extra_zeros) * HASH_SIZE

        self._collect_proof_siblings(proof, next_idx, next_offset, next_n)
