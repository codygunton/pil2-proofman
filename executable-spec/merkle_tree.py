# QUESTION: Is this just a generic merkle tree implementation with a Poseidon2 hash? If so, is there a standard python merkle tree library that we might be able to use instead of this? ANS: Not quite generic - it has FRI-specific features: (1) variable arity (2, 3, 4) matching C++ MerkleTreeGL, (2) specific leaf hashing using linear_hash with width parameter, (3) the lastLevelVerification optimization for proof size. Standard libraries (merkletools, pymerkle) use binary trees with SHA256/Keccak. We need Poseidon2 over Goldilocks for STARK compatibility. This implementation mirrors merkleTreeGL.hpp to ensure identical roots/proofs. Can simplify at cost of C++ divergence? N - must produce identical Merkle roots to C++ for proof compatibility.
"""
Merkle tree implementation for FRI using Poseidon2 hashing.

This module implements variable-arity Merkle trees matching the C++ implementation.

C++ Reference: pil2-stark/src/starkpil/merkleTree/merkleTreeGL.hpp
"""

from typing import List, Tuple, Optional
import math
from poseidon2_ffi import poseidon2_hash, linear_hash, hash_seq, CAPACITY


# Hash size (capacity of sponge)
HASH_SIZE = 4


class MerkleTree:
    """
    Variable-arity Merkle tree using Poseidon2 hashing.

    Attributes:
        height: Number of leaf nodes
        width: Number of field elements per leaf
        arity: Tree branching factor (2, 3, or 4)
        nodes: Flattened array of all tree nodes
    """

    def __init__(
        self,
        arity: int = 4,
        last_level_verification: int = 0,
        custom: bool = False
    ):
        """
        Initialize Merkle tree configuration.

        Args:
            arity: Branching factor (2, 3, or 4)
            last_level_verification: Optimization level for verification
            custom: Custom tree flag

        C++ Reference: MerkleTreeGL constructor
        """
        if arity not in [2, 3, 4]:
            raise ValueError(f"arity must be 2, 3, or 4, got {arity}")

        self.arity = arity
        self.last_level_verification = last_level_verification
        self.custom = custom
        self.n_field_elements = HASH_SIZE

        # Sponge width based on arity
        self.sponge_width = {2: 8, 3: 12, 4: 16}[arity]

        # Will be set during merkelize
        self.height = 0
        self.width = 0
        self.nodes: List[int] = []
        self.num_nodes = 0

    def _get_num_nodes(self, height: int) -> int:
        """
        Calculate total number of nodes in tree including padding.

        C++ Reference: MerkleTreeGL::getNumNodes
        """
        num_nodes = height
        nodes_level = height

        while nodes_level > 1:
            extra_zeros = (self.arity - (nodes_level % self.arity)) % self.arity
            num_nodes += extra_zeros
            next_n = (nodes_level + (self.arity - 1)) // self.arity
            num_nodes += next_n
            nodes_level = next_n

        return num_nodes * self.n_field_elements

    def merkelize(self, source: List[int], height: int, width: int) -> None:
        """
        Build Merkle tree from source data.

        Args:
            source: Flattened leaf data (height * width elements)
            height: Number of rows/leaves
            width: Number of field elements per row

        C++ Reference: MerkleTreeGL::merkelize
        """
        self.height = height
        self.width = width
        self.num_nodes = self._get_num_nodes(height)
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

        # Build tree bottom-up
        pending = height
        next_index = 0

        while pending > 1:
            extra_zeros = (self.arity - (pending % self.arity)) % self.arity

            # Pad with zeros if needed
            if extra_zeros > 0:
                for i in range(extra_zeros * HASH_SIZE):
                    self.nodes[next_index + pending * HASH_SIZE + i] = 0

            next_n = (pending + (self.arity - 1)) // self.arity

            # Hash each group of arity nodes
            for i in range(next_n):
                # Prepare input: arity nodes concatenated
                input_data = [0] * self.sponge_width
                for a in range(self.arity):
                    node_idx = next_index + (i * self.arity + a) * HASH_SIZE
                    for j in range(HASH_SIZE):
                        if a * HASH_SIZE + j < self.sponge_width:
                            input_data[a * HASH_SIZE + j] = self.nodes[node_idx + j]

                # Hash and store parent
                parent_hash = hash_seq(input_data, self.sponge_width)
                parent_idx = next_index + (pending + extra_zeros + i) * HASH_SIZE
                for j in range(HASH_SIZE):
                    self.nodes[parent_idx + j] = parent_hash[j]

            next_index += (pending + extra_zeros) * HASH_SIZE
            pending = next_n

    def get_root(self) -> List[int]:
        """
        Get the Merkle root.

        Returns:
            List of HASH_SIZE field elements

        C++ Reference: MerkleTreeGL::getRoot
        """
        if self.num_nodes == 0:
            return [0] * HASH_SIZE
        return self.nodes[self.num_nodes - HASH_SIZE:self.num_nodes]

    def get_merkle_proof_length(self) -> int:
        """
        Get number of levels in the proof.

        C++ Reference: MerkleTreeGL::getMerkleProofLength
        """
        if self.height > 1:
            return math.ceil(math.log(self.height) / math.log(self.arity)) - self.last_level_verification
        return 0

    def get_num_siblings(self) -> int:
        """
        Get number of sibling elements per level.

        C++ Reference: MerkleTreeGL::getNumSiblings
        """
        return (self.arity - 1) * self.n_field_elements

    def get_merkle_proof_size(self) -> int:
        """
        Get total size of Merkle proof.

        C++ Reference: MerkleTreeGL::getMerkleProofSize
        """
        return self.get_merkle_proof_length() * self.get_num_siblings()

    def get_group_proof(self, idx: int) -> List[int]:
        """
        Generate Merkle proof for leaf at index.

        Args:
            idx: Leaf index (0-indexed)

        Returns:
            List of proof elements

        C++ Reference: MerkleTreeGL::genMerkleProof
        """
        proof = []
        self._gen_merkle_proof(proof, idx, 0, self.height)
        return proof

    def _gen_merkle_proof(
        self,
        proof: List[int],
        idx: int,
        offset: int,
        n: int
    ) -> None:
        """
        Recursive Merkle proof generation.

        C++ Reference: MerkleTreeGL::genMerkleProof (recursive internal)
        """
        if n <= 1:
            return

        # Check if we've reached the last level verification depth
        if self.last_level_verification > 0:
            if n <= self.arity ** self.last_level_verification:
                return

        curr_idx = idx % self.arity
        next_idx = idx // self.arity
        si = idx - curr_idx

        # Copy siblings (all nodes in group except current)
        for i in range(self.arity):
            if i != curr_idx:
                node_offset = offset + (si + i) * HASH_SIZE
                for j in range(HASH_SIZE):
                    proof.append(self.nodes[node_offset + j])

        # Calculate next level offset
        extra_zeros = (self.arity - (n % self.arity)) % self.arity
        next_n = (n + (self.arity - 1)) // self.arity
        next_offset = offset + (n + extra_zeros) * HASH_SIZE

        # Recurse
        self._gen_merkle_proof(proof, next_idx, next_offset, next_n)

    def verify_group_proof(
        self,
        root: List[int],
        proof: List[List[int]],
        idx: int,
        leaf_data: List[int]
    ) -> bool:
        """
        Verify Merkle proof for a leaf.

        Args:
            root: Expected root hash
            proof: List of sibling arrays at each level
            idx: Leaf index
            leaf_data: Original leaf data

        Returns:
            True if proof is valid

        C++ Reference: MerkleTreeGL::verifyGroupProof
        """
        # Hash leaf data
        computed = linear_hash(leaf_data, self.sponge_width)
        query_idx = idx

        for level_siblings in proof:
            curr_idx = query_idx % self.arity
            query_idx = query_idx // self.arity

            # Arrange siblings and current value
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

        # Compare with root
        return computed == root[:HASH_SIZE]
