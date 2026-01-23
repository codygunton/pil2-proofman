"""Merkle tree commitment using Poseidon2."""

from dataclasses import dataclass, field
from typing import List, Optional, Union
import math
import numpy as np
from poseidon2_ffi import linear_hash, hash_seq

# --- Constants ---

HASH_SIZE = 4

# --- Type Aliases ---

MerkleRoot = List[int]
LeafData = List[int]


# --- FFI Boundary Helpers ---

def _to_int_list(data: List[Union[int, object]]) -> List[int]:
    """Convert FF/FF3/int elements to plain int for FFI calls."""
    return [int(x) for x in data]


# --- Data Classes ---

@dataclass
class QueryProof:
    """Query proof containing leaf values and Merkle authentication path.

    Corresponds to C++ MerkleProof in proof_stark.hpp lines 39-69.

    Attributes:
        v: Leaf values at query index - list of columns, each column is a list of elements
           For base field polynomials: [[val1], [val2], ...] (one element per column)
           For extension field: [[v0, v1, v2], ...] (FIELD_EXTENSION elements per column)
        mp: Merkle path - list of sibling hashes per level, from leaf to root
           Each level has (arity - 1) * HASH_SIZE elements
    """
    v: List[List[int]] = field(default_factory=list)
    mp: List[List[int]] = field(default_factory=list)


# --- Data Layout ---

def transpose_for_merkle(data: List[int], height: int, width: int, elem_size: int) -> List[int]:
    """Transpose data layout for Merkle tree construction.

    Reorders elements so that those belonging to the same Merkle leaf are contiguous.
    This matches the pil2-stark C++ memory layout convention.
    """
    h = height // width
    result = np.array(data, dtype=object).reshape(h, width, elem_size).transpose(1, 0, 2).flatten()
    return list(result)


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
        self.nodes: List[int] = []
        self.num_nodes = 0

        # Store source data for query proof value extraction
        self.source_data: Optional[List[int]] = None
        self.n_cols: int = 0  # Number of columns (polynomials)

    # --- Core Operations ---

    def merkelize(self, source: LeafData, height: int, width: int, n_cols: int = 0) -> None:
        """Build Merkle tree from source data.

        Args:
            source: Flattened leaf data (height * width elements)
            height: Number of leaves (rows)
            width: Elements per leaf (columns * elem_size)
            n_cols: Number of polynomial columns (for query proof extraction)
        """
        self.height = height
        self.width = width
        self.n_cols = n_cols if n_cols > 0 else width
        self.num_nodes = self._compute_num_nodes(height)
        self.nodes = [0] * self.num_nodes

        # Convert to int at FFI boundary (supports FF/FF3 arrays)
        int_source = _to_int_list(source)

        # Store source data for later query proof extraction
        self.source_data = int_source

        if height == 0:
            return

        # Hash each leaf row
        for i in range(height):
            row_start = i * width
            row_data = int_source[row_start:row_start + width]
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

    def get_group_proof(self, idx: int) -> List[int]:
        """Generate Merkle proof (siblings only) for leaf at index."""
        proof: List[int] = []
        self._collect_proof_siblings(proof, idx, 0, self.height)
        return proof

    def get_query_proof(self, idx: int, elem_size: int = 1) -> QueryProof:
        """Extract complete query proof with leaf values and Merkle path.

        This is the main method for generating query proofs for STARK proofs.
        It returns both the polynomial values at the query index and the
        Merkle authentication path.

        Args:
            idx: Query index (leaf index in the tree)
            elem_size: Elements per column (1 for base field, 3 for extension)

        Returns:
            QueryProof with:
            - v: List of column values at idx, each is [elem_size] elements
            - mp: List of sibling hashes per level, structured for C++ compatibility

        Raises:
            ValueError: If source_data not available or idx out of range
        """
        if self.source_data is None:
            raise ValueError("Source data not stored - cannot extract leaf values")
        if idx < 0 or idx >= self.height:
            raise ValueError(f"Query index {idx} out of range [0, {self.height})")

        # Extract leaf values from source data
        # Source layout: height rows, each row has width elements
        # width = n_cols * elem_size (for base field elem_size=1)
        row_start = idx * self.width
        row_data = self.source_data[row_start:row_start + self.width]

        # Split row into columns
        v = []
        for col in range(self.n_cols):
            col_start = col * elem_size
            col_values = row_data[col_start:col_start + elem_size]
            v.append(col_values)

        # Get Merkle siblings
        flat_siblings = self.get_group_proof(idx)

        # Structure siblings into levels
        # Each level has (arity - 1) * HASH_SIZE elements
        siblings_per_level = (self.arity - 1) * HASH_SIZE
        mp = []
        for i in range(0, len(flat_siblings), siblings_per_level):
            level = flat_siblings[i:i + siblings_per_level]
            mp.append(level)

        return QueryProof(v=v, mp=mp)

    def get_last_level_nodes(self) -> List[int]:
        """Extract last level verification nodes.

        When lastLevelVerification > 0, the verifier needs access to
        the internal nodes at (total_levels - lastLevelVerification) from bottom.
        This is equivalent to lastLevelVerification levels below the root.

        Returns:
            List of arity^lastLevelVerification * HASH_SIZE elements,
            or empty list if lastLevelVerification == 0.
            The actual nodes are at the beginning, followed by zero padding
            if the actual node count is less than arity^lastLevelVerification.
        """
        if self.last_level_verification == 0:
            return []

        # Trace through tree structure to find the target level's offset
        # Target level is last_level_verification levels below the root
        pending = self.height
        next_index = 0
        levels_info = []  # [(offset, n_nodes_at_level), ...]

        while pending > 1:
            extra_zeros = (self.arity - (pending % self.arity)) % self.arity
            next_n = (pending + (self.arity - 1)) // self.arity
            levels_info.append((next_index * HASH_SIZE, pending))
            next_index += pending + extra_zeros
            pending = next_n

        # Root level
        n_levels = len(levels_info)  # Number of levels excluding root

        # Target level is last_level_verification from root (top)
        target_level = n_levels - self.last_level_verification
        if target_level < 0:
            target_level = 0

        # Get offset and actual node count at target level
        target_offset, actual_nodes = levels_info[target_level]

        # Expected size (for padding)
        expected_nodes = self.arity ** self.last_level_verification

        # Extract actual nodes and pad with zeros
        actual_size = actual_nodes * HASH_SIZE
        result = list(self.nodes[target_offset:target_offset + actual_size])

        # Pad to expected size
        padding_size = expected_nodes * HASH_SIZE - len(result)
        if padding_size > 0:
            result.extend([0] * padding_size)

        return result

    @staticmethod
    def verify_merkle_root(
        root: MerkleRoot,
        level: List[int],
        height: int,
        last_level_verification: int,
        arity: int,
        sponge_width: int
    ) -> bool:
        """Verify Merkle root from last-level nodes.

        C++ reference: merkleTreeGL.hpp lines 70-99

        Computes the root by hashing up from the last level and compares
        against the expected root.

        Args:
            root: Expected root (HASH_SIZE elements)
            level: Last level nodes (num_nodes * HASH_SIZE elements)
            height: Tree height (number of leaves)
            last_level_verification: Number of levels to skip from bottom
            arity: Tree arity (2, 3, or 4)
            sponge_width: Hash sponge width

        Returns:
            True if computed root matches expected root
        """
        if last_level_verification == 0:
            return True  # Nothing to verify

        # Compute actual number of nodes at the target level
        # Target level is last_level_verification levels below the root
        # Trace down from height to find actual node count at that level
        pending = height
        levels_node_count = []
        while pending > 1:
            levels_node_count.append(pending)
            pending = (pending + arity - 1) // arity

        # Target level is (n_levels - last_level_verification)
        n_levels = len(levels_node_count)
        target_level = n_levels - last_level_verification
        if target_level < 0:
            target_level = 0

        actual_nodes = levels_node_count[target_level] if target_level < n_levels else 1

        # Compute root from last level by hashing upward
        # Start with actual number of nodes (rest are zero padding)
        current_level = list(level)
        pending = actual_nodes

        while pending > 1:
            next_n = (pending + arity - 1) // arity
            next_level = []

            for i in range(next_n):
                hash_input = [0] * sponge_width
                for a in range(arity):
                    child_idx = i * arity + a
                    if child_idx < pending:
                        for j in range(HASH_SIZE):
                            if a * HASH_SIZE + j < sponge_width:
                                hash_input[a * HASH_SIZE + j] = current_level[child_idx * HASH_SIZE + j]

                parent_hash = hash_seq(hash_input, sponge_width)
                next_level.extend(parent_hash[:HASH_SIZE])

            current_level = next_level
            pending = next_n

        # Compare computed root with expected root
        return current_level[:HASH_SIZE] == root[:HASH_SIZE]

    def verify_group_proof(
        self,
        root: MerkleRoot,
        proof: List[List[int]],
        idx: int,
        leaf_data: LeafData
    ) -> bool:
        """Verify Merkle proof for a leaf."""
        computed = linear_hash(_to_int_list(leaf_data), self.sponge_width)

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
        proof: List[int],
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
