/-
  Merkle tree verification using Poseidon2.

  Translates: executable-spec/primitives/merkle_verifier.py

  Provides a clean interface for Merkle tree verification that hides the
  complexity of the `last_level_verification` optimization internally.

  The `last_level_verification` optimization allows skipping proof verification
  for the top N levels of the tree by including pre-computed hashes at that level
  directly in the proof. This reduces proof size for each query while adding a
  small fixed overhead.
-/
import FFI.Poseidon2

open FFI.Poseidon2

namespace Primitives.MerkleVerifier

-- ============================================================================
-- Constants
-- ============================================================================

/-- Hash output size: 4 Goldilocks field elements. -/
def HASH_SIZE : Nat := 4

-- ============================================================================
-- Configuration
-- ============================================================================

/-- Merkle tree configuration for verification.

    Captures all tree parameters needed for verification.

    Attributes:
    - arity: Tree branching factor (2, 3, or 4)
    - domain_bits: Log2 of the number of leaves
    - last_level_verification: Number of top levels to skip in per-query verification

    Translates: merkle_verifier.py:33-65 (MerkleConfig dataclass) -/
structure MerkleConfig where
  arity : Nat
  domain_bits : Nat
  last_level_verification : Nat
  deriving Repr, BEq

/-- Poseidon2 sponge width for this arity: {2: 8, 3: 12, 4: 16}.
    Translates: merkle_verifier.py:50-52 -/
def MerkleConfig.sponge_width (c : MerkleConfig) : Nat :=
  c.arity * HASH_SIZE

/-- Number of sibling levels in each query proof.
    n_siblings = ceil(domain_bits / log2(arity)) - last_level_verification
    Translates: merkle_verifier.py:54-59 -/
def MerkleConfig.n_siblings (c : MerkleConfig) : Nat :=
  -- log2(arity): for arity 2 -> 1, arity 4 -> 2, arity 3 -> not exact but ceil handles it
  let log2_arity := if c.arity == 4 then 2
                    else if c.arity == 2 then 1
                    else 2  -- arity 3: use 2 as approximation for ceiling division
  let total_levels := (c.domain_bits + log2_arity - 1) / log2_arity
  if total_levels > c.last_level_verification then
    total_levels - c.last_level_verification
  else 0

/-- Number of sibling hash elements per level: (arity - 1) * HASH_SIZE.
    Translates: merkle_verifier.py:62-64 -/
def MerkleConfig.siblings_per_level (c : MerkleConfig) : Nat :=
  (c.arity - 1) * HASH_SIZE

-- ============================================================================
-- MerkleVerifier structure
-- ============================================================================

/-- Merkle tree verifier with encapsulated last_level_verification logic.

    Wraps a MerkleConfig, the expected root, and optionally the pre-verified
    last-level nodes for the last_level_verification optimization.

    Translates: merkle_verifier.py:70-104 -/
structure MerkleVerifier where
  root : Array UInt64
  config : MerkleConfig
  last_level_nodes : Array UInt64
  last_level_verified : Bool
  deriving Repr

-- ============================================================================
-- Constructor
-- ============================================================================

/-- Create a new MerkleVerifier with root, config, and optional last-level nodes.
    Translates: merkle_verifier.py:85-104 (__init__) -/
def MerkleVerifier.new (root : Array UInt64) (config : MerkleConfig)
    (last_level_nodes : Array UInt64 := #[]) : MerkleVerifier :=
  { root := root
    config := config
    last_level_nodes := last_level_nodes
    last_level_verified := false }

-- ============================================================================
-- Internal helpers
-- ============================================================================

/-- Build hash input for parent node from child hash and siblings.

    In a Merkle tree with arity N, each parent hashes N children together.
    This function constructs that hash input by placing the child hash at
    its position and filling other positions with sibling hashes.

    Translates: merkle_verifier.py:306-331 (_build_parent_hash_input) -/
def build_parent_hash_input (sponge_width arity : Nat)
    (child_hash : Array UInt64) (siblings : Array UInt64)
    (child_position : Nat) : Array UInt64 :=
  Id.run do
    let mut hash_input : Array UInt64 := Array.replicate sponge_width 0
    let mut sibling_idx : Nat := 0

    for position in [:arity] do
      for hash_element in [:HASH_SIZE] do
        let buffer_idx := position * HASH_SIZE + hash_element
        if buffer_idx < sponge_width then
          if position == child_position then
            hash_input := hash_input.set! buffer_idx (child_hash[hash_element]!)
          else
            hash_input := hash_input.set! buffer_idx
              (siblings[sibling_idx * HASH_SIZE + hash_element]!)
      if position != child_position then
        sibling_idx := sibling_idx + 1

    hash_input

/-- Compute the number of nodes at each level by tracing from height to root.
    Returns an array of node counts per level (from bottom/leaves up).
    Used by verify_merkle_root to find the target level.

    Translates: merkle_tree.py:298-303 (inside verify_merkle_root) -/
def compute_levels_node_count (height arity : Nat) : Array Nat :=
  Id.run do
    let mut pending := height
    let mut levels : Array Nat := #[]
    -- Use a fuel bound to ensure termination
    let fuel := height + 1
    for _ in [:fuel] do
      if pending > 1 then
        levels := levels.push pending
        pending := (pending + arity - 1) / arity
    levels

/-- Verify Merkle root from last-level nodes.

    Computes the root by hashing up from the last level and compares
    against the expected root.

    Translates: merkle_tree.py:265-337 (MerkleTree.verify_merkle_root static method) -/
def verify_merkle_root (root : Array UInt64) (level : Array UInt64)
    (height : Nat) (last_level_verification : Nat)
    (arity : Nat) (sponge_width : Nat) : Bool :=
  if last_level_verification == 0 then true
  else Id.run do
    -- Compute actual number of nodes at the target level
    let levels := compute_levels_node_count height arity
    let n_levels := levels.size
    let target_level := if n_levels > last_level_verification
                        then n_levels - last_level_verification
                        else 0
    let actual_nodes := if target_level < n_levels then levels[target_level]! else 1

    -- Compute root from last level by hashing upward
    let mut current_level := level
    let mut pending := actual_nodes

    -- Use fuel bound for termination
    let fuel := height + 1
    for _ in [:fuel] do
      if pending > 1 then
        let next_n := (pending + arity - 1) / arity
        let mut next_level : Array UInt64 := #[]

        for i in [:next_n] do
          let mut hash_input : Array UInt64 := Array.replicate sponge_width 0
          for a in [:arity] do
            let child_idx := i * arity + a
            if child_idx < pending then
              for j in [:HASH_SIZE] do
                if a * HASH_SIZE + j < sponge_width then
                  hash_input := hash_input.set! (a * HASH_SIZE + j)
                    (current_level[child_idx * HASH_SIZE + j]!)

          let parent_hash := hashSeq hash_input sponge_width.toUInt64
          for j in [:HASH_SIZE] do
            next_level := next_level.push (parent_hash[j]!)

        current_level := next_level
        pending := next_n

    -- Compare computed root with expected root
    let mut match_ := true
    for i in [:HASH_SIZE] do
      if current_level[i]! != root[i]! then
        match_ := false
    match_

-- ============================================================================
-- Query verification
-- ============================================================================

/-- Verify last-level nodes against root (once per verifier instance).

    If last_level_verification > 0 and not yet verified, computes the root
    from the last-level nodes and compares with the expected root.

    Translates: merkle_verifier.py:280-304 (_verify_last_level_once)

    Returns (success, updated verifier with verified flag set). -/
def MerkleVerifier.verify_last_level_once (mv : MerkleVerifier) : Bool × MerkleVerifier :=
  if mv.last_level_verified then (true, mv)
  else if mv.config.last_level_verification == 0 then
    (true, { mv with last_level_verified := true })
  else
    let height := 2 ^ mv.config.domain_bits
    let result := verify_merkle_root mv.root mv.last_level_nodes
                    height mv.config.last_level_verification
                    mv.config.arity mv.config.sponge_width
    if result then
      (true, { mv with last_level_verified := true })
    else
      (false, mv)

/-- Check computed hash against target (root or last-level node).
    Translates: merkle_verifier.py:333-339 (_check_against_target) -/
def MerkleVerifier.check_against_target (mv : MerkleVerifier)
    (computed_hash : Array UInt64) (node_idx : Nat) : Bool :=
  if mv.config.last_level_verification == 0 then
    -- Compare against root
    Id.run do
      let mut ok := true
      for i in [:HASH_SIZE] do
        if computed_hash[i]! != mv.root[i]! then
          ok := false
      ok
  else
    -- Compare against last-level node
    Id.run do
      let mut ok := true
      for i in [:HASH_SIZE] do
        if computed_hash[i]! != mv.last_level_nodes[node_idx * HASH_SIZE + i]! then
          ok := false
      ok

/-- Verify a single query proof.

    Hides the last_level_verification logic internally:
    - If last_level_verification == 0: verify up to root
    - Otherwise: verify up to last-level boundary, check against pre-verified nodes

    The last-level nodes are verified once (lazily) against the root on first query.

    Args:
    - root: expected Merkle root (already stored in mv)
    - leaf_values: leaf data to hash (polynomial evaluations as UInt64)
    - siblings: sibling hashes per level (array of arrays, n_siblings levels)
    - query_idx: index of the leaf being verified

    Translates: merkle_verifier.py:240-276 (verify_query)

    Returns (success, updated verifier). -/
def MerkleVerifier.verify_query (mv : MerkleVerifier)
    (leaf_values : Array UInt64) (siblings : Array (Array UInt64))
    (query_idx : Nat) : Bool × MerkleVerifier :=
  -- Lazy verification of last-level nodes against root
  let (ok, mv) := mv.verify_last_level_once
  if !ok then (false, mv)
  else Id.run do
    -- Hash leaf data
    let mut current_hash := linearHash leaf_values mv.config.sponge_width.toUInt64
    let mut current_idx := query_idx

    -- Walk up the tree through sibling levels
    for level_siblings in siblings do
      let child_position := current_idx % mv.config.arity
      current_idx := current_idx / mv.config.arity

      let hash_input := build_parent_hash_input mv.config.sponge_width mv.config.arity
                          current_hash level_siblings child_position
      current_hash := hashSeq hash_input mv.config.sponge_width.toUInt64

    -- Check against target (root or last-level node)
    let result := mv.check_against_target current_hash current_idx
    (result, mv)

-- ============================================================================
-- Utility: flatten last-level nodes
-- ============================================================================

/-- Flatten nested last_levels structure to flat array.
    Translates: merkle_verifier.py:341-355 (_flatten_last_levels) -/
def flatten_last_levels (last_levels : Array (Array UInt64)) : Array UInt64 :=
  if last_levels.size == 0 then #[]
  else Id.run do
    let mut result : Array UInt64 := #[]
    for node in last_levels do
      for elem in node do
        result := result.push elem
    result

end Primitives.MerkleVerifier
