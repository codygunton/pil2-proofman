import LSpec
import Primitives.MerkleVerifier

open Primitives.MerkleVerifier
open LSpec

-- ============================================================================
-- MerkleConfig Tests
-- ============================================================================

def configConstructionTests : TestSeq :=
  let c2 := MerkleConfig.mk 2 10 0
  let c4 := MerkleConfig.mk 4 12 0
  let c3 := MerkleConfig.mk 3 9 0
  let c_llv := MerkleConfig.mk 4 12 2
  group "MerkleConfig construction" (
    test "arity 2: sponge_width = 8"
      (c2.sponge_width == 8) $
    test "arity 4: sponge_width = 16"
      (c4.sponge_width == 16) $
    test "arity 3: sponge_width = 12"
      (c3.sponge_width == 12) $
    test "arity 2: siblings_per_level = 4"
      (c2.siblings_per_level == 4) $
    test "arity 4: siblings_per_level = 12"
      (c4.siblings_per_level == 12) $
    test "arity 3: siblings_per_level = 8"
      (c3.siblings_per_level == 8) $
    test "with llv: sponge_width unchanged"
      (c_llv.sponge_width == 16)
  )

def configNSiblingsTests : TestSeq :=
  -- arity 2, domain_bits=10 -> 10 levels, no llv -> 10 siblings
  let c1 := MerkleConfig.mk 2 10 0
  -- arity 4, domain_bits=12 -> ceil(12/2) = 6 levels, no llv -> 6 siblings
  let c2 := MerkleConfig.mk 4 12 0
  -- arity 4, domain_bits=12, llv=2 -> 6 - 2 = 4 siblings
  let c3 := MerkleConfig.mk 4 12 2
  -- arity 2, domain_bits=3, llv=1 -> 3 - 1 = 2 siblings
  let c4 := MerkleConfig.mk 2 3 1
  group "MerkleConfig.n_siblings" (
    test "arity 2, 10 bits, no llv -> 10 siblings"
      (c1.n_siblings == 10) $
    test "arity 4, 12 bits, no llv -> 6 siblings"
      (c2.n_siblings == 6) $
    test "arity 4, 12 bits, llv=2 -> 4 siblings"
      (c3.n_siblings == 4) $
    test "arity 2, 3 bits, llv=1 -> 2 siblings"
      (c4.n_siblings == 2)
  )

-- ============================================================================
-- MerkleVerifier Construction Tests
-- ============================================================================

def verifierConstructionTests : TestSeq :=
  let root : Array UInt64 := #[1, 2, 3, 4]
  let config := MerkleConfig.mk 4 10 0
  let mv := MerkleVerifier.new root config
  group "MerkleVerifier.new" (
    test "root is stored"
      (mv.root == root) $
    test "config is stored"
      (mv.config == config) $
    test "last_level_nodes is empty by default"
      (mv.last_level_nodes == #[]) $
    test "not yet verified"
      (mv.last_level_verified == false)
  )

def verifierWithLLVTests : TestSeq :=
  let root : Array UInt64 := #[10, 20, 30, 40]
  let config := MerkleConfig.mk 4 12 2
  let lln : Array UInt64 := #[100, 200, 300, 400, 500, 600, 700, 800]
  let mv := MerkleVerifier.new root config lln
  group "MerkleVerifier.new with last_level_nodes" (
    test "root is stored"
      (mv.root == root) $
    test "config has llv=2"
      (mv.config.last_level_verification == 2) $
    test "last_level_nodes stored"
      (mv.last_level_nodes.size == 8) $
    test "last_level_nodes match"
      (mv.last_level_nodes == lln) $
    test "not yet verified"
      (mv.last_level_verified == false)
  )

-- ============================================================================
-- build_parent_hash_input Tests
-- ============================================================================

def buildParentHashInputTests : TestSeq :=
  -- arity 2: sponge_width=8, child at position 0
  let child : Array UInt64 := #[1, 2, 3, 4]
  let siblings : Array UInt64 := #[5, 6, 7, 8]  -- 1 sibling for arity 2
  let result0 := build_parent_hash_input 8 2 child siblings 0
  -- child at position 0: result = [1,2,3,4, 5,6,7,8]
  -- child at position 1: result = [5,6,7,8, 1,2,3,4]
  let result1 := build_parent_hash_input 8 2 child siblings 1
  group "build_parent_hash_input" (
    test "arity 2, child at pos 0: child first"
      (result0[0]! == 1 && result0[1]! == 2 && result0[2]! == 3 && result0[3]! == 4) $
    test "arity 2, child at pos 0: sibling second"
      (result0[4]! == 5 && result0[5]! == 6 && result0[6]! == 7 && result0[7]! == 8) $
    test "arity 2, child at pos 1: sibling first"
      (result1[0]! == 5 && result1[1]! == 6 && result1[2]! == 7 && result1[3]! == 8) $
    test "arity 2, child at pos 1: child second"
      (result1[4]! == 1 && result1[5]! == 2 && result1[6]! == 3 && result1[7]! == 4) $
    test "result has correct size"
      (result0.size == 8)
  )

def buildParentArity4Tests : TestSeq :=
  -- arity 4: sponge_width=16, child at position 2
  let child : Array UInt64 := #[10, 20, 30, 40]
  -- 3 siblings for arity 4: positions 0, 1, 3
  let siblings : Array UInt64 := #[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
  let result := build_parent_hash_input 16 4 child siblings 2
  group "build_parent_hash_input arity 4" (
    test "result has correct size"
      (result.size == 16) $
    -- Position 0: sibling 0 -> [1,2,3,4]
    test "position 0: sibling 0"
      (result[0]! == 1 && result[1]! == 2 && result[2]! == 3 && result[3]! == 4) $
    -- Position 1: sibling 1 -> [5,6,7,8]
    test "position 1: sibling 1"
      (result[4]! == 5 && result[5]! == 6 && result[6]! == 7 && result[7]! == 8) $
    -- Position 2: child -> [10,20,30,40]
    test "position 2: child"
      (result[8]! == 10 && result[9]! == 20 && result[10]! == 30 && result[11]! == 40) $
    -- Position 3: sibling 2 -> [9,10,11,12]
    test "position 3: sibling 2"
      (result[12]! == 9 && result[13]! == 10 && result[14]! == 11 && result[15]! == 12)
  )

-- ============================================================================
-- compute_levels_node_count Tests
-- ============================================================================

def levelsNodeCountTests : TestSeq :=
  -- height=8, arity=2: levels = [8, 4, 2]
  let l1 := compute_levels_node_count 8 2
  -- height=16, arity=4: levels = [16, 4]
  let l2 := compute_levels_node_count 16 4
  -- height=4, arity=2: levels = [4, 2]
  let l3 := compute_levels_node_count 4 2
  -- height=1, arity=2: no levels (already root)
  let l4 := compute_levels_node_count 1 2
  group "compute_levels_node_count" (
    test "height=8, arity=2: 3 levels"
      (l1.size == 3) $
    test "height=8, arity=2: levels = [8, 4, 2]"
      (l1 == #[8, 4, 2]) $
    test "height=16, arity=4: 2 levels"
      (l2.size == 2) $
    test "height=16, arity=4: levels = [16, 4]"
      (l2 == #[16, 4]) $
    test "height=4, arity=2: levels = [4, 2]"
      (l3 == #[4, 2]) $
    test "height=1: no levels"
      (l4.size == 0)
  )

-- ============================================================================
-- check_against_target Tests
-- ============================================================================

def checkAgainstTargetTests : TestSeq :=
  -- No last_level_verification: compare against root
  let config_no_llv := MerkleConfig.mk 4 10 0
  let root : Array UInt64 := #[100, 200, 300, 400]
  let mv := MerkleVerifier.new root config_no_llv

  -- Match
  let hash_match : Array UInt64 := #[100, 200, 300, 400]
  -- Mismatch
  let hash_no_match : Array UInt64 := #[100, 200, 300, 999]

  -- With last_level_verification: compare against last-level node
  let config_llv := MerkleConfig.mk 4 10 2
  let lln : Array UInt64 := #[10, 20, 30, 40, 50, 60, 70, 80]
  let mv_llv := MerkleVerifier.new root config_llv lln
  let hash_node0 : Array UInt64 := #[10, 20, 30, 40]  -- matches node 0
  let hash_node1 : Array UInt64 := #[50, 60, 70, 80]  -- matches node 1

  group "check_against_target" (
    test "no llv: matching hash -> true"
      (mv.check_against_target hash_match 0 == true) $
    test "no llv: non-matching hash -> false"
      (mv.check_against_target hash_no_match 0 == false) $
    test "llv: hash matches node 0 -> true"
      (mv_llv.check_against_target hash_node0 0 == true) $
    test "llv: hash matches node 1 -> true"
      (mv_llv.check_against_target hash_node1 1 == true) $
    test "llv: wrong hash for node 0 -> false"
      (mv_llv.check_against_target hash_node1 0 == false)
  )

-- ============================================================================
-- flatten_last_levels Tests
-- ============================================================================

def flattenTests : TestSeq :=
  group "flatten_last_levels" (
    test "empty -> empty"
      (flatten_last_levels #[] == #[]) $
    test "single node"
      (flatten_last_levels #[#[1, 2, 3, 4]] == #[1, 2, 3, 4]) $
    test "two nodes"
      (flatten_last_levels #[#[1, 2, 3, 4], #[5, 6, 7, 8]] == #[1, 2, 3, 4, 5, 6, 7, 8]) $
    test "three nodes"
      (flatten_last_levels #[#[10, 20, 30, 40], #[50, 60, 70, 80], #[90, 100, 110, 120]] ==
       #[10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120])
  )

-- ============================================================================
-- Constants Tests
-- ============================================================================

def constantsTests : TestSeq :=
  group "MerkleVerifier constants" (
    test "HASH_SIZE = 4"
      (HASH_SIZE == 4) $
    test "HASH_SIZE matches FFI.Poseidon2.HASH_SIZE"
      (HASH_SIZE == FFI.Poseidon2.HASH_SIZE)
  )

-- ============================================================================
-- verify_last_level_once Tests (structural, no FFI)
-- ============================================================================

def verifyLastLevelOnceTests : TestSeq :=
  -- When llv=0, should always succeed and set verified flag
  let config0 := MerkleConfig.mk 4 10 0
  let root : Array UInt64 := #[1, 2, 3, 4]
  let mv0 := MerkleVerifier.new root config0
  let (ok0, mv0') := mv0.verify_last_level_once
  -- When already verified, should return true immediately
  let (ok0_again, _) := mv0'.verify_last_level_once
  group "verify_last_level_once" (
    test "llv=0: succeeds"
      (ok0 == true) $
    test "llv=0: sets verified flag"
      (mv0'.last_level_verified == true) $
    test "already verified: succeeds again"
      (ok0_again == true)
  )

-- ============================================================================
-- Main Test Runner
-- ============================================================================

def allTests : TestSeq :=
  constantsTests ++
  configConstructionTests ++
  configNSiblingsTests ++
  verifierConstructionTests ++
  verifierWithLLVTests ++
  buildParentHashInputTests ++
  buildParentArity4Tests ++
  levelsNodeCountTests ++
  checkAgainstTargetTests ++
  flattenTests ++
  verifyLastLevelOnceTests

def main : IO UInt32 :=
  lspecIO (.ofList [("MerkleVerifier", [allTests])]) []
