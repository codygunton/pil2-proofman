import LSpec
import Primitives.Transcript

open Primitives.Transcript
open LSpec

-- ============================================================================
-- Construction Tests
-- ============================================================================

def constructionTests : TestSeq :=
  let t2 := Transcript.new 2
  let t3 := Transcript.new 3
  let t4 := Transcript.new 4
  group "Transcript.new" (
    -- Arity 2: width=8, rate=4, outSize=8
    test "arity 2: spongeWidth = 8"
      (t2.spongeWidth == 8) $
    test "arity 2: pendingSize (rate) = 4"
      (t2.pendingSize == 4) $
    test "arity 2: stateSize = 4"
      (t2.stateSize == 4) $
    test "arity 2: outSize = 8"
      (t2.outSize == 8) $
    test "arity 2: state has 8 elements"
      (t2.state.size == 8) $
    test "arity 2: pending has 8 elements"
      (t2.pending.size == 8) $
    test "arity 2: out has 8 elements"
      (t2.out.size == 8) $

    -- Arity 3: width=12, rate=8, outSize=12
    test "arity 3: spongeWidth = 12"
      (t3.spongeWidth == 12) $
    test "arity 3: pendingSize (rate) = 8"
      (t3.pendingSize == 8) $
    test "arity 3: stateSize = 4"
      (t3.stateSize == 4) $
    test "arity 3: outSize = 12"
      (t3.outSize == 12) $

    -- Arity 4: width=16, rate=12, outSize=16
    test "arity 4: spongeWidth = 16"
      (t4.spongeWidth == 16) $
    test "arity 4: pendingSize (rate) = 12"
      (t4.pendingSize == 12) $
    test "arity 4: stateSize = 4"
      (t4.stateSize == 4) $
    test "arity 4: outSize = 16"
      (t4.outSize == 16) $

    -- Initial cursor positions
    test "initial pendingCursor = 0"
      (t4.pendingCursor == 0) $
    test "initial outCursor = 0"
      (t4.outCursor == 0) $

    -- All arrays initialized to zero
    test "initial state is all zeros"
      (t4.state == Array.replicate 16 (0 : UInt64)) $
    test "initial pending is all zeros"
      (t4.pending == Array.replicate 16 (0 : UInt64)) $
    test "initial out is all zeros"
      (t4.out == Array.replicate 16 (0 : UInt64))
  )

-- ============================================================================
-- Absorption Tracking Tests
-- ============================================================================

/- Note: These tests verify the structural behavior of absorption (cursor
   management, field reduction) WITHOUT calling Poseidon2. They work because
   the absorption does not trigger a permutation until pending is full. -/

def absorptionTests : TestSeq :=
  let t := Transcript.new 4  -- rate=12
  -- Absorb 1 element: pendingCursor should advance to 1
  let t1 := t.absorbOne 42
  -- Absorb 2 more elements
  let t3 := (t1.absorbOne 100).absorbOne 200
  group "absorption tracking" (
    test "after absorb 1: pendingCursor = 1"
      (t1.pendingCursor == 1) $
    test "after absorb 1: pending[0] = 42"
      (t1.pending[0]! == 42) $
    test "after absorb 1: outCursor = 0 (invalidated)"
      (t1.outCursor == 0) $

    test "after absorb 3: pendingCursor = 3"
      (t3.pendingCursor == 3) $
    test "after absorb 3: pending[0] = 42"
      (t3.pending[0]! == 42) $
    test "after absorb 3: pending[1] = 100"
      (t3.pending[1]! == 100) $
    test "after absorb 3: pending[2] = 200"
      (t3.pending[2]! == 200)
  )

-- ============================================================================
-- Field Reduction Tests
-- ============================================================================

/- absorbOne reduces elements mod GOLDILOCKS_PRIME before storing. -/

def reductionTests : TestSeq :=
  let p := (0xFFFFFFFF00000001 : UInt64)  -- GOLDILOCKS_PRIME
  let t := Transcript.new 4
  -- Absorb p (should reduce to 0)
  let t1 := t.absorbOne p
  -- Absorb p+1 (should reduce to 1)
  let t2 := t.absorbOne (p + 1)
  -- Absorb 0 (should stay 0)
  let t3 := t.absorbOne 0
  group "absorption field reduction" (
    test "absorb p reduces to 0"
      (t1.pending[0]! == 0) $
    test "absorb p+1 reduces to 1"
      (t2.pending[0]! == 1) $
    test "absorb 0 stays 0"
      (t3.pending[0]! == 0)
  )

-- ============================================================================
-- put() Tests
-- ============================================================================

def putTests : TestSeq :=
  let t := Transcript.new 4  -- rate=12
  -- put with empty array should not change anything
  let t0 := t.put #[]
  -- put with 3 elements
  let t3 := t.put #[10, 20, 30]
  group "Transcript.put" (
    test "put empty: pendingCursor unchanged"
      (t0.pendingCursor == 0) $
    test "put 3 elements: pendingCursor = 3"
      (t3.pendingCursor == 3) $
    test "put 3 elements: pending[0] = 10"
      (t3.pending[0]! == 10) $
    test "put 3 elements: pending[1] = 20"
      (t3.pending[1]! == 20) $
    test "put 3 elements: pending[2] = 30"
      (t3.pending[2]! == 30)
  )

-- ============================================================================
-- setState Tests
-- ============================================================================

def setStateTests : TestSeq :=
  let t := Transcript.new 4
  let newState := Array.replicate 16 (42 : UInt64)
  let newOut := Array.replicate 16 (99 : UInt64)
  let t' := t.setState newState newOut 8 3
  group "Transcript.setState" (
    test "state is updated"
      (t'.state == newState) $
    test "out is updated"
      (t'.out == newOut) $
    test "outCursor is updated"
      (t'.outCursor == 8) $
    test "pendingCursor is updated"
      (t'.pendingCursor == 3) $
    test "pending defaults to zeros"
      (t'.pending == Array.replicate 16 (0 : UInt64))
  )

def setStateWithPendingTests : TestSeq :=
  let t := Transcript.new 4
  let newPending := Array.replicate 16 (7 : UInt64)
  let t' := t.setState
    (Array.replicate 16 0) (Array.replicate 16 0)
    0 5 (some newPending)
  group "Transcript.setState with pending" (
    test "pending is set from argument"
      (t'.pending == newPending) $
    test "pendingCursor is set"
      (t'.pendingCursor == 5)
  )

-- ============================================================================
-- Constants Tests
-- ============================================================================

def constantsTests : TestSeq :=
  group "Transcript constants" (
    test "HASH_SIZE = 4"
      (HASH_SIZE == 4) $
    test "FFI CAPACITY = 4"
      (FFI.Poseidon2.CAPACITY == 4) $
    test "FFI HASH_SIZE = 4"
      (FFI.Poseidon2.HASH_SIZE == 4)
  )

-- ============================================================================
-- Permutation trigger boundary tests (arity 2, rate=4)
-- ============================================================================

/- With arity=2, rate=4. After absorbing exactly 3 elements, pendingCursor=3
   (no permutation yet). After absorbing the 4th element, permutation triggers.
   Since we can't actually run poseidon2, we can only test up to the boundary. -/

def boundaryTests : TestSeq :=
  let t := Transcript.new 2  -- rate=4
  -- Absorb 3 of 4 rate elements (no permutation yet)
  let t3 := ((t.absorbOne 1).absorbOne 2).absorbOne 3
  group "permutation boundary (arity=2, rate=4)" (
    test "after 3 absorbs: pendingCursor = 3"
      (t3.pendingCursor == 3) $
    test "after 3 absorbs: pending[0] = 1"
      (t3.pending[0]! == 1) $
    test "after 3 absorbs: pending[1] = 2"
      (t3.pending[1]! == 2) $
    test "after 3 absorbs: pending[2] = 3"
      (t3.pending[2]! == 3) $
    -- Note: absorbing a 4th element would trigger applyPermutation which calls
    -- poseidon2Hash FFI. Since FFI is not linked, we cannot test past this point
    -- in pure structural tests.
    test "outCursor = 0 after absorbs (squeeze invalidated)"
      (t3.outCursor == 0)
  )

-- ============================================================================
-- Main Test Runner
-- ============================================================================

def allTests : TestSeq :=
  constantsTests ++
  constructionTests ++
  absorptionTests ++
  reductionTests ++
  putTests ++
  setStateTests ++
  setStateWithPendingTests ++
  boundaryTests

def main : IO UInt32 :=
  lspecIO (.ofList [("Transcript", [allTests])]) []
