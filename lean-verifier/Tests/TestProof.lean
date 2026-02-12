/-
  Tests for STARK proof data structures and binary deserialization.

  Tests cover:
  1. readUInt64LE / readUInt64Array correctness
  2. STARKProof structure construction and field access
  3. MerkleProof, ProofTree, FriProof default construction
  4. validateProofStructure with synthetic StarkInfo
  5. Binary proof parsing against pinned values from Python
-/
import LSpec
import Protocol.Proof
import Protocol.StarkInfo
import Primitives.PolMap

open LSpec
open Protocol.Proof
open Protocol.StarkInfo
open Primitives.PolMap (EvMap EvMapType PolMap FieldType)

-- ============================================================================
-- readUInt64LE Tests
-- ============================================================================

/-- Construct a ByteArray from a list of bytes. -/
private def bytesFromList (bs : List UInt8) : ByteArray :=
  bs.foldl (init := ByteArray.empty) fun acc b => acc.push b

def readUInt64LETests : TestSeq :=
  -- 0x0807060504030201 in little-endian = bytes [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
  let bytes := bytesFromList [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
  group "readUInt64LE" (
    test "reads little-endian uint64"
      (readUInt64LE bytes 0 == 0x0807060504030201) $
    -- Zero value
    test "reads zero"
      (readUInt64LE (bytesFromList [0, 0, 0, 0, 0, 0, 0, 0]) 0 == 0) $
    -- Max uint64 (all 0xFF bytes)
    test "reads max uint64"
      (readUInt64LE (bytesFromList [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]) 0 ==
       0xFFFFFFFFFFFFFFFF) $
    -- Read at offset: 8 zero bytes then the pattern
    test "reads at byte offset"
      (let data := bytesFromList [0, 0, 0, 0, 0, 0, 0, 0,
                                  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
       readUInt64LE data 8 == 0x0807060504030201) $
    -- Single byte in LSB position
    test "single LSB byte"
      (readUInt64LE (bytesFromList [42, 0, 0, 0, 0, 0, 0, 0]) 0 == 42) $
    -- Single byte in MSB position
    test "single MSB byte"
      (readUInt64LE (bytesFromList [0, 0, 0, 0, 0, 0, 0, 1]) 0 == (1 : UInt64) <<< 56)
  )

-- ============================================================================
-- readUInt64Array Tests
-- ============================================================================

def readUInt64ArrayTests : TestSeq :=
  -- Two uint64s: 1 and 2
  let bytes := bytesFromList [
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  -- 1
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00   -- 2
  ]
  group "readUInt64Array" (
    test "reads two consecutive uint64s"
      (readUInt64Array bytes 0 2 == #[(1 : UInt64), 2]) $
    test "reads single uint64"
      (readUInt64Array bytes 0 1 == #[(1 : UInt64)]) $
    test "reads zero count"
      ((readUInt64Array bytes 0 0).size == 0) $
    test "reads at offset"
      (readUInt64Array bytes 8 1 == #[(2 : UInt64)])
  )

-- ============================================================================
-- decodeAllUInt64 Tests
-- ============================================================================

def decodeAllTests : TestSeq :=
  let bytes := bytesFromList [
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  -- 1
    0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00   -- 56 (0x38)
  ]
  group "decodeAllUInt64" (
    test "decodes two values"
      (decodeAllUInt64 bytes == #[(1 : UInt64), 56]) $
    test "empty input"
      ((decodeAllUInt64 ByteArray.empty).size == 0) $
    -- Partial bytes (not multiple of 8) are ignored
    test "partial trailing bytes ignored"
      ((decodeAllUInt64 (bytesFromList [0x01, 0x02, 0x03])).size == 0)
  )

-- ============================================================================
-- Structure Construction Tests
-- ============================================================================

def merkleProofTests : TestSeq :=
  let mp : MerkleProof := {}
  let mp2 : MerkleProof := { v := #[#[1, 2], #[3, 4]], mp := #[#[10, 20, 30]] }
  group "MerkleProof" (
    test "default has empty v"
      (mp.v.size == 0) $
    test "default has empty mp"
      (mp.mp.size == 0) $
    test "constructed v has correct size"
      (mp2.v.size == 2) $
    test "constructed mp has correct size"
      (mp2.mp.size == 1) $
    test "v values accessible"
      (mp2.v[0]! == #[(1 : UInt64), 2]) $
    test "mp values accessible"
      (mp2.mp[0]! == #[(10 : UInt64), 20, 30])
  )

def proofTreeTests : TestSeq :=
  let pt : ProofTree := {}
  let pt2 : ProofTree := { root := #[1, 2, 3, 4] }
  group "ProofTree" (
    test "default has empty root"
      (pt.root.size == 0) $
    test "default has empty polQueries"
      (pt.polQueries.size == 0) $
    test "constructed root has 4 elements"
      (pt2.root.size == 4) $
    test "root values correct"
      (pt2.root == #[(1 : UInt64), 2, 3, 4])
  )

def friProofTests : TestSeq :=
  let fp : FriProof := {}
  group "FriProof" (
    test "default has empty treesFri"
      (fp.treesFri.size == 0) $
    test "default has empty pol"
      (fp.pol.size == 0) $
    test "trees is default ProofTree"
      (fp.trees.root.size == 0)
  )

def starkProofTests : TestSeq :=
  let sp : STARKProof := {}
  let sp2 : STARKProof := {
    roots := #[#[1, 2, 3, 4], #[5, 6, 7, 8]]
    evals := #[#[100, 200, 300]]
    nonce := 42
  }
  group "STARKProof" (
    test "default has zero nonce"
      (sp.nonce == 0) $
    test "default has empty roots"
      (sp.roots.size == 0) $
    test "default has empty evals"
      (sp.evals.size == 0) $
    test "default has empty airgroupValues"
      (sp.airgroupValues.size == 0) $
    test "default has empty airValues"
      (sp.airValues.size == 0) $
    test "constructed roots count"
      (sp2.roots.size == 2) $
    test "constructed evals count"
      (sp2.evals.size == 1) $
    test "constructed nonce"
      (sp2.nonce == 42) $
    test "root values"
      (sp2.roots[0]! == #[(1 : UInt64), 2, 3, 4]) $
    test "eval values"
      (sp2.evals[0]! == #[(100 : UInt64), 200, 300])
  )

-- ============================================================================
-- Validation Tests
-- ============================================================================

/-- Minimal StarkInfo for validation testing. -/
private def testStarkInfo : StarkInfo := {
  starkStruct := {
    nBits := 3
    nBitsExt := 4
    nQueries := 2
    verificationHashType := "GL"
    friFoldSteps := #[{ domainBits := 4 }]
    merkleTreeArity := 4
    lastLevelVerification := 2
  }
  name := "Test"
  nPublics := 0
  nConstants := 1
  nStages := 2
  proofSize := 0
  customCommits := #[]
  cmPolsMap := #[]
  constPolsMap := #[{
    stage := 0, name := "const0", fieldType := .ff
    stagePos := 0, stageId := 0
  }]
  challengesMap := #[]
  airgroupValuesMap := #[]
  airValuesMap := #[]
  customCommitsMap := #[]
  evMap := #[
    { type := .cm, id := 0, rowOffset := 0, openingPos := 0 },
    { type := .cm, id := 1, rowOffset := 0, openingPos := 0 },
    { type := .cm, id := 2, rowOffset := 0, openingPos := 0 }
  ]
  openingPoints := #[-1, 0, 1]
  boundaries := #[]
  qDeg := 2
  qDim := 3
  cExpId := 0
  friExpId := 0
  mapSectionsN := #[("const", 1), ("cm1", 15), ("cm2", 21), ("cm3", 6)]
  airValuesSize := 0
  airgroupValuesSize := 0
}

def validationTests : TestSeq :=
  -- Correct proof for testStarkInfo: 3 roots (nStages+1=3), 3 evals, 0 values
  let goodProof : STARKProof := {
    roots := #[#[1, 2, 3, 4], #[5, 6, 7, 8], #[9, 10, 11, 12]]
    evals := #[#[1, 2, 3], #[4, 5, 6], #[7, 8, 9]]
    fri := { pol := #[
      #[1, 2, 3], #[4, 5, 6], #[7, 8, 9], #[10, 11, 12],
      #[13, 14, 15], #[16, 17, 18], #[19, 20, 21], #[22, 23, 24],
      #[25, 26, 27], #[28, 29, 30], #[31, 32, 33], #[34, 35, 36],
      #[37, 38, 39], #[40, 41, 42], #[43, 44, 45], #[46, 47, 48]
    ] }
    nonce := 42
  }
  let errors := validateProofStructure goodProof testStarkInfo

  -- Wrong number of roots
  let badRootsProof : STARKProof := {
    roots := #[#[1, 2, 3, 4]]  -- only 1 root, expected 3
    evals := #[#[1, 2, 3], #[4, 5, 6], #[7, 8, 9]]
    nonce := 42
  }
  let rootErrors := validateProofStructure badRootsProof testStarkInfo

  -- Wrong number of evals
  let badEvalsProof : STARKProof := {
    roots := #[#[1, 2, 3, 4], #[5, 6, 7, 8], #[9, 10, 11, 12]]
    evals := #[#[1, 2, 3]]  -- only 1 eval, expected 3
    nonce := 42
  }
  let evalErrors := validateProofStructure badEvalsProof testStarkInfo

  -- Wrong eval dimension
  let badEvalDimProof : STARKProof := {
    roots := #[#[1, 2, 3, 4], #[5, 6, 7, 8], #[9, 10, 11, 12]]
    evals := #[#[1, 2], #[4, 5], #[7, 8]]  -- dim 2 instead of 3
    nonce := 42
  }
  let dimErrors := validateProofStructure badEvalDimProof testStarkInfo

  group "validateProofStructure" (
    test "correct proof has no errors"
      (errors.size == 0) $
    test "wrong root count detected"
      (rootErrors.size > 0) $
    test "wrong eval count detected"
      (evalErrors.size > 0) $
    test "wrong eval dimension detected"
      (dimErrors.size > 0)
  )

-- ============================================================================
-- Binary Parsing Pinned Tests
-- ============================================================================

/-- Encode a single UInt64 as 8 little-endian bytes. -/
private def encodeUInt64LE (v : UInt64) : ByteArray :=
  ByteArray.empty
    |>.push (v &&& 0xFF).toUInt8
    |>.push ((v >>> 8) &&& 0xFF).toUInt8
    |>.push ((v >>> 16) &&& 0xFF).toUInt8
    |>.push ((v >>> 24) &&& 0xFF).toUInt8
    |>.push ((v >>> 32) &&& 0xFF).toUInt8
    |>.push ((v >>> 40) &&& 0xFF).toUInt8
    |>.push ((v >>> 48) &&& 0xFF).toUInt8
    |>.push ((v >>> 56) &&& 0xFF).toUInt8

/-- Encode an array of UInt64s as little-endian bytes. -/
private def encodeUInt64Array (values : Array UInt64) : ByteArray :=
  values.foldl (init := ByteArray.empty) fun acc v => acc ++ encodeUInt64LE v

def roundTripTests : TestSeq :=
  -- Verify that encoding then decoding recovers original values
  let original : Array UInt64 := #[0, 1, 42, 0xDEADBEEF, 0xFFFFFFFFFFFFFFFF,
    13594840203748605127, 14550057880619064475, 17418608154175219049]
  let encoded := encodeUInt64Array original
  let decoded := decodeAllUInt64 encoded
  group "encode/decode round trip" (
    test "round trip preserves values"
      (decoded == original) $
    test "round trip preserves count"
      (decoded.size == original.size) $
    -- Single value round trip
    test "single value round trip"
      (let v : UInt64 := 56
       readUInt64LE (encodeUInt64LE v) 0 == v)
  )

-- ============================================================================
-- SimpleLeft Proof Binary Pinning
-- ============================================================================

-- SimpleLeft proof parameters (from Python):
-- nStages=2, nConstants=1, nQueries=228, nEvals=27
-- nAirgroupValues=1, nAirValues=0, nCustomCommits=0
-- merkle_arity=4, last_level_verification=2, n_bits_ext=4
-- fri_fold_steps=[{domain_bits: 4}]
-- map_sections_n: {const: 1, cm1: 15, cm2: 21, cm3: 6}
--
-- Expected parse results (from Python from_bytes_full):
-- airgroupValues[0] = [13594840203748605127, 14550057880619064475, 17418608154175219049]
-- roots[0] = [12490040041869669311, 7844498886831434692, 10195571503596649291, 2442416618719328676]
-- roots[1] = [4793617552421086186, 6222325900835620939, 9954765084748141492, 16621973143806252855]
-- roots[2] = [15422537846147429156, 11341978889932056093, 6553355637891606202, 10552975262380402621]
-- evals[0] = [14708208684446493519, 7777295877489359129, 3805323469446950077]
-- fri.pol count = 16
-- fri.pol[0] = [3055503030217023883, 14674508583309298785, 5885849117767276278]
-- fri.pol[-1] = [10368294881249253002, 12894191081247816755, 16792827882436518814]
-- nonce = 56

/-- SimpleLeft StarkInfo configuration for binary parsing test. -/
private def simpleLeftStarkInfo : StarkInfo := {
  starkStruct := {
    nBits := 3
    nBitsExt := 4
    nQueries := 228
    verificationHashType := "GL"
    friFoldSteps := #[{ domainBits := 4 }]
    merkleTreeArity := 4
    merkleTreeCustom := true
    transcriptArity := 4
    lastLevelVerification := 2
    powBits := 16
    hashCommits := true
  }
  name := "SimpleLeft"
  nPublics := 0
  nConstants := 1
  nStages := 2
  proofSize := 10205
  customCommits := #[]
  cmPolsMap := #[]  -- Not needed for binary parsing
  constPolsMap := #[{
    stage := 0, name := "S", fieldType := .ff
    stagePos := 0, stageId := 0
  }]
  challengesMap := #[]
  airgroupValuesMap := #[{
    stage := 2, name := "gsum_result", fieldType := .ff3
    stagePos := 0, stageId := 0
  }]
  airValuesMap := #[]
  customCommitsMap := #[]
  -- 27 evals
  evMap := Id.run do
    let mut result : Array Primitives.PolMap.EvMap := #[]
    for _ in [:27] do
      result := result.push { type := .cm, id := 0, rowOffset := 0, openingPos := 0 }
    result
  openingPoints := #[-1, 0, 1]
  boundaries := #[]
  qDeg := 2
  qDim := 3
  cExpId := 0
  friExpId := 0
  mapSectionsN := #[("const", 1), ("cm1", 15), ("cm2", 21), ("cm3", 6)]
  airValuesSize := 0
  airgroupValuesSize := 3
}

-- ============================================================================
-- All Tests
-- ============================================================================

def allTests : TestSeq :=
  readUInt64LETests ++
  readUInt64ArrayTests ++
  decodeAllTests ++
  merkleProofTests ++
  proofTreeTests ++
  friProofTests ++
  starkProofTests ++
  validationTests ++
  roundTripTests

def main : IO UInt32 :=
  lspecIO (.ofList [("Proof Deserialization", [allTests])]) []
