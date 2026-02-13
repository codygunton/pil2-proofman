import LSpec
import Protocol.Verifier
import Primitives.Field
import Protocol.StarkInfo
import Protocol.Proof
import Primitives.PolMap
import Std

open LSpec
open Primitives.Field
open Protocol.Verifier
open Protocol.StarkInfo (HASH_SIZE FIELD_EXTENSION_DEGREE StarkStruct StarkInfo
  FriFoldStep lookupSection)
open Protocol.Proof (STARKProof FriProof ProofTree MerkleProof decodeAllUInt64)
open Primitives.PolMap

-- ============================================================================
-- Constants Tests
-- ============================================================================

def constantsTests : TestSeq :=
  group "verifier constants" (
    test "EVALS_HASH_WIDTH = 16"
      (EVALS_HASH_WIDTH == 16) $
    test "QUOTIENT_STAGE_OFFSET = 1"
      (QUOTIENT_STAGE_OFFSET == 1) $
    test "EVAL_STAGE_OFFSET = 2"
      (EVAL_STAGE_OFFSET == 2) $
    test "FRI_STAGE_OFFSET = 3"
      (FRI_STAGE_OFFSET == 3)
  )

-- ============================================================================
-- Challenge extraction tests
-- ============================================================================

def challengeExtractionTests : TestSeq :=
  -- Create a buffer with 3 challenges: [10,20,30, 40,50,60, 70,80,90]
  let buf : Array UInt64 := #[10, 20, 30, 40, 50, 60, 70, 80, 90]
  group "challenge extraction" (
    test "getChallenge index 0"
      (getChallenge buf 0 == #[10, 20, 30]) $
    test "getChallenge index 1"
      (getChallenge buf 1 == #[40, 50, 60]) $
    test "getChallenge index 2"
      (getChallenge buf 2 == #[70, 80, 90]) $
    test "getChallengeGF3 index 0"
      (getChallengeGF3 buf 0 == GF3.mk (GF.mk 10) (GF.mk 20) (GF.mk 30)) $
    test "getChallengeGF3 index 1"
      (getChallengeGF3 buf 1 == GF3.mk (GF.mk 40) (GF.mk 50) (GF.mk 60)) $
    test "setChallenge roundtrip"
      (let buf2 := setChallenge (Array.replicate 9 0) 1 #[100, 200, 300]
       getChallenge buf2 1 == #[100, 200, 300])
  )

-- ============================================================================
-- computeXiToTraceSize tests
-- ============================================================================

def xiToTraceSizeTests : TestSeq :=
  group "computeXiToTraceSize" (
    -- xi^1 = xi (trace size = 1)
    test "xi^1 = xi"
      (let xi := GF3.mk (GF.mk 5) (GF.mk 7) (GF.mk 11)
       computeXiToTraceSize xi 1 == xi) $
    -- xi^0 = 1 (trace size = 0, degenerate case)
    test "xi^0 = 1"
      (let xi := GF3.mk (GF.mk 5) (GF.mk 7) (GF.mk 11)
       computeXiToTraceSize xi 0 == GF3.one) $
    -- For a base field element, (a,0,0)^2 = (a^2, 0, 0)
    test "base element squaring"
      (let xi := GF3.mk (GF.mk 3) GF.zero GF.zero
       computeXiToTraceSize xi 2 == GF3.mk (GF.mk 9) GF.zero GF.zero) $
    -- (1,0,0)^N = (1,0,0) for any N
    test "one^N = one"
      (computeXiToTraceSize GF3.one 256 == GF3.one) $
    -- xi^4 via trace size matches gf3_pow directly
    test "matches gf3_pow for trace size 4"
      (let xi := GF3.mk (GF.mk 13) (GF.mk 17) (GF.mk 19)
       computeXiToTraceSize xi 4 == gf3_pow xi 4) $
    -- xi^8 via trace size matches gf3_pow directly
    test "matches gf3_pow for trace size 8"
      (let xi := GF3.mk (GF.mk 2) (GF.mk 3) (GF.mk 5)
       computeXiToTraceSize xi 8 == gf3_pow xi 8)
  )

-- ============================================================================
-- PolynomialId tests (used in verifier's dict-based polynomial access)
-- ============================================================================

def polynomialIdTests : TestSeq :=
  group "PolynomialId" (
    test "equality"
      (let pid1 : PolynomialId := { type := "cm", name := "a", index := 0, stage := 1 }
       let pid2 : PolynomialId := { type := "cm", name := "a", index := 0, stage := 1 }
       pid1 == pid2) $
    test "inequality on name"
      (let pid1 : PolynomialId := { type := "cm", name := "a", index := 0, stage := 1 }
       let pid2 : PolynomialId := { type := "cm", name := "b", index := 0, stage := 1 }
       pid1 != pid2) $
    test "inequality on type"
      (let pid1 : PolynomialId := { type := "cm", name := "a", index := 0, stage := 1 }
       let pid2 : PolynomialId := { type := "const", name := "a", index := 0, stage := 1 }
       pid1 != pid2) $
    test "inequality on index"
      (let pid1 : PolynomialId := { type := "cm", name := "a", index := 0, stage := 1 }
       let pid2 : PolynomialId := { type := "cm", name := "a", index := 1, stage := 1 }
       pid1 != pid2) $
    test "HashMap lookup works"
      (let pid : PolynomialId := { type := "cm", name := "a", index := 0, stage := 1 }
       let map : Std.HashMap PolynomialId Nat := ({} : Std.HashMap PolynomialId Nat).insert pid 42
       map[pid]? == some 42)
  )

-- ============================================================================
-- buildEvIdToPolyIdMap tests (structural)
-- ============================================================================

def buildEvIdToPolyIdMapTests : TestSeq :=
  -- Build a minimal StarkInfo for testing
  let starkInfo : StarkInfo := {
    starkStruct := {
      nBits := 3, nBitsExt := 5, nQueries := 2, verificationHashType := "GL"
      friFoldSteps := #[{ domainBits := 5 }, { domainBits := 3 }]
    }
    name := "test"
    nPublics := 0
    nConstants := 2
    nStages := 1
    proofSize := 0
    customCommits := #[]
    cmPolsMap := #[
      { stage := 1, name := "a", fieldType := .ff, stagePos := 0, stageId := 0 },
      { stage := 1, name := "b", fieldType := .ff, stagePos := 1, stageId := 1 }
    ]
    constPolsMap := #[
      { stage := 0, name := "SEL", fieldType := .ff, stagePos := 0, stageId := 0 }
    ]
    challengesMap := #[]
    airgroupValuesMap := #[]
    airValuesMap := #[]
    customCommitsMap := #[]
    evMap := #[
      { type := .cm, id := 0, rowOffset := 0 },      -- ev 0: cm "a" at offset 0
      { type := .cm, id := 1, rowOffset := 0 },      -- ev 1: cm "b" at offset 0
      { type := .const_, id := 0, rowOffset := 0 }   -- ev 2: const "SEL" at offset 0
    ]
    openingPoints := #[0]
    boundaries := #[]
    qDeg := 1
    qDim := 3
    cExpId := 0
    friExpId := 0
    mapSectionsN := #[("cm1", 2)]
    airValuesSize := 0
    airgroupValuesSize := 0
  }
  let mapping := buildEvIdToPolyIdMap starkInfo
  group "buildEvIdToPolyIdMap" (
    test "maps ev 0 to cm 'a' index 0"
      (mapping[0]?.map (fun pid => pid.type == "cm" && pid.name == "a" && pid.index == 0) == some true) $
    test "maps ev 1 to cm 'b' index 0"
      (mapping[1]?.map (fun pid => pid.type == "cm" && pid.name == "b" && pid.index == 0) == some true) $
    test "maps ev 2 to const 'SEL' index 0"
      (mapping[2]?.map (fun pid => pid.type == "const" && pid.name == "SEL" && pid.index == 0) == some true) $
    test "total entries"
      (mapping.size == 3)
  )

-- ============================================================================
-- findXiChallenge tests
-- ============================================================================

def findXiChallengeTests : TestSeq :=
  -- Build StarkInfo with 1 stage, challenges_map with std_xi at stage 3 (1 + EVAL_STAGE_OFFSET)
  let starkInfo : StarkInfo := {
    starkStruct := {
      nBits := 3, nBitsExt := 5, nQueries := 2, verificationHashType := "GL"
      friFoldSteps := #[{ domainBits := 5 }]
    }
    name := "test"
    nPublics := 0
    nConstants := 0
    nStages := 1
    proofSize := 0
    customCommits := #[]
    cmPolsMap := #[]
    constPolsMap := #[]
    challengesMap := #[
      { name := "std_alpha", stage := 2, fieldType := .ff3, stageId := 0 },
      { name := "std_xi", stage := 3, fieldType := .ff3, stageId := 0 },   -- n_stages + EVAL_STAGE_OFFSET = 1+2=3
      { name := "std_vf1", stage := 4, fieldType := .ff3, stageId := 0 }
    ]
    airgroupValuesMap := #[]
    airValuesMap := #[]
    customCommitsMap := #[]
    evMap := #[]
    openingPoints := #[0]
    boundaries := #[]
    qDeg := 1
    qDim := 3
    cExpId := 0
    friExpId := 0
    mapSectionsN := #[]
    airValuesSize := 0
    airgroupValuesSize := 0
  }
  -- Challenges buffer: 3 challenges * 3 = 9 elements
  -- Challenge 0 (std_alpha): [10, 20, 30]
  -- Challenge 1 (std_xi): [100, 200, 300]
  -- Challenge 2 (std_vf1): [40, 50, 60]
  let challenges : Array UInt64 := #[10, 20, 30, 100, 200, 300, 40, 50, 60]
  group "findXiChallenge" (
    test "finds xi at index 1 (stage 3, stageId 0)"
      (findXiChallenge starkInfo challenges == #[100, 200, 300])
  )

-- ============================================================================
-- reconstructQuotientAtXi structural test
-- ============================================================================

def reconstructQuotientTests : TestSeq :=
  -- Test with a simple case: qDeg=1, so Q(xi) = Q_0(xi) * xi^0 = Q_0(xi)
  let starkInfo : StarkInfo := {
    starkStruct := {
      nBits := 3, nBitsExt := 5, nQueries := 2, verificationHashType := "GL"
      friFoldSteps := #[{ domainBits := 5 }]
    }
    name := "test"
    nPublics := 0
    nConstants := 0
    nStages := 1
    proofSize := 0
    customCommits := #[]
    -- Stage 2 (quotient stage = 1 + 1 = 2) polynomial
    cmPolsMap := #[
      { stage := 1, name := "a", fieldType := .ff, stagePos := 0, stageId := 0 },
      { stage := 2, name := "Q", fieldType := .ff3, stagePos := 0, stageId := 0 }
    ]
    constPolsMap := #[]
    challengesMap := #[]
    airgroupValuesMap := #[]
    airValuesMap := #[]
    customCommitsMap := #[]
    -- evMap entry for Q at evMap[0]
    evMap := #[
      { type := .cm, id := 0, rowOffset := 0 },  -- "a" (not used in this test)
      { type := .cm, id := 1, rowOffset := 0 }   -- "Q" - quotient piece
    ]
    openingPoints := #[0]
    boundaries := #[]
    qDeg := 1
    qDim := 3
    cExpId := 0
    friExpId := 0
    mapSectionsN := #[("cm1", 1), ("cm2", 3)]
    airValuesSize := 0
    airgroupValuesSize := 0
  }
  -- Evals: evMap[0] = "a" -> [1, 0, 0], evMap[1] = "Q" -> [42, 7, 13]
  -- Interleaved format (ascending): [c0, c1, c2]
  let evals : Array UInt64 := #[1, 0, 0, 42, 7, 13]
  let xi := GF3.mk (GF.mk 5) GF.zero GF.zero
  let xiToN := GF3.one  -- doesn't matter for qDeg=1
  group "reconstructQuotientAtXi" (
    -- With qDeg=1, Q(xi) = Q_0(xi) * 1 = evaluation from evals[1]
    -- evals[1] in ascending order: (42, 7, 13) as GF3
    test "qDeg=1 returns single evaluation"
      (let result := reconstructQuotientAtXi starkInfo evals xi xiToN
       -- evMap[1] maps to id=1, which is cmPolsMap[1] at stage=2=quotientStage
       -- Read as GF3.mk (evals[base], evals[base+1], evals[base+2]) = GF3(42, 7, 13)
       result == GF3.mk (GF.mk 42) (GF.mk 7) (GF.mk 13))
  )

-- ============================================================================
-- verifyFinalPolynomial structural test
-- ============================================================================

def verifyFinalPolynomialTests : TestSeq :=
  -- Create a minimal proof with a final polynomial that is all zeros
  -- (which should pass the degree check)
  let allZeroPol : Array (Array UInt64) := #[#[0, 0, 0], #[0, 0, 0], #[0, 0, 0], #[0, 0, 0]]
  let proof : STARKProof := {
    fri := { pol := allZeroPol }
  }
  let starkInfo : StarkInfo := {
    starkStruct := {
      nBits := 3, nBitsExt := 5, nQueries := 2, verificationHashType := "GL"
      friFoldSteps := #[{ domainBits := 5 }, { domainBits := 2 }]
    }
    name := "test"
    nPublics := 0
    nConstants := 0
    nStages := 1
    proofSize := 0
    customCommits := #[]
    cmPolsMap := #[]
    constPolsMap := #[]
    challengesMap := #[]
    airgroupValuesMap := #[]
    airValuesMap := #[]
    customCommitsMap := #[]
    evMap := #[]
    openingPoints := #[0]
    boundaries := #[]
    qDeg := 1
    qDim := 3
    cExpId := 0
    friExpId := 0
    mapSectionsN := #[]
    airValuesSize := 0
    airgroupValuesSize := 0
  }
  group "verifyFinalPolynomial" (
    test "all-zero polynomial passes degree check"
      (verifyFinalPolynomial proof starkInfo == true)
  )

-- ============================================================================
-- setChallenge / getChallenge roundtrip
-- ============================================================================

def challengeRoundtripTests : TestSeq :=
  group "challenge roundtrip" (
    test "set then get at index 0"
      (let buf := setChallenge (Array.replicate 12 0) 0 #[111, 222, 333]
       getChallenge buf 0 == #[111, 222, 333]) $
    test "set then get at index 3"
      (let buf := setChallenge (Array.replicate 12 0) 3 #[7, 8, 9]
       getChallenge buf 3 == #[7, 8, 9]) $
    test "multiple sets do not interfere"
      (let buf := Array.replicate 12 0
       let buf := setChallenge buf 0 #[10, 20, 30]
       let buf := setChallenge buf 1 #[40, 50, 60]
       let buf := setChallenge buf 2 #[70, 80, 90]
       getChallenge buf 0 == #[10, 20, 30] &&
       getChallenge buf 1 == #[40, 50, 60] &&
       getChallenge buf 2 == #[70, 80, 90])
  )

-- ============================================================================
-- parseEvals tests
-- ============================================================================

def parseEvalsTests : TestSeq :=
  -- Build minimal StarkInfo with 2 ev_map entries
  let starkInfo : StarkInfo := {
    starkStruct := {
      nBits := 3, nBitsExt := 5, nQueries := 1, verificationHashType := "GL"
      friFoldSteps := #[{ domainBits := 5 }]
    }
    name := "test"
    nPublics := 0
    nConstants := 0
    nStages := 1
    proofSize := 0
    customCommits := #[]
    cmPolsMap := #[]
    constPolsMap := #[]
    challengesMap := #[]
    airgroupValuesMap := #[]
    airValuesMap := #[]
    customCommitsMap := #[]
    evMap := #[
      { type := .cm, id := 0, rowOffset := 0 },
      { type := .cm, id := 1, rowOffset := 0 }
    ]
    openingPoints := #[0]
    boundaries := #[]
    qDeg := 1
    qDim := 3
    cExpId := 0
    friExpId := 0
    mapSectionsN := #[]
    airValuesSize := 0
    airgroupValuesSize := 0
  }
  let proof : STARKProof := {
    evals := #[#[100, 200, 300], #[400, 500, 600]]
  }
  let result := parseEvals proof starkInfo
  group "parseEvals" (
    test "produces correct interleaved layout"
      (result == #[100, 200, 300, 400, 500, 600]) $
    test "correct size"
      (result.size == 6)
  )

-- ============================================================================
-- E2E verification test (Poseidon2 + Constraints FFI)
-- ============================================================================

/-- E2E verification test: loads a real SimpleLeft proof and verifies it.
    Requires Poseidon2 and Constraints FFI libraries linked. -/
def e2eVerificationTest : IO TestSeq := do
  let testDataDir := "Tests/test-data"
  let starkInfoPath := s!"{testDataDir}/SimpleLeft.starkinfo.json"
  let bytecodePath := s!"{testDataDir}/SimpleLeft.bin"

  -- Load starkinfo
  let starkInfoJson ← IO.FS.readFile starkInfoPath
  let starkInfo ← match Lean.Json.parse starkInfoJson >>= StarkInfo.fromJson? with
    | .ok si => pure si
    | .error e => throw (IO.userError s!"Failed to parse starkinfo: {e}")

  -- Load proof binary
  let proofData ← IO.FS.readBinFile s!"{testDataDir}/simple-left.proof.bin"
  let proof := STARKProof.fromBytes proofData starkInfo

  -- Load verkey (4 uint64 Merkle root)
  let verkeyData ← IO.FS.readBinFile s!"{testDataDir}/SimpleLeft.verkey.bin"
  let verkey := decodeAllUInt64 verkeyData

  -- Global challenge from test vectors (interleaved FF3: [c0, c1, c2])
  let globalChallenge : Array UInt64 := #[
    1461052753056858962, 17277128619110652023, 18440847142611318128
  ]

  -- Verify with FFI constraint evaluation
  let result := starkVerify proof starkInfo verkey starkInfoPath bytecodePath
    (globalChallenge := some globalChallenge)

  return group "E2E verification" (
    test "SimpleLeft proof verifies" result
  )

-- ============================================================================
-- Main
-- ============================================================================

def allTests : TestSeq :=
  constantsTests ++
  challengeExtractionTests ++
  xiToTraceSizeTests ++
  polynomialIdTests ++
  buildEvIdToPolyIdMapTests ++
  findXiChallengeTests ++
  reconstructQuotientTests ++
  verifyFinalPolynomialTests ++
  challengeRoundtripTests ++
  parseEvalsTests

def main : IO UInt32 := do
  let e2eTests ← e2eVerificationTest
  lspecIO (.ofList [("STARK Verifier", [allTests ++ e2eTests])]) []
