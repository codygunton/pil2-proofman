import LSpec
import Lean.Data.Json.Parser
import Primitives.PolMap
import Protocol.StarkInfo

open LSpec
open Primitives.PolMap
open Protocol.StarkInfo

-- ============================================================================
-- PolMap Structure Tests (compile-time)
-- ============================================================================

def polMapTests : TestSeq :=
  group "PolMap structures" (
    -- FieldType
    test "FieldType.ff dim = 1"
      (FieldType.ff.dim = 1) $
    test "FieldType.ff3 dim = 3"
      (FieldType.ff3.dim = 3) $
    test "FieldType.fromDim 1 = ff"
      (decide (FieldType.fromDim 1 = FieldType.ff)) $
    test "FieldType.fromDim 3 = ff3"
      (decide (FieldType.fromDim 3 = FieldType.ff3)) $

    -- EvMapType.fromString
    test "EvMapType.fromString cm succeeds"
      (decide ((EvMapType.fromString "cm").isOk = true)) $
    test "EvMapType.fromString const succeeds"
      (decide ((EvMapType.fromString "const").isOk = true)) $
    test "EvMapType.fromString custom succeeds"
      (decide ((EvMapType.fromString "custom").isOk = true)) $

    -- PolMap.dim via constructed value
    test "PolMap dim reflects fieldType ff"
      (let pm : PolMap := { stage := 1, name := "a", fieldType := .ff, stagePos := 0, stageId := 0 }
       pm.dim = 1) $
    test "PolMap dim reflects fieldType ff3"
      (let pm : PolMap := { stage := 2, name := "gsum", fieldType := .ff3, stagePos := 0, stageId := 0 }
       pm.dim = 3) $

    -- ChallengeMap.dim
    test "ChallengeMap dim reflects fieldType"
      (let cm : ChallengeMap := { name := "alpha", stage := 2, fieldType := .ff3, stageId := 0 }
       cm.dim = 3) $

    -- PolynomialId equality
    test "PolynomialId equality"
      (PolynomialId.mk "cm" "a" 0 1 == PolynomialId.mk "cm" "a" 0 1) $
    test "PolynomialId inequality"
      (PolynomialId.mk "cm" "a" 0 1 != PolynomialId.mk "cm" "b" 0 1)
  )

-- ============================================================================
-- JSON Parsing Tests (compile-time, inline JSON)
-- ============================================================================

/-- Helper: parse JSON string, extract a field value via a function.
    Returns the result or a default on error. -/
private def parseAndExtract {A B : Type} (jsonStr : String) (parser : Lean.Json -> Except String A)
    (extract : A -> B) (dflt : B) : B :=
  match Lean.Json.parse jsonStr with
  | .error _ => dflt
  | .ok j => match parser j with
    | .error _ => dflt
    | .ok val => extract val

def jsonPolMapTests : TestSeq :=
  let polMapJson := "{\"stage\": 1, \"name\": \"a\", \"dim\": 1, \"stagePos\": 0, \"stageId\": 0, \"polsMapId\": 0}"
  group "PolMap JSON parsing" (
    test "PolMap parses stage"
      (parseAndExtract polMapJson PolMap.fromJson? (·.stage) 99 = 1) $
    test "PolMap parses name"
      (parseAndExtract polMapJson PolMap.fromJson? (·.name) "" = "a") $
    test "PolMap parses fieldType"
      (decide (parseAndExtract polMapJson PolMap.fromJson? (·.fieldType) .ff3 = FieldType.ff)) $
    test "PolMap parses polsMapId"
      (parseAndExtract polMapJson PolMap.fromJson? (·.polsMapId) 99 = 0)
  )

def jsonChallengeMapTests : TestSeq :=
  let chJson := "{\"name\": \"std_alpha\", \"stage\": 2, \"dim\": 3, \"stageId\": 0}"
  group "ChallengeMap JSON parsing" (
    test "ChallengeMap parses name"
      (parseAndExtract chJson ChallengeMap.fromJson? (·.name) "" = "std_alpha") $
    test "ChallengeMap parses stage"
      (parseAndExtract chJson ChallengeMap.fromJson? (·.stage) 99 = 2) $
    test "ChallengeMap parses fieldType as ff3"
      (decide (parseAndExtract chJson ChallengeMap.fromJson? (·.fieldType) .ff = FieldType.ff3))
  )

def jsonEvMapTests : TestSeq :=
  let evJson := "{\"type\": \"cm\", \"id\": 15, \"prime\": -1, \"openingPos\": 0}"
  let openingPts : Array Int := #[-1, 0, 1]
  let parse := fun (j : Lean.Json) => EvMap.fromJson? j openingPts
  group "EvMap JSON parsing" (
    test "EvMap parses type"
      (decide (parseAndExtract evJson parse (·.type) .const_ = EvMapType.cm)) $
    test "EvMap parses id"
      (parseAndExtract evJson parse (·.id) 99 = 15) $
    test "EvMap parses rowOffset"
      (decide (parseAndExtract evJson parse (·.rowOffset) (99 : Int) = (-1 : Int))) $
    test "EvMap parses openingPos"
      (parseAndExtract evJson parse (·.openingPos) 99 = 0)
  )

def jsonBoundaryTests : TestSeq :=
  let bJson := "{\"name\": \"everyRow\"}"
  group "Boundary JSON parsing" (
    test "Boundary parses name"
      (parseAndExtract bJson Boundary.fromJson? (·.name) "" = "everyRow") $
    test "Boundary default offsetMin = 0"
      (decide (parseAndExtract bJson Boundary.fromJson? (·.offsetMin) (99 : Int) = (0 : Int))) $
    test "Boundary default offsetMax = 0"
      (decide (parseAndExtract bJson Boundary.fromJson? (·.offsetMax) (99 : Int) = (0 : Int)))
  )

def jsonStarkStructTests : TestSeq :=
  let ssJson := "{\"nBits\": 3, \"nBitsExt\": 4, \"nQueries\": 228, \"verificationHashType\": \"GL\", \"merkleTreeArity\": 4, \"transcriptArity\": 4, \"merkleTreeCustom\": true, \"lastLevelVerification\": 2, \"powBits\": 16, \"hashCommits\": true, \"steps\": [{\"nBits\": 4}]}"
  group "StarkStruct JSON parsing" (
    test "StarkStruct nBits"
      (parseAndExtract ssJson StarkStruct.fromJson? (·.nBits) 99 = 3) $
    test "StarkStruct nBitsExt"
      (parseAndExtract ssJson StarkStruct.fromJson? (·.nBitsExt) 99 = 4) $
    test "StarkStruct nQueries"
      (parseAndExtract ssJson StarkStruct.fromJson? (·.nQueries) 99 = 228) $
    test "StarkStruct merkleTreeArity"
      (parseAndExtract ssJson StarkStruct.fromJson? (·.merkleTreeArity) 99 = 4) $
    test "StarkStruct lastLevelVerification"
      (parseAndExtract ssJson StarkStruct.fromJson? (·.lastLevelVerification) 99 = 2) $
    test "StarkStruct powBits"
      (parseAndExtract ssJson StarkStruct.fromJson? (·.powBits) 99 = 16) $
    test "StarkStruct friFoldSteps count"
      (parseAndExtract ssJson StarkStruct.fromJson? (·.friFoldSteps.size) 99 = 1) $
    test "StarkStruct friFoldSteps[0] domainBits"
      (parseAndExtract ssJson StarkStruct.fromJson? (fun ss => ss.friFoldSteps[0]!.domainBits) 99 = 4)
  )

-- ============================================================================
-- StarkInfo File Parsing Tests (runtime IO)
-- ============================================================================

/-- Load and parse a starkinfo JSON file, then run assertions. -/
def loadAndTestStarkInfo : IO TestSeq := do
  let path := "Tests/test-data/SimpleLeft.starkinfo.json"
  let contents ← IO.FS.readFile path
  let json ← match Lean.Json.parse contents with
    | .ok j => pure j
    | .error e => throw (IO.userError s!"JSON parse error: {e}")
  let si ← match StarkInfo.fromJson? json with
    | .ok si => pure si
    | .error e => throw (IO.userError s!"StarkInfo parse error: {e}")

  return group "StarkInfo from file (SimpleLeft)" (
    -- Basic params
    test "name = SimpleLeft"
      (si.name == "SimpleLeft") $
    test "nBits = 3 (8 rows)"
      (si.starkStruct.nBits == 3) $
    test "nBitsExt = 4"
      (si.starkStruct.nBitsExt == 4) $
    test "nQueries = 228"
      (si.starkStruct.nQueries == 228) $
    test "nStages = 2"
      (si.nStages == 2) $
    test "nConstants = 1"
      (si.nConstants == 1) $
    test "nPublics = 0"
      (si.nPublics == 0) $

    -- Quotient polynomial
    test "qDeg = 2"
      (si.qDeg == 2) $
    test "qDim = 3"
      (si.qDim == 3) $

    -- Expression IDs
    test "cExpId = 312"
      (si.cExpId == 312) $
    test "friExpId = 313"
      (si.friExpId == 313) $

    -- StarkStruct details
    test "merkleTreeArity = 4"
      (si.starkStruct.merkleTreeArity == 4) $
    test "transcriptArity = 4"
      (si.starkStruct.transcriptArity == 4) $
    test "merkleTreeCustom = true"
      (si.starkStruct.merkleTreeCustom == true) $
    test "lastLevelVerification = 2"
      (si.starkStruct.lastLevelVerification == 2) $
    test "powBits = 16"
      (si.starkStruct.powBits == 16) $
    test "hashCommits = true"
      (si.starkStruct.hashCommits == true) $
    test "verificationHashType = GL"
      (si.starkStruct.verificationHashType == "GL") $

    -- FRI fold steps
    test "friFoldSteps has 1 step"
      (si.starkStruct.friFoldSteps.size == 1) $
    test "friFoldSteps[0].domainBits = 4"
      (si.starkStruct.friFoldSteps[0]!.domainBits == 4) $

    -- Opening points
    test "openingPoints has 3 entries"
      (si.openingPoints.size == 3) $
    test "openingPoints = [-1, 0, 1]"
      (si.openingPoints == #[-1, 0, 1]) $

    -- Boundaries
    test "boundaries has 1 entry"
      (si.boundaries.size == 1) $
    test "boundaries[0].name = everyRow"
      (si.boundaries[0]!.name == "everyRow") $

    -- Committed polynomial map
    test "cmPolsMap has 24 entries"
      (si.cmPolsMap.size == 24) $
    test "cmPolsMap[0].name = a"
      (si.cmPolsMap[0]!.name == "a") $
    test "cmPolsMap[0].stage = 1"
      (si.cmPolsMap[0]!.stage == 1) $
    test "cmPolsMap[0].fieldType = ff"
      (si.cmPolsMap[0]!.fieldType == FieldType.ff) $
    test "cmPolsMap[15].name = gsum"
      (si.cmPolsMap[15]!.name == "gsum") $
    test "cmPolsMap[15].fieldType = ff3"
      (si.cmPolsMap[15]!.fieldType == FieldType.ff3) $
    test "cmPolsMap[15].stage = 2"
      (si.cmPolsMap[15]!.stage == 2) $

    -- Constant polynomial map
    test "constPolsMap has 1 entry"
      (si.constPolsMap.size == 1) $
    test "constPolsMap[0].name = __L1__"
      (si.constPolsMap[0]!.name == "__L1__") $

    -- Challenges map
    test "challengesMap has 6 entries"
      (si.challengesMap.size == 6) $
    test "challengesMap[0].name = std_alpha"
      (si.challengesMap[0]!.name == "std_alpha") $
    test "challengesMap[3].name = std_xi"
      (si.challengesMap[3]!.name == "std_xi") $

    -- Evaluation map
    test "evMap has 27 entries"
      (si.evMap.size == 27) $
    test "evMap[0].type = cm"
      (si.evMap[0]!.type == EvMapType.cm) $
    test "evMap[0].id = 15"
      (si.evMap[0]!.id == 15) $
    test "evMap[0].rowOffset = -1"
      (decide (si.evMap[0]!.rowOffset = -1)) $
    test "evMap[1].type = const"
      (si.evMap[1]!.type == EvMapType.const_) $
    test "evMap[26].rowOffset = 1 (last entry)"
      (decide (si.evMap[26]!.rowOffset = 1)) $

    -- Airgroup values map
    test "airgroupValuesMap has 1 entry"
      (si.airgroupValuesMap.size == 1) $
    test "airgroupValuesMap[0].name = Simple.gsum_result"
      (si.airgroupValuesMap[0]!.name == "Simple.gsum_result") $

    -- Custom commits (empty for SimpleLeft)
    test "customCommits is empty"
      (si.customCommits.size == 0) $
    test "customCommitsMap is empty"
      (si.customCommitsMap.size == 0) $

    -- Map sections
    test "mapSectionsN has entries"
      (si.mapSectionsN.size > 0) $
    test "cm1 section = 15"
      (si.getNCols "cm1" == 15) $
    test "cm2 section = 21"
      (si.getNCols "cm2" == 21) $
    test "cm3 section = 6"
      (si.getNCols "cm3" == 6) $
    test "const section = 1"
      (si.getNCols "const" == 1) $

    -- Challenge lookup
    test "hasChallenge std_alpha"
      (si.hasChallenge "std_alpha" == true) $
    test "hasChallenge nonexistent"
      (si.hasChallenge "nonexistent" == false) $
    test "getChallengeIndex std_xi = some 3"
      (si.getChallengeIndex "std_xi" == some 3) $
    test "getChallengeIndex nonexistent = none"
      (si.getChallengeIndex "nonexistent" == none) $

    -- Proof size is computed and positive
    test "proofSize > 0"
      (si.proofSize > 0)
  )

-- ============================================================================
-- Main Test Runner
-- ============================================================================

def main : IO UInt32 := do
  -- Compile-time tests
  let compiletimeTests :=
    polMapTests ++
    jsonPolMapTests ++
    jsonChallengeMapTests ++
    jsonEvMapTests ++
    jsonBoundaryTests ++
    jsonStarkStructTests

  -- IO tests (file parsing)
  let fileTests ← loadAndTestStarkInfo

  let allTests := compiletimeTests ++ fileTests
  lspecIO (.ofList [("StarkInfo + PolMap", [allTests])]) []
