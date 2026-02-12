import LSpec
import Protocol.Data
import Protocol.AirConfig
import Primitives.Field

open LSpec
open Protocol.Data
open Protocol.AirConfig
open Primitives.Field

-- ============================================================================
-- EvalKey Tests
-- ============================================================================

def evalKeyTests : TestSeq :=
  let k1 := EvalKey.current "a"
  let k2 := EvalKey.next "a"
  let k3 := EvalKey.prev "a"
  let k4 := EvalKey.current "a" 1
  group "EvalKey" (
    test "current row offset is 0"
      (k1.rowOffset == 0) $
    test "next row offset is 1"
      (k2.rowOffset == 1) $
    test "prev row offset is -1"
      (k3.rowOffset == -1) $
    test "default index is 0"
      (k1.index == 0) $
    test "custom index"
      (k4.index == 1) $
    test "name preserved"
      (k1.name == "a") $
    -- Equality: same fields => equal
    test "structural equality (same)"
      (EvalKey.current "a" 0 == EvalKey.current "a" 0) $
    -- Equality: different name => not equal
    test "different name is not equal"
      (EvalKey.current "a" != EvalKey.current "b") $
    -- Equality: different offset => not equal
    test "different offset is not equal"
      (EvalKey.current "a" != EvalKey.next "a") $
    -- Equality: different index => not equal
    test "different index is not equal"
      (EvalKey.current "a" 0 != EvalKey.current "a" 1)
  )

-- ============================================================================
-- VerifierData Construction Tests
-- ============================================================================

def emptyConstructionTests : TestSeq :=
  let vd := VerifierData.empty
  group "VerifierData.empty" (
    test "evals size is 0"
      (vd.evals.size == 0) $
    test "challenges size is 0"
      (vd.challenges.size == 0) $
    test "publicInputs size is 0"
      (vd.publicInputs.size == 0) $
    test "airgroupValues size is 0"
      (vd.airgroupValues.size == 0) $
    test "publicsFlat is empty"
      (vd.publicsFlat.size == 0) $
    test "airValuesFlat is empty"
      (vd.airValuesFlat.size == 0) $
    test "proofValuesFlat is empty"
      (vd.proofValuesFlat.size == 0)
  )

def structLiteralTests : TestSeq :=
  let vd : VerifierData := {
    evals := {}
    challenges := {}
    publicInputs := {}
    airgroupValues := {}
    publicsFlat := #[1, 2, 3]
    airValuesFlat := #[4, 5]
  }
  group "VerifierData struct literal" (
    test "publicsFlat has 3 elements"
      (vd.publicsFlat.size == 3) $
    test "airValuesFlat has 2 elements"
      (vd.airValuesFlat.size == 2) $
    test "proofValuesFlat defaults to empty"
      (vd.proofValuesFlat.size == 0)
  )

-- ============================================================================
-- VerifierData Eval Insertion and Lookup Tests
-- ============================================================================

def evalInsertionTests : TestSeq :=
  let val1 := GF3.mk (GF.mk 100) (GF.mk 200) (GF.mk 300)
  let val2 := GF3.mk (GF.mk 400) (GF.mk 500) (GF.mk 600)
  let val3 := GF3.mk (GF.mk 700) (GF.mk 800) (GF.mk 900)
  let vd := VerifierData.empty
    |>.insertEval (EvalKey.current "a" 0) val1
    |>.insertEval (EvalKey.next "a" 0) val2
    |>.insertEval (EvalKey.current "b" 1) val3
  group "VerifierData eval insertion" (
    test "evals size is 3"
      (vd.evals.size == 3) $
    test "lookup current a[0]"
      (vd.getEval (EvalKey.current "a" 0) == some val1) $
    test "lookup next a[0]"
      (vd.getEval (EvalKey.next "a" 0) == some val2) $
    test "lookup current b[1]"
      (vd.getEval (EvalKey.current "b" 1) == some val3) $
    test "lookup missing key returns none"
      (vd.getEval (EvalKey.prev "a" 0) == none)
  )

-- ============================================================================
-- VerifierData Accessor Tests (col, nextCol, etc.)
-- ============================================================================

def accessorTests : TestSeq :=
  let val_cur := GF3.mk (GF.mk 10) (GF.mk 20) (GF.mk 30)
  let val_next := GF3.mk (GF.mk 40) (GF.mk 50) (GF.mk 60)
  let val_prev := GF3.mk (GF.mk 70) (GF.mk 80) (GF.mk 90)
  let vd := VerifierData.empty
    |>.insertEval { name := "a", index := 0, rowOffset := 0 } val_cur
    |>.insertEval { name := "a", index := 0, rowOffset := 1 } val_next
    |>.insertEval { name := "a", index := 0, rowOffset := -1 } val_prev
  group "VerifierData accessors" (
    test "col returns current row eval"
      (vd.col "a" == some val_cur) $
    test "nextCol returns next row eval"
      (vd.nextCol "a" == some val_next) $
    test "prevCol returns prev row eval"
      (vd.prevCol "a" == some val_prev) $
    test "getConst returns (name, 0, 0)"
      (vd.getConst "a" == some val_cur) $
    test "nextConst returns (name, 0, 1)"
      (vd.nextConst "a" == some val_next) $
    test "prevConst returns (name, 0, -1)"
      (vd.prevConst "a" == some val_prev) $
    test "col missing returns none"
      (vd.col "missing" == none) $
    test "getEvalByName with explicit args"
      (vd.getEvalByName "a" 0 1 == some val_next)
  )

-- ============================================================================
-- VerifierData Challenge Tests
-- ============================================================================

def challengeTests : TestSeq :=
  let alpha := GF3.mk (GF.mk 111) (GF.mk 222) (GF.mk 333)
  let beta := GF3.mk (GF.mk 444) (GF.mk 555) (GF.mk 666)
  let vd := VerifierData.empty
    |>.insertChallenge "std_alpha" alpha
    |>.insertChallenge "std_beta" beta
  group "VerifierData challenges" (
    test "challenges size is 2"
      (vd.challenges.size == 2) $
    test "lookup std_alpha"
      (vd.challenge "std_alpha" == some alpha) $
    test "lookup std_beta"
      (vd.challenge "std_beta" == some beta) $
    test "lookup missing challenge returns none"
      (vd.challenge "missing" == none)
  )

-- ============================================================================
-- VerifierData Public Input Tests
-- ============================================================================

def publicInputTests : TestSeq :=
  let vd := VerifierData.empty
    |>.insertPublicInput "input_a" (GF.mk 42)
    |>.insertPublicInput "input_b" (GF.mk 99)
  group "VerifierData publicInputs" (
    test "publicInputs size is 2"
      (vd.publicInputs.size == 2) $
    test "lookup input_a"
      (vd.publicInputs["input_a"]? == some (GF.mk 42)) $
    test "lookup input_b"
      (vd.publicInputs["input_b"]? == some (GF.mk 99)) $
    test "lookup missing returns none"
      (vd.publicInputs["missing"]? == none)
  )

-- ============================================================================
-- VerifierData Airgroup Value Tests
-- ============================================================================

def airgroupValueTests : TestSeq :=
  let agv0 := GF3.mk (GF.mk 1000) (GF.mk 2000) (GF.mk 3000)
  let agv1 := GF3.mk (GF.mk 4000) (GF.mk 5000) (GF.mk 6000)
  let vd := VerifierData.empty
    |>.insertAirgroupValue 0 agv0
    |>.insertAirgroupValue 1 agv1
  group "VerifierData airgroupValues" (
    test "airgroupValues size is 2"
      (vd.airgroupValues.size == 2) $
    test "lookup index 0"
      (vd.airgroupValue 0 == agv0) $
    test "lookup index 1"
      (vd.airgroupValue 1 == agv1) $
    -- Missing index returns GF3.zero (matches Python behavior)
    test "missing index returns zero"
      (vd.airgroupValue 99 == GF3.zero)
  )

-- ============================================================================
-- VerifierData Overwrite Tests
-- ============================================================================

def overwriteTests : TestSeq :=
  let val1 := GF3.mk (GF.mk 1) (GF.mk 2) (GF.mk 3)
  let val2 := GF3.mk (GF.mk 4) (GF.mk 5) (GF.mk 6)
  let key := EvalKey.current "x"
  let vd := VerifierData.empty
    |>.insertEval key val1
    |>.insertEval key val2  -- Overwrite
  group "VerifierData overwrite" (
    test "overwritten eval returns new value"
      (vd.getEval key == some val2) $
    test "evals size is 1 (not 2)"
      (vd.evals.size == 1)
  )

-- ============================================================================
-- AirConfig Tests
-- ============================================================================

def airConfigTests : TestSeq :=
  let ac1 := AirConfig.from_starkinfo "/path/to/starkinfo.json"
  let ac2 := AirConfig.from_starkinfo "/path/to/starkinfo.json"
    (global_info_path := some "/path/to/globalInfo.json")
    (airgroup_id := 2) (air_id := 3)
  group "AirConfig" (
    test "default airgroup_id is 0"
      (ac1.airgroup_id == 0) $
    test "default air_id is 0"
      (ac1.air_id == 0) $
    test "default global_info_path is none"
      (ac1.global_info_path.isNone) $
    test "starkinfo_path preserved"
      (ac1.starkinfo_path == "/path/to/starkinfo.json") $
    test "custom airgroup_id"
      (ac2.airgroup_id == 2) $
    test "custom air_id"
      (ac2.air_id == 3) $
    test "global_info_path set"
      (ac2.global_info_path.isSome) $
    test "global_info_path value"
      (ac2.global_info_path == some "/path/to/globalInfo.json")
  )

def airConfigStructTests : TestSeq :=
  let ac : AirConfig := {
    starkinfo_path := "/test/path.json"
    airgroup_id := 5
    air_id := 7
  }
  group "AirConfig struct literal" (
    test "starkinfo_path"
      (ac.starkinfo_path == "/test/path.json") $
    test "airgroup_id"
      (ac.airgroup_id == 5) $
    test "air_id"
      (ac.air_id == 7) $
    test "global_info_path defaults to none"
      (ac.global_info_path.isNone)
  )

-- ============================================================================
-- Main Test Runner
-- ============================================================================

def allTests : TestSeq :=
  evalKeyTests ++
  emptyConstructionTests ++
  structLiteralTests ++
  evalInsertionTests ++
  accessorTests ++
  challengeTests ++
  publicInputTests ++
  airgroupValueTests ++
  overwriteTests ++
  airConfigTests ++
  airConfigStructTests

def main : IO UInt32 :=
  lspecIO (.ofList [("Protocol.Data + AirConfig", [allTests])]) []
