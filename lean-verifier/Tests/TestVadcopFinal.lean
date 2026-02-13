/-
  End-to-end test for VADCOP final proof verification.

  Translates: executable-spec/tests/test_zisk_vadcop_final_e2e.py

  Tests that the Lean verifier correctly verifies the aggregated VADCOP final
  proof — the outermost STARK proof that binds all per-AIR recursive proofs
  into a single cryptographic statement.

  The VadcopFinal proof differs from per-AIR proofs in two ways:
  1. Transcript initialization: seeds with verkey + hashed publics + root1
     (instead of global_challenge)
  2. Binary format: prepends [n_publics, publics...] header before standard body

  All test fixtures are self-contained in Tests/test-data/zisk/.
-/
import LSpec
import Protocol.Verifier
import Protocol.StarkInfo
import Protocol.Proof
import Primitives.Field
import Lean.Data.Json
import Lean.Data.Json.Parser

open LSpec
open Protocol.Verifier
open Protocol.StarkInfo (StarkInfo)
open Protocol.Proof (STARKProof readUInt64LE readUInt64Array)
open Primitives.Field

-- ============================================================================
-- Configuration
-- ============================================================================

def TEST_DATA_DIR : String := "Tests/test-data/zisk"

def vadcopStarkInfoPath : String :=
  s!"{TEST_DATA_DIR}/vadcop_final/vadcop_final.starkinfo.json"

def vadcopVerkeyPath : String :=
  s!"{TEST_DATA_DIR}/vadcop_final/vadcop_final.verkey.json"

def vadcopBytecodePath : String :=
  s!"{TEST_DATA_DIR}/vadcop_final/vadcop_final.bin"

def vadcopProofBinPath : String :=
  s!"{TEST_DATA_DIR}/vadcop_final.proof.bin"

-- ============================================================================
-- Helpers
-- ============================================================================

/-- Load verkey JSON: array of uint64 values. -/
def loadVerkeyJson (path : String) : IO (Array UInt64) := do
  let contents ← IO.FS.readFile path
  match Lean.Json.parse contents with
  | .ok json =>
    let arr ← IO.ofExcept (json.getArr?)
    let mut result : Array UInt64 := #[]
    for item in arr do
      match item with
      | .num n => result := result.push (n.mantissa.toNat.toUInt64)
      | _ => throw (IO.userError "Expected number in verkey array")
    return result
  | .error e => throw (IO.userError s!"JSON parse error: {e}")

/-- Parse a VadcopFinal proof binary with embedded publics header.

    VadcopFinal proofs prepend [n_publics: u64] [publics: n_publics × u64]
    before the standard proof body.

    Translates: proof.py:161-177 from_vadcop_final_bytes -/
def parseVadcopFinalProof (data : ByteArray) (starkInfo : StarkInfo)
    : STARKProof × Array UInt64 :=
  let nPublics := (readUInt64LE data 0).toNat
  let headerSize := 8 + nPublics * 8
  let publics := readUInt64Array data 8 nPublics
  -- Parse the remaining bytes as a standard proof
  let proofData := data.extract headerSize data.size
  let proof := STARKProof.fromBytes proofData starkInfo
  (proof, publics)

-- ============================================================================
-- Test runner
-- ============================================================================

def main : IO UInt32 := do
  -- Check if test fixtures exist
  let siExists ← System.FilePath.pathExists vadcopStarkInfoPath
  let vkExists ← System.FilePath.pathExists vadcopVerkeyPath
  let proofExists ← System.FilePath.pathExists vadcopProofBinPath
  let bcExists ← System.FilePath.pathExists vadcopBytecodePath

  if !siExists || !vkExists || !proofExists || !bcExists then
    IO.eprintln s!"VadcopFinal E2E test: fixtures missing"
    IO.eprintln s!"  starkinfo: {siExists}"
    IO.eprintln s!"  verkey: {vkExists}"
    IO.eprintln s!"  proof: {proofExists}"
    IO.eprintln s!"  bytecode: {bcExists}"
    return 1

  -- Load starkinfo
  IO.println "Loading VadcopFinal starkinfo..."
  let siJson ← IO.FS.readFile vadcopStarkInfoPath
  let starkInfo ← match Lean.Json.parse siJson >>= StarkInfo.fromJson? with
    | .ok si => pure si
    | .error e => throw (IO.userError s!"Failed to parse starkinfo: {e}")

  -- Load proof with embedded publics
  IO.println "Parsing VadcopFinal proof..."
  let proofData ← IO.FS.readBinFile vadcopProofBinPath
  let (proof, publics) := parseVadcopFinalProof proofData starkInfo
  IO.println s!"  publics: {publics.size} elements"

  -- Load verkey
  let verkey ← loadVerkeyJson vadcopVerkeyPath

  -- Verify: globalChallenge = none triggers VadcopFinal transcript path
  IO.println "Verifying VadcopFinal proof..."
  let result := starkVerify proof starkInfo verkey vadcopStarkInfoPath vadcopBytecodePath
    (globalChallenge := none)
    (publics := some publics)

  if result then
    IO.println "  PASSED"
  else
    IO.println "  FAILED"

  let allTests := test "VadcopFinal proof verifies" result

  lspecIO (.ofList [("VADCOP Final Verifier E2E", [allTests])]) []
