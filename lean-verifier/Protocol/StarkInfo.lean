/-
  StarkInfo configuration loaded from starkinfo.json.

  Translates: executable-spec/protocol/stark_info.py

  StarkStruct: Protocol-level parameters defining the STARK proof system structure.
  StarkInfo: AIR-specific metadata defining the constraint system and polynomial layout.
-/
import Lean.Data.Json
import Primitives.PolMap

namespace Protocol.StarkInfo

open Lean (Json)
open Primitives.PolMap

-- ============================================================================
-- Constants
-- ============================================================================

/-- Poseidon2 hash output size in field elements. -/
def HASH_SIZE : Nat := 4

/-- Cubic extension degree. -/
def FIELD_EXTENSION_DEGREE : Nat := 3

-- ============================================================================
-- FriFoldStep
-- ============================================================================

/-- FRI recursive folding layer configuration. -/
structure FriFoldStep where
  domainBits : Nat
  deriving Repr, BEq, Inhabited

instance : ToString FriFoldStep where
  toString f := s!"FriFoldStep(domainBits={f.domainBits})"

-- ============================================================================
-- StarkStruct
-- ============================================================================

/-- Core STARK protocol parameters.

    Fields:
    - `nBits`: Log2 of trace size (number of rows = 2^nBits)
    - `nBitsExt`: Log2 of extended domain size
    - `nQueries`: Number of FRI queries
    - `verificationHashType`: Hash type (e.g., "GL")
    - `friFoldSteps`: FRI folding step configurations
    - `merkleTreeArity`: Merkle tree branching factor
    - `merkleTreeCustom`: Whether to use custom Merkle tree
    - `transcriptArity`: Transcript Merkle tree arity
    - `lastLevelVerification`: Number of last levels verified directly
    - `powBits`: Proof-of-work difficulty bits
    - `hashCommits`: Whether to hash commitments -/
structure StarkStruct where
  nBits : Nat
  nBitsExt : Nat
  nQueries : Nat
  verificationHashType : String
  friFoldSteps : Array FriFoldStep := #[]
  merkleTreeArity : Nat := 16
  merkleTreeCustom : Bool := false
  transcriptArity : Nat := 16
  lastLevelVerification : Nat := 0
  powBits : Nat := 0
  hashCommits : Bool := false
  deriving Repr, BEq, Inhabited

instance : ToString StarkStruct where
  toString s := s!"StarkStruct(nBits={s.nBits}, nBitsExt={s.nBitsExt}, nQueries={s.nQueries})"

/-- Parse StarkStruct from JSON. -/
def StarkStruct.fromJson? (j : Json) : Except String StarkStruct := do
  let nBits ← j.getObjValAs? Nat "nBits"
  let nBitsExt ← j.getObjValAs? Nat "nBitsExt"
  let nQueries ← j.getObjValAs? Nat "nQueries"
  let verificationHashType ← j.getObjValAs? String "verificationHashType"
  let powBits := (j.getObjValAs? Nat "powBits").toOption.getD 0
  let merkleTreeArity := (j.getObjValAs? Nat "merkleTreeArity").toOption.getD 16
  let transcriptArity := (j.getObjValAs? Nat "transcriptArity").toOption.getD 16
  let merkleTreeCustom := (j.getObjValAs? Bool "merkleTreeCustom").toOption.getD false
  let lastLevelVerification := (j.getObjValAs? Nat "lastLevelVerification").toOption.getD 0
  let hashCommits := (j.getObjValAs? Bool "hashCommits").toOption.getD false
  -- Parse FRI fold steps from "steps" array
  let steps ← match j.getObjVal? "steps" with
    | .ok (.arr arr) =>
      arr.mapM fun s => do
        let nb ← s.getObjValAs? Nat "nBits"
        pure (FriFoldStep.mk nb)
    | .ok _ => .error "starkStruct.steps: expected array"
    | .error _ => pure #[]
  return {
    nBits, nBitsExt, nQueries, verificationHashType
    friFoldSteps := steps
    merkleTreeArity, merkleTreeCustom, transcriptArity
    lastLevelVerification, powBits, hashCommits
  }

-- ============================================================================
-- StarkInfo
-- ============================================================================

/-- STARK configuration loaded from starkinfo.json.

    This is the main configuration bundle that describes an AIR's constraint
    system, polynomial layout, and proof structure. -/
structure StarkInfo where
  -- Core parameters
  starkStruct : StarkStruct
  name : String

  -- Polynomial counts
  nPublics : Nat
  nConstants : Nat
  nStages : Nat

  -- Proof size
  proofSize : Nat

  -- Polynomial mappings
  customCommits : Array CustomCommits
  cmPolsMap : Array PolMap
  constPolsMap : Array PolMap
  challengesMap : Array ChallengeMap
  airgroupValuesMap : Array PolMap
  airValuesMap : Array PolMap
  customCommitsMap : Array (Array PolMap)
  evMap : Array EvMap

  -- Opening points and boundaries
  openingPoints : Array Int
  boundaries : Array Boundary

  -- Quotient polynomial
  qDeg : Nat
  qDim : Nat

  -- Expression IDs (for bytecode interpreter)
  cExpId : Nat
  friExpId : Nat

  -- Memory layout
  mapSectionsN : Array (String × Nat)

  -- Value sizes
  airValuesSize : Nat
  airgroupValuesSize : Nat
  deriving Repr, Inhabited

instance : ToString StarkInfo where
  toString si := s!"StarkInfo({si.name}, nBits={si.starkStruct.nBits}, nStages={si.nStages})"

-- ============================================================================
-- JSON Parsing Helpers
-- ============================================================================

/-- Look up a key in an association list. -/
def lookupSection (sections : Array (String × Nat)) (key : String) : Nat :=
  match sections.find? (fun p => p.1 == key) with
  | some (_, v) => v
  | none => 0

-- ============================================================================
-- StarkInfo JSON Parsing
-- ============================================================================

/-- Parse basic parameters from JSON. -/
private def parseBasicParams (j : Json) :
    Except String (String × Nat × Nat × Nat × Nat × Nat × Nat × Nat) := do
  let name ← j.getObjValAs? String "name"
  let nPublics ← j.getObjValAs? Nat "nPublics"
  let nConstants ← j.getObjValAs? Nat "nConstants"
  let nStages ← j.getObjValAs? Nat "nStages"
  let qDeg ← j.getObjValAs? Nat "qDeg"
  let qDim ← j.getObjValAs? Nat "qDim"
  let cExpId := (j.getObjValAs? Nat "cExpId").toOption.getD 0
  let friExpId := (j.getObjValAs? Nat "friExpId").toOption.getD 0
  return (name, nPublics, nConstants, nStages, qDeg, qDim, cExpId, friExpId)

/-- Parse custom commits from JSON. -/
private def parseCustomCommits (j : Json) : Except String (Array CustomCommits) := do
  match j.getObjVal? "customCommits" with
  | .ok (.arr arr) => arr.mapM CustomCommits.fromJson?
  | _ => pure #[]

/-- Parse opening points from JSON. -/
private def parseOpeningPoints (j : Json) : Except String (Array Int) := do
  match j.getObjVal? "openingPoints" with
  | .ok (.arr arr) => arr.mapM (fun v => v.getInt?)
  | _ => pure #[]

/-- Parse boundaries from JSON. -/
private def parseBoundaries (j : Json) : Except String (Array Boundary) := do
  match j.getObjVal? "boundaries" with
  | .ok (.arr arr) => arr.mapM Boundary.fromJson?
  | _ => pure #[]

/-- Parse challenges map from JSON. -/
private def parseChallenges (j : Json) : Except String (Array ChallengeMap) := do
  match j.getObjVal? "challengesMap" with
  | .ok (.arr arr) => arr.mapM ChallengeMap.fromJson?
  | _ => pure #[]

/-- Parse airgroup values map from JSON. Returns (map, totalSize). -/
private def parseAirgroupValues (j : Json) : Except String (Array PolMap × Nat) := do
  match j.getObjVal? "airgroupValuesMap" with
  | .ok (.arr arr) => do
    let mut result : Array PolMap := #[]
    let mut totalSize : Nat := 0
    for item in arr do
      let name ← item.getObjValAs? String "name"
      let stage ← item.getObjValAs? Nat "stage"
      let ft := if stage == 1 then FieldType.ff else FieldType.ff3
      let pm : PolMap := {
        stage, name, fieldType := ft
        stagePos := 0, stageId := 0
      }
      result := result.push pm
      totalSize := totalSize + ft.dim
    pure (result, totalSize)
  | _ => pure (#[], 0)

/-- Parse air values map from JSON. Returns (map, totalSize). -/
private def parseAirValues (j : Json) : Except String (Array PolMap × Nat) := do
  match j.getObjVal? "airValuesMap" with
  | .ok (.arr arr) => do
    let mut result : Array PolMap := #[]
    let mut totalSize : Nat := 0
    for item in arr do
      let name ← item.getObjValAs? String "name"
      let stage ← item.getObjValAs? Nat "stage"
      let ft := if stage == 1 then FieldType.ff else FieldType.ff3
      let pm : PolMap := {
        stage, name, fieldType := ft
        stagePos := 0, stageId := 0
      }
      result := result.push pm
      totalSize := totalSize + ft.dim
    pure (result, totalSize)
  | _ => pure (#[], 0)

/-- Parse committed polynomial maps from JSON. -/
private def parseCmPolsMap (j : Json) : Except String (Array PolMap) := do
  match j.getObjVal? "cmPolsMap" with
  | .ok (.arr arr) => arr.mapM PolMap.fromJson?
  | _ => pure #[]

/-- Parse constant polynomial maps from JSON. -/
private def parseConstPolsMap (j : Json) : Except String (Array PolMap) := do
  match j.getObjVal? "constPolsMap" with
  | .ok (.arr arr) => arr.mapM PolMap.fromJson?
  | _ => pure #[]

/-- Parse custom commits polynomial maps from JSON. -/
private def parseCustomCommitsMap (j : Json) : Except String (Array (Array PolMap)) := do
  match j.getObjVal? "customCommitsMap" with
  | .ok (.arr outerArr) => do
    let mut result : Array (Array PolMap) := #[]
    let mut commitIdx : Nat := 0
    for inner in outerArr do
      match inner with
      | .arr innerArr => do
        let pols ← innerArr.mapM fun polData => do
          let mut pol ← PolMap.fromJson? polData
          pol := { pol with commitId := commitIdx }
          pure pol
        result := result.push pols
      | _ => pure ()
      commitIdx := commitIdx + 1
    pure result
  | _ => pure #[]

/-- Parse evaluation map from JSON. -/
private def parseEvMap (j : Json) (openingPoints : Array Int) : Except String (Array EvMap) := do
  match j.getObjVal? "evMap" with
  | .ok (.arr arr) => arr.mapM (fun item => EvMap.fromJson? item openingPoints)
  | _ => pure #[]

/-- Parse map sections from JSON. -/
private def parseMapSections (j : Json) : Except String (Array (String × Nat)) := do
  match j.getObjVal? "mapSectionsN" with
  | .ok (.obj kvs) =>
    let mut result : Array (String × Nat) := #[]
    for (k, v) in kvs do
      match v.getNat? with
      | .ok n => result := result.push (k, n)
      | .error _ => pure ()
    pure result
  | _ => pure #[]

-- ============================================================================
-- Proof Size Computation
-- ============================================================================

/-- Compute ceiling division. -/
private def ceilDiv (a b : Nat) : Nat :=
  (a + b - 1) / b

/-- Compute log2 (integer, rounded down). -/
private def log2Nat (n : Nat) : Nat :=
  if n <= 1 then 0
  else 1 + log2Nat (n / 2)

/-- Compute total proof size in field elements. -/
private def computeProofSize (ss : StarkStruct) (nStages : Nat) (nConstants : Nat)
    (evMapSize : Nat) (airgroupValuesMapSize : Nat) (airValuesMapSize : Nat)
    (customCommits : Array CustomCommits) (mapSectionsN : Array (String × Nat)) : Nat :=
  Id.run do
    let mut size : Nat := 0

    -- Values and roots
    size := size + airgroupValuesMapSize * FIELD_EXTENSION_DEGREE
    size := size + airValuesMapSize * FIELD_EXTENSION_DEGREE
    size := size + (nStages + 1) * HASH_SIZE

    -- Evaluations
    size := size + evMapSize * FIELD_EXTENSION_DEGREE

    -- Merkle proof siblings
    let logArity := log2Nat ss.merkleTreeArity
    let nSiblings0 := if logArity > 0 then
      ceilDiv ss.friFoldSteps[0]!.domainBits logArity - ss.lastLevelVerification
    else 0
    let nSiblingsPerLevel := (ss.merkleTreeArity - 1) * HASH_SIZE

    -- Constants Merkle proofs
    size := size + ss.nQueries * nConstants
    size := size + ss.nQueries * nSiblings0 * nSiblingsPerLevel

    -- Custom commits Merkle proofs
    for cc in customCommits do
      let sectionKey := cc.name ++ "0"
      let sectionWidth := lookupSection mapSectionsN sectionKey
      size := size + ss.nQueries * sectionWidth
      size := size + ss.nQueries * nSiblings0 * nSiblingsPerLevel

    -- Stage commitments Merkle proofs
    for i in [:nStages + 1] do
      let sect := s!"cm{i + 1}"
      let sectionWidth := lookupSection mapSectionsN sect
      size := size + ss.nQueries * sectionWidth
      size := size + ss.nQueries * nSiblings0 * nSiblingsPerLevel

    -- FRI roots
    size := size + (ss.friFoldSteps.size - 1) * HASH_SIZE

    -- Last level verification nodes
    if ss.lastLevelVerification > 0 then
      let numNodesLevel := ss.merkleTreeArity ^ ss.lastLevelVerification
      size := size + (ss.friFoldSteps.size - 1) * numNodesLevel * HASH_SIZE
      size := size + (nStages + 2 + customCommits.size) * numNodesLevel * HASH_SIZE

    -- FRI query proofs
    for i in [1:ss.friFoldSteps.size] do
      let nSiblings := if logArity > 0 then
        ceilDiv ss.friFoldSteps[i]!.domainBits logArity - ss.lastLevelVerification
      else 0
      let foldFactor := 1 <<< (ss.friFoldSteps[i-1]!.domainBits - ss.friFoldSteps[i]!.domainBits)
      size := size + ss.nQueries * foldFactor * FIELD_EXTENSION_DEGREE
      size := size + ss.nQueries * nSiblings * nSiblingsPerLevel

    -- Final polynomial + nonce
    let finalPolDegree := 1 <<< ss.friFoldSteps[ss.friFoldSteps.size - 1]!.domainBits
    size := size + finalPolDegree * FIELD_EXTENSION_DEGREE
    size := size + 1  -- nonce

    size

-- ============================================================================
-- StarkInfo.fromJson?
-- ============================================================================

/-- Parse a StarkInfo from a JSON value. -/
def StarkInfo.fromJson? (j : Json) : Except String StarkInfo := do
  -- Parse StarkStruct
  let ssJson ← j.getObjVal? "starkStruct"
  let starkStruct ← StarkStruct.fromJson? ssJson

  -- Parse basic parameters
  let (name, nPublics, nConstants, nStages, qDeg, qDim, cExpId, friExpId) ←
    parseBasicParams j

  -- Parse custom commits
  let customCommits ← parseCustomCommits j

  -- Parse opening points
  let openingPoints ← parseOpeningPoints j

  -- Parse boundaries
  let boundaries ← parseBoundaries j

  -- Parse challenges
  let challengesMap ← parseChallenges j

  -- Parse values maps
  let (airgroupValuesMap, airgroupValuesSize) ← parseAirgroupValues j
  let (airValuesMap, airValuesSize) ← parseAirValues j

  -- Parse polynomial maps
  let cmPolsMap ← parseCmPolsMap j
  let constPolsMap ← parseConstPolsMap j
  let customCommitsMap ← parseCustomCommitsMap j

  -- Parse evaluation map
  let evMap ← parseEvMap j openingPoints

  -- Parse map sections
  let mapSectionsN ← parseMapSections j

  -- Compute proof size
  let proofSize := computeProofSize starkStruct nStages nConstants
    evMap.size airgroupValuesMap.size airValuesMap.size
    customCommits mapSectionsN

  return {
    starkStruct, name
    nPublics, nConstants, nStages
    proofSize
    customCommits, cmPolsMap, constPolsMap, challengesMap
    airgroupValuesMap, airValuesMap, customCommitsMap, evMap
    openingPoints, boundaries
    qDeg, qDim
    cExpId, friExpId
    mapSectionsN
    airValuesSize, airgroupValuesSize
  }

-- ============================================================================
-- Accessor Methods
-- ============================================================================

/-- Get number of columns in a section. -/
def StarkInfo.getNCols (si : StarkInfo) (sect : String) : Nat :=
  lookupSection si.mapSectionsN sect

/-- Check if a challenge with given name exists. -/
def StarkInfo.hasChallenge (si : StarkInfo) (name : String) : Bool :=
  si.challengesMap.any (fun cm => cm.name == name)

/-- Get the index of a challenge by name. Returns none if not found. -/
def StarkInfo.getChallengeIndex (si : StarkInfo) (name : String) : Option Nat :=
  si.challengesMap.findIdx? (fun cm => cm.name == name)

end Protocol.StarkInfo
