/-
  Polynomial map types.

  Translates: executable-spec/primitives/pol_map.py

  These structures describe how polynomials are organized in the STARK proof
  system and how they map to different stages.
-/
import Lean.Data.Json

namespace Primitives.PolMap

open Lean (Json FromJson)

-- ============================================================================
-- Polynomial Identification
-- ============================================================================

/-- Identifies a polynomial in verification context.

    Used as dict key for buffer-free polynomial access in the verifier.
    The verifier parses proof data into a map from PolynomialId to field elements.

    Fields:
    - `type`: "cm" (committed), "const" (constant), "custom" (custom commit)
    - `name`: Polynomial name from starkinfo (e.g., "a", "gsum")
    - `index`: Array index for multi-instance polynomials (0 for scalars)
    - `stage`: Stage number (1+ for committed, 0 for constants) -/
structure PolynomialId where
  type : String
  name : String
  index : Nat
  stage : Nat
  deriving Repr, BEq, Hashable, Inhabited

instance : ToString PolynomialId where
  toString p := s!"PolynomialId({p.type}, {p.name}, {p.index}, {p.stage})"

-- ============================================================================
-- Field Type
-- ============================================================================

/-- Field element type for type-safe field discrimination.
    - `ff` (dim 1): Base Goldilocks field
    - `ff3` (dim 3): Cubic extension field -/
inductive FieldType where
  | ff  : FieldType  -- Base field, dim = 1
  | ff3 : FieldType  -- Cubic extension, dim = 3
  deriving Repr, BEq, DecidableEq, Inhabited

/-- Get the dimension of a FieldType (1 for FF, 3 for FF3). -/
def FieldType.dim : FieldType -> Nat
  | .ff  => 1
  | .ff3 => 3

/-- Convert an integer dimension to a FieldType. -/
def FieldType.fromDim (d : Nat) : FieldType :=
  if d == 1 then .ff else .ff3

instance : ToString FieldType where
  toString
    | .ff  => "FF"
    | .ff3 => "FF3"

-- ============================================================================
-- PolMap
-- ============================================================================

/-- Maps a polynomial to its location in the proof system.

    Corresponds to C++ PolMap in stark_info.hpp.

    Fields:
    - `stage`: Stage number
    - `name`: Polynomial name
    - `fieldType`: Base (FF) or extension (FF3)
    - `stagePos`: Position within the stage buffer
    - `stageId`: ID within the stage
    - `imPol`: Whether this is an intermediate polynomial
    - `lengths`: Length metadata for array polynomials
    - `commitId`: Commitment ID (for custom commits)
    - `expId`: Expression ID (for bytecode interpreter)
    - `polsMapId`: Global polynomial map ID -/
structure PolMap where
  stage : Nat
  name : String
  fieldType : FieldType
  stagePos : Nat
  stageId : Nat
  imPol : Bool := false
  lengths : Array Nat := #[]
  commitId : Nat := 0
  expId : Nat := 0
  polsMapId : Nat := 0
  deriving Repr, BEq, Inhabited

/-- Backwards compatibility: returns 1 for FF, 3 for FF3. -/
def PolMap.dim (p : PolMap) : Nat := p.fieldType.dim

instance : ToString PolMap where
  toString p := s!"PolMap({p.stage}, {p.name}, {p.fieldType}, stagePos={p.stagePos})"

-- ============================================================================
-- EvMap
-- ============================================================================

/-- Evaluation source type.

    Corresponds to C++ enum EvMap::eType in stark_info.hpp. -/
inductive EvMapType where
  | cm     : EvMapType  -- Committed polynomial
  | const_ : EvMapType  -- Constant polynomial
  | custom : EvMapType  -- Custom commit
  deriving Repr, BEq, DecidableEq, Inhabited

instance : ToString EvMapType where
  toString
    | .cm     => "cm"
    | .const_ => "const"
    | .custom => "custom"

/-- Convert string to EvMapType.

    Corresponds to C++ EvMap::setType(). -/
def EvMapType.fromString (s : String) : Except String EvMapType :=
  if s == "cm" then .ok .cm
  else if s == "const" then .ok .const_
  else if s == "custom" then .ok .custom
  else .error s!"EvMap: invalid type string: {s}"

/-- Maps an evaluation point to its polynomial source.

    Corresponds to C++ class EvMap in stark_info.hpp.

    Fields:
    - `type`: Source type (cm, const, custom)
    - `id`: Polynomial ID within source type
    - `rowOffset`: Row offset for evaluation (-1, 0, or 1). C++ name: "prime"
    - `commitId`: Commitment ID (only for custom type)
    - `openingPos`: Position in opening points array -/
structure EvMap where
  type : EvMapType
  id : Nat
  rowOffset : Int  -- C++: "prime" - row offset for evaluation point
  commitId : Nat := 0
  openingPos : Nat := 0
  deriving Repr, BEq, Inhabited

instance : ToString EvMap where
  toString e := s!"EvMap({e.type}, id={e.id}, rowOffset={e.rowOffset})"

-- ============================================================================
-- ChallengeMap
-- ============================================================================

/-- Maps a challenge to its derivation stage.

    Fields:
    - `name`: Challenge name (e.g., "std_alpha", "std_xi")
    - `stage`: Stage number when challenge is derived
    - `fieldType`: Base (FF) or extension (FF3)
    - `stageId`: ID within the stage -/
structure ChallengeMap where
  name : String
  stage : Nat
  fieldType : FieldType
  stageId : Nat
  deriving Repr, BEq, Inhabited

/-- Backwards compatibility: returns 1 for FF, 3 for FF3. -/
def ChallengeMap.dim (c : ChallengeMap) : Nat := c.fieldType.dim

instance : ToString ChallengeMap where
  toString c := s!"ChallengeMap({c.name}, stage={c.stage}, {c.fieldType})"

-- ============================================================================
-- CustomCommits
-- ============================================================================

/-- Custom commitment configuration.

    Corresponds to C++ class CustomCommits in stark_info.hpp.

    Fields:
    - `name`: Custom commit name
    - `stageWidths`: Number of columns at each stage
    - `publicValues`: Indices of public values used -/
structure CustomCommits where
  name : String
  stageWidths : Array Nat := #[]
  publicValues : Array Nat := #[]
  deriving Repr, BEq, Inhabited

instance : ToString CustomCommits where
  toString c := s!"CustomCommits({c.name})"

-- ============================================================================
-- Boundary
-- ============================================================================

/-- Constraint boundary specification.

    Corresponds to C++ class Boundary in stark_info.hpp.

    Fields:
    - `name`: Boundary name (e.g., "everyRow", "everyFrame")
    - `offsetMin`: Minimum row offset (only for "everyFrame")
    - `offsetMax`: Maximum row offset (only for "everyFrame") -/
structure Boundary where
  name : String
  offsetMin : Int := 0
  offsetMax : Int := 0
  deriving Repr, BEq, Inhabited

instance : ToString Boundary where
  toString b := s!"Boundary({b.name})"

-- ============================================================================
-- JSON Parsing
-- ============================================================================

/-- Parse a PolMap from JSON.

    Note: stagePos falls back to stageId if not present (matches Python
    constPolsMap parsing where stage_pos=const_data["stageId"]). -/
def PolMap.fromJson? (j : Json) : Except String PolMap := do
  let stage ← j.getObjValAs? Nat "stage"
  let name ← j.getObjValAs? String "name"
  let dim ← j.getObjValAs? Nat "dim"
  let stageId ← j.getObjValAs? Nat "stageId"
  let polsMapId ← j.getObjValAs? Nat "polsMapId"
  -- stagePos falls back to stageId if not present
  let stagePos := (j.getObjValAs? Nat "stagePos").toOption.getD stageId
  -- Optional fields
  let imPol := j.getObjVal? "imPol" |>.isOk
  let expId := (j.getObjValAs? Nat "expId").toOption.getD 0
  let lengths : Array Nat := match j.getObjValAs? (Array Nat) "lengths" with
    | .ok arr => arr
    | .error _ => #[]
  return {
    stage
    name
    fieldType := FieldType.fromDim dim
    stagePos
    stageId
    imPol
    lengths
    commitId := 0
    expId
    polsMapId
  }

/-- Parse an EvMap from JSON. -/
def EvMap.fromJson? (j : Json) (openingPoints : Array Int) : Except String EvMap := do
  let typeStr ← j.getObjValAs? String "type"
  let type ← EvMapType.fromString typeStr
  let id ← j.getObjValAs? Nat "id"
  let rowOffset ← j.getObjValAs? Int "prime"
  let commitId := if typeStr == "custom"
    then (j.getObjValAs? Nat "commitId").toOption.getD 0
    else 0
  let openingPos ← match j.getObjValAs? Nat "openingPos" with
    | .ok pos => pure pos
    | .error _ =>
      -- Look up row_offset in opening_points array
      match openingPoints.findIdx? (· == rowOffset) with
      | some idx => pure idx
      | none => .error s!"Opening point {rowOffset} not found in opening_points"
  return { type, id, rowOffset, commitId, openingPos }

/-- Parse a ChallengeMap from JSON. -/
def ChallengeMap.fromJson? (j : Json) : Except String ChallengeMap := do
  let name ← j.getObjValAs? String "name"
  let stage ← j.getObjValAs? Nat "stage"
  let dim ← j.getObjValAs? Nat "dim"
  let stageId ← j.getObjValAs? Nat "stageId"
  return { name, stage, fieldType := FieldType.fromDim dim, stageId }

/-- Parse a CustomCommits from JSON. -/
def CustomCommits.fromJson? (j : Json) : Except String CustomCommits := do
  let name ← j.getObjValAs? String "name"
  let stageWidths : Array Nat := match j.getObjValAs? (Array Nat) "stageWidths" with
    | .ok arr => arr
    | .error _ => #[]
  let publicValues : Array Nat := match j.getObjVal? "publicValues" with
    | .ok (.arr pvs) =>
      pvs.filterMap (fun pv => (pv.getObjValAs? Nat "idx").toOption)
    | _ => #[]
  return { name, stageWidths, publicValues }

/-- Parse a Boundary from JSON. -/
def Boundary.fromJson? (j : Json) : Except String Boundary := do
  let name ← j.getObjValAs? String "name"
  let offsetMin := (j.getObjValAs? Int "offsetMin").toOption.getD 0
  let offsetMax := (j.getObjValAs? Int "offsetMax").toOption.getD 0
  return { name, offsetMin, offsetMax }

end Primitives.PolMap
