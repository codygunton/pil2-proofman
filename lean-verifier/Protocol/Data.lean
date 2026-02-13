/-
  Verifier data structures for constraint evaluation.

  Translates: executable-spec/protocol/data.py:71-91 (VerifierData)

  Architecture Overview:
    The STARK verifier uses VerifierData as a dict-based container for
    polynomial evaluations at the challenge point xi. Constraint modules
    access evaluations by (name, index, row_offset) keys:

    - name: Polynomial name (e.g., "a", "gsum", "im_cluster")
    - index: Array index for multi-instance polynomials (0 for scalars)
    - row_offset: Row shift for evaluation (0=xi, 1=xi*omega, -1=xi*omega^(-1))

    The verifier populates this from the proof's eval section + the ev_map.
-/
import Primitives.Field
import Std

namespace Protocol.Data

open Primitives.Field

-- ============================================================================
-- Evaluation Key
-- ============================================================================

/-- Key for polynomial evaluation lookup: (name, index, row_offset).

    Translates the Python tuple key `(str, int, int)` used in VerifierData.evals.

    - `name`: Polynomial name from starkinfo (e.g., "a", "gsum")
    - `index`: Array index for multi-instance polynomials (0 for scalars)
    - `rowOffset`: Row offset for evaluation point:
        0 = evaluation at xi
        1 = evaluation at xi * omega (next row)
       -1 = evaluation at xi * omega^(-1) (previous row) -/
structure EvalKey where
  name : String
  index : Nat
  rowOffset : Int
  deriving Repr, BEq, Hashable, Inhabited

instance : ToString EvalKey where
  toString k := s!"EvalKey({k.name}, {k.index}, {k.rowOffset})"

/-- Convenience constructor for common case: current row (offset=0). -/
def EvalKey.current (name : String) (index : Nat := 0) : EvalKey :=
  { name, index, rowOffset := 0 }

/-- Convenience constructor for next row (offset=1). -/
def EvalKey.next (name : String) (index : Nat := 0) : EvalKey :=
  { name, index, rowOffset := 1 }

/-- Convenience constructor for previous row (offset=-1). -/
def EvalKey.prev (name : String) (index : Nat := 0) : EvalKey :=
  { name, index, rowOffset := -1 }

-- ============================================================================
-- VerifierData
-- ============================================================================

/-- Evaluation data for constraint module verification.

    Translates: data.py:71-91 VerifierData

    This provides a clean dict-based interface for verifier constraint evaluation.
    The verifier populates this from proof evaluations via the ev_map, then
    constraint modules access evaluations through VerifierConstraintContext.

    Attributes:
    - `evals`: Polynomial evaluations keyed by (name, index, row_offset)
    - `challenges`: Fiat-Shamir challenges keyed by name
    - `publicInputs`: Public inputs keyed by name
    - `airgroupValues`: AIR group accumulated values keyed by index
    - `publicsFlat`: Raw public inputs array (for bytecode adapter)
    - `airValuesFlat`: Raw AIR values array (for bytecode adapter)
    - `proofValuesFlat`: Raw proof values array (for bytecode adapter) -/
structure VerifierData where
  evals : Std.HashMap EvalKey GF3
  challenges : Std.HashMap String GF3
  publicInputs : Std.HashMap String GF
  airgroupValues : Std.HashMap Nat GF3
  /-- Raw public inputs array for bytecode adapter (not used by hand-written modules). -/
  publicsFlat : Array UInt64 := #[]
  /-- Raw AIR values array for bytecode adapter (not used by hand-written modules). -/
  airValuesFlat : Array UInt64 := #[]
  /-- Raw proof values array for bytecode adapter (not used by hand-written modules). -/
  proofValuesFlat : Array UInt64 := #[]

instance : Inhabited VerifierData where
  default := {
    evals := {}
    challenges := {}
    publicInputs := {}
    airgroupValues := {}
  }

instance : ToString VerifierData where
  toString vd :=
    s!"VerifierData(evals={vd.evals.size}, challenges={vd.challenges.size}, " ++
    s!"publicInputs={vd.publicInputs.size}, airgroupValues={vd.airgroupValues.size})"

-- ============================================================================
-- VerifierData constructors
-- ============================================================================

/-- Create an empty VerifierData. -/
def VerifierData.empty : VerifierData :=
  { evals := {}
    challenges := {}
    publicInputs := {}
    airgroupValues := {} }

-- ============================================================================
-- VerifierData accessors
-- ============================================================================

/-- Look up a polynomial evaluation at (name, index, rowOffset).
    Returns none if the key is not present. -/
def VerifierData.getEval (vd : VerifierData) (key : EvalKey) : Option GF3 :=
  vd.evals[key]?

/-- Look up a polynomial evaluation by name, index, and row offset.
    Returns none if the key is not present. -/
def VerifierData.getEvalByName (vd : VerifierData)
    (name : String) (index : Nat := 0) (rowOffset : Int := 0) : Option GF3 :=
  vd.evals[EvalKey.mk name index rowOffset]?

/-- Get column evaluation at current row (offset=0).
    Mirrors VerifierConstraintContext.col() in constraints/base.py:207-209. -/
def VerifierData.col (vd : VerifierData) (name : String) (index : Nat := 0) : Option GF3 :=
  vd.getEvalByName name index 0

/-- Get column evaluation at next row (offset=1).
    Mirrors VerifierConstraintContext.next_col() in constraints/base.py:211-213. -/
def VerifierData.nextCol (vd : VerifierData) (name : String) (index : Nat := 0) : Option GF3 :=
  vd.getEvalByName name index 1

/-- Get column evaluation at previous row (offset=-1).
    Mirrors VerifierConstraintContext.prev_col() in constraints/base.py:215-217. -/
def VerifierData.prevCol (vd : VerifierData) (name : String) (index : Nat := 0) : Option GF3 :=
  vd.getEvalByName name index (-1)

/-- Get constant polynomial evaluation (index=0, offset=0).
    Mirrors VerifierConstraintContext.const() in constraints/base.py:219-221. -/
def VerifierData.getConst (vd : VerifierData) (name : String) : Option GF3 :=
  vd.getEvalByName name 0 0

/-- Get constant polynomial evaluation at next row (index=0, offset=1).
    Mirrors VerifierConstraintContext.next_const() in constraints/base.py:223-225. -/
def VerifierData.nextConst (vd : VerifierData) (name : String) : Option GF3 :=
  vd.getEvalByName name 0 1

/-- Get constant polynomial evaluation at previous row (index=0, offset=-1).
    Mirrors VerifierConstraintContext.prev_const() in constraints/base.py:227-229. -/
def VerifierData.prevConst (vd : VerifierData) (name : String) : Option GF3 :=
  vd.getEvalByName name 0 (-1)

/-- Look up a Fiat-Shamir challenge by name.
    Mirrors VerifierConstraintContext.challenge() in constraints/base.py:231-232. -/
def VerifierData.challenge (vd : VerifierData) (name : String) : Option GF3 :=
  vd.challenges[name]?

/-- Look up an airgroup value by index, returning zero if missing.
    Mirrors VerifierConstraintContext.airgroup_value() in constraints/base.py:234-235. -/
def VerifierData.airgroupValue (vd : VerifierData) (index : Nat) : GF3 :=
  vd.airgroupValues[index]?.getD GF3.zero

-- ============================================================================
-- VerifierData mutators
-- ============================================================================

/-- Insert a polynomial evaluation. -/
def VerifierData.insertEval (vd : VerifierData) (key : EvalKey) (val : GF3) : VerifierData :=
  { vd with evals := vd.evals.insert key val }

/-- Insert a challenge. -/
def VerifierData.insertChallenge (vd : VerifierData) (name : String) (val : GF3) : VerifierData :=
  { vd with challenges := vd.challenges.insert name val }

/-- Insert a public input. -/
def VerifierData.insertPublicInput (vd : VerifierData)
    (name : String) (val : GF) : VerifierData :=
  { vd with publicInputs := vd.publicInputs.insert name val }

/-- Insert an airgroup value. -/
def VerifierData.insertAirgroupValue (vd : VerifierData)
    (index : Nat) (val : GF3) : VerifierData :=
  { vd with airgroupValues := vd.airgroupValues.insert index val }

end Protocol.Data
