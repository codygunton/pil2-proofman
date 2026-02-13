/-
  Fiat-Shamir transcript using Poseidon2 sponge.

  Translates: executable-spec/primitives/transcript.py

  The transcript is a Poseidon2-based sponge with configurable arity (2, 3, or 4).
  Arity determines the sponge width: width = HASH_SIZE * arity.
  The rate is width - HASH_SIZE (= HASH_SIZE * (arity - 1)).

  Key design: purely functional -- every operation returns a new Transcript.
-/
import FFI.Poseidon2
import Primitives.Field

open FFI.Poseidon2
open Primitives.Field

namespace Primitives.Transcript

-- ============================================================================
-- Constants
-- ============================================================================

/-- Hash output size (= capacity): 4 Goldilocks field elements. -/
def HASH_SIZE : Nat := 4

-- ============================================================================
-- Transcript structure
-- ============================================================================

/-- Fiat-Shamir transcript using Poseidon2 sponge construction.

    Fields:
    - `arity`: sponge arity (2, 3, or 4)
    - `spongeWidth`: total sponge width = HASH_SIZE * arity
    - `stateSize`: capacity portion = HASH_SIZE
    - `pendingSize`: rate portion = HASH_SIZE * (arity - 1)
    - `outSize`: output buffer size = spongeWidth
    - `state`: sponge state (outSize elements, only first stateSize used for chaining)
    - `pending`: absorption buffer (outSize elements, only first pendingSize used)
    - `out`: squeeze output buffer (outSize elements)
    - `pendingCursor`: next write position in pending
    - `outCursor`: remaining readable elements in out (counts down from outSize)

    Translates: `Transcript.__init__` in transcript.py (lines 30-45). -/
structure Transcript where
  arity       : Nat
  spongeWidth : Nat
  stateSize   : Nat
  pendingSize : Nat
  outSize     : Nat
  state       : Array UInt64
  pending     : Array UInt64
  out         : Array UInt64
  pendingCursor : Nat
  outCursor     : Nat
  deriving Repr

-- ============================================================================
-- Constructor
-- ============================================================================

/-- Create a new transcript with the given arity.

    Arity must be 2, 3, or 4:
    - arity=2: width=8,  rate=4
    - arity=3: width=12, rate=8
    - arity=4: width=16, rate=12

    Translates: `Transcript.__init__` in transcript.py (lines 30-45). -/
def Transcript.new (arity : Nat := 4) : Transcript :=
  let spongeWidth := HASH_SIZE * arity
  let stateSize := HASH_SIZE
  let pendingSize := HASH_SIZE * (arity - 1)
  let outSize := spongeWidth
  { arity       := arity
    spongeWidth := spongeWidth
    stateSize   := stateSize
    pendingSize := pendingSize
    outSize     := outSize
    state       := Array.replicate outSize 0
    pending     := Array.replicate outSize 0
    out         := Array.replicate outSize 0
    pendingCursor := 0
    outCursor     := 0 }

-- ============================================================================
-- Internal operations
-- ============================================================================

/-- Apply Poseidon2 permutation to the transcript.

    1. Zero-pads pending buffer up to pendingSize.
    2. Constructs permutation input: pending[0..pendingSize] ++ state[0..HASH_SIZE].
    3. Applies Poseidon2 permutation.
    4. Stores result in out, copies to state, resets cursors.

    Translates: `Transcript._apply_permutation` in transcript.py (lines 113-130). -/
def Transcript.applyPermutation (t : Transcript) : Transcript :=
  -- Zero-pad pending up to pendingSize
  let pending := Id.run do
    let mut p := t.pending
    for i in [t.pendingCursor:t.pendingSize] do
      p := p.set! i 0
    p

  -- Construct permutation input: pending[0..pendingSize] ++ state[0..HASH_SIZE]
  let permInput := Id.run do
    let mut inp := Array.replicate t.spongeWidth 0
    for i in [:t.pendingSize] do
      inp := inp.set! i (pending[i]!)
    for i in [:HASH_SIZE] do
      inp := inp.set! (t.pendingSize + i) (t.state[i]!)
    inp

  -- Apply Poseidon2 permutation via FFI
  let result := poseidon2Hash permInput t.spongeWidth.toUInt64

  { t with
    out           := result
    outCursor     := t.outSize
    pending       := Array.replicate t.outSize 0
    pendingCursor := 0
    state         := result }

/-- Absorb a single field element into the sponge.

    Stores `element mod p` into the pending buffer. Resets outCursor to 0
    (invalidating any pending squeeze). Triggers permutation when pending is full.

    Translates: `Transcript._absorb_one` in transcript.py (lines 92-99). -/
def Transcript.absorbOne (t : Transcript) (element : UInt64) : Transcript :=
  let reduced := element % GOLDILOCKS_PRIME
  let t := { t with
    pending       := t.pending.set! t.pendingCursor reduced
    pendingCursor := t.pendingCursor + 1
    outCursor     := 0 }
  if t.pendingCursor == t.pendingSize then
    t.applyPermutation
  else
    t

/-- Squeeze one field element from the sponge.

    If outCursor is 0, applies permutation first to generate fresh output.
    Reads from the output buffer in reverse order (C++ compatibility):
      idx = (outSize - outCursor) % outSize
    Then decrements outCursor.

    Returns (element, updated transcript).

    Translates: `Transcript._squeeze_one` in transcript.py (lines 101-111). -/
def Transcript.squeezeOne (t : Transcript) : UInt64 × Transcript :=
  let t := if t.outCursor == 0 then t.applyPermutation else t
  -- Read in reverse order (C++ compatibility)
  let idx := (t.outSize - t.outCursor) % t.outSize
  let result := t.out[idx]!
  let t := { t with outCursor := t.outCursor - 1 }
  (result, t)

-- ============================================================================
-- Public API
-- ============================================================================

/-- Absorb field elements into the sponge.

    Translates: `Transcript.put` in transcript.py (lines 49-52). -/
def Transcript.put (t : Transcript) (elements : Array UInt64) : Transcript :=
  Id.run do
    let mut t := t
    for elem in elements do
      t := t.absorbOne elem
    t

/-- Squeeze 3 field elements as a cubic extension field challenge.

    Returns an array of 3 field elements [c0, c1, c2] representing a GF3 challenge.

    Translates: `Transcript.get_field` in transcript.py (lines 54-56). -/
def Transcript.getField (t : Transcript) : Array UInt64 × Transcript :=
  let (v0, t) := t.squeezeOne
  let (v1, t) := t.squeezeOne
  let (v2, t) := t.squeezeOne
  (#[v0, v1, v2], t)

/-- Get current sponge state (for grinding challenge).

    Flushes any pending absorption first. Returns first `nOutputs` elements
    of the state (defaults to stateSize = HASH_SIZE = 4).

    Translates: `Transcript.get_state` in transcript.py (lines 58-66). -/
def Transcript.getState (t : Transcript) (nOutputs : Option Nat := none) :
    Array UInt64 × Transcript :=
  let t := if t.pendingCursor > 0 then t.applyPermutation else t
  let n := nOutputs.getD t.stateSize
  let result := t.state[:n].toArray
  (result, t)

/-- Generate n pseudorandom indices, each using nBits bits.

    Squeezes enough field elements to extract n*nBits bits total,
    then bit-packs them into indices. Uses 63 bits per field element
    (Goldilocks elements are < 2^64, but only 63 bits are usable
    for uniform bit extraction).

    Translates: `Transcript.get_permutations` in transcript.py (lines 68-88). -/
def Transcript.getPermutations (t : Transcript) (n : Nat) (nBits : Nat) :
    Array Nat × Transcript :=
  -- Calculate number of field elements needed: ceil(n * nBits / 63)
  let nFields := ((n * nBits - 1) / 63) + 1

  -- Squeeze nFields elements
  let (fields, t) := Id.run do
    let mut t := t
    let mut fields : Array UInt64 := #[]
    for _ in [:nFields] do
      let (v, t') := t.squeezeOne
      fields := fields.push v
      t := t'
    (fields, t)

  -- Extract bit-packed indices
  let result := Id.run do
    let mut result : Array Nat := #[]
    let mut curBit : Nat := 0
    let mut curField : Nat := 0
    for _ in [:n] do
      let mut index : Nat := 0
      for j in [:nBits] do
        let bit := ((fields[curField]!).toNat >>> curBit) &&& 1
        index := index ||| (bit <<< j)
        curBit := curBit + 1
        if curBit == 63 then
          curBit := 0
          curField := curField + 1
      result := result.push index
    result

  (result, t)

/-- Restore transcript state from captured values.

    Used to replay Fiat-Shamir transcript from a known state.

    Translates: `Transcript.set_state` in transcript.py (lines 132-154). -/
def Transcript.setState (t : Transcript)
    (state : Array UInt64) (out : Array UInt64)
    (outCursor : Nat) (pendingCursor : Nat)
    (pending : Option (Array UInt64) := none) : Transcript :=
  { t with
    state         := state
    out           := out
    outCursor     := outCursor
    pendingCursor := pendingCursor
    pending       := pending.getD (Array.replicate t.outSize 0) }

end Primitives.Transcript
