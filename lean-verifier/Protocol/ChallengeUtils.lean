/-
  VADCOP global challenge derivation.

  Translates: executable-spec/protocol/utils/challenge_utils.py

  The global_challenge is derived from publics and proof values using Fiat-Shamir,
  matching the C++ implementation in proofman/src/challenge_accumulation.rs

  The computation has three steps:
  1. Hash [verkey, root1, air_values] through transcript to get 16-element state
  2. Expand to latticeSize elements via Poseidon2 hash chain
  3. Hash [publics, proof_values_stage1, accumulated_contribution] to get challenge
-/
import Primitives.Transcript
import Primitives.Field
import FFI.Poseidon2

namespace Protocol.ChallengeUtils

open Primitives.Transcript
open Primitives.Field
open FFI.Poseidon2

-- ============================================================================
-- Internal contribution computation
-- ============================================================================

/-- Compute internal contribution by hashing verkey + root1 + air_values,
    then expanding to latticeSize via Poseidon2 hash chain.

    Translates: challenge_utils.py:26-96 calculate_internal_contribution

    The algorithm:
    1. Hash [verkey, root1, air_values] through transcript
    2. Get 16-element state
    3. Expand to lattice_size via Poseidon2 hash chain:
       values[0..16] = state[0..16]
       for j in 0..n_hashes:
         values[(j+1)*16..(j+2)*16] = poseidon2_hash(values[j*16..(j+1)*16]) -/
def calculateInternalContribution
    (transcriptArity : Nat)
    (verkey : Array UInt64)
    (root1 : Array UInt64)
    (airValues : Array UInt64 := #[])
    (latticeSize : Nat := 368) : Array UInt64 :=
  -- Build values to hash: [verkey, root1, air_values]
  let valuesToHash := verkey ++ root1 ++ airValues

  -- Hash through a fresh Poseidon2 transcript
  let hashTranscript := (Transcript.new transcriptArity).put valuesToHash

  -- Get transcript state (16 elements)
  let (initialState, _) := hashTranscript.getState (some 16)

  -- Expand to latticeSize via Poseidon2 hash chain
  Id.run do
    let mut valuesRow : Array UInt64 := Array.replicate latticeSize 0

    -- Copy initial 16 elements
    for i in [:16] do
      if i < initialState.size then
        valuesRow := valuesRow.set! i initialState[i]!

    -- Chain hash to expand
    let nHashes := latticeSize / 16 - 1
    for j in [:nHashes] do
      -- Take input from current block
      let mut inputBlock : Array UInt64 := Array.mkEmpty 16
      for k in [:16] do
        inputBlock := inputBlock.push valuesRow[j * 16 + k]!

      -- Hash and put into next block
      let outputBlock := poseidon2Hash inputBlock 16
      for k in [:16] do
        valuesRow := valuesRow.set! ((j + 1) * 16 + k) outputBlock[k]!

    valuesRow

-- ============================================================================
-- Contribution accumulation
-- ============================================================================

/-- Element-wise sum of per-AIR contribution vectors (mod Goldilocks prime).

    Translates: challenge_utils.py:166-185 accumulate_contributions -/
def accumulateContributions
    (contributions : Array (Array UInt64))
    (latticeSize : Nat := 368) : Array UInt64 :=
  Id.run do
    let mut accumulated : Array UInt64 := Array.replicate latticeSize 0
    for contribution in contributions do
      for i in [:latticeSize] do
        if i < contribution.size then
          -- Modular addition: (a + b) mod p
          let a := accumulated[i]!
          let b := contribution[i]!
          let sum := gf_add (GF.mk a) (GF.mk b)
          accumulated := accumulated.set! i sum.val
    accumulated

-- ============================================================================
-- Global challenge derivation (multi-AIR)
-- ============================================================================

/-- Derive global_challenge from multiple AIR contributions.

    Translates: challenge_utils.py:188-228 derive_global_challenge_multi_air

    Algorithm:
    1. Accumulate per-AIR contributions via element-wise addition
    2. Hash [publics, proof_values_stage1, accumulated] via transcript
    3. Extract 3-element cubic extension challenge -/
def deriveGlobalChallengeMultiAir
    (publics : Array UInt64)
    (nPublics : Nat)
    (proofValuesStage1 : Array UInt64)
    (contributions : Array (Array UInt64))
    (transcriptArity : Nat := 4)
    (latticeSize : Nat := 368) : Array UInt64 :=
  let accumulated := accumulateContributions contributions latticeSize
  Id.run do
    let mut transcript := Transcript.new transcriptArity

    -- Phase 1: Hash public inputs
    if nPublics > 0 then
      transcript := transcript.put (publics[:nPublics].toArray)

    -- Phase 2: Hash Stage 1 proof values (if any)
    if proofValuesStage1.size > 0 then
      transcript := transcript.put proofValuesStage1

    -- Phase 3: Hash the full accumulated contribution
    transcript := transcript.put accumulated

    -- Phase 4: Extract 3 field elements
    let (challenge, _) := transcript.getField
    challenge

end Protocol.ChallengeUtils
