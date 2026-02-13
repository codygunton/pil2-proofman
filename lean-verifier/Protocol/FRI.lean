/-
  FRI (Fast Reed-Solomon IOP of Proximity) verification.

  Translates: executable-spec/protocol/fri.py

  FRI protocol overview:
  - Multiple folding steps, each reducing the polynomial domain by a power of 2
  - At each step, the verifier recomputes the folded value from sibling evaluations
    and a random challenge, then checks it against the prover's committed value
  - After all steps, the final polynomial must have degree below the claimed bound

  Key functions:
  - `verify_fold`: Core FRI folding verification (recompute folded value from siblings)
  - `verify_fri_folding`: Verify one FRI folding step across all queries
  - `verify_final_polynomial`: Check the degree bound of the final FRI polynomial
-/
import Primitives.Field
import Primitives.Polynomial
import Protocol.StarkInfo
import Protocol.Proof

open Primitives.Field
open Primitives.Polynomial
open Protocol.StarkInfo (StarkStruct StarkInfo FriFoldStep FIELD_EXTENSION_DEGREE)
open Protocol.Proof (STARKProof FriProof ProofTree MerkleProof FF3Val)

namespace Protocol.FRI

-- ============================================================================
-- Helpers
-- ============================================================================

/-- Compute w_inv^(-idx) which equals w^idx.

    In Python: `w_inv ** (-idx)` where w_inv is the inverse root of unity.
    - For idx == 0: returns 1 (any element to the zero power)
    - For idx > 0: w_inv^(-idx) = (w_inv^(-1))^idx = w^idx

    Since we have w_inv but need w^idx, we compute:
      w^idx = get_omega(prev_bits)^idx

    Translates: fri.py:112 `w_inv ** (-idx)` -/
def compute_w_pow_idx (prev_bits : Nat) (idx : Nat) : GF :=
  let w := get_omega prev_bits
  gf_pow w idx

/-- Compute SHIFT^(2^k) where k depends on accumulated folding rounds.

    In the FRI protocol, the coset shift evolves across rounds:
    - Round 0: no shift (k = 0, SHIFT^1 = SHIFT)
    - Round i > 0: SHIFT^(2^(n_bits_ext - prev_bits))

    Translates: fri.py:100-101 `shift_pow = SHIFT ** (1 << k)` -/
def compute_shift_pow (fri_round : Nat) (n_bits_ext prev_bits : Nat) : GF :=
  let k := if fri_round > 0 then n_bits_ext - prev_bits else 0
  gf_pow SHIFT (1 <<< k)

/-- Compute SHIFT_INV^(2^k) where k depends on accumulated folding rounds.

    Inverse coset shift for the prover-side folding.

    Translates: fri.py:37-38 `shift_inv_pow = SHIFT_INV ** (1 << k)` -/
def compute_shift_inv_pow (fri_round : Nat) (n_bits_ext prev_bits : Nat) : GF :=
  let k := if fri_round > 0 then n_bits_ext - prev_bits else 0
  gf_pow SHIFT_INV (1 <<< k)

-- ============================================================================
-- Core: verify_fold
-- ============================================================================

/-- Verify a single FRI fold step by recomputing the expected folded value.

    Given sibling polynomial evaluations at a query position and a FRI challenge,
    reconstruct the folded value by interpolation then evaluation at the challenge.

    Algorithm:
    1. Convert siblings to GF3 elements (interleaved format: each sibling = [c0, c1, c2])
    2. If fold_factor > 1, convert from evaluation form to coefficient form (INTT)
    3. Compute the evaluation point from the challenge and coset parameters
    4. Evaluate the interpolated polynomial at the evaluation point (Horner)

    Args:
    - fri_round: Current FRI round index (0-based, but verify_fold is only called for rounds >= 1)
    - n_bits_ext: Log2 of extended domain size
    - current_bits: Log2 of current domain size (after folding)
    - prev_bits: Log2 of previous domain size (before folding)
    - challenge: FRI folding challenge as [c0, c1, c2] interleaved UInt64
    - idx: Query index in the current domain
    - siblings: Array of sibling evaluations, each as [c0, c1, c2]

    Returns: Recomputed folded GF3 value.

    Translates: fri.py:86-114 FRI.verify_fold -/
def verify_fold
    (fri_round : Nat)
    (n_bits_ext : Nat)
    (current_bits : Nat)
    (prev_bits : Nat)
    (challenge : Array UInt64)
    (idx : Nat)
    (siblings : Array (Array UInt64)) : GF3 :=
  -- Convert challenge to GF3 (interleaved [c0, c1, c2])
  let challenge_gf3 := GF3.mk
    (GF.mk (challenge[0]!))
    (GF.mk (challenge[1]!))
    (GF.mk (challenge[2]!))

  -- Coset shift for verification (forward direction)
  let shift_pow := compute_shift_pow fri_round n_bits_ext prev_bits

  let fold_factor := 1 <<< (prev_bits - current_bits)

  -- Convert siblings to GF3 coefficients
  -- Each sibling is [c0, c1, c2] in interleaved format
  let coeffs_raw : Array GF3 := Id.run do
    let mut result : Array GF3 := Array.mkEmpty siblings.size
    for s in siblings do
      result := result.push (GF3.mk (GF.mk s[0]!) (GF.mk s[1]!) (GF.mk s[2]!))
    result

  -- Convert evaluations to coefficients via INTT if fold_factor > 1
  let coeffs := if fold_factor > 1 then
    let n_bits := log2 fold_factor
    to_coefficients_cubic coeffs_raw n_bits
  else
    coeffs_raw

  if coeffs.size == 0 then GF3.zero
  else
    -- Compute evaluation point: challenge * (shift_pow * w_inv^(-idx))^(-1)
    -- Python: eval_point = challenge_ff3 * int((shift_pow * (w_inv ** (-idx))) ** -1)
    -- w_inv^(-idx) = w^idx, so: (shift_pow * w^idx)^(-1)
    let w_to_idx := compute_w_pow_idx prev_bits idx
    let denominator := gf_mul shift_pow w_to_idx
    let inv_denominator := gf_inv denominator
    -- Embed the base field inverse into GF3 and multiply by challenge
    let inv_gf3 := GF3.mk inv_denominator GF.zero GF.zero
    let eval_point := gf3_mul challenge_gf3 inv_gf3

    -- Evaluate polynomial at eval_point using Horner's method
    evaluate_poly_at coeffs eval_point

-- ============================================================================
-- Prover-side fold (for completeness / potential testing)
-- ============================================================================

/-- Fold a polynomial by factor 2^(prev_bits - current_bits) using a challenge.

    This is the prover-side folding operation. For each output group:
    1. Gather fold_factor evaluations
    2. Convert to coefficients (INTT)
    3. Scale by coset adjustment factors
    4. Evaluate at challenge point (Horner)

    Translates: fri.py:25-65 FRI.fold -/
def fold
    (fri_round : Nat)
    (pol : Array GF3)
    (challenge : Array UInt64)
    (n_bits_ext : Nat)
    (prev_bits : Nat)
    (current_bits : Nat) : Array GF3 :=
  let challenge_gf3 := GF3.mk
    (GF.mk (challenge[0]!))
    (GF.mk (challenge[1]!))
    (GF.mk (challenge[2]!))

  -- Coset shift: SHIFT_INV^(2^k)
  let shift_inv_pow := compute_shift_inv_pow fri_round n_bits_ext prev_bits

  let n_out := 1 <<< current_bits  -- Output size
  let fold_factor := (1 <<< prev_bits) / n_out  -- Points per group
  let w_inv := get_omega_inv prev_bits

  Id.run do
    let mut result : Array GF3 := Array.mkEmpty n_out
    for g in [:n_out] do
      -- Gather fold_factor evaluations for this group
      let mut evals : Array GF3 := Array.mkEmpty fold_factor
      for i in [:fold_factor] do
        let pol_idx := g + i * n_out
        if pol_idx < pol.size then
          evals := evals.push pol[pol_idx]!
        else
          evals := evals.push GF3.zero

      -- Convert evaluations to coefficients (interpolation)
      if fold_factor > 1 then
        let n_bits := log2 fold_factor
        evals := to_coefficients_cubic evals n_bits

      -- Scale coefficients by (shift_inv * w_inv^g)^i
      let scale := gf_mul shift_inv_pow (gf_pow w_inv g)
      let mut acc := GF.one
      for i in [:fold_factor] do
        if i < evals.size then
          evals := evals.set! i (gf3_mul_base evals[i]! acc)
        acc := gf_mul acc scale

      -- Evaluate at challenge point (Horner)
      let folded := evaluate_poly_at evals challenge_gf3
      result := result.push folded
    result

-- ============================================================================
-- FRI Folding Verification (query-level)
-- ============================================================================

/-- Extract the FRI challenge for a given step from the interleaved challenges buffer.

    The challenges buffer contains all Fiat-Shamir challenges in interleaved format.
    FRI step challenges start after the constraint challenges.

    Args:
    - challenges: Flat interleaved challenges buffer (3 UInt64s per challenge)
    - n_challenges_map: Number of constraint challenges (from stark_info.challenges_map)
    - step: FRI step index

    Returns: Challenge as [c0, c1, c2] array.

    Translates: verifier.py:933-934 -/
def get_fri_challenge (challenges : Array UInt64) (n_challenges_map : Nat) (step : Nat) : Array UInt64 :=
  let idx := n_challenges_map + step
  let base := idx * 3
  #[challenges[base]!, challenges[base + 1]!, challenges[base + 2]!]

/-- Gather sibling evaluations from FRI tree query proof.

    Extracts fold_factor sibling GF3 values from the proof query values.
    Each sibling occupies FIELD_EXTENSION_DEGREE (3) consecutive entries.

    Translates: verifier.py:926-931 -/
def gather_siblings (fri_vals : Array (Array UInt64)) (n_x : Nat) : Array (Array UInt64) :=
  Id.run do
    let mut siblings : Array (Array UInt64) := Array.mkEmpty n_x
    for i in [:n_x] do
      let mut sibling : Array UInt64 := Array.mkEmpty 3
      for j in [:3] do
        let val_idx := i * 3 + j
        if val_idx < fri_vals.size then
          sibling := sibling.push fri_vals[val_idx]![0]!
        else
          sibling := sibling.push 0
      siblings := siblings.push sibling
    siblings

/-- Verify one FRI folding step across all query points.

    For each query:
    1. Gather sibling evaluations from the proof
    2. Recompute the folded value using verify_fold
    3. Check it matches the claimed value in the next FRI layer (or final polynomial)

    Args:
    - proof: The STARK proof
    - stark_info: STARK configuration
    - challenges: Interleaved challenges buffer
    - step: FRI step index (1-based; step 0 is the initial polynomial)
    - fri_queries: Array of query indices

    Returns: true if all queries are consistent.

    Translates: verifier.py:905-961 _verify_fri_folding -/
def verify_fri_folding
    (proof : STARKProof)
    (stark_info : StarkInfo)
    (challenges : Array UInt64)
    (step : Nat)
    (fri_queries : Array Nat) : Bool :=
  let stark_struct := stark_info.starkStruct
  let n_queries := stark_struct.nQueries
  let n_steps := stark_struct.friFoldSteps.size

  Id.run do
    let mut is_valid := true
    for query_idx in [:n_queries] do
      if is_valid then
        let raw_idx := fri_queries[query_idx]!
        let idx := raw_idx % (1 <<< stark_struct.friFoldSteps[step]!.domainBits)

        -- Number of siblings (fold factor for this step)
        let n_x := 1 <<< (stark_struct.friFoldSteps[step - 1]!.domainBits -
                           stark_struct.friFoldSteps[step]!.domainBits)

        -- Gather siblings from proof
        let fri_vals := proof.fri.treesFri[step - 1]!.polQueries[query_idx]![0]!.v
        let siblings := gather_siblings fri_vals n_x

        -- Get FRI challenge for this step
        let challenge := get_fri_challenge challenges stark_info.challengesMap.size step

        -- Recompute folded value
        let computed := verify_fold
          step
          stark_struct.nBitsExt
          stark_struct.friFoldSteps[step]!.domainBits
          stark_struct.friFoldSteps[step - 1]!.domainBits
          challenge
          idx
          siblings

        -- Get expected value from next layer or final polynomial
        let expected_c0 : UInt64 :=
          if step < n_steps - 1 then
            let next_bits := stark_struct.friFoldSteps[step + 1]!.domainBits
            let sibling_pos := idx >>> next_bits
            let next_fri_vals := proof.fri.treesFri[step]!.polQueries[query_idx]![0]!.v
            next_fri_vals[sibling_pos * 3]![0]!
          else
            proof.fri.pol[idx]![0]!

        let expected_c1 : UInt64 :=
          if step < n_steps - 1 then
            let next_bits := stark_struct.friFoldSteps[step + 1]!.domainBits
            let sibling_pos := idx >>> next_bits
            let next_fri_vals := proof.fri.treesFri[step]!.polQueries[query_idx]![0]!.v
            next_fri_vals[sibling_pos * 3 + 1]![0]!
          else
            proof.fri.pol[idx]![1]!

        let expected_c2 : UInt64 :=
          if step < n_steps - 1 then
            let next_bits := stark_struct.friFoldSteps[step + 1]!.domainBits
            let sibling_pos := idx >>> next_bits
            let next_fri_vals := proof.fri.treesFri[step]!.polQueries[query_idx]![0]!.v
            next_fri_vals[sibling_pos * 3 + 2]![0]!
          else
            proof.fri.pol[idx]![2]!

        let expected := GF3.mk (GF.mk expected_c0) (GF.mk expected_c1) (GF.mk expected_c2)

        if computed != expected then
          is_valid := false

    is_valid

-- ============================================================================
-- Final Polynomial Verification
-- ============================================================================

/-- Verify that the final FRI polynomial has the correct degree bound.

    The final polynomial must have degree less than the claimed bound. We check
    this by converting to coefficient form (via INTT) and verifying that all
    coefficients above the degree bound are zero.

    The degree bound is determined by:
    - last_step: domain_bits of the last FRI fold step
    - blowup_factor: n_bits_ext - n_bits (the LDE blowup)
    - If blowup_factor > last_step: all coefficients must be zero from index 0
    - Otherwise: coefficients from index 2^(last_step - blowup_factor) onward must be zero

    Translates: verifier.py:964-994 _verify_final_polynomial -/
def verify_final_polynomial (final_pol : Array FF3Val) (stark_struct : StarkStruct) : Bool :=
  let final_pol_size := final_pol.size
  if final_pol_size == 0 then true
  else
    -- Convert final polynomial from interleaved FF3Val format to Array GF3
    let final_pol_gf3 : Array GF3 := Id.run do
      let mut arr : Array GF3 := Array.mkEmpty final_pol_size
      for entry in final_pol do
        arr := arr.push (GF3.mk (GF.mk entry[0]!) (GF.mk entry[1]!) (GF.mk entry[2]!))
      arr

    -- Convert from evaluation form to coefficient form
    let n_bits := log2 final_pol_size
    let coeffs := to_coefficients_cubic final_pol_gf3 n_bits

    -- Determine degree bound
    let last_step := stark_struct.friFoldSteps[stark_struct.friFoldSteps.size - 1]!.domainBits
    let blowup_factor := stark_struct.nBitsExt - stark_struct.nBits
    let init := if blowup_factor > last_step then 0
                else (1 <<< (last_step - blowup_factor))

    -- Check that high-degree coefficients are zero
    Id.run do
      let mut valid := true
      for i in [init:final_pol_size] do
        if valid then
          let coeff := coeffs[i]!
          if coeff.c0.val != 0 || coeff.c1.val != 0 || coeff.c2.val != 0 then
            valid := false
      valid

-- ============================================================================
-- x_div_x_sub computation (for DEEP-ALI)
-- ============================================================================

/-- Compute 1/(x - xi * omega^opening_point) for the DEEP-ALI quotient.

    For each query point x and each opening point, computes the denominator
    of the DEEP quotient polynomial. Used by the verifier to reconstruct
    committed polynomials from their evaluations.

    Args:
    - xi: Evaluation point challenge as GF3
    - omega_extended: Root of unity for extended domain
    - omega_trace: Root of unity for trace domain
    - opening_points: Array of opening point offsets (may be negative)
    - fri_queries: Query indices
    - n_queries: Number of queries

    Returns: Flat interleaved array of 1/(x - xi*w^op) values,
             indexed as [query_idx * n_opening_points + opening_idx] * 3 + component.

    Translates: verifier.py:634-675 _compute_x_div_x_sub -/
def compute_x_div_x_sub
    (xi : GF3)
    (omega_extended : GF)
    (omega_trace : GF)
    (shift : GF)
    (opening_points : Array Int)
    (fri_queries : Array Nat)
    (n_queries : Nat) : Array UInt64 :=
  let n_opening_points := opening_points.size
  Id.run do
    let mut result : Array UInt64 := Array.replicate (n_queries * n_opening_points * 3) 0
    for query_idx in [:n_queries] do
      let query_position := fri_queries[query_idx]!
      -- x = shift * omega_extended^query_position
      let x_base := gf_mul shift (gf_pow omega_extended query_position)
      let x := GF3.mk x_base GF.zero GF.zero

      for opening_idx in [:n_opening_points] do
        let opening_point := opening_points[opening_idx]!

        -- Compute omega_trace^|opening_point|, invert if negative
        let abs_op := opening_point.natAbs
        let omega_power_raw := gf_pow omega_trace abs_op
        let omega_power := if opening_point < 0
          then gf_inv omega_power_raw
          else omega_power_raw

        -- shifted_challenge = xi * omega^opening_point (embed base to GF3)
        let shifted_challenge := gf3_mul_base xi omega_power

        -- inv_difference = 1/(x - shifted_challenge)
        let diff := gf3_sub x shifted_challenge
        let inv_difference := gf3_inv diff

        -- Store in result buffer
        let buffer_idx := (query_idx * n_opening_points + opening_idx) * 3
        result := result.set! buffer_idx inv_difference.c0.val
        result := result.set! (buffer_idx + 1) inv_difference.c1.val
        result := result.set! (buffer_idx + 2) inv_difference.c2.val

    result

-- ============================================================================
-- xi^N computation
-- ============================================================================

/-- Compute xi^N where N is the trace size, using repeated squaring.

    Needed for reconstructing the quotient polynomial Q(xi) from split pieces
    and for computing the vanishing polynomial Z_H(xi) = xi^N - 1.

    Translates: verifier.py:678-683 _compute_xi_to_trace_size -/
def compute_xi_to_trace_size (xi : GF3) (trace_size : Nat) : GF3 :=
  gf3_pow xi trace_size

end Protocol.FRI
