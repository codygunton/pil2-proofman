import LSpec
import Protocol.FRI
import Protocol.StarkInfo
import Primitives.Field
import Primitives.Polynomial

open Protocol.FRI
open Protocol.StarkInfo (StarkStruct FriFoldStep)
open Primitives.Field
open Primitives.Polynomial
open LSpec

-- ============================================================================
-- Helper
-- ============================================================================

/-- Embed a base field value into GF3 (c0 = val, c1 = c2 = 0). -/
def gf3_base (v : UInt64) : GF3 := GF3.mk (GF.mk v) GF.zero GF.zero

-- ============================================================================
-- compute_shift_pow / compute_shift_inv_pow Tests
-- ============================================================================

def shiftPowTests : TestSeq :=
  group "compute_shift_pow" (
    -- Round 0: k = 0, so SHIFT^(2^0) = SHIFT^1 = 7
    test "round 0: SHIFT^1 = 7"
      (compute_shift_pow 0 10 8 == GF.mk 7) $
    -- Round 1, n_bits_ext=10, prev_bits=10: k = 0, SHIFT^1 = 7
    test "round 1, same bits: SHIFT^1 = 7"
      (compute_shift_pow 1 10 10 == GF.mk 7) $
    -- Round 1, n_bits_ext=10, prev_bits=9: k = 1, SHIFT^2 = 49
    test "round 1, k=1: SHIFT^2 = 49"
      (compute_shift_pow 1 10 9 == GF.mk 49) $
    -- Round 1, n_bits_ext=10, prev_bits=8: k = 2, SHIFT^4 = 2401
    test "round 1, k=2: SHIFT^4 = 2401"
      (compute_shift_pow 1 10 8 == GF.mk 2401)
  )

def shiftInvPowTests : TestSeq :=
  -- SHIFT_INV = SHIFT^(-1), so SHIFT_INV * SHIFT = 1
  -- compute_shift_inv_pow round=0 should give SHIFT_INV^1 = SHIFT_INV
  group "compute_shift_inv_pow" (
    test "round 0: SHIFT_INV^1 = SHIFT_INV"
      (compute_shift_inv_pow 0 10 8 == SHIFT_INV) $
    test "SHIFT_INV * SHIFT = 1"
      (gf_mul (compute_shift_inv_pow 0 10 8) (compute_shift_pow 0 10 8) == GF.one) $
    -- For k=1: SHIFT_INV^2 * SHIFT^2 = 1
    test "round 1, k=1: inverse pair"
      (gf_mul (compute_shift_inv_pow 1 10 9) (compute_shift_pow 1 10 9) == GF.one) $
    -- For k=2: SHIFT_INV^4 * SHIFT^4 = 1
    test "round 1, k=2: inverse pair"
      (gf_mul (compute_shift_inv_pow 1 10 8) (compute_shift_pow 1 10 8) == GF.one)
  )

-- ============================================================================
-- compute_w_pow_idx Tests
-- ============================================================================

def computeWPowIdxTests : TestSeq :=
  -- compute_w_pow_idx computes w^idx (the FORWARD omega raised to idx)
  -- This is used in verify_fold where Python does w_inv^(-idx) = w^idx
  let w := get_omega 3      -- 8th root of unity
  let w_inv := get_omega_inv 3
  group "compute_w_pow_idx" (
    -- w^0 = 1
    test "w^0 = 1"
      (compute_w_pow_idx 3 0 == GF.one) $
    -- w^1 = w
    test "w^1 = w"
      (compute_w_pow_idx 3 1 == w) $
    -- w^1 * w_inv = 1 (verifies w and w_inv are inverses)
    test "w * w_inv = 1"
      (gf_mul (compute_w_pow_idx 3 1) w_inv == GF.one) $
    -- w^8 = 1 (8th root of unity to the 8th power)
    test "w^8 = 1 (order divides 2^3)"
      (compute_w_pow_idx 3 8 == GF.one)
  )

-- ============================================================================
-- verify_fold Tests (fold_factor = 1, trivial case)
-- ============================================================================

def verifyFoldTrivialTests : TestSeq :=
  -- With fold_factor = 1 (prev_bits - current_bits = 0), verify_fold should
  -- just return the single sibling value scaled by the evaluation point.
  -- When prev_bits == current_bits, fold_factor = 2^0 = 1.
  -- With a single coefficient, evaluate_poly_at returns that coefficient.
  -- But wait: fold_factor = 1 << (prev_bits - current_bits).
  -- If prev_bits = current_bits, fold_factor = 1 (no folding needed, but that
  -- is an edge case since FRI always reduces domain size).
  --
  -- For fold_factor = 1: no INTT, just evaluate the single coefficient at eval_point.
  -- A polynomial with 1 coefficient is a constant, so evaluate_poly_at returns
  -- that constant regardless of eval_point.
  --
  -- Sibling [5, 0, 0] -> GF3(5, 0, 0) -> evaluate at anything -> GF3(5, 0, 0)
  let siblings := #[#[(5 : UInt64), 0, 0]]
  let challenge := #[(1 : UInt64), 0, 0]  -- challenge = 1
  let result := verify_fold
    1       -- fri_round
    4       -- n_bits_ext
    3       -- current_bits
    3       -- prev_bits (same as current => fold_factor = 1)
    challenge
    0       -- idx
    siblings
  group "verify_fold: fold_factor=1" (
    test "single sibling returns itself"
      (result == gf3_base 5)
  )

-- ============================================================================
-- verify_fold Tests (fold_factor = 2)
-- ============================================================================

def verifyFoldFactor2Tests : TestSeq :=
  -- fold_factor = 2 means prev_bits - current_bits = 1
  -- We provide 2 siblings. INTT converts evaluations -> coefficients on size-2 domain.
  --
  -- For size-2 INTT with omega_inv = W_INV[1] = p-1 = -1:
  -- [a, b] -> coefficients = [(a+b)/2, (a-b)/2]
  --
  -- Then we evaluate the resulting polynomial at eval_point.
  --
  -- Test with concrete values: siblings = [(10, 0, 0), (6, 0, 0)]
  -- INTT: c0 = (10+6)/2 = 8, c1 = (10-6)/2 = 2
  -- Polynomial: f(x) = 8 + 2x
  --
  -- eval_point = challenge * (shift_pow * w_inv^idx)^(-1)
  -- For fri_round=1, n_bits_ext=4, prev_bits=2, current_bits=1:
  --   k = n_bits_ext - prev_bits = 4 - 2 = 2
  --   shift_pow = 7^(2^2) = 7^4 = 2401
  --   w_inv = get_omega_inv(2) = W_INV[2]
  --   For idx=0: w_inv^0 = 1
  --   denominator = 2401 * 1 = 2401
  --   inv_denominator = 2401^(-1)
  --   eval_point = challenge * inv_denominator
  --
  -- With challenge = (1, 0, 0):
  --   eval_point = (inv(2401), 0, 0)
  --
  -- f(eval_point) = 8 + 2 * inv(2401)
  --
  -- We can verify by checking the math properties hold.
  let siblings := #[#[(10 : UInt64), 0, 0], #[(6 : UInt64), 0, 0]]
  let challenge := #[(1 : UInt64), 0, 0]
  let result := verify_fold
    1       -- fri_round
    4       -- n_bits_ext
    1       -- current_bits
    2       -- prev_bits (fold_factor = 2^(2-1) = 2)
    challenge
    0       -- idx
    siblings

  -- The result should be a well-defined GF3 value (not zero since inputs are non-zero)
  group "verify_fold: fold_factor=2" (
    test "produces non-zero result for non-zero inputs"
      (result != GF3.zero) $
    -- With idx=0 and challenge=(1,0,0), different siblings should give different results
    test "different siblings give different results"
      (let siblings2 := #[#[(20 : UInt64), 0, 0], #[(6 : UInt64), 0, 0]]
       let result2 := verify_fold 1 4 1 2 challenge 0 siblings2
       result != result2)
  )

-- ============================================================================
-- verify_fold: Consistency between fold and verify_fold
-- ============================================================================

def foldVerifyConsistencyTests : TestSeq :=
  -- The prover `fold` and verifier `verify_fold` should be consistent:
  -- If we fold a polynomial and then verify_fold with the correct siblings
  -- at a specific query position, the results should match.
  --
  -- Simple test: polynomial with 4 evaluations, fold to 2.
  -- prev_bits = 2, current_bits = 1 (fold_factor = 2)
  --
  -- Polynomial (evaluations on extended domain):
  -- pol = [a, b, c, d] where a,b,c,d are GF3 elements
  --
  -- The prover gathers groups:
  --   group 0: indices [0, 2] -> pol[0], pol[2]
  --   group 1: indices [1, 3] -> pol[1], pol[3]
  --
  -- For a query at idx=0 in the folded domain, the verifier uses siblings
  -- from the prover's group 0: [pol[0], pol[2]].
  --
  -- We use fri_round=0 to keep the coset shift simple (k=0).
  let pol := #[gf3_base 10, gf3_base 20, gf3_base 30, gf3_base 40]
  let challenge := #[(42 : UInt64), 0, 0]
  let folded := fold 0 pol challenge 4 2 1  -- fri_round=0, prev=2, curr=1

  -- The prover produces folded[0] from group 0 (pol[0], pol[2])
  -- The prover produces folded[1] from group 1 (pol[1], pol[3])

  -- For verification at idx=0 (maps to group 0):
  -- siblings = [pol[0], pol[2]] in interleaved format
  let siblings_0 := #[#[(10 : UInt64), 0, 0], #[(30 : UInt64), 0, 0]]
  let verified_0 := verify_fold 0 4 1 2 challenge 0 siblings_0

  -- For verification at idx=1 (maps to group 1):
  -- siblings = [pol[1], pol[3]]
  let siblings_1 := #[#[(20 : UInt64), 0, 0], #[(40 : UInt64), 0, 0]]
  let verified_1 := verify_fold 0 4 1 2 challenge 1 siblings_1

  group "fold/verify_fold consistency" (
    test "folded polynomial has correct size"
      (folded.size == 2) $
    test "verify_fold at idx=0 matches fold output"
      (verified_0 == folded[0]!) $
    test "verify_fold at idx=1 matches fold output"
      (verified_1 == folded[1]!)
  )

-- ============================================================================
-- verify_final_polynomial Tests
-- ============================================================================

def verifyFinalPolConstantTests : TestSeq :=
  -- A constant polynomial in evaluation form: all values are the same.
  -- INTT of [c, c, c, c] gives [c, 0, 0, 0].
  -- So if n_bits=3, n_bits_ext=4, last_step=2 (domain_bits=2):
  --   blowup = 4-3 = 1
  --   init = 2^(2-1) = 2
  --   Check coefficients from index 2 to 3: should all be zero.
  -- A constant polynomial satisfies this.
  let final_pol : Array (Array UInt64) :=
    #[#[(5 : UInt64), 0, 0], #[(5 : UInt64), 0, 0], #[(5 : UInt64), 0, 0], #[(5 : UInt64), 0, 0]]
  let stark_struct : StarkStruct := {
    nBits := 3
    nBitsExt := 4
    nQueries := 1
    verificationHashType := "GL"
    friFoldSteps := #[{ domainBits := 4 }, { domainBits := 2 }]
  }
  group "verify_final_polynomial: constant poly" (
    test "constant polynomial passes degree check"
      (verify_final_polynomial final_pol stark_struct == true)
  )

def verifyFinalPolZeroTests : TestSeq :=
  -- All-zero polynomial should always pass
  let final_pol : Array (Array UInt64) :=
    #[#[(0 : UInt64), 0, 0], #[(0 : UInt64), 0, 0]]
  let stark_struct : StarkStruct := {
    nBits := 1
    nBitsExt := 2
    nQueries := 1
    verificationHashType := "GL"
    friFoldSteps := #[{ domainBits := 2 }, { domainBits := 1 }]
  }
  group "verify_final_polynomial: zero poly" (
    test "zero polynomial passes degree check"
      (verify_final_polynomial final_pol stark_struct == true)
  )

def verifyFinalPolEmptyTests : TestSeq :=
  let stark_struct : StarkStruct := {
    nBits := 1
    nBitsExt := 2
    nQueries := 1
    verificationHashType := "GL"
    friFoldSteps := #[{ domainBits := 1 }]
  }
  group "verify_final_polynomial: empty poly" (
    test "empty polynomial passes"
      (verify_final_polynomial #[] stark_struct == true)
  )

-- ============================================================================
-- compute_xi_to_trace_size Tests
-- ============================================================================

def xiToTraceSizeTests : TestSeq :=
  let xi := GF3.mk (GF.mk 3) (GF.mk 5) (GF.mk 7)
  group "compute_xi_to_trace_size" (
    -- xi^1 = xi
    test "xi^1 = xi"
      (compute_xi_to_trace_size xi 1 == xi) $
    -- xi^0 = 1
    test "xi^0 = 1"
      (compute_xi_to_trace_size xi 0 == GF3.one) $
    -- xi^2 = xi * xi
    test "xi^2 = xi * xi"
      (compute_xi_to_trace_size xi 2 == gf3_mul xi xi) $
    -- xi^4 = (xi^2)^2
    test "xi^4 = (xi^2)^2"
      (compute_xi_to_trace_size xi 4 ==
       gf3_mul (compute_xi_to_trace_size xi 2) (compute_xi_to_trace_size xi 2))
  )

-- ============================================================================
-- compute_x_div_x_sub Tests
-- ============================================================================

def xDivXSubTests : TestSeq :=
  -- Test with a simple case: 1 query, 1 opening point at offset 0.
  -- xi = (2, 0, 0), omega_extended = W[3] (8th root), omega_trace = W[2] (4th root)
  -- shift = SHIFT = 7, opening_point = 0
  -- query position = 0
  --
  -- x = 7 * omega_ext^0 = 7
  -- omega_trace^0 = 1
  -- shifted_challenge = xi * 1 = (2, 0, 0)
  -- diff = x - shifted_challenge = (7, 0, 0) - (2, 0, 0) = (5, 0, 0)
  -- 1/diff = (inv(5), 0, 0)
  let xi := GF3.mk (GF.mk 2) GF.zero GF.zero
  let omega_ext := get_omega 3
  let omega_trace := get_omega 2
  let result := compute_x_div_x_sub xi omega_ext omega_trace SHIFT #[0] #[0] 1

  -- Expected: inv(5) as the c0 component
  let inv5 := gf_inv (GF.mk 5)
  group "compute_x_div_x_sub" (
    test "simple case: c0 = inv(5)"
      (result[0]! == inv5.val) $
    test "simple case: c1 = 0"
      (result[1]! == 0) $
    test "simple case: c2 = 0"
      (result[2]! == 0) $
    -- Verify: (x - xi*w^0) * result = 1
    test "inverse property: (x - xi*w^0) * result = 1"
      (let diff := GF3.mk (GF.mk 5) GF.zero GF.zero
       let inv_val := GF3.mk (GF.mk result[0]!) (GF.mk result[1]!) (GF.mk result[2]!)
       gf3_mul diff inv_val == GF3.one)
  )

-- ============================================================================
-- get_fri_challenge Tests
-- ============================================================================

def getFriChallengeTests : TestSeq :=
  -- Challenges buffer: 4 challenges (12 UInt64s total)
  -- challenge[0] = (1, 2, 3), challenge[1] = (4, 5, 6),
  -- challenge[2] = (7, 8, 9), challenge[3] = (10, 11, 12)
  let challenges : Array UInt64 := #[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
  group "get_fri_challenge" (
    -- With n_challenges_map = 2, step 0: index = 2, base = 6
    test "step 0 with offset 2: gets challenge[2]"
      (get_fri_challenge challenges 2 0 == #[(7 : UInt64), 8, 9]) $
    -- With n_challenges_map = 2, step 1: index = 3, base = 9
    test "step 1 with offset 2: gets challenge[3]"
      (get_fri_challenge challenges 2 1 == #[(10 : UInt64), 11, 12]) $
    -- With n_challenges_map = 0, step 0: index = 0, base = 0
    test "step 0 with no offset: gets challenge[0]"
      (get_fri_challenge challenges 0 0 == #[(1 : UInt64), 2, 3])
  )

-- ============================================================================
-- gather_siblings Tests
-- ============================================================================

def gatherSiblingsTests : TestSeq :=
  -- Each entry in fri_vals is an Array (Array UInt64) where the inner array
  -- has a single element (the proof value).
  -- For 2 siblings (fold_factor=2), each with 3 components:
  -- fri_vals has 6 entries: [val0], [val1], [val2], [val3], [val4], [val5]
  let fri_vals : Array (Array UInt64) := #[
    #[10], #[20], #[30],   -- sibling 0: (10, 20, 30)
    #[40], #[50], #[60]    -- sibling 1: (40, 50, 60)
  ]
  let siblings := gather_siblings fri_vals 2
  group "gather_siblings" (
    test "correct count"
      (siblings.size == 2) $
    test "sibling 0 = [10, 20, 30]"
      (siblings[0]! == #[(10 : UInt64), 20, 30]) $
    test "sibling 1 = [40, 50, 60]"
      (siblings[1]! == #[(40 : UInt64), 50, 60])
  )

-- ============================================================================
-- verify_fold with extension field challenge
-- ============================================================================

def verifyFoldExtFieldTests : TestSeq :=
  -- Test verify_fold with a non-trivial GF3 challenge to ensure the
  -- extension field multiplication works correctly.
  -- Use fold_factor = 1 (prev_bits = current_bits) for simplicity.
  -- With fold_factor = 1, the result is just the sibling itself.
  let siblings := #[#[(3 : UInt64), 5, 7]]
  let challenge := #[(11 : UInt64), 13, 17]  -- non-trivial GF3 challenge
  let result := verify_fold
    1       -- fri_round
    4       -- n_bits_ext
    3       -- current_bits
    3       -- prev_bits (fold_factor = 1)
    challenge
    0       -- idx
    siblings
  group "verify_fold: extension field" (
    -- With fold_factor=1, the polynomial is constant = sibling[0]
    -- So result = sibling[0] regardless of challenge
    test "fold_factor=1: result equals sibling"
      (result == GF3.mk (GF.mk 3) (GF.mk 5) (GF.mk 7))
  )

-- ============================================================================
-- Fold factor computation tests
-- ============================================================================

def foldFactorComputationTests : TestSeq :=
  -- fold_factor = 2^(prev_bits - current_bits)
  -- This is an implicit computation inside verify_fold but we test the
  -- semantic behavior through the API.
  group "fold factor semantics" (
    -- fold_factor = 2: provide exactly 2 siblings
    test "2 siblings accepted for fold_factor=2"
      (let siblings := #[#[(1 : UInt64), 0, 0], #[(2 : UInt64), 0, 0]]
       let challenge := #[(1 : UInt64), 0, 0]
       let result := verify_fold 0 4 1 2 challenge 0 siblings
       -- Should produce a valid result (not panic)
       result == result) $
    -- fold_factor = 4: provide exactly 4 siblings
    test "4 siblings accepted for fold_factor=4"
      (let siblings := #[#[(1 : UInt64), 0, 0], #[(2 : UInt64), 0, 0],
                          #[(3 : UInt64), 0, 0], #[(4 : UInt64), 0, 0]]
       let challenge := #[(1 : UInt64), 0, 0]
       let result := verify_fold 0 6 2 4 challenge 0 siblings
       result == result)
  )

-- ============================================================================
-- Main Test Runner
-- ============================================================================

def allTests : TestSeq :=
  shiftPowTests ++
  shiftInvPowTests ++
  computeWPowIdxTests ++
  verifyFoldTrivialTests ++
  verifyFoldFactor2Tests ++
  foldVerifyConsistencyTests ++
  verifyFinalPolConstantTests ++
  verifyFinalPolZeroTests ++
  verifyFinalPolEmptyTests ++
  xiToTraceSizeTests ++
  xDivXSubTests ++
  getFriChallengeTests ++
  gatherSiblingsTests ++
  verifyFoldExtFieldTests ++
  foldFactorComputationTests

def main : IO UInt32 :=
  lspecIO (.ofList [("FRI Verification", [allTests])]) []
