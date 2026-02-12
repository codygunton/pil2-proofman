import LSpec
import Primitives.Polynomial
import Primitives.Field

open Primitives.Polynomial
open Primitives.Field
open LSpec

-- ============================================================================
-- log2 Tests
-- ============================================================================

def log2Tests : TestSeq :=
  group "log2" (
    test "log2(1) = 0"
      (log2 1 == 0) $
    test "log2(2) = 1"
      (log2 2 == 1) $
    test "log2(4) = 2"
      (log2 4 == 2) $
    test "log2(8) = 3"
      (log2 8 == 3) $
    test "log2(16) = 4"
      (log2 16 == 4) $
    test "log2(1024) = 10"
      (log2 1024 == 10) $
    test "log2(4096) = 12"
      (log2 4096 == 12)
  )

-- ============================================================================
-- evaluate_poly_at Tests
-- ============================================================================

/-- Helper: embed a base field value into GF3 (c0 = val, c1 = c2 = 0). -/
def gf3_base (v : UInt64) : GF3 := GF3.mk (GF.mk v) GF.zero GF.zero

def evaluateConstantTests : TestSeq :=
  -- Constant polynomial: f(x) = 5, evaluated at x=anything should give 5
  let coeffs := #[gf3_base 5]
  let result_at_0 := evaluate_poly_at coeffs GF3.zero
  let result_at_1 := evaluate_poly_at coeffs GF3.one
  let result_at_7 := evaluate_poly_at coeffs (gf3_base 7)
  group "evaluate_poly_at: constant" (
    test "f(x) = 5, f(0) = 5"
      (result_at_0 == gf3_base 5) $
    test "f(x) = 5, f(1) = 5"
      (result_at_1 == gf3_base 5) $
    test "f(x) = 5, f(7) = 5"
      (result_at_7 == gf3_base 5)
  )

def evaluateLinearTests : TestSeq :=
  -- Linear polynomial: f(x) = 3 + 2x
  -- f(0) = 3, f(1) = 5, f(2) = 7, f(10) = 23
  let coeffs := #[gf3_base 3, gf3_base 2]
  group "evaluate_poly_at: linear" (
    test "f(x) = 3+2x, f(0) = 3"
      (evaluate_poly_at coeffs GF3.zero == gf3_base 3) $
    test "f(x) = 3+2x, f(1) = 5"
      (evaluate_poly_at coeffs GF3.one == gf3_base 5) $
    test "f(x) = 3+2x, f(2) = 7"
      (evaluate_poly_at coeffs (gf3_base 2) == gf3_base 7) $
    test "f(x) = 3+2x, f(10) = 23"
      (evaluate_poly_at coeffs (gf3_base 10) == gf3_base 23)
  )

def evaluateQuadraticTests : TestSeq :=
  -- Quadratic polynomial: f(x) = 1 + 2x + 3x^2
  -- f(0) = 1, f(1) = 6, f(2) = 1 + 4 + 12 = 17, f(3) = 1 + 6 + 27 = 34
  let coeffs := #[gf3_base 1, gf3_base 2, gf3_base 3]
  group "evaluate_poly_at: quadratic" (
    test "f(x) = 1+2x+3x^2, f(0) = 1"
      (evaluate_poly_at coeffs GF3.zero == gf3_base 1) $
    test "f(x) = 1+2x+3x^2, f(1) = 6"
      (evaluate_poly_at coeffs GF3.one == gf3_base 6) $
    test "f(x) = 1+2x+3x^2, f(2) = 17"
      (evaluate_poly_at coeffs (gf3_base 2) == gf3_base 17) $
    test "f(x) = 1+2x+3x^2, f(3) = 34"
      (evaluate_poly_at coeffs (gf3_base 3) == gf3_base 34)
  )

def evaluateEmptyTests : TestSeq :=
  group "evaluate_poly_at: edge cases" (
    test "empty polynomial evaluates to 0"
      (evaluate_poly_at #[] GF3.one == GF3.zero) $
    test "single zero coefficient"
      (evaluate_poly_at #[GF3.zero] (gf3_base 42) == GF3.zero)
  )

-- ============================================================================
-- evaluate_poly_at with extension field elements
-- ============================================================================

def evaluateGF3Tests : TestSeq :=
  -- Polynomial f(x) = a0 + a1*x where a0, a1 are GF3 elements
  -- Use the generator x = (0, 1, 0)
  let gen := GF3.mk GF.zero GF.one GF.zero
  -- f(x) = 1 + x*x (coefficients: [1, 0, 1] as GF3 elements)
  let coeffs := #[GF3.one, GF3.zero, GF3.one]
  -- f(gen) = 1 + gen^2 = 1 + (0,0,1) = (1, 0, 1)
  let expected := GF3.mk GF.one GF.zero GF.one
  group "evaluate_poly_at: GF3 elements" (
    test "f(x) = 1+x^2, f(gen) = (1, 0, 1)"
      (evaluate_poly_at coeffs gen == expected) $
    -- f(x) = gen, f(1) should be gen itself
    test "f(x) = gen (constant), f(1) = gen"
      (evaluate_poly_at #[gen] GF3.one == gen)
  )

-- ============================================================================
-- bit_reverse Tests
-- ============================================================================

def bitReverseTests : TestSeq :=
  -- n=4 (n_bits=2): indices [0,1,2,3] -> bit reverse -> [0,2,1,3]
  let arr4 := #[gf3_base 10, gf3_base 20, gf3_base 30, gf3_base 40]
  let rev4 := bit_reverse arr4 2
  -- n=8 (n_bits=3): indices [0,1,2,3,4,5,6,7] -> [0,4,2,6,1,5,3,7]
  let arr8 := #[gf3_base 0, gf3_base 1, gf3_base 2, gf3_base 3,
                gf3_base 4, gf3_base 5, gf3_base 6, gf3_base 7]
  let rev8 := bit_reverse arr8 3
  group "bit_reverse" (
    test "n=4: element 0 stays at 0"
      (rev4[0]! == gf3_base 10) $
    test "n=4: element 1 goes to 2"
      (rev4[1]! == gf3_base 30) $
    test "n=4: element 2 goes to 1"
      (rev4[2]! == gf3_base 20) $
    test "n=4: element 3 stays at 3"
      (rev4[3]! == gf3_base 40) $
    -- n=8 bit reversal: 0->0, 1->4, 2->2, 3->6, 4->1, 5->5, 6->3, 7->7
    test "n=8: element at 0 = original[0]"
      (rev8[0]! == gf3_base 0) $
    test "n=8: element at 1 = original[4]"
      (rev8[1]! == gf3_base 4) $
    test "n=8: element at 2 = original[2]"
      (rev8[2]! == gf3_base 2) $
    test "n=8: element at 3 = original[6]"
      (rev8[3]! == gf3_base 6) $
    test "n=1: single element unchanged"
      (bit_reverse #[gf3_base 42] 0 == #[gf3_base 42]) $
    test "empty array unchanged"
      (bit_reverse #[] 0 == #[])
  )

-- ============================================================================
-- to_coefficients_cubic Tests (INTT)
-- ============================================================================

def inttBasicTests : TestSeq :=
  -- INTT of a constant array should give the constant at index 0
  -- If all evaluations are 5, then the polynomial is f(x) = 5 (constant).
  -- INTT([5, 5, 5, 5]) should give [5, 0, 0, 0]
  let const_evals := #[gf3_base 5, gf3_base 5, gf3_base 5, gf3_base 5]
  let const_coeffs := to_coefficients_cubic const_evals 2
  group "to_coefficients_cubic: basic" (
    test "constant poly: c0 = 5"
      (const_coeffs[0]! == gf3_base 5) $
    test "constant poly: c1 = 0"
      (const_coeffs[1]! == GF3.zero) $
    test "constant poly: c2 = 0"
      (const_coeffs[2]! == GF3.zero) $
    test "constant poly: c3 = 0"
      (const_coeffs[3]! == GF3.zero)
  )

def inttRoundtripTests : TestSeq :=
  -- Verify that INTT recovers correct coefficients for a known polynomial.
  -- If we have polynomial f(x) = c0 + c1*x with known coefficients,
  -- and we evaluate at the domain points omega^0, omega^1, ..., omega^(n-1),
  -- then INTT should recover [c0, c1, 0, 0, ...].

  -- For n=2 (n_bits=1), omega = W[1] = p-1 = -1 (mod p)
  -- Domain = {1, -1}
  -- f(x) = 3 + 7x
  -- f(1) = 10, f(-1) = 3 - 7 = -4 = p-4
  let p_minus_4 := GOLDILOCKS_PRIME - 4
  let evals2 := #[gf3_base 10, gf3_base p_minus_4]
  let coeffs2 := to_coefficients_cubic evals2 1
  group "to_coefficients_cubic: roundtrip" (
    test "n=2 INTT: recovers c0 = 3"
      (coeffs2[0]! == gf3_base 3) $
    test "n=2 INTT: recovers c1 = 7"
      (coeffs2[1]! == gf3_base 7)
  )

def inttSingletonTests : TestSeq :=
  -- Single element INTT should return the element unchanged
  let single := #[gf3_base 42]
  let result := to_coefficients_cubic single 0
  group "to_coefficients_cubic: edge cases" (
    test "singleton: returned unchanged"
      (result[0]! == gf3_base 42) $
    test "singleton: correct size"
      (result.size == 1)
  )

-- ============================================================================
-- interleaved_to_coefficients Tests
-- ============================================================================

def interleavedCoeffTests : TestSeq :=
  -- 2 GF3 elements: (5,0,0) and (5,0,0) -> constant poly
  let interleaved : Array UInt64 := #[5, 0, 0, 5, 0, 0]
  let coeffs := interleaved_to_coefficients interleaved 2
  group "interleaved_to_coefficients" (
    test "constant poly from interleaved: c0 = (5,0,0)"
      (coeffs[0]! == gf3_base 5) $
    test "constant poly from interleaved: c1 = 0"
      (coeffs[1]! == GF3.zero)
  )

-- ============================================================================
-- Main Test Runner
-- ============================================================================

def allTests : TestSeq :=
  log2Tests ++
  evaluateConstantTests ++
  evaluateLinearTests ++
  evaluateQuadraticTests ++
  evaluateEmptyTests ++
  evaluateGF3Tests ++
  bitReverseTests ++
  inttBasicTests ++
  inttRoundtripTests ++
  inttSingletonTests ++
  interleavedCoeffTests

def main : IO UInt32 :=
  lspecIO (.ofList [("Polynomial", [allTests])]) []
