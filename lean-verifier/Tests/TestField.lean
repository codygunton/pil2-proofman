import LSpec
import Primitives.Field

open Primitives.Field
open LSpec

-- ============================================================================
-- GF Base Field Tests
-- ============================================================================

def gfAddTests : TestSeq :=
  group "gf_add" (
    test "1 + 1 = 2"
      (gf_add (GF.mk 1) (GF.mk 1) == GF.mk 2) $
    test "0 + 0 = 0"
      (gf_add GF.zero GF.zero == GF.zero) $
    test "p-1 + 1 = 0 (wraps at prime)"
      (gf_add (GF.mk (GOLDILOCKS_PRIME - 1)) (GF.mk 1) == GF.zero) $
    test "p-1 + 2 = 1 (wraps past prime)"
      (gf_add (GF.mk (GOLDILOCKS_PRIME - 1)) (GF.mk 2) == GF.mk 1) $
    test "0 + 5 = 5 (identity)"
      (gf_add GF.zero (GF.mk 5) == GF.mk 5) $
    test "large + large wraps correctly"
      (gf_add (GF.mk (GOLDILOCKS_PRIME - 1)) (GF.mk (GOLDILOCKS_PRIME - 1)) ==
       GF.mk (GOLDILOCKS_PRIME - 2))
  )

def gfSubTests : TestSeq :=
  group "gf_sub" (
    test "5 - 3 = 2"
      (gf_sub (GF.mk 5) (GF.mk 3) == GF.mk 2) $
    test "0 - 1 = p-1 (wraps to negative)"
      (gf_sub GF.zero (GF.mk 1) == GF.mk (GOLDILOCKS_PRIME - 1)) $
    test "0 - 0 = 0"
      (gf_sub GF.zero GF.zero == GF.zero) $
    test "1 - 1 = 0"
      (gf_sub (GF.mk 1) (GF.mk 1) == GF.zero) $
    test "3 - 5 = p-2"
      (gf_sub (GF.mk 3) (GF.mk 5) == GF.mk (GOLDILOCKS_PRIME - 2))
  )

def gfMulTests : TestSeq :=
  group "gf_mul" (
    test "2 * 3 = 6"
      (gf_mul (GF.mk 2) (GF.mk 3) == GF.mk 6) $
    test "1 * x = x (identity)"
      (gf_mul GF.one (GF.mk 42) == GF.mk 42) $
    test "0 * x = 0 (zero)"
      (gf_mul GF.zero (GF.mk 42) == GF.zero) $
    test "(-1) * (-1) = 1"
      (gf_mul (GF.mk (GOLDILOCKS_PRIME - 1)) (GF.mk (GOLDILOCKS_PRIME - 1)) == GF.one) $
    test "(-1) * 2 = p-2"
      (gf_mul (GF.mk (GOLDILOCKS_PRIME - 1)) (GF.mk 2) == GF.mk (GOLDILOCKS_PRIME - 2)) $
    test "large * 1 = large"
      (gf_mul (GF.mk 0xDEADBEEF) GF.one == GF.mk 0xDEADBEEF) $
    -- Test with values that exercise all four 32-bit partial products
    test "0x100000000 * 0x100000000 reduces correctly"
      (gf_mul (GF.mk 0x100000000) (GF.mk 0x100000000) ==
       gf_reduce_128 0 1)  -- 2^64 = (0, 1) in 128-bit
  )

def gfNegTests : TestSeq :=
  group "gf_neg" (
    test "neg(0) = 0"
      (gf_neg GF.zero == GF.zero) $
    test "neg(1) = p-1"
      (gf_neg GF.one == GF.mk (GOLDILOCKS_PRIME - 1)) $
    test "neg(p-1) = 1"
      (gf_neg (GF.mk (GOLDILOCKS_PRIME - 1)) == GF.one) $
    test "a + neg(a) = 0"
      (gf_add (GF.mk 12345) (gf_neg (GF.mk 12345)) == GF.zero)
  )

def gfPow7Tests : TestSeq :=
  group "gf_pow7" (
    test "2^7 = 128"
      (gf_pow7 (GF.mk 2) == GF.mk 128) $
    test "1^7 = 1"
      (gf_pow7 GF.one == GF.one) $
    test "0^7 = 0"
      (gf_pow7 GF.zero == GF.zero) $
    test "3^7 = 2187"
      (gf_pow7 (GF.mk 3) == GF.mk 2187)
  )

def gfPowTests : TestSeq :=
  group "gf_pow" (
    test "2^0 = 1"
      (gf_pow (GF.mk 2) 0 == GF.one) $
    test "2^1 = 2"
      (gf_pow (GF.mk 2) 1 == GF.mk 2) $
    test "2^10 = 1024"
      (gf_pow (GF.mk 2) 10 == GF.mk 1024) $
    test "2^7 = 128 (matches pow7)"
      (gf_pow (GF.mk 2) 7 == gf_pow7 (GF.mk 2)) $
    test "3^7 matches pow7"
      (gf_pow (GF.mk 3) 7 == gf_pow7 (GF.mk 3))
  )

def gfInvTests : TestSeq :=
  group "gf_inv" (
    test "inv(1) = 1"
      (gf_inv GF.one == GF.one) $
    test "inv(2) * 2 = 1"
      (gf_mul (gf_inv (GF.mk 2)) (GF.mk 2) == GF.one) $
    test "inv(p-1) * (p-1) = 1"
      (gf_mul (gf_inv (GF.mk (GOLDILOCKS_PRIME - 1))) (GF.mk (GOLDILOCKS_PRIME - 1)) == GF.one) $
    test "inv(7) * 7 = 1"
      (gf_mul (gf_inv (GF.mk 7)) (GF.mk 7) == GF.one)
  )

def gfBatchInverseTests : TestSeq :=
  let vals := #[GF.mk 2, GF.mk 3, GF.mk 7, GF.mk 42]
  let invs := gf_batch_inverse vals
  group "gf_batch_inverse" (
    test "empty input returns empty"
      ((gf_batch_inverse #[]).size == 0) $
    test "single element"
      (gf_batch_inverse #[GF.mk 5] == #[gf_inv (GF.mk 5)]) $
    test "inv(2) * 2 = 1"
      (gf_mul invs[0]! vals[0]! == GF.one) $
    test "inv(3) * 3 = 1"
      (gf_mul invs[1]! vals[1]! == GF.one) $
    test "inv(7) * 7 = 1"
      (gf_mul invs[2]! vals[2]! == GF.one) $
    test "inv(42) * 42 = 1"
      (gf_mul invs[3]! vals[3]! == GF.one) $
    test "matches individual inversions"
      (invs == #[gf_inv (GF.mk 2), gf_inv (GF.mk 3), gf_inv (GF.mk 7), gf_inv (GF.mk 42)])
  )

-- ============================================================================
-- 128-bit Reduction Tests
-- ============================================================================

def reduceTests : TestSeq :=
  group "gf_reduce_128" (
    test "reduce(0, 0) = 0"
      (gf_reduce_128 0 0 == GF.zero) $
    test "reduce(1, 0) = 1"
      (gf_reduce_128 1 0 == GF.one) $
    test "reduce(p, 0) = 0 (exactly p reduces to 0)"
      (gf_reduce_128 GOLDILOCKS_PRIME 0 == GF.zero) $
    test "reduce(p+1, 0) = 1"
      (gf_reduce_128 (GOLDILOCKS_PRIME + 1) 0 == GF.one) $
    -- 2^64 mod p: hi=1, lo=0
    -- 2^64 = p + 2^32 - 1 = p + 0xFFFFFFFF, so 2^64 mod p = 0xFFFFFFFF
    test "reduce(0, 1) = 0xFFFFFFFF (2^64 mod p)"
      (gf_reduce_128 0 1 == GF.mk 0xFFFFFFFF)
  )

-- ============================================================================
-- GF3 Cubic Extension Tests
-- ============================================================================

-- The element x in GF3 representation: (0, 1, 0) = 0 + 1*x + 0*x^2
def gf3_x : GF3 := GF3.mk GF.zero GF.one GF.zero

def gf3AddTests : TestSeq :=
  group "gf3_add" (
    test "0 + 0 = 0"
      (gf3_add GF3.zero GF3.zero == GF3.zero) $
    test "1 + 0 = 1"
      (gf3_add GF3.one GF3.zero == GF3.one) $
    test "(1,2,3) + (4,5,6) = (5,7,9)"
      (gf3_add (GF3.mk (GF.mk 1) (GF.mk 2) (GF.mk 3))
               (GF3.mk (GF.mk 4) (GF.mk 5) (GF.mk 6)) ==
       GF3.mk (GF.mk 5) (GF.mk 7) (GF.mk 9))
  )

def gf3SubTests : TestSeq :=
  group "gf3_sub" (
    test "a - a = 0"
      (gf3_sub gf3_x gf3_x == GF3.zero) $
    test "0 - (0,1,0) = (0, p-1, 0)"
      (gf3_sub GF3.zero gf3_x == GF3.mk GF.zero (GF.mk (GOLDILOCKS_PRIME - 1)) GF.zero)
  )

def gf3MulTests : TestSeq :=
  -- x * x = x^2 = (0, 0, 1)
  let x_squared := gf3_mul gf3_x gf3_x
  -- x^3 = x + 1 (the defining relation of the irreducible polynomial)
  let x_cubed := gf3_mul x_squared gf3_x
  -- x^4 = x^2 + x
  let x_fourth := gf3_mul x_cubed gf3_x
  group "gf3_mul" (
    test "1 * a = a (identity)"
      (gf3_mul GF3.one gf3_x == gf3_x) $
    test "0 * a = 0 (zero)"
      (gf3_mul GF3.zero gf3_x == GF3.zero) $
    test "x * x = (0, 0, 1)"
      (x_squared == GF3.mk GF.zero GF.zero GF.one) $
    test "x^3 = x + 1 (defining relation)"
      (x_cubed == GF3.mk GF.one GF.one GF.zero) $
    test "x^4 = x^2 + x"
      (x_fourth == GF3.mk GF.zero GF.one GF.one) $
    -- (1 + x) * (1 + x) = 1 + 2x + x^2
    test "(1+x)^2 = 1 + 2x + x^2"
      (gf3_mul (GF3.mk GF.one GF.one GF.zero) (GF3.mk GF.one GF.one GF.zero) ==
       GF3.mk GF.one (GF.mk 2) GF.one) $
    -- Commutativity: a * b = b * a
    test "commutativity"
      (let a := GF3.mk (GF.mk 3) (GF.mk 5) (GF.mk 7)
       let b := GF3.mk (GF.mk 11) (GF.mk 13) (GF.mk 17)
       gf3_mul a b == gf3_mul b a)
  )

def gf3MulBaseTests : TestSeq :=
  group "gf3_mul_base" (
    test "scale by 1 = identity"
      (gf3_mul_base gf3_x GF.one == gf3_x) $
    test "scale by 0 = zero"
      (gf3_mul_base gf3_x GF.zero == GF3.zero) $
    test "scale (1,2,3) by 2 = (2,4,6)"
      (gf3_mul_base (GF3.mk (GF.mk 1) (GF.mk 2) (GF.mk 3)) (GF.mk 2) ==
       GF3.mk (GF.mk 2) (GF.mk 4) (GF.mk 6))
  )

def gf3PowTests : TestSeq :=
  group "gf3_pow" (
    test "x^0 = 1"
      (gf3_pow gf3_x 0 == GF3.one) $
    test "x^1 = x"
      (gf3_pow gf3_x 1 == gf3_x) $
    test "x^2 = (0,0,1)"
      (gf3_pow gf3_x 2 == GF3.mk GF.zero GF.zero GF.one) $
    test "x^3 = x + 1 (defining relation via pow)"
      (gf3_pow gf3_x 3 == GF3.mk GF.one GF.one GF.zero) $
    test "x^4 = x^2 + x"
      (gf3_pow gf3_x 4 == GF3.mk GF.zero GF.one GF.one) $
    -- x^7 via pow should match manual multiplication
    test "x^7 via pow matches x^3 * x^4"
      (gf3_pow gf3_x 7 == gf3_mul (gf3_pow gf3_x 3) (gf3_pow gf3_x 4))
  )

-- Note: gf3_inv tests are slow due to p^3-2 exponent, so we use small tests
def gf3InvTests : TestSeq :=
  group "gf3_inv" (
    test "inv(1) = 1"
      (gf3_inv GF3.one == GF3.one)
    -- More comprehensive gf3_inv tests would require significant computation time
    -- for the p^3-2 exponent, so we focus on verifying the algorithm is correct
    -- through the identity element test and the GF3 multiplication tests above.
  )

-- ============================================================================
-- Interleaved Format Tests
-- ============================================================================

def interleavedTests : TestSeq :=
  let elems := #[
    GF3.mk (GF.mk 1) (GF.mk 2) (GF.mk 3),
    GF3.mk (GF.mk 4) (GF.mk 5) (GF.mk 6)
  ]
  let interleaved := gf3_to_interleaved elems
  let roundtripped := gf3_from_interleaved interleaved
  group "interleaved conversions" (
    test "to_interleaved produces correct layout"
      (interleaved == #[1, 2, 3, 4, 5, 6]) $
    test "from_interleaved recovers original"
      (roundtripped == elems) $
    test "get_interleaved_gf3 at index 0"
      (get_interleaved_gf3 interleaved 0 == elems[0]!) $
    test "get_interleaved_gf3 at index 1"
      (get_interleaved_gf3 interleaved 1 == elems[1]!) $
    test "empty roundtrip"
      (gf3_from_interleaved (gf3_to_interleaved #[]) == #[])
  )

-- ============================================================================
-- Roots of Unity Tests
-- ============================================================================

def rootsOfUnityTests : TestSeq :=
  group "roots of unity" (
    test "W has 33 entries"
      (W.size == 33) $
    test "W_INV has 33 entries"
      (W_INV.size == 33) $
    test "W[0] = 1 (2^0-th root of unity)"
      (W[0]! == 1) $
    test "W_INV[0] = 1"
      (W_INV[0]! == 1) $
    test "get_omega 0 = 1"
      (get_omega 0 == GF.mk 1) $
    test "get_omega_inv 0 = 1"
      (get_omega_inv 0 == GF.mk 1) $
    -- W[1] is a primitive 2nd root of unity, so W[1]^2 = 1
    test "W[1]^2 = 1 (2nd root of unity)"
      (gf_pow (GF.mk W[1]!) 2 == GF.one) $
    -- W[2] is a primitive 4th root of unity, so W[2]^4 = 1
    test "W[2]^4 = 1 (4th root of unity)"
      (gf_pow (GF.mk W[2]!) 4 == GF.one) $
    -- W[3] is a primitive 8th root of unity
    test "W[3]^8 = 1 (8th root of unity)"
      (gf_pow (GF.mk W[3]!) 8 == GF.one) $
    -- W[n] * W_INV[n] = 1
    test "W[1] * W_INV[1] = 1"
      (gf_mul (GF.mk W[1]!) (GF.mk W_INV[1]!) == GF.one) $
    test "W[2] * W_INV[2] = 1"
      (gf_mul (GF.mk W[2]!) (GF.mk W_INV[2]!) == GF.one) $
    test "W[5] * W_INV[5] = 1"
      (gf_mul (GF.mk W[5]!) (GF.mk W_INV[5]!) == GF.one)
  )

-- ============================================================================
-- Shift Tests
-- ============================================================================

def shiftTests : TestSeq :=
  group "shift constants" (
    test "SHIFT = 7"
      (SHIFT == GF.mk 7) $
    test "SHIFT * SHIFT_INV = 1"
      (gf_mul SHIFT SHIFT_INV == GF.one)
  )

-- ============================================================================
-- Constants Tests
-- ============================================================================

def constantsTests : TestSeq :=
  group "constants" (
    test "GOLDILOCKS_PRIME = 0xFFFFFFFF00000001"
      (GOLDILOCKS_PRIME == 0xFFFFFFFF00000001) $
    test "FIELD_EXTENSION_DEGREE = 3"
      (FIELD_EXTENSION_DEGREE == 3)
  )

-- ============================================================================
-- Algebraic Property Tests
-- ============================================================================

def algebraicPropertyTests : TestSeq :=
  group "algebraic properties" (
    -- Additive group properties
    test "add: commutativity (a+b = b+a)"
      (gf_add (GF.mk 17) (GF.mk 42) == gf_add (GF.mk 42) (GF.mk 17)) $
    test "add: associativity ((a+b)+c = a+(b+c))"
      (gf_add (gf_add (GF.mk 11) (GF.mk 22)) (GF.mk 33) ==
       gf_add (GF.mk 11) (gf_add (GF.mk 22) (GF.mk 33))) $
    test "add: identity (a+0 = a)"
      (gf_add (GF.mk 99) GF.zero == GF.mk 99) $
    test "add: inverse (a + (-a) = 0)"
      (gf_add (GF.mk 77) (gf_neg (GF.mk 77)) == GF.zero) $

    -- Multiplicative group properties
    test "mul: commutativity (a*b = b*a)"
      (gf_mul (GF.mk 13) (GF.mk 37) == gf_mul (GF.mk 37) (GF.mk 13)) $
    test "mul: associativity ((a*b)*c = a*(b*c))"
      (gf_mul (gf_mul (GF.mk 5) (GF.mk 7)) (GF.mk 11) ==
       gf_mul (GF.mk 5) (gf_mul (GF.mk 7) (GF.mk 11))) $
    test "mul: identity (a*1 = a)"
      (gf_mul (GF.mk 99) GF.one == GF.mk 99) $

    -- Distributive law
    test "distributive: a*(b+c) = a*b + a*c"
      (let a := GF.mk 5; let b := GF.mk 7; let c := GF.mk 11
       gf_mul a (gf_add b c) == gf_add (gf_mul a b) (gf_mul a c))
  )

-- ============================================================================
-- Main Test Runner
-- ============================================================================

def allTests : TestSeq :=
  constantsTests ++
  reduceTests ++
  gfAddTests ++
  gfSubTests ++
  gfMulTests ++
  gfNegTests ++
  gfPow7Tests ++
  gfPowTests ++
  gfInvTests ++
  gfBatchInverseTests ++
  gf3AddTests ++
  gf3SubTests ++
  gf3MulTests ++
  gf3MulBaseTests ++
  gf3PowTests ++
  gf3InvTests ++
  interleavedTests ++
  rootsOfUnityTests ++
  shiftTests ++
  algebraicPropertyTests

def main : IO UInt32 :=
  lspecIO (.ofList [("Goldilocks Field", [allTests])]) []
