/-
  Polynomial operations (verifier subset).

  Translates: executable-spec/primitives/polynomial.py

  Only the verifier-needed functions are included:
  - evaluate_poly_at: evaluate a polynomial at a point (used in FRI folding)
  - to_coefficients_cubic: INTT for GF3 polynomials (used in FRI final poly check)
  - log2: utility for computing log2 of power-of-2 values

  Protocol Invariant: If you can change an implementation detail without changing
  the resulting proof bytes, that detail does NOT belong in the protocol specification.
-/
import Primitives.Field

open Primitives.Field

namespace Primitives.Polynomial

-- ============================================================================
-- Utility
-- ============================================================================

/-- Compute log2 of size (must be a power of 2).
    Translates: polynomial.py:124-131 -/
def log2 (size : Nat) : Nat :=
  Id.run do
    let mut s := size
    let mut res : Nat := 0
    while s > 1 do
      s := s / 2
      res := res + 1
    res

-- ============================================================================
-- Polynomial evaluation
-- ============================================================================

/-- Evaluate a GF3 polynomial (in coefficient form) at a point using Horner's method.

    For coefficients [c0, c1, c2, ..., cn], computes:
      c0 + c1*x + c2*x^2 + ... + cn*x^n

    Using Horner's method (from highest degree down):
      ((cn*x + c_{n-1})*x + c_{n-2})*x + ... + c0

    Translates: the evaluation done in fri.py:62 via galois.Poly -/
def evaluate_poly_at (coeffs : Array GF3) (x : GF3) : GF3 :=
  if coeffs.size == 0 then GF3.zero
  else Id.run do
    -- Horner's method: start from highest degree coefficient
    let mut result := coeffs[coeffs.size - 1]!
    -- Iterate from second-highest to lowest
    let n := coeffs.size
    for i' in [1:n] do
      let i := n - 1 - i'
      result := gf3_add (gf3_mul result x) coeffs[i]!
    result

-- ============================================================================
-- Inverse NTT (INTT) for GF3
-- ============================================================================

/-- Bit-reversal permutation for an array of size 2^n_bits.
    Standard FFT preprocessing step. -/
def bit_reverse (arr : Array GF3) (n_bits : Nat) : Array GF3 :=
  let n := arr.size
  if n <= 1 then arr
  else Id.run do
    let mut result := arr
    for i in [:n] do
      -- Compute bit-reversed index
      let mut rev : Nat := 0
      let mut x := i
      for _ in [:n_bits] do
        rev := rev * 2 + x % 2
        x := x / 2
      if i < rev then
        -- Swap elements at i and rev
        let tmp := result[i]!
        result := result.set! i result[rev]!
        result := result.set! rev tmp
    result

/-- INTT (Inverse Number Theoretic Transform) for GF3 polynomials.

    Converts polynomial evaluations on a domain of size n to coefficient form.
    This is the inverse of NTT using the inverse roots of unity.

    Algorithm:
    1. Apply bit-reversal permutation
    2. Cooley-Tukey butterfly with inverse roots of unity
    3. Divide all coefficients by n

    For GF3 elements, the transform operates component-wise over the base field
    on each GF coefficient (c0, c1, c2). We implement this by treating GF3 as
    opaque elements and using gf3_mul_base for the twiddle factor multiplication
    (since twiddle factors are base field elements).

    Translates: polynomial.py:92-121 (to_coefficients_cubic)
    Reference: ntt.py:68-93 (NTT.intt) -/
def to_coefficients_cubic (evals : Array GF3) (n_bits : Nat) : Array GF3 :=
  let n := evals.size
  if n <= 1 then evals
  else Id.run do
    -- Step 1: bit-reverse the input
    let mut data := bit_reverse evals n_bits

    -- Step 2: Cooley-Tukey butterfly INTT
    -- For INTT we use inverse roots of unity (omega_inv)
    let mut len : Nat := 2
    let mut step : Nat := 1
    -- We iterate log2(n) times
    for s in [:n_bits] do
      -- omega_inv for this stage: inverse root of unity for subgroup of size 2^(s+1)
      let w_inv := get_omega_inv (s + 1)

      -- Process each butterfly group
      let mut k : Nat := 0
      let fuel := n / len
      for _ in [:fuel] do
        let mut w := GF.one
        for j in [:step] do
          let u := data[k + j]!
          let v := gf3_mul_base data[k + j + step]! w
          data := data.set! (k + j) (gf3_add u v)
          data := data.set! (k + j + step) (gf3_sub u v)
          w := gf_mul w w_inv
        k := k + len

      len := len * 2
      step := step * 2

    -- Step 3: Divide by n (multiply by n^(-1) in the field)
    let n_inv := gf_inv (GF.mk n.toUInt64)
    for i in [:n] do
      data := data.set! i (gf3_mul_base data[i]! n_inv)

    data

-- ============================================================================
-- Coefficient-form operations
-- ============================================================================

/-- Convert interleaved base-field evaluations to GF3 coefficient form.

    Used by the verifier's final polynomial check: takes the interleaved
    representation, interprets as GF3 evaluations, and converts to coefficients.

    This is a convenience wrapper around to_coefficients_cubic that handles
    the interleaved-to-GF3 conversion.

    Translates: verifier.py:980-983 (final polynomial coefficient conversion) -/
def interleaved_to_coefficients (interleaved : Array UInt64) (n : Nat) : Array GF3 :=
  let evals := gf3_from_interleaved interleaved
  let n_bits := log2 n
  to_coefficients_cubic evals n_bits

end Primitives.Polynomial
