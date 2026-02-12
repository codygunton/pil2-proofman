/-
  Goldilocks field GF(p) where p = 2^64 - 2^32 + 1, and cubic extension GF(p^3).

  Translates: executable-spec/primitives/field.py
  Reduction algorithm: executable-spec/primitives/poseidon2-ffi/src/lib.rs:39-73
-/
namespace Primitives.Field

-- ============================================================================
-- Constants
-- ============================================================================

/-- Goldilocks prime: p = 2^64 - 2^32 + 1 = 0xFFFFFFFF00000001 -/
def GOLDILOCKS_PRIME : UInt64 := 0xFFFFFFFF00000001

/-- Cubic extension degree for GF(p^3). -/
def FIELD_EXTENSION_DEGREE : Nat := 3

/-- 2^32 - 1 = 0xFFFFFFFF, used in reduction corrections. -/
private def CORRECTION : UInt64 := 0xFFFFFFFF

/-- Mask for lower 32 bits. -/
private def MASK32 : UInt64 := 0xFFFFFFFF

-- ============================================================================
-- GF: Goldilocks base field
-- ============================================================================

/-- Goldilocks field element wrapping a UInt64.
    Invariant: val < GOLDILOCKS_PRIME (enforced by reduction in operations). -/
structure GF where
  val : UInt64
  deriving Repr, BEq, Hashable

instance : ToString GF where
  toString g := toString g.val

instance : Inhabited GF where
  default := GF.mk 0

/-- Zero element. -/
def GF.zero : GF := GF.mk 0

/-- One element. -/
def GF.one : GF := GF.mk 1

-- ============================================================================
-- 128-bit reduction (from Rust poseidon2-ffi/src/lib.rs:39-73)
-- ============================================================================

/-- Reduce a 128-bit value (lo, hi) modulo GOLDILOCKS_PRIME.

    Direct translation of the Rust `reduce` function:
      lo = x & 0xFFFFFFFFFFFFFFFF  (low 64 bits)
      hi = x >> 64                  (high 64 bits)

    The algorithm exploits the Goldilocks prime structure p = 2^64 - 2^32 + 1:
      x mod p = lo - hi_high + hi_low * (2^32 - 1)  (with borrow/carry corrections)
-/
def gf_reduce_128 (lo hi : UInt64) : GF :=
  let rhh := hi >>> 32               -- Upper 32 bits of hi
  let rhl := hi &&& MASK32           -- Lower 32 bits of hi

  -- aux1 = lo - rhh (with borrow handling)
  let aux1_raw := lo - rhh           -- UInt64 wrapping subtraction
  let borrow := lo < rhh
  let aux1 := if borrow then aux1_raw - CORRECTION else aux1_raw

  -- aux = rhl * 0xFFFFFFFF (fits in 64 bits since rhl < 2^32)
  let aux := CORRECTION * rhl

  -- result = aux1 + aux (with carry handling)
  let result_raw := aux1 + aux       -- UInt64 wrapping addition
  let carry := result_raw < aux1
  let result := if carry then result_raw + CORRECTION else result_raw

  -- Final reduction if result >= p
  if result >= GOLDILOCKS_PRIME then GF.mk (result - GOLDILOCKS_PRIME)
  else GF.mk result

-- ============================================================================
-- GF arithmetic
-- ============================================================================

/-- Add two field elements: (a + b) mod p. -/
def gf_add (a b : GF) : GF :=
  let sum := a.val + b.val            -- Wrapping addition
  let overflow := sum < a.val         -- Detect overflow
  if overflow || sum >= GOLDILOCKS_PRIME then
    GF.mk (sum - GOLDILOCKS_PRIME)
  else
    GF.mk sum

/-- Subtract two field elements: (a - b) mod p.
    If a < b, wraps by adding p. -/
def gf_sub (a b : GF) : GF :=
  if a.val >= b.val then
    GF.mk (a.val - b.val)
  else
    -- a - b + p: since a < b, a - b wraps to a - b + 2^64,
    -- and we need a - b + p = (a - b + 2^64) - (2^64 - p) = (a - b + 2^64) - 0xFFFFFFFF
    let diff := a.val - b.val         -- Wraps to a - b + 2^64
    GF.mk (diff - CORRECTION)

/-- Multiply two field elements using 32-bit limb decomposition.

    Since Lean 4 has no UInt128, we split each 64-bit operand into two 32-bit halves
    and compute the 128-bit product via schoolbook multiplication, then reduce. -/
def gf_mul (a b : GF) : GF :=
  let al := a.val &&& MASK32         -- Low 32 bits of a
  let ah := a.val >>> 32             -- High 32 bits of a
  let bl := b.val &&& MASK32         -- Low 32 bits of b
  let bh := b.val >>> 32             -- High 32 bits of b

  -- Four 64-bit partial products (each fits in 64 bits since inputs are 32-bit)
  let ll := al * bl                  -- [0, 63]
  let lh := al * bh                  -- [32, 95]
  let hl := ah * bl                  -- [32, 95]
  let hh := ah * bh                  -- [64, 127]

  -- Accumulate into (result_hi, result_lo) representing 128 bits.
  --
  -- result_lo = low 64 bits of (ll + (lh << 32) + (hl << 32))
  -- result_hi = hh + (lh >> 32) + (hl >> 32) + carries from result_lo
  --
  -- Step 1: mid = lh + hl (can overflow into 65 bits)
  let mid := lh + hl
  let mid_carry : UInt64 := if mid < lh then 1 else 0  -- 1 if 64-bit overflow

  -- Step 2: Add (mid << 32) to ll for result_lo
  let mid_lo := mid <<< 32           -- Low 32 bits of mid, shifted up
  let result_lo := ll + mid_lo
  let carry1 : UInt64 := if result_lo < ll then 1 else 0

  -- Step 3: result_hi = hh + (mid >> 32) + (mid_carry << 32) + carry1
  let mid_hi := mid >>> 32
  let result_hi := hh + mid_hi + (mid_carry <<< 32) + carry1

  gf_reduce_128 result_lo result_hi

/-- Negate a field element: (-a) mod p. -/
def gf_neg (a : GF) : GF :=
  if a.val == 0 then GF.zero
  else GF.mk (GOLDILOCKS_PRIME - a.val)

/-- Compute x^7 (S-box for Poseidon2): x^2, x^3=x*x^2, x^4=x^2*x^2, x^7=x^3*x^4. -/
def gf_pow7 (x : GF) : GF :=
  let x2 := gf_mul x x
  let x3 := gf_mul x x2
  let x4 := gf_mul x2 x2
  gf_mul x3 x4

/-- Compute a^n by repeated squaring. -/
def gf_pow (a : GF) (n : Nat) : GF :=
  if n == 0 then GF.one
  else Id.run do
    let mut result := GF.one
    let mut base := a
    let mut exp := n
    while exp > 0 do
      if exp % 2 == 1 then
        result := gf_mul result base
      base := gf_mul base base
      exp := exp / 2
    result

/-- Compute multiplicative inverse via Fermat's little theorem: a^(p-2) mod p. -/
def gf_inv (a : GF) : GF :=
  -- p - 2 = 0xFFFFFFFF00000001 - 2 = 0xFFFFFFFEFFFFFFFF
  -- As a Nat: 18446744069414584319
  gf_pow a (GOLDILOCKS_PRIME.toNat - 2)

/-- Montgomery batch inversion: convert N inversions into 3N-3 multiplications + 1 inversion.

    Algorithm:
    1. Forward pass: cumprods[i] = values[0] * values[1] * ... * values[i]
    2. Single inversion: inv_total = cumprods[N-1]^(-1)
    3. Backward pass: extract individual inverses using cumprods -/
def gf_batch_inverse (values : Array GF) : Array GF :=
  let n := values.size
  if n == 0 then #[]
  else if n == 1 then #[gf_inv values[0]!]
  else Id.run do
    -- Forward pass: compute prefix products
    let mut cumprods : Array GF := Array.replicate n GF.zero
    cumprods := cumprods.set! 0 values[0]!
    for i in [1:n] do
      cumprods := cumprods.set! i (gf_mul cumprods[i-1]! values[i]!)

    -- Single inversion of total product
    let mut z := gf_inv cumprods[n-1]!

    -- Backward pass: extract individual inverses
    let mut results : Array GF := Array.replicate n GF.zero
    for i' in [1:n] do
      let i := n - i'
      results := results.set! i (gf_mul z cumprods[i-1]!)
      z := gf_mul z values[i]!
    results := results.set! 0 z
    results

-- ============================================================================
-- GF3: Goldilocks cubic extension field
-- ============================================================================

/-- Cubic extension element: c0 + c1*x + c2*x^2 where x^3 = x + 1.
    Irreducible polynomial: t^3 - t - 1 over GF(p). -/
structure GF3 where
  c0 : GF
  c1 : GF
  c2 : GF
  deriving Repr, BEq, Hashable

instance : ToString GF3 where
  toString g := s!"GF3({g.c0}, {g.c1}, {g.c2})"

instance : Inhabited GF3 where
  default := GF3.mk GF.zero GF.zero GF.zero

/-- Zero element. -/
def GF3.zero : GF3 := GF3.mk GF.zero GF.zero GF.zero

/-- One element. -/
def GF3.one : GF3 := GF3.mk GF.one GF.zero GF.zero

-- ============================================================================
-- GF3 arithmetic
-- ============================================================================

/-- Add two cubic extension elements (componentwise). -/
def gf3_add (a b : GF3) : GF3 :=
  GF3.mk (gf_add a.c0 b.c0) (gf_add a.c1 b.c1) (gf_add a.c2 b.c2)

/-- Subtract two cubic extension elements (componentwise). -/
def gf3_sub (a b : GF3) : GF3 :=
  GF3.mk (gf_sub a.c0 b.c0) (gf_sub a.c1 b.c1) (gf_sub a.c2 b.c2)

/-- Multiply two cubic extension elements.

    With irreducible polynomial x^3 - x - 1, we have x^3 = x + 1 and x^4 = x^2 + x.

    Product of (a0 + a1*x + a2*x^2) * (b0 + b1*x + b2*x^2):
      Unreduced terms: a0*b0 + (a0*b1 + a1*b0)*x + (a0*b2 + a1*b1 + a2*b0)*x^2
                      + (a1*b2 + a2*b1)*x^3 + (a2*b2)*x^4

    Reduction using x^3 = x + 1, x^4 = x^2 + x:
      cross = a1*b2 + a2*b1   (coefficient of x^3)
      top   = a2*b2           (coefficient of x^4)

      c0 = a0*b0 + cross               (from cross*1)
      c1 = a0*b1 + a1*b0 + cross + top (from cross*x and top*x)
      c2 = a0*b2 + a1*b1 + a2*b0 + top (from top*x^2)
-/
def gf3_mul (a b : GF3) : GF3 :=
  let a0b0 := gf_mul a.c0 b.c0
  let a0b1 := gf_mul a.c0 b.c1
  let a0b2 := gf_mul a.c0 b.c2
  let a1b0 := gf_mul a.c1 b.c0
  let a1b1 := gf_mul a.c1 b.c1
  let a1b2 := gf_mul a.c1 b.c2
  let a2b0 := gf_mul a.c2 b.c0
  let a2b1 := gf_mul a.c2 b.c1
  let a2b2 := gf_mul a.c2 b.c2

  let cross := gf_add a1b2 a2b1     -- coefficient of x^3
  let top := a2b2                     -- coefficient of x^4

  let c0 := gf_add a0b0 cross
  let c1 := gf_add (gf_add (gf_add a0b1 a1b0) cross) top
  let c2 := gf_add (gf_add (gf_add a0b2 a1b1) a2b0) top

  GF3.mk c0 c1 c2

/-- Negate a cubic extension element. -/
def gf3_neg (a : GF3) : GF3 :=
  GF3.mk (gf_neg a.c0) (gf_neg a.c1) (gf_neg a.c2)

/-- Multiply GF3 element by a base field scalar (scale all components). -/
def gf3_mul_base (a : GF3) (s : GF) : GF3 :=
  GF3.mk (gf_mul a.c0 s) (gf_mul a.c1 s) (gf_mul a.c2 s)

/-- Compute a^n for cubic extension by repeated squaring. -/
def gf3_pow (a : GF3) (n : Nat) : GF3 :=
  if n == 0 then GF3.one
  else Id.run do
    let mut result := GF3.one
    let mut base := a
    let mut exp := n
    while exp > 0 do
      if exp % 2 == 1 then
        result := gf3_mul result base
      base := gf3_mul base base
      exp := exp / 2
    result

/-- Compute multiplicative inverse in GF3 via Fermat: a^(p^3 - 2).

    For GF(p^3), the group order is p^3 - 1, so a^(-1) = a^(p^3 - 2). -/
def gf3_inv (a : GF3) : GF3 :=
  -- p^3 - 2 is a large number. We compute it as a Nat.
  let p := GOLDILOCKS_PRIME.toNat
  let p3_minus_2 := p * p * p - 2
  gf3_pow a p3_minus_2

-- ============================================================================
-- Interleaved format conversions (C++ compatibility)
-- ============================================================================

/-- Convert array of GF3 to interleaved UInt64 array: [c0,c1,c2,c0,c1,c2,...]. -/
def gf3_to_interleaved (arr : Array GF3) : Array UInt64 :=
  Id.run do
    let mut result : Array UInt64 := Array.replicate (arr.size * 3) 0
    for i in [:arr.size] do
      let elem := arr[i]!
      result := result.set! (i * 3)     elem.c0.val
      result := result.set! (i * 3 + 1) elem.c1.val
      result := result.set! (i * 3 + 2) elem.c2.val
    result

/-- Convert interleaved UInt64 array to array of GF3. -/
def gf3_from_interleaved (arr : Array UInt64) : Array GF3 :=
  let n := arr.size / 3
  Id.run do
    let mut result : Array GF3 := Array.replicate n GF3.zero
    for i in [:n] do
      let c0 := GF.mk arr[i * 3]!
      let c1 := GF.mk arr[i * 3 + 1]!
      let c2 := GF.mk arr[i * 3 + 2]!
      result := result.set! i (GF3.mk c0 c1 c2)
    result

/-- Extract a single GF3 from interleaved buffer at logical index i. -/
def get_interleaved_gf3 (arr : Array UInt64) (i : Nat) : GF3 :=
  let base := i * 3
  GF3.mk (GF.mk arr[base]!) (GF.mk arr[base + 1]!) (GF.mk arr[base + 2]!)

-- ============================================================================
-- Roots of unity tables
-- ============================================================================

/-- Precomputed primitive roots of unity: W[n] is a primitive 2^n-th root of unity in GF(p).
    33 entries for subgroups of order 2^0 through 2^32. -/
def W : Array UInt64 := #[
  1,
  18446744069414584320,
  281474976710656,
  16777216,
  4096,
  64,
  8,
  2198989700608,
  4404853092538523347,
  6434636298004421797,
  4255134452441852017,
  9113133275150391358,
  4355325209153869931,
  4308460244895131701,
  7126024226993609386,
  1873558160482552414,
  8167150655112846419,
  5718075921287398682,
  3411401055030829696,
  8982441859486529725,
  1971462654193939361,
  6553637399136210105,
  8124823329697072476,
  5936499541590631774,
  2709866199236980323,
  8877499657461974390,
  3757607247483852735,
  4969973714567017225,
  2147253751702802259,
  2530564950562219707,
  1905180297017055339,
  3524815499551269279,
  7277203076849721926
]

/-- Precomputed inverses of roots of unity: W_INV[n] = W[n]^(-1) mod p.
    33 entries for subgroups of order 2^0 through 2^32. -/
def W_INV : Array UInt64 := #[
  1,
  18446744069414584320,
  18446462594437873665,
  18446742969902956801,
  18442240469788262401,
  18158513693329981441,
  16140901060737761281,
  274873712576,
  9171943329124577373,
  5464760906092500108,
  4088309022520035137,
  6141391951880571024,
  386651765402340522,
  11575992183625933494,
  2841727033376697931,
  8892493137794983311,
  9071788333329385449,
  15139302138664925958,
  14996013474702747840,
  5708508531096855759,
  6451340039662992847,
  5102364342718059185,
  10420286214021487819,
  13945510089405579673,
  17538441494603169704,
  16784649996768716373,
  8974194941257008806,
  16194875529212099076,
  5506647088734794298,
  7731871677141058814,
  16558868196663692994,
  9896756522253134970,
  1644488454024429189
]

/-- Domain shift for coset LDE. -/
def SHIFT : GF := GF.mk 7

/-- Inverse of domain shift. Computed as 7^(p-2) mod p. -/
def SHIFT_INV : GF := gf_inv (GF.mk 7)

/-- Get primitive 2^n_bits-th root of unity. -/
def get_omega (n_bits : Nat) : GF := GF.mk (W[n_bits]!)

/-- Get inverse of primitive 2^n_bits-th root of unity. -/
def get_omega_inv (n_bits : Nat) : GF := GF.mk (W_INV[n_bits]!)

end Primitives.Field
