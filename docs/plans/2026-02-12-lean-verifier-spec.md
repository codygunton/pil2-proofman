# Lean 4 STARK Verifier Specification — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Translate the Python STARK proof verifier (`executable-spec/protocol/verifier.py` and all its dependencies) into an executable Lean 4 specification that can verify real STARK proofs.

**Architecture:** Layered translation mirroring the Python package structure exactly. Primitives (field, transcript, Merkle) are pure Lean 4. Poseidon2 hashing uses FFI to the existing Rust implementation. Constraint evaluation uses FFI to a Rust reimplementation of the bytecode evaluator. All data flows through the same types as Python, translated to Lean 4 structures.

**Tech Stack:** Lean 4, Lake (build system), LSpec (testing), Lean 4 FFI (`@[extern]`), Rust FFI (Poseidon2 + constraint evaluator)

---

## Progress Summary

**Status: ALL 10 TASKS COMPLETE** — E2E SimpleLeft proof verification passes.

| Task | Description | Status | Tests |
|------|-------------|--------|-------|
| 10 | Project scaffolding | DONE | Build passes |
| 1 | Goldilocks field arithmetic (GF, GF3) | DONE | 87 tests |
| 2 | Poseidon2 FFI + Transcript | DONE | 48 transcript + 10 poseidon2 |
| 3 | Merkle verifier + Polynomial utils | DONE | 49 merkle + 42 polynomial |
| 4 | StarkInfo + PolMap (config parsing) | DONE | 82 tests |
| 5 | VerifierData + AirConfig | DONE | 56 tests |
| 6 | Proof deserialization | DONE | 35 tests |
| 7 | FRI verification | DONE | 38 tests |
| 8 | Main verifier | DONE | 33 tests (incl. E2E) |
| 9 | Constraint evaluation FFI | DONE | 1 Rust unit test + E2E |

**Total: 480+ tests across 10 test executables, all passing.**

### Key Implementation Decisions (Deviations from Plan)

1. **Constraint FFI**: Used a **Rust reimplementation** of the bytecode evaluator instead of C++ FFI wrapper. This avoids linking the entire pil2-stark C++ library and is self-contained. The Rust evaluator (`lean-verifier/ffi/constraints/`) parses the same `.bin` bytecode format and produces identical results. A C shim (`lean_shim.c`) bridges Lean's `@[extern]` calls to the Rust staticlib.

2. **Poseidon2 FFI**: Created a **standalone Rust staticlib** (`lean-verifier/ffi/poseidon2/`) that directly provides the `@[extern]` symbols Lean expects, bypassing the PyO3-based `poseidon2-ffi` crate. Manual Lean FFI declarations (~5 functions from `lean.h`) avoid version-locked dependencies.

3. **Bug fix (Task 9)**: The Rust bytecode evaluator stored `tmp1` registers as `u64` (base field only), discarding the `c1`/`c2` components of FF3 values. In verify mode, even "base field" operations produce full FF3 results. Fixed by changing `tmp1: HashMap<u16, u64>` → `HashMap<u16, FF3>`.

### Test Executables

```
test-field       87 tests   Goldilocks GF + GF3 arithmetic
test-transcript  48 tests   Fiat-Shamir transcript (Poseidon2 sponge)
test-starkinfo   82 tests   StarkInfo JSON parsing
test-data        56 tests   VerifierData, AirConfig structures
test-proof       35 tests   Binary proof deserialization
test-merkle      49 tests   Merkle tree verification
test-polynomial  42 tests   Polynomial INTT, evaluation
test-fri         38 tests   FRI fold verification
test-verifier    33 tests   Full verifier incl. E2E SimpleLeft
test-poseidon2   10 tests   Poseidon2 hash, linear_hash, grinding
```

### Commits

```
62317898 feat(lean): initialize Lean 4 verifier project scaffold
94468b29 feat(lean): implement Goldilocks field arithmetic in Lean 4
da85cd5c feat(lean): add Poseidon2 FFI declarations and Fiat-Shamir transcript
ff7c3139 feat(lean): add StarkInfo JSON parser and PolMap types
ea0e1041 feat(lean): implement Tasks 2-6,9 — Poseidon2 FFI, Transcript, Merkle, Polynomial, StarkInfo, PolMap, Data, AirConfig, Proof, Constraint FFI
a97e3b78 feat(lean): implement FRI verification and main STARK verifier (Tasks 7-8)
88172dd2 feat(lean): add Poseidon2 Rust FFI with C shim for Lean runtime
(pending)  fix(lean): constraint evaluator tmp1 FF3 bug + E2E wiring
```

### Remaining Work (Future)

- **More E2E AIRs**: Add Lookup2_12 and Permutation1_6 proof verification
- **Zisk AIRs**: Verify Zisk proofs (12 AIRs from GPU prover)
- **Lean proofs**: Add formal correctness proofs for field arithmetic
- **CI**: GitHub Actions workflow for `lake build` + test execution

---

## Dependency Graph

```
                    ┌──────────────────────┐
                    │  Protocol/Verifier   │  ← Task 8 (main entry)
                    └────────┬─────────────┘
          ┌──────────┬───────┴────────┬──────────────┐
          ▼          ▼                ▼              ▼
    Protocol/FRI  Protocol/Proof  Protocol/Data  Protocol/StarkInfo
     (Task 7)      (Task 6)       (Task 5)        (Task 4)
          │          │                              │
          ▼          ▼                              ▼
   Primitives/    Primitives/                 Primitives/PolMap
   Polynomial     Transcript                    (Task 4)
    (Task 3)       (Task 2)
          │          │
          ▼          ▼
   Primitives/   FFI/Poseidon2
     Field          (Task 2)
    (Task 1)
          │
          └──────────────────────────────┐
                                         ▼
                              Primitives/MerkleVerifier
                                    (Task 3)
```

**Build order:** Task 1 → Task 2 → Task 3 → Tasks 4,5,6 (parallel) → Task 7 → Task 8 → Task 9 (E2E)

## Python → Lean 4 Translation Reference

This table maps Python constructs to their Lean 4 equivalents. Every task below should reference this table.

| Python | Lean 4 | Notes |
|--------|--------|-------|
| `int` (field element) | `UInt64` | Wrapping arithmetic matches Goldilocks |
| `FF` (galois base field) | `structure GF : Type where val : UInt64` | Custom struct with modular ops |
| `FF3` (cubic extension) | `structure GF3 : Type where c0 c1 c2 : GF` | 3-tuple of base elements |
| `list[int]` | `Array UInt64` | Lean arrays are dynamic |
| `np.ndarray` (uint64) | `Array UInt64` | No numpy equivalent needed |
| `InterleavedFF3` | `Array UInt64` | Same flat layout as Python |
| `dict[K, V]` | `Std.HashMap K V` | From Std library |
| `dataclass` | `structure` | Direct mapping |
| `NamedTuple` | `structure` | Direct mapping |
| `Enum` | `inductive` | Direct mapping |
| `for i in range(n)` | `for i in [:n] do` or `Id.run do let mut ...` | Use `Id.run` for mutable loops |
| `a % b` | `a % b` | UInt64 wrapping mod |
| `a ** b` | Custom `pow` function | Repeated squaring |
| `len(arr)` | `arr.size` | |
| `arr[i]` | `arr[i]!` or `arr.get! i` | `!` panics on OOB |
| `arr[start:end]` | `arr.extract start end` | |
| `pickle.load` | N/A | Field constructed at init |
| `json.load` | `Lean.Json.parse` | Built-in JSON support |
| `bytes` (binary proof) | `ByteArray` | `toUInt64LE!` for parsing |

---

## Task 1: Goldilocks Field Arithmetic

**Translates:** `executable-spec/primitives/field.py:1-300`

**Files:**
- Create: `lean-verifier/Primitives/Field.lean`
- Test: `lean-verifier/Tests/TestField.lean`

This is the foundation — every other module depends on it.

### Step 1: Write failing tests for base field

Create `lean-verifier/Tests/TestField.lean`:

```lean
import LSpec
import Primitives.Field

open LSpec Primitives.Field

def main : IO UInt32 := lspecIO <|
  .group "GF base field" [
    .test "add: 1 + 1 = 2" <|
      gf_add (GF.mk 1) (GF.mk 1) == GF.mk 2,
    .test "add: wraps at prime" <|
      gf_add (GF.mk GOLDILOCKS_PRIME_MINUS_1) (GF.mk 1) == GF.mk 0,
    .test "mul: 2 * 3 = 6" <|
      gf_mul (GF.mk 2) (GF.mk 3) == GF.mk 6,
    .test "mul: prime-1 * prime-1 = 1" <|
      gf_mul (GF.mk GOLDILOCKS_PRIME_MINUS_1) (GF.mk GOLDILOCKS_PRIME_MINUS_1) == GF.mk 1,
    .test "sub: 0 - 1 = prime-1" <|
      gf_sub (GF.mk 0) (GF.mk 1) == GF.mk GOLDILOCKS_PRIME_MINUS_1,
    .test "pow7: 2^7 = 128" <|
      gf_pow7 (GF.mk 2) == GF.mk 128,
    .test "inverse: inv(2) * 2 = 1" <|
      gf_mul (gf_inv (GF.mk 2)) (GF.mk 2) == GF.mk 1,
    .test "batch_inverse consistency" <|
      let vals := #[GF.mk 2, GF.mk 3, GF.mk 7]
      let invs := batch_inverse vals
      (gf_mul invs[0]! (GF.mk 2) == GF.mk 1) &&
      (gf_mul invs[1]! (GF.mk 3) == GF.mk 1) &&
      (gf_mul invs[2]! (GF.mk 7) == GF.mk 1)
  ]
```

### Step 2: Run test to verify it fails

Run: `cd lean-verifier && lake build Tests.TestField && lake env lean --run Tests/TestField.lean`
Expected: Compilation fails — `Primitives.Field` module not found

### Step 3: Implement GF base field

Create `lean-verifier/Primitives/Field.lean`:

```lean
/-
  Goldilocks field GF(p) where p = 2^64 - 2^32 + 1.

  Translates: executable-spec/primitives/field.py:37-43
  Python: FF = galois.GF(GOLDILOCKS_PRIME)

  All arithmetic is modular. UInt64 wrapping arithmetic is used for
  intermediate computations, with explicit reduction modulo p.
-/
namespace Primitives.Field

/-- Goldilocks prime: 2^64 - 2^32 + 1 = 0xFFFFFFFF00000001 -/
def GOLDILOCKS_PRIME : UInt64 := 0xFFFFFFFF00000001
def GOLDILOCKS_PRIME_MINUS_1 : UInt64 := 0xFFFFFFFF00000000
def FIELD_EXTENSION_DEGREE : Nat := 3

/-- Base field element GF(p). -/
structure GF where
  val : UInt64
  deriving Repr, BEq, Hashable

/-- Reduce a UInt64 that may be >= p.
    Python equivalent: implicit in galois library. -/
@[inline] def gf_reduce (x : UInt64) : GF :=
  if x >= GOLDILOCKS_PRIME then GF.mk (x - GOLDILOCKS_PRIME)
  else GF.mk x

/-- Modular addition.
    Python: FF(a) + FF(b) -/
@[inline] def gf_add (a b : GF) : GF :=
  let sum := a.val + b.val  -- UInt64 wrapping add
  -- If overflow occurred or sum >= p, subtract p
  if sum < a.val || sum >= GOLDILOCKS_PRIME then
    GF.mk (sum - GOLDILOCKS_PRIME)
  else GF.mk sum

/-- Modular subtraction.
    Python: FF(a) - FF(b) -/
@[inline] def gf_sub (a b : GF) : GF :=
  if a.val >= b.val then GF.mk (a.val - b.val)
  else GF.mk (a.val - b.val + GOLDILOCKS_PRIME)  -- wrapping handles it

/-- Modular multiplication using 128-bit intermediate.
    Python: FF(a) * FF(b)
    Translates: poseidon2-ffi/src/lib.rs:88-90 (reduce function)

    The key insight: for Goldilocks p = 2^64 - 2^32 + 1:
    x mod p = rl - rh + rh * 2^32 (mod p)
    where x = rh * 2^64 + rl

    Since Lean 4 UInt64 is wrapping, we need to be careful with
    the reduction. We use the same algorithm as the Rust FFI. -/
-- NOTE: This requires either:
-- (a) Lean 4 UInt128 (not in stdlib), or
-- (b) FFI to C for mul+reduce, or
-- (c) Schoolbook multiplication with 32-bit limbs
-- For the initial implementation, use option (c):
def gf_mul (a b : GF) : GF :=
  -- Split into 32-bit halves: a = ah * 2^32 + al, b = bh * 2^32 + bl
  let al := a.val &&& 0xFFFFFFFF
  let ah := a.val >>> 32
  let bl := b.val &&& 0xFFFFFFFF
  let bh := b.val >>> 32
  -- Product terms (each fits in 64 bits since inputs are 32-bit)
  let ll := al * bl          -- low * low
  let lh := al * bh          -- low * high
  let hl := ah * bl          -- high * low
  let hh := ah * bh          -- high * high
  -- Accumulate into 128-bit result: [r3:r2:r1:r0] as 32-bit limbs
  -- result_low = ll + (lh_lo + hl_lo) << 32
  -- result_high = hh + (lh_hi + hl_hi) + carry
  let mid := lh + hl         -- may overflow, need carry
  let mid_carry : UInt64 := if mid < lh then 1 else 0
  let result_lo := ll + (mid <<< 32)
  let carry_lo : UInt64 := if result_lo < ll then 1 else 0
  let result_hi := hh + (mid >>> 32) + (mid_carry <<< 32) + carry_lo
  -- Now reduce: (result_hi * 2^64 + result_lo) mod p
  -- Using Goldilocks reduction from Rust lib.rs:39-73
  gf_reduce_128 result_lo result_hi

/-- Goldilocks reduction: (hi * 2^64 + lo) mod p.
    Direct translation of poseidon2-ffi/src/lib.rs:39-73 -/
def gf_reduce_128 (lo hi : UInt64) : GF :=
  let rhh := hi >>> 32
  let rhl := hi &&& 0xFFFFFFFF
  -- aux1 = lo - rhh (with borrow)
  let aux1 := lo - rhh
  let aux1 := if lo < rhh then aux1 - 0xFFFFFFFF else aux1
  -- aux = rhl * 0xFFFFFFFF
  let aux := 0xFFFFFFFF * rhl
  -- result = aux1 + aux
  let result := aux1 + aux
  let result := if result < aux1 then result + 0xFFFFFFFF else result
  -- Final reduction
  if result >= GOLDILOCKS_PRIME then GF.mk (result - GOLDILOCKS_PRIME)
  else GF.mk result

/-- x^7 (S-box for Poseidon2).
    Translates: poseidon2-ffi/src/lib.rs:94-99 -/
def gf_pow7 (x : GF) : GF :=
  let x2 := gf_mul x x
  let x3 := gf_mul x x2
  let x4 := gf_mul x2 x2
  gf_mul x3 x4

/-- Modular inverse via Fermat's little theorem: a^(-1) = a^(p-2) mod p.
    Python: galois handles this internally. -/
def gf_inv (a : GF) : GF :=
  gf_pow a (GOLDILOCKS_PRIME - 2)

/-- Modular exponentiation by repeated squaring.
    Python: a ** n (galois uses repeated squaring internally) -/
def gf_pow (base : GF) (exp : UInt64) : GF := Id.run do
  let mut result := GF.mk 1
  let mut b := base
  let mut e := exp
  while e > 0 do
    if e &&& 1 == 1 then
      result := gf_mul result b
    b := gf_mul b b
    e := e >>> 1
  return result

/-- Montgomery batch inversion.
    Translates: executable-spec/primitives/field.py:302-320
    Python: batch_inverse(values) -/
def batch_inverse (vals : Array GF) : Array GF := Id.run do
  let n := vals.size
  if n == 0 then return #[]
  -- Forward pass: accumulate products
  let mut partials : Array GF := Array.mkEmpty n
  let mut acc := GF.mk 1
  for i in [:n] do
    partials := partials.push acc
    acc := gf_mul acc vals[i]!
  -- Invert the accumulated product
  let mut inv_acc := gf_inv acc
  -- Backward pass: extract individual inverses
  let mut result := Array.mkArray n (GF.mk 0)
  for i' in [:n] do
    let i := n - 1 - i'
    result := result.set! i (gf_mul inv_acc partials[i]!)
    inv_acc := gf_mul inv_acc vals[i]!
  return result

end Primitives.Field
```

### Step 4: Run test to verify it passes

Run: `cd lean-verifier && lake build Tests.TestField && lake env lean --run Tests/TestField.lean`
Expected: All 8 tests PASS

### Step 5: Write failing tests for GF3 (cubic extension)

Add to `lean-verifier/Tests/TestField.lean`:

```lean
-- Known test vectors from Python:
-- FF3([1, 0, 0]) = 1 (base element embedded in extension)
-- FF3([0, 1, 0]) = x (generator of extension)
-- The irreducible polynomial is x^3 - x - 1

def gf3Tests : TestSeq :=
  .group "GF3 cubic extension" [
    .test "add: (1,0,0) + (0,1,0) = (1,1,0)" <|
      gf3_add (GF3.mk (GF.mk 1) (GF.mk 0) (GF.mk 0))
              (GF3.mk (GF.mk 0) (GF.mk 1) (GF.mk 0))
      == GF3.mk (GF.mk 1) (GF.mk 1) (GF.mk 0),
    .test "mul: (0,1,0) * (0,1,0) = (0,0,1) [x*x = x^2]" <|
      gf3_mul (GF3.mk (GF.mk 0) (GF.mk 1) (GF.mk 0))
              (GF3.mk (GF.mk 0) (GF.mk 1) (GF.mk 0))
      == GF3.mk (GF.mk 0) (GF.mk 0) (GF.mk 1),
    .test "mul: x^3 = x + 1 (irreducible poly)" <|
      -- x^3 mod (x^3 - x - 1) = x + 1
      let x := GF3.mk (GF.mk 0) (GF.mk 1) (GF.mk 0)
      let x2 := gf3_mul x x
      let x3 := gf3_mul x x2
      x3 == GF3.mk (GF.mk 1) (GF.mk 1) (GF.mk 0),
    .test "sub: (1,0,0) - (1,0,0) = (0,0,0)" <|
      gf3_sub (GF3.mk (GF.mk 1) (GF.mk 0) (GF.mk 0))
              (GF3.mk (GF.mk 1) (GF.mk 0) (GF.mk 0))
      == GF3.mk (GF.mk 0) (GF.mk 0) (GF.mk 0),
    .test "inverse: inv(x) * x = 1" <|
      let x := GF3.mk (GF.mk 0) (GF.mk 1) (GF.mk 0)
      let one := GF3.mk (GF.mk 1) (GF.mk 0) (GF.mk 0)
      gf3_mul (gf3_inv x) x == one
  ]
```

### Step 6: Implement GF3

Add to `lean-verifier/Primitives/Field.lean`:

```lean
/-- Cubic extension field element GF(p^3).
    Represents a + b*x + c*x^2 where x^3 = x + 1.
    Translates: executable-spec/primitives/field.py:47-51
    Python: FF3 = galois.GF(GOLDILOCKS_PRIME**3, irreducible_poly=x^3-x-1) -/
structure GF3 where
  c0 : GF  -- constant coefficient
  c1 : GF  -- x coefficient
  c2 : GF  -- x^2 coefficient
  deriving Repr, BEq, Hashable

/-- GF3 addition: component-wise. -/
@[inline] def gf3_add (a b : GF3) : GF3 :=
  GF3.mk (gf_add a.c0 b.c0) (gf_add a.c1 b.c1) (gf_add a.c2 b.c2)

/-- GF3 subtraction: component-wise. -/
@[inline] def gf3_sub (a b : GF3) : GF3 :=
  GF3.mk (gf_sub a.c0 b.c0) (gf_sub a.c1 b.c1) (gf_sub a.c2 b.c2)

/-- GF3 multiplication with reduction by x^3 = x + 1.
    (a0 + a1*x + a2*x^2)(b0 + b1*x + b2*x^2) mod (x^3 - x - 1)

    Direct expansion and reduction:
    x^3 → x + 1
    x^4 → x^2 + x
    So:
    c0 = a0*b0 + a1*b2 + a2*b1       (from x^3 = x+1, the +1 part)
    c1 = a0*b1 + a1*b0 + a1*b2 + a2*b1 + a2*b2   (x terms + x^3→x part)
    c2 = a0*b2 + a1*b1 + a2*b0 + a2*b2            (x^2 terms + x^4→x^2 part)

    Python: galois handles this via polynomial multiplication mod irr. poly. -/
def gf3_mul (a b : GF3) : GF3 :=
  -- Standard terms
  let a0b0 := gf_mul a.c0 b.c0
  let a0b1 := gf_mul a.c0 b.c1
  let a0b2 := gf_mul a.c0 b.c2
  let a1b0 := gf_mul a.c1 b.c0
  let a1b1 := gf_mul a.c1 b.c1
  let a1b2 := gf_mul a.c1 b.c2
  let a2b0 := gf_mul a.c2 b.c0
  let a2b1 := gf_mul a.c2 b.c1
  let a2b2 := gf_mul a.c2 b.c2
  -- Reduction: x^3 = x + 1, x^4 = x^2 + x
  -- cross = a1*b2 + a2*b1 (coefficient of x^3 before reduction)
  let cross := gf_add a1b2 a2b1
  -- top = a2*b2 (coefficient of x^4 before reduction)
  let top := a2b2
  GF3.mk
    (gf_add a0b0 cross)                          -- c0: +cross (from x^3→+1)
    (gf_add (gf_add a0b1 a1b0) (gf_add cross top))  -- c1: +cross (x^3→x) +top (x^4→x)
    (gf_add (gf_add a0b2 a1b1) (gf_add a2b0 top))   -- c2: +top (x^4→x^2)

/-- GF3 exponentiation by repeated squaring. -/
def gf3_pow (base : GF3) (exp : UInt64) : GF3 := Id.run do
  let mut result := GF3.mk (GF.mk 1) (GF.mk 0) (GF.mk 0)
  let mut b := base
  let mut e := exp
  while e > 0 do
    if e &&& 1 == 1 then
      result := gf3_mul result b
    b := gf3_mul b b
    e := e >>> 1
  return result

/-- GF3 inverse via Fermat: a^(-1) = a^(p^3 - 2).
    For efficiency, use the tower inversion formula instead. -/
def gf3_inv (a : GF3) : GF3 :=
  -- Use norm-based inversion (more efficient than p^3-2 exponentiation)
  -- norm(a) = a * a^p * a^(p^2) is in GF(p)
  -- a^(-1) = a^(p) * a^(p^2) / norm(a)
  -- For simplicity in the spec, use Frobenius:
  -- a^p: Frobenius endomorphism for x^3 - x - 1 over GF(p)
  -- This is equivalent to evaluating the polynomial at x^p
  -- For now, use brute-force p^3-2 exponentiation via repeated squaring
  -- (acceptable for a spec; optimize later if needed)
  sorry -- TODO: implement using tower inversion or Frobenius
```

**NOTE:** The `gf3_inv` implementation is non-trivial. The recommended approach for the spec is either:
1. Tower inversion (compute norm in base field, invert there, scale)
2. Extended Euclidean algorithm on polynomials mod the irreducible
3. Exponentiation to p^3-2 (correct but slow for spec purposes)

The implementer should use approach (1) for correctness and validate against Python test vectors.

### Step 7: Write tests for interleaved format conversion

```lean
-- Tests for interleaved FF3 format: [c0,c1,c2,c0,c1,c2,...]
-- Translates: executable-spec/primitives/field.py:137-158
def interleavedTests : TestSeq :=
  .group "Interleaved FF3" [
    .test "to_interleaved roundtrip" <|
      let elem := GF3.mk (GF.mk 1) (GF.mk 2) (GF.mk 3)
      let arr := gf3_to_interleaved #[elem]
      arr == #[1, 2, 3],
    .test "from_interleaved roundtrip" <|
      let arr : Array UInt64 := #[1, 2, 3, 4, 5, 6]
      let elems := gf3_from_interleaved arr
      elems.size == 2 &&
      elems[0]! == GF3.mk (GF.mk 1) (GF.mk 2) (GF.mk 3) &&
      elems[1]! == GF3.mk (GF.mk 4) (GF.mk 5) (GF.mk 6)
  ]
```

### Step 8: Implement interleaved conversion functions

```lean
/-- Convert GF3 array to interleaved [c0,c1,c2,c0,c1,c2,...].
    Translates: field.py:147-158 ff3_to_interleaved_numpy() -/
def gf3_to_interleaved (arr : Array GF3) : Array UInt64 := Id.run do
  let mut result := Array.mkEmpty (arr.size * 3)
  for elem in arr do
    result := result.push elem.c0.val
    result := result.push elem.c1.val
    result := result.push elem.c2.val
  return result

/-- Convert interleaved [c0,c1,c2,...] to GF3 array.
    Translates: field.py:139-144 ff3_from_interleaved_numpy() -/
def gf3_from_interleaved (arr : Array UInt64) : Array GF3 := Id.run do
  let n := arr.size / 3
  let mut result := Array.mkEmpty n
  for i in [:n] do
    result := result.push (GF3.mk
      (GF.mk arr[i * 3]!)
      (GF.mk arr[i * 3 + 1]!)
      (GF.mk arr[i * 3 + 2]!))
  return result

/-- Extract single GF3 from interleaved buffer at index.
    Translates: verifier.py:51-53 _get_challenge() -/
def get_interleaved_gf3 (arr : Array UInt64) (idx : Nat) : GF3 :=
  GF3.mk
    (GF.mk arr[idx * 3]!)
    (GF.mk arr[idx * 3 + 1]!)
    (GF.mk arr[idx * 3 + 2]!)
```

### Step 9: Add roots of unity table

```lean
/-- Precomputed roots of unity: W[i] = generator of the 2^i-th roots of unity subgroup.
    Translates: field.py:210-288 (W and W_INV tables)
    Python: W = [primitive_root^(2^32 / 2^i) for i in range(33)] -/
def W : Array UInt64 := #[
  1,                    -- W[0]  = 1
  18446744069414584320, -- W[1]  = p-1 (order 2)
  281474976710656,      -- W[2]  (order 4)
  -- ... (33 entries total, copy from field.py:210-255)
]

/-- Inverse roots of unity.
    Translates: field.py:260-288 (W_INV table) -/
def W_INV : Array UInt64 := #[
  1,
  18446744069414584320,
  18446744069414584319,
  -- ... (33 entries total, copy from field.py:260-288)
]

/-- Get omega (primitive root of unity) for domain of size 2^n_bits.
    Translates: field.py:289-293 get_omega() -/
def get_omega (n_bits : Nat) : GF := GF.mk W[n_bits]!

/-- Get inverse omega for domain of size 2^n_bits.
    Translates: field.py:294-299 get_omega_inv() -/
def get_omega_inv (n_bits : Nat) : GF := GF.mk W_INV[n_bits]!
```

### Step 10: Run all field tests, commit

Run: `cd lean-verifier && lake build Tests.TestField && lake env lean --run Tests/TestField.lean`
Expected: All tests PASS

```bash
git add lean-verifier/Primitives/Field.lean lean-verifier/Tests/TestField.lean
git commit -m "feat(lean): add Goldilocks GF and GF3 field arithmetic"
```

---

## Task 2: Poseidon2 FFI + Transcript

**Translates:**
- `executable-spec/primitives/poseidon2-ffi/src/lib.rs` → FFI bindings
- `executable-spec/primitives/transcript.py:1-155` → Pure Lean

**Files:**
- Create: `lean-verifier/FFI/Poseidon2.lean` (Lean extern declarations)
- Create: `lean-verifier/ffi/poseidon2_lean.c` (C wrapper around Rust .so)
- Create: `lean-verifier/Primitives/Transcript.lean`
- Test: `lean-verifier/Tests/TestTranscript.lean`

### Step 1: Create C wrapper header for Poseidon2

Create `lean-verifier/ffi/poseidon2_lean.h`:

```c
#ifndef POSEIDON2_LEAN_H
#define POSEIDON2_LEAN_H

#include <stdint.h>
#include <stdbool.h>

#define POSEIDON2_CAPACITY 4

// Full permutation: output must have space for `width` elements
int poseidon2_hash(const uint64_t *input, size_t width, uint64_t *output);

// Sponge hash: output must have space for CAPACITY elements
int poseidon2_linear_hash(const uint64_t *input, size_t input_len,
                          size_t width, uint64_t *output);

// Hash and return first CAPACITY elements
int poseidon2_hash_seq(const uint64_t *input, size_t width, uint64_t *output);

// PoW grinding
int poseidon2_grinding(const uint64_t *challenge, uint32_t pow_bits,
                       uint64_t *out_nonce);

// PoW verification
bool poseidon2_verify_grinding(const uint64_t *challenge, uint64_t nonce,
                               uint32_t pow_bits);

#endif
```

### Step 2: Implement C wrapper

Create `lean-verifier/ffi/poseidon2_lean.c`:

This wraps the Rust `poseidon2_ffi` shared library. The Rust library already compiles to a `.so`. We create a thin C shim that Lean's FFI can call.

**Alternative approach (recommended):** Compile the Rust Poseidon2 as a C-compatible library directly:
- Add `crate-type = ["cdylib", "staticlib"]` to `poseidon2-ffi/Cargo.toml`
- Add `#[no_mangle] pub extern "C" fn` wrappers in Rust
- This avoids a C intermediary entirely

The implementer should choose whichever approach is simpler to integrate with Lake.

### Step 3: Create Lean FFI declarations

Create `lean-verifier/FFI/Poseidon2.lean`:

```lean
/-
  FFI bindings to Poseidon2 hash (Goldilocks field).

  Translates: executable-spec/primitives/poseidon2-ffi/src/lib.rs
  The Rust implementation is used via C FFI.

  Functions exposed:
  - poseidon2_hash: full permutation (width 4/8/12/16)
  - linear_hash: sponge hash for variable-length input
  - hash_seq: permutation returning first 4 elements
  - verify_grinding: PoW verification
-/
namespace FFI.Poseidon2

def CAPACITY : Nat := 4

-- These are @[extern] declarations that bind to C functions.
-- The actual implementation is in ffi/poseidon2_lean.c (or Rust cdylib).

/-- Full Poseidon2 permutation.
    Python: poseidon2_hash(input_data, width) -/
@[extern "lean_poseidon2_hash"]
opaque poseidon2_hash (input : @& Array UInt64) (width : UInt64) : Array UInt64

/-- Sponge hash for variable-length input. Returns CAPACITY elements.
    Python: linear_hash(input_data, width) -/
@[extern "lean_poseidon2_linear_hash"]
opaque linear_hash (input : @& Array UInt64) (width : UInt64) : Array UInt64

/-- Hash and return first CAPACITY elements.
    Python: hash_seq(input_data, width) -/
@[extern "lean_poseidon2_hash_seq"]
opaque hash_seq (input : @& Array UInt64) (width : UInt64) : Array UInt64

/-- Verify grinding nonce.
    Python: verify_grinding(challenge, nonce, pow_bits) -/
@[extern "lean_poseidon2_verify_grinding"]
opaque verify_grinding (challenge : @& Array UInt64) (nonce : UInt64)
  (pow_bits : UInt32) : Bool

end FFI.Poseidon2
```

### Step 4: Write failing transcript tests

Create `lean-verifier/Tests/TestTranscript.lean`:

```lean
import LSpec
import Primitives.Transcript

open LSpec Primitives.Transcript

-- Test vectors derived from Python:
-- t = Transcript(arity=4)
-- t.put([1, 2, 3, 4])
-- challenge = t.get_field()
-- (run in Python to get exact values)

def main : IO UInt32 := lspecIO <|
  .group "Transcript" [
    .test "empty transcript get_field deterministic" <|
      -- Two transcripts with same input should produce same challenge
      let t1 := Transcript.new 4 false
      let t2 := Transcript.new 4 false
      let (c1, _) := t1.put #[1, 2, 3, 4] |>.get_field
      let (c2, _) := t2.put #[1, 2, 3, 4] |>.get_field
      c1 == c2,
    .test "different input produces different challenge" <|
      let t1 := Transcript.new 4 false |>.put #[1, 2, 3, 4]
      let t2 := Transcript.new 4 false |>.put #[5, 6, 7, 8]
      let (c1, _) := t1.get_field
      let (c2, _) := t2.get_field
      c1 != c2
    -- More tests will use Python-generated test vectors
  ]
```

### Step 5: Implement Transcript

Create `lean-verifier/Primitives/Transcript.lean`:

```lean
/-
  Fiat-Shamir transcript using Poseidon2 sponge.

  Translates: executable-spec/primitives/transcript.py:1-155

  The transcript absorbs field elements and squeezes challenges.
  It uses a Poseidon2 sponge with configurable arity.

  Key behavior:
  - Arity determines sponge width: arity=2 → width=8, arity=3 → width=12, arity=4 → width=16
  - Rate = width - CAPACITY (absorb this many elements per permutation)
  - Squeeze reads in reverse order (C++ compatibility)
-/
namespace Primitives.Transcript

open FFI.Poseidon2

/-- Transcript state.
    Translates: transcript.py:27-47 Transcript.__init__ -/
structure Transcript where
  width : Nat           -- Sponge width (8, 12, or 16)
  rate : Nat            -- width - CAPACITY
  state : Array UInt64  -- Current sponge state
  pos : Nat             -- Current position in rate portion
  custom : Bool         -- Custom Merkle tree mode

/-- Create a new transcript.
    Translates: transcript.py:28-47 -/
def Transcript.new (arity : Nat) (custom : Bool) : Transcript :=
  let width := (arity + 1) * CAPACITY
  { width := width
    rate := width - CAPACITY
    state := Array.mkArray width 0
    pos := 0
    custom := custom }

/-- Absorb field elements into the transcript.
    Translates: transcript.py:49-75 put() -/
def Transcript.put (t : Transcript) (values : Array UInt64) : Transcript := Id.run do
  let mut state := t.state
  let mut pos := t.pos
  for v in values do
    state := state.set! pos v
    pos := pos + 1
    if pos == t.rate then
      state := poseidon2_hash state t.width.toUInt64
      pos := 0
  return { t with state := state, pos := pos }

/-- Squeeze a single field element from the transcript.
    Translates: transcript.py:77-95 get_field()
    NOTE: reads in reverse order for C++ compatibility -/
def Transcript.get_field (t : Transcript) : UInt64 × Transcript :=
  -- If we haven't squeezed yet, permute first
  let state := if t.pos > 0 then
    poseidon2_hash t.state t.width.toUInt64
  else t.state
  -- Read from capacity portion (indices width-CAPACITY to width-1)
  -- In reverse order per C++ convention
  let idx := t.width - 1  -- Start from last element
  let value := state[idx]!
  (value, { t with state := state, pos := 0 })

/-- Get transcript state (3 GF3 challenges = 9 base elements).
    Translates: transcript.py:97-125 get_state() -/
def Transcript.get_state (t : Transcript) : Array UInt64 × Transcript :=
  sorry -- Full implementation following transcript.py:97-125

/-- Get permutation indices for FRI queries.
    Translates: transcript.py:127-155 get_permutations() -/
def Transcript.get_permutations (t : Transcript) (n_queries : Nat) (n_bits : Nat)
    : Array Nat × Transcript :=
  sorry -- Full implementation following transcript.py:127-155

end Primitives.Transcript
```

### Step 6: Run tests, commit

Run: `cd lean-verifier && lake build Tests.TestTranscript && lake env lean --run Tests/TestTranscript.lean`
Expected: PASS

```bash
git add lean-verifier/FFI/ lean-verifier/ffi/ lean-verifier/Primitives/Transcript.lean lean-verifier/Tests/TestTranscript.lean
git commit -m "feat(lean): add Poseidon2 FFI and Fiat-Shamir transcript"
```

---

## Task 3: Merkle Verifier + Polynomial Utils

**Translates:**
- `executable-spec/primitives/merkle_verifier.py:1-356` → Pure Lean
- `executable-spec/primitives/polynomial.py:1-132` → Pure Lean (verifier subset)

**Files:**
- Create: `lean-verifier/Primitives/MerkleVerifier.lean`
- Create: `lean-verifier/Primitives/Polynomial.lean`
- Test: `lean-verifier/Tests/TestMerkle.lean`
- Test: `lean-verifier/Tests/TestPolynomial.lean`

### Step 1: Write Merkle verifier tests

Test vectors should be generated from Python by running:
```python
from primitives.merkle_verifier import MerkleVerifier, MerkleConfig
# Create a small tree and extract a proof, then verify
```

### Step 2: Implement MerkleVerifier

```lean
/-
  Merkle tree verification using Poseidon2.

  Translates: executable-spec/primitives/merkle_verifier.py:1-356

  Key concepts:
  - MerkleConfig: arity, domain_bits, last_level_verification
  - verify_query: verify a single leaf's Merkle path
  - last_level_verification: optimization that embeds bottom tree levels
    in the proof, verified separately via verifyMerkleRoot
-/
namespace Primitives.MerkleVerifier

-- Structure definitions following merkle_verifier.py:33-68

structure MerkleConfig where
  arity : Nat
  domain_bits : Nat
  last_level_verification : Nat
  custom : Bool
  deriving Repr

structure MerkleVerifier where
  config : MerkleConfig
  n_cols : Nat
  n_field_elements : Nat  -- HASH_SIZE = 4

-- Factory methods: for_stage, for_const, for_custom_commit, for_fri_step
-- Each corresponds to merkle_verifier.py:72-168

-- verify_query: merkle_verifier.py:170-280
-- verify_merkle_root: merkle_verifier.py:282-356

end Primitives.MerkleVerifier
```

### Step 3: Implement polynomial utilities (verifier subset)

```lean
/-
  Polynomial operations (verifier subset).

  Translates: executable-spec/primitives/polynomial.py:92-132
  The verifier only needs to_coefficients_cubic (INTT for final polynomial check).
-/
namespace Primitives.Polynomial

/-- Convert evaluations to coefficients using INTT.
    Translates: polynomial.py:92-123 to_coefficients_cubic() -/
def to_coefficients_cubic (evals : Array Primitives.Field.GF3) (n_bits : Nat)
    : Array Primitives.Field.GF3 :=
  sorry -- INTT implementation using roots of unity from Field.lean

end Primitives.Polynomial
```

### Step 4: Run tests, commit

```bash
git add lean-verifier/Primitives/MerkleVerifier.lean lean-verifier/Primitives/Polynomial.lean lean-verifier/Tests/
git commit -m "feat(lean): add Merkle verifier and polynomial INTT"
```

---

## Task 4: StarkInfo + PolMap (Config Parsing)

**Translates:**
- `executable-spec/protocol/stark_info.py:1-471` → Pure Lean
- `executable-spec/primitives/pol_map.py:1-168` → Pure Lean

**Files:**
- Create: `lean-verifier/Primitives/PolMap.lean`
- Create: `lean-verifier/Protocol/StarkInfo.lean`
- Test: `lean-verifier/Tests/TestStarkInfo.lean`

### Step 1: Implement PolMap structures

```lean
/-
  Polynomial map types.

  Translates: executable-spec/primitives/pol_map.py:1-168

  These are the data structures that describe the AIR:
  - PolynomialId: identifies a polynomial by (type, name, index, stage)
  - EvMap: describes where a polynomial is evaluated (which opening point)
  - PolMap: describes polynomial layout in committed buffers
  - ChallengeMap: describes Fiat-Shamir challenges
-/
namespace Primitives.PolMap

/-- Polynomial identifier. Key for looking up polynomial values.
    Translates: pol_map.py:17-35 -/
structure PolynomialId where
  type : String    -- "cm" (committed), "const", "custom", "q" (quotient)
  name : String    -- column name (e.g., "a", "gsum")
  index : Nat      -- column index within group
  stage : Nat      -- protocol stage number
  deriving Repr, BEq, Hashable

/-- Field element type (base or extension). -/
inductive FieldType where
  | base : FieldType       -- dim = 1
  | extension : FieldType  -- dim = 3
  deriving Repr, BEq

-- ... (PolMap, EvMap, ChallengeMap, CustomCommits, Boundary)
-- Direct 1:1 translation of pol_map.py structures

end Primitives.PolMap
```

### Step 2: Implement StarkInfo JSON parser

```lean
/-
  StarkInfo configuration loaded from starkinfo.json.

  Translates: executable-spec/protocol/stark_info.py:1-471

  This is a large configuration structure that describes the STARK:
  - Proof structure parameters (n_bits, n_queries, FRI steps, etc.)
  - Polynomial maps (which columns, their types, offsets)
  - Evaluation map (which polynomials are opened at which points)
  - Challenge map (Fiat-Shamir challenge ordering)

  All parsing uses Lean.Json (built-in JSON support).
-/
namespace Protocol.StarkInfo

open Lean (Json)

structure FriFoldStep where
  n_bits : Nat
  domain_bits : Nat
  deriving Repr

structure StarkStruct where
  n_bits : Nat
  n_bits_ext : Nat
  n_queries : Nat
  pow_bits : Nat
  fri_fold_steps : Array FriFoldStep
  merkle_tree_arity : Nat
  merkle_tree_custom : Bool
  transcript_arity : Nat
  last_level_verification : Nat
  deriving Repr

structure StarkInfo where
  stark_struct : StarkStruct
  n_stages : Nat
  n_constants : Nat
  -- ... all fields from stark_info.py:63-108
  deriving Repr

/-- Load StarkInfo from JSON file.
    Translates: stark_info.py:109-117 from_json() -/
def StarkInfo.from_json (path : System.FilePath) : IO StarkInfo := do
  let contents ← IO.FS.readFile path
  match Json.parse contents with
  | .ok json => parse_starkinfo json
  | .error e => throw (IO.userError s!"JSON parse error: {e}")

end Protocol.StarkInfo
```

### Step 3: Test against actual starkinfo.json files

```lean
-- Load a real starkinfo.json and verify parsed values
def main : IO UInt32 := lspecIO <|
  .group "StarkInfo" [
    .test "parse SimpleLeft starkinfo" do
      let si ← StarkInfo.from_json "test-data/SimpleLeft.starkinfo.json"
      pure (si.stark_struct.n_bits == 3 && si.n_stages == 2)
  ]
```

### Step 4: Commit

```bash
git add lean-verifier/Primitives/PolMap.lean lean-verifier/Protocol/StarkInfo.lean lean-verifier/Tests/
git commit -m "feat(lean): add StarkInfo parser and PolMap types"
```

---

## Task 5: VerifierData + AirConfig

**Translates:**
- `executable-spec/protocol/data.py:71-91` → Pure Lean
- `executable-spec/protocol/air_config.py:259-309` → Pure Lean (verifier subset)

**Files:**
- Create: `lean-verifier/Protocol/Data.lean`
- Create: `lean-verifier/Protocol/AirConfig.lean`
- Test: `lean-verifier/Tests/TestData.lean`

### Step 1: Implement VerifierData

```lean
/-
  Verifier data structures.

  Translates: executable-spec/protocol/data.py:71-91

  VerifierData provides dict-based storage for constraint evaluation.
  The constraint module accesses polynomial evaluations by name.
-/
namespace Protocol.Data

open Primitives.Field

/-- Verifier-side data for constraint evaluation.
    Translates: data.py:71-91 -/
structure VerifierData where
  evals : Std.HashMap (String × Nat × Nat) GF3  -- (name, index, offset) → eval
  challenges : Std.HashMap String GF3            -- challenge_name → value
  airgroup_values : Std.HashMap Nat GF3          -- index → value
  publics_flat : Array UInt64                     -- public inputs (base field)
  air_values_flat : Array UInt64                  -- AIR-specific values

end Protocol.Data
```

### Step 2: Implement AirConfig (verifier subset)

```lean
/-
  AIR configuration bundle.

  Translates: executable-spec/protocol/air_config.py:259-309
  Only the verifier-relevant parts (no ProverHelpers).
-/
namespace Protocol.AirConfig

/-- AIR configuration combining StarkInfo with optional GlobalInfo.
    Translates: air_config.py:259-309 -/
structure AirConfig where
  stark_info : Protocol.StarkInfo.StarkInfo
  airgroup_id : Nat
  air_id : Nat

/-- Load AirConfig from starkinfo.json file.
    Translates: air_config.py:285-309 from_starkinfo() -/
def AirConfig.from_starkinfo (path : System.FilePath) : IO AirConfig := do
  let si ← Protocol.StarkInfo.StarkInfo.from_json path
  return { stark_info := si, airgroup_id := 0, air_id := 0 }

end Protocol.AirConfig
```

### Step 3: Commit

```bash
git add lean-verifier/Protocol/Data.lean lean-verifier/Protocol/AirConfig.lean
git commit -m "feat(lean): add VerifierData and AirConfig"
```

---

## Task 6: Proof Deserialization

**Translates:** `executable-spec/protocol/proof.py:44-376` → Pure Lean (binary parsing)

**Files:**
- Create: `lean-verifier/Protocol/Proof.lean`
- Test: `lean-verifier/Tests/TestProof.lean`

### Step 1: Write test loading a real binary proof

```lean
-- Test: load SimpleLeft.proof.bin, verify parsed structure
def main : IO UInt32 := lspecIO <|
  .group "Proof" [
    .test "parse SimpleLeft binary proof" do
      let bytes ← IO.FS.readBinFile "test-data/SimpleLeft.proof.bin"
      let si ← Protocol.StarkInfo.StarkInfo.from_json "test-data/SimpleLeft.starkinfo.json"
      let proof := Protocol.Proof.from_bytes_full bytes si
      -- Verify non-empty sections
      pure (proof.stage_trees.size > 0 && proof.evals.size > 0)
  ]
```

### Step 2: Implement proof structures

```lean
/-
  STARK proof data structures and binary deserialization.

  Translates: executable-spec/protocol/proof.py:1-376

  Binary proof format (13 sections):
  1. airgroup_values     5. const_tree_proof    9. FRI queries
  2. air_values          6. custom_commit_proofs 10. final_pol
  3. roots (per stage)   7. stage_tree_proofs   11. nonce (PoW)
  4. evals               8. FRI roots

  All multi-byte values are little-endian uint64.
-/
namespace Protocol.Proof

/-- Merkle proof for a single query. -/
structure MerkleProof where
  values : Array UInt64     -- leaf values
  siblings : Array (Array UInt64)  -- path siblings

/-- Per-stage proof tree (root + Merkle proofs per query). -/
structure ProofTree where
  root : Array UInt64       -- Merkle root (HASH_SIZE elements)
  proofs : Array MerkleProof

/-- FRI layer proof. -/
structure FriProof where
  root : Array UInt64
  proofs : Array MerkleProof

/-- Complete STARK proof.
    Translates: proof.py:44-75 -/
structure STARKProof where
  airgroup_values : Array UInt64
  air_values : Array UInt64
  evals : Array UInt64
  stage_trees : Array ProofTree
  const_tree : ProofTree
  custom_commit_trees : Array ProofTree
  fri_proofs : Array FriProof
  final_pol : Array UInt64
  nonce : UInt64

/-- Parse binary proof.
    Translates: proof.py:180-376 from_bytes_full()

    Key: uses ByteArray.toUInt64LE! for each 8-byte chunk. -/
def from_bytes_full (data : ByteArray) (si : Protocol.StarkInfo.StarkInfo)
    : STARKProof :=
  sorry -- Binary parsing implementation

end Protocol.Proof
```

### Step 3: Run test, commit

```bash
git add lean-verifier/Protocol/Proof.lean lean-verifier/Tests/TestProof.lean
git commit -m "feat(lean): add binary proof deserialization"
```

---

## Task 7: FRI Verification

**Translates:** `executable-spec/protocol/fri.py:1-130` → Pure Lean

**Files:**
- Create: `lean-verifier/Protocol/FRI.lean`
- Test: `lean-verifier/Tests/TestFRI.lean`

### Step 1: Write FRI fold verification test

Test vectors from Python (generate with `tests/create-test-vectors.py`).

### Step 2: Implement FRI

```lean
/-
  FRI (Fast Reed-Solomon IOP of Proximity) verification.

  Translates: executable-spec/protocol/fri.py:1-130

  The verifier checks:
  1. FRI folding: recompute folded value from siblings and challenge
  2. Consistency: folded values match committed values in next layer
  3. Final polynomial: degree bound check via INTT
-/
namespace Protocol.FRI

open Primitives.Field

/-- Verify a single FRI folding step.
    Translates: fri.py:72-130 verify_fold()

    Given siblings at a query position, recompute the folded value
    using the FRI challenge and verify it matches the committed value
    in the next FRI layer. -/
def verify_fold (step : Nat) (n_bits_ext : Nat) (step_bits : Nat)
    (prev_step_bits : Nat) (challenge : GF3) (idx : Nat)
    (values : Array UInt64) : GF3 :=
  sorry -- Implementation following fri.py:72-130

end Protocol.FRI
```

### Step 3: Run tests, commit

```bash
git add lean-verifier/Protocol/FRI.lean lean-verifier/Tests/TestFRI.lean
git commit -m "feat(lean): add FRI fold verification"
```

---

## Task 8: Main Verifier

**Translates:** `executable-spec/protocol/verifier.py:1-995` → Pure Lean

This is the final assembly task. All dependencies are in place.

**Files:**
- Create: `lean-verifier/Protocol/Verifier.lean`
- Test: `lean-verifier/Tests/TestVerifier.lean`

### Step 1: Write E2E test

```lean
/-
  End-to-end verifier test: load a real proof and verify it.
  Translates: executable-spec/tests/test_verifier_e2e.py
-/

def main : IO UInt32 := lspecIO <|
  .group "Verifier E2E" [
    .test "SimpleLeft valid proof" do
      let proof_bytes ← IO.FS.readBinFile "test-data/SimpleLeft.proof.bin"
      let si ← Protocol.StarkInfo.StarkInfo.from_json "test-data/SimpleLeft.starkinfo.json"
      let proof := Protocol.Proof.from_bytes_full proof_bytes si
      let config := Protocol.AirConfig.AirConfig.from_starkinfo "test-data/SimpleLeft.starkinfo.json"
      let verkey := load_verkey "test-data/SimpleLeft.verkey"
      let result := Protocol.Verifier.stark_verify proof config verkey none none none
      pure result,  -- Should be true
    .test "Lookup2_12 valid proof" do
      -- Same pattern for Lookup2_12
      sorry,
    .test "corrupted root fails" do
      -- Modify a root byte and verify it returns false
      sorry
  ]
```

### Step 2: Implement stark_verify

```lean
/-
  STARK proof verification.

  Translates: executable-spec/protocol/verifier.py:1-995

  This is the main entry point. Verification phases:
  1. Parse proof components (evals, air values)
  2. Reconstruct Fiat-Shamir transcript to derive challenges
  3. Verify grinding
  4. Derive FRI query indices
  5. Run verification checks:
     a. Q(xi) = C(xi): quotient matches constraint evaluation
     b. FRI consistency
     c. Stage Merkle trees
     d. Constant Merkle tree
     e. Custom commit Merkle trees
     f. FRI layer Merkle trees
     g. FRI folding correctness
     h. Final polynomial degree bound
-/
namespace Protocol.Verifier

open Primitives.Field
open Primitives.Transcript
open Primitives.MerkleVerifier

/-- Verify a STARK proof. Returns true if valid.
    Translates: verifier.py:58-172 stark_verify() -/
def stark_verify
    (proof : Protocol.Proof.STARKProof)
    (air_config : Protocol.AirConfig.AirConfig)
    (verkey : Array UInt64)
    (global_challenge : Option (Array UInt64))
    (publics : Option (Array UInt64))
    (proof_values : Option (Array UInt64))
    : Bool :=
  let si := air_config.stark_info
  let ss := si.stark_struct

  -- Phase 1: Parse proof components (verifier.py:81-83)
  let evals := parse_evals proof si
  let airgroup_values := parse_airgroup_values proof si

  -- Phase 2: Reconstruct transcript (verifier.py:85)
  let challenges := reconstruct_transcript proof si global_challenge verkey publics

  -- Phase 3: Verify PoW (verifier.py:88-92)
  let grinding_idx := si.challenges_map.size + ss.fri_fold_steps.size
  let grinding_challenge := get_interleaved_gf3 challenges grinding_idx
  if !(FFI.Poseidon2.verify_grinding
    #[grinding_challenge.c0.val, grinding_challenge.c1.val, grinding_challenge.c2.val]
    proof.nonce ss.pow_bits.toUInt32) then
    return false

  -- Phase 4: FRI queries (verifier.py:95-98)
  let transcript_perm := Transcript.new ss.transcript_arity ss.merkle_tree_custom
  let transcript_perm := transcript_perm
    |>.put #[grinding_challenge.c0.val, grinding_challenge.c1.val, grinding_challenge.c2.val]
    |>.put #[proof.nonce]
  let (fri_queries, _) := transcript_perm.get_permutations ss.n_queries ss.fri_fold_steps[0]!.domain_bits

  -- Phase 5: Verification checks (verifier.py:108-172)
  let mut is_valid := true

  -- Check a: Q(xi) = C(xi)
  -- ... (translate verifier.py:110-129)

  -- Check b: FRI consistency
  -- ... (translate verifier.py:131-139)

  -- Checks c-g: Merkle trees
  -- ... (translate verifier.py:141-163)

  -- Check h: Final polynomial
  -- ... (translate verifier.py:165-171)

  is_valid

-- Private helper functions follow, each translating one function from verifier.py

/-- Translates: verifier.py:174-176 -/
private def parse_evals (proof : Protocol.Proof.STARKProof) (si : Protocol.StarkInfo.StarkInfo)
    : Array UInt64 := proof.evals

/-- Translates: verifier.py:382-484 -/
private def reconstruct_transcript
    (proof : Protocol.Proof.STARKProof) (si : Protocol.StarkInfo.StarkInfo)
    (global_challenge : Option (Array UInt64)) (verkey : Array UInt64)
    (publics : Option (Array UInt64))
    : Array UInt64 :=
  sorry -- Full transcript reconstruction following verifier.py

-- ... (remaining ~15 private helper functions)

end Protocol.Verifier
```

### Step 3: Run E2E test, commit

Run: `cd lean-verifier && lake build Tests.TestVerifier && lake env lean --run Tests/TestVerifier.lean`
Expected: SimpleLeft PASS

```bash
git add lean-verifier/Protocol/Verifier.lean lean-verifier/Tests/TestVerifier.lean
git commit -m "feat(lean): add STARK verifier with E2E tests"
```

---

## Task 9: Constraint Evaluation FFI

**Translates:** `executable-spec/constraints/` → FFI to C++ bytecode evaluator

**Files:**
- Create: `lean-verifier/FFI/Constraints.lean` (Lean extern declarations)
- Create: `lean-verifier/ffi/constraints_lean.cpp` (C wrapper around C++ evaluator)
- Create: `lean-verifier/ffi/constraints_lean.h`
- Test: `lean-verifier/Tests/TestConstraints.lean`

### Step 1: Design the C API

The constraint evaluator needs these inputs:
- Path to `.bin` bytecode file
- Evaluation point (xi as 3 uint64s)
- Polynomial evaluations (interleaved FF3)
- Challenge values (interleaved FF3)
- Public inputs, airgroup values, air values

```c
// constraints_lean.h
#ifndef CONSTRAINTS_LEAN_H
#define CONSTRAINTS_LEAN_H

#include <stdint.h>

// Evaluate constraint polynomial at a single point (verifier mode).
// Returns 3 uint64s (GF3 result) written to `output`.
int constraint_evaluate_verifier(
    const char *bytecode_path,    // Path to .bin file
    const uint64_t *evals,        // Polynomial evaluations (interleaved FF3)
    size_t n_evals,               // Number of evaluation entries
    const uint64_t *challenges,   // Challenge values (interleaved FF3)
    size_t n_challenges,          // Number of challenges
    const uint64_t *publics,      // Public inputs
    size_t n_publics,
    const uint64_t *airgroup_values, // Airgroup accumulated values
    size_t n_airgroup_values,
    const uint64_t *air_values,   // AIR-specific values
    size_t n_air_values,
    const uint64_t *x_div_x_sub, // Precomputed x/(x-xi) values
    size_t n_x_div_x_sub,
    uint64_t *output              // Result: 3 uint64s (GF3)
);

#endif
```

### Step 2: Implement C++ wrapper

This calls into the existing `ExpressionsPack::calculateExpressions` from pil2-stark.

### Step 3: Create Lean FFI bindings

```lean
namespace FFI.Constraints

/-- Evaluate constraint polynomial at verifier evaluation point.
    Translates: constraints/bytecode_adapter.py BytecodeConstraintModule -/
@[extern "lean_constraint_evaluate_verifier"]
opaque evaluate_verifier
    (bytecode_path : @& String)
    (evals : @& Array UInt64)
    (challenges : @& Array UInt64)
    (publics : @& Array UInt64)
    (airgroup_values : @& Array UInt64)
    (air_values : @& Array UInt64)
    (x_div_x_sub : @& Array UInt64)
    : Array UInt64  -- 3 elements: c0, c1, c2

end FFI.Constraints
```

### Step 4: Test against Python-generated vectors, commit

```bash
git add lean-verifier/FFI/Constraints.lean lean-verifier/ffi/constraints_lean.*
git commit -m "feat(lean): add constraint evaluator FFI"
```

---

## Task 10: Project Scaffolding (Do This First!)

**This task should be done BEFORE Task 1.** It sets up the Lean 4 project structure.

**Files:**
- Create: `lean-verifier/lakefile.lean`
- Create: `lean-verifier/lean-toolchain`
- Create: `lean-verifier/LeanVerifier.lean` (root module)

### Step 1: Initialize Lean 4 project

```bash
# Install elan if not present
curl https://elan.lean-lang.org/elan-init.sh -sSf | sh

# Create project
mkdir -p lean-verifier && cd lean-verifier
lake init LeanVerifier
```

### Step 2: Configure lakefile.lean

```lean
import Lake
open Lake DSL

package LeanVerifier where
  -- Package-level config
  moreLinkArgs := #[
    "-L", "ffi",
    "-lposeidon2_lean"
  ]

@[default_target]
lean_lib Primitives where
  srcDir := "."

lean_lib Protocol where
  srcDir := "."

lean_lib FFI where
  srcDir := "."

-- FFI C library for Poseidon2
extern_lib poseidon2_lean pkg := do
  let src := pkg.dir / "ffi" / "poseidon2_lean.c"
  let obj := pkg.buildDir / "ffi" / "poseidon2_lean.o"
  buildO obj src #["-I", (pkg.dir / "ffi").toString] #[]

-- Test executables
lean_exe TestField where
  root := `Tests.TestField

lean_exe TestTranscript where
  root := `Tests.TestTranscript

lean_exe TestVerifier where
  root := `Tests.TestVerifier

-- LSpec dependency for testing
require LSpec from git
  "https://github.com/argumentcomputer/LSpec" @ "main"
```

### Step 3: Create directory structure

```bash
mkdir -p Primitives Protocol FFI Tests ffi
```

### Step 4: Create root module

Create `lean-verifier/LeanVerifier.lean`:

```lean
/-
  Lean 4 STARK Verifier Specification.

  A faithful translation of the Python executable spec
  (executable-spec/protocol/verifier.py and dependencies).

  Module structure mirrors the Python package:
    Primitives/ → primitives/ (field, transcript, Merkle, polynomial)
    Protocol/   → protocol/  (verifier, FRI, proof, stark_info)
    FFI/        → poseidon2-ffi/ + constraint evaluator C++ bindings
-/
```

### Step 5: Verify project builds

```bash
cd lean-verifier && lake build
```

### Step 6: Commit

```bash
git add lean-verifier/
git commit -m "feat(lean): initialize Lean 4 verifier project scaffold"
```

---

## Execution Order Summary

```
Task 10 (scaffold)          ~15 min
  ↓
Task 1 (field arithmetic)   ~2 hours (most complex primitive)
  ↓
Task 2 (poseidon2 + transcript)  ~1.5 hours (FFI setup is fiddly)
  ↓
Task 3 (merkle + polynomial)     ~1.5 hours
  ↓
┌─────────────────────────────────┐
│ Task 4 (starkinfo)       ~1 hr │
│ Task 5 (data/airconfig)  ~30m  │  ← Can be done in parallel
│ Task 6 (proof parsing)   ~1 hr │
└─────────────────────────────────┘
  ↓
Task 7 (FRI)                ~1 hour
  ↓
Task 8 (verifier)           ~2 hours (assembly + debugging)
  ↓
Task 9 (constraint FFI)     ~1.5 hours (C++ integration)
```

## Validation Strategy

After each task, run the corresponding test suite. After Task 8, verify against all 3 AIR proofs:
1. **SimpleLeft** (8 rows, no FRI folding) — simplest
2. **Lookup2_12** (4096 rows, FRI folding) — exercises full path
3. **Permutation1_6** (64 rows, FRI folding) — another FRI test

The test data files (`*.proof.bin`, `*.starkinfo.json`) from `executable-spec/tests/test-data/` should be copied or symlinked into `lean-verifier/test-data/`.

## Key Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| GF3 multiplication formula wrong | Validate against Python `FF3([0,1,0]) * FF3([0,1,0])` test vectors |
| Poseidon2 FFI linking issues | Start with pure Lean Poseidon2 (translate Rust), add FFI later |
| Binary proof parsing off-by-one | Compare parsed values byte-by-byte against Python `from_bytes_full` |
| Lean UInt64 overflow semantics | Lean UInt64 is modular (wrapping), same as Goldilocks arithmetic |
| Transcript challenge mismatch | Generate Python transcript trace with known inputs, compare |
