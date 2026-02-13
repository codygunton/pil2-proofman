/-
  FFI bindings to Poseidon2 hash (Goldilocks field).

  Translates: executable-spec/primitives/poseidon2-ffi/src/lib.rs

  These are @[extern] opaque declarations that will link against a C library
  implementing Poseidon2 over the Goldilocks field. The library is not yet
  compiled, so these declarations will typecheck but cannot be executed.

  The C API is expected to provide:
    lean_poseidon2_hash         -- full permutation
    lean_poseidon2_linear_hash  -- sponge-based variable-length hash
    lean_poseidon2_hash_seq     -- permutation returning only capacity elements
    lean_poseidon2_verify_grinding -- proof-of-work verification
-/
namespace FFI.Poseidon2

/-- Capacity (and hash output size): 4 Goldilocks field elements. -/
def CAPACITY : Nat := 4

/-- Hash output size in field elements (= CAPACITY). -/
def HASH_SIZE : Nat := 4

/-- Supported sponge widths: 4, 8, 12, 16 (= CAPACITY * arity for arity in {1,2,3,4}). -/
def SUPPORTED_WIDTHS : List Nat := [4, 8, 12, 16]

/-- Full Poseidon2 permutation.

    Applies the Poseidon2 permutation to `input`, which must have exactly `width`
    elements. Returns an array of `width` field elements.

    Supported widths: 4, 8, 12, 16.

    Translates: `poseidon2_hash` in lib.rs (lines 241-257). -/
@[extern "lean_poseidon2_hash"]
opaque poseidon2Hash (input : @& Array UInt64) (width : UInt64) : Array UInt64

/-- Sponge-based variable-length hash.

    Hashes variable-length `input` using Poseidon2 sponge construction with the
    given `width`. Returns CAPACITY (4) field elements.

    If `input` fits within CAPACITY elements, returns input zero-padded to CAPACITY.
    Otherwise absorbs in rate-sized chunks and squeezes.

    Translates: `linear_hash` in lib.rs (lines 267-319). -/
@[extern "lean_poseidon2_linear_hash"]
opaque linearHash (input : @& Array UInt64) (width : UInt64) : Array UInt64

/-- Permutation returning only capacity elements.

    Applies full Poseidon2 permutation and returns first CAPACITY (4) elements.
    Input must have exactly `width` elements.

    Translates: `hash_seq` in lib.rs (lines 322-327). -/
@[extern "lean_poseidon2_hash_seq"]
opaque hashSeq (input : @& Array UInt64) (width : UInt64) : Array UInt64

/-- Verify a proof-of-work nonce.

    Checks that hash(challenge || nonce)[0] < 2^(64 - powBits).
    Challenge must have exactly 3 elements (width-1 for width=4).

    Translates: `verify_grinding` in lib.rs (lines 380-398). -/
@[extern "lean_poseidon2_verify_grinding"]
opaque verifyGrinding (challenge : @& Array UInt64) (nonce : UInt64) (powBits : UInt32) : Bool

end FFI.Poseidon2
