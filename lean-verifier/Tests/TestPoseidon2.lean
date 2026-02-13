import FFI.Poseidon2
import LSpec

open FFI.Poseidon2
open LSpec

-- Reference vectors from Python poseidon2_ffi (Goldilocks field)

def expected_hash_zeros_w4 : Array UInt64 :=
  #[0x0c60525cbe99b163, 0xf3f06ac0a08e5cf0, 0xfb9b12e25e93be1c, 0x497755568b1d4ff2]

def expected_hash_1234_w4 : Array UInt64 :=
  #[0xbfc09a6eb742aaf6, 0x9db223c74155d899, 0x53d5ac5540de6647, 0xa7db43cd73587152]

def expected_hash_zeros_w8 : Array UInt64 :=
  #[0x3a7def562f511210, 0xab0afaf9756476a0, 0x8faf5cc269ff0a14, 0xd6818fc87ccd41ba,
    0x8baed826fea3ff62, 0xe133a5f5d18335c6, 0x291171699652ccaa, 0xc63ff85a9e199a0d]

def expected_hash_zeros_w12 : Array UInt64 :=
  #[0xef311849263abcb4, 0x8bf04d36f9a01799, 0x9e570c4df0f2699f, 0x6927c3a96db0b2ad,
    0x760d22fbb5fc5de0, 0xafd1fedcdef654f4, 0xbb8c81621d5d5aed, 0x298915feb162422c,
    0x2082259c8351dacb, 0x90e205e0814883e3, 0x2fd0c9106556082d, 0xa08b335154cbefc5]

def expected_linear_hash_short : Array UInt64 := #[1, 2, 3, 0]

def expected_linear_hash_long : Array UInt64 :=
  #[0x8dff18bc249818e0, 0xe29176b96bf39b15, 0x59de807c63d140e1, 0xdb6e876fa8fa39db]

def expected_linear_hash_5elem : Array UInt64 :=
  #[0x38bba8b7d121d4f2, 0x76ac5d52ac2f8d38, 0x18c4a24f7d5336d0, 0xa27a91eba70ce22a]

def arrayEq (a b : Array UInt64) : Bool :=
  a.size == b.size && (List.range a.size).all fun i => a[i]! == b[i]!

def hashTests : TestSeq :=
  group "poseidon2Hash" (
    test "hash zeros w4"
      (arrayEq (poseidon2Hash #[0, 0, 0, 0] 4) expected_hash_zeros_w4) $
    test "hash [1,2,3,4] w4"
      (arrayEq (poseidon2Hash #[1, 2, 3, 4] 4) expected_hash_1234_w4) $
    test "hash zeros w8"
      (arrayEq (poseidon2Hash #[0, 0, 0, 0, 0, 0, 0, 0] 8) expected_hash_zeros_w8) $
    test "hash zeros w12"
      (arrayEq (poseidon2Hash #[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 12) expected_hash_zeros_w12)
  )

def linearHashTests : TestSeq :=
  group "linearHash" (
    test "short input (fits in capacity)"
      (arrayEq (linearHash #[1, 2, 3] 8) expected_linear_hash_short) $
    test "long input (8 elements, sponge)"
      (arrayEq (linearHash #[1, 2, 3, 4, 5, 6, 7, 8] 8) expected_linear_hash_long) $
    test "5 elements (partial block)"
      (arrayEq (linearHash #[1, 2, 3, 4, 5] 8) expected_linear_hash_5elem)
  )

def hashSeqTests : TestSeq :=
  group "hashSeq" (
    test "hashSeq [1,2,3,4] w4 = poseidon2Hash first 4"
      (arrayEq (hashSeq #[1, 2, 3, 4] 4) expected_hash_1234_w4)
  )

def grindingTests : TestSeq :=
  let challenge : Array UInt64 := #[0x123456789abcdef0, 0xfedcba9876543210, 0xdeadbeef12345678]
  group "verifyGrinding" (
    test "valid nonce"
      (verifyGrinding challenge 4 4) $
    test "invalid nonce"
      (!verifyGrinding challenge 999999 4)
  )

def allTests : TestSeq :=
  hashTests ++ linearHashTests ++ hashSeqTests ++ grindingTests

def main : IO UInt32 :=
  lspecIO (.ofList [("Poseidon2 FFI", [allTests])]) []
