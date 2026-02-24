(sec:precompiles)=
# Precompiles

Precompile AIRs provide accelerated circuits for cryptographic operations.
All four precompile AIRs require the Compressor stage in the recursion
pipeline due to their large verifier circuits.

(sec:add256)=
## Add256

The {src}`Add256 AIR <zisk/precompiles/big_int/src/add256.rs#Add256SM>` ($2^{20}$ {src}`rows <zisk/pil/zisk.pil:74>`) provides 256-bit unsigned addition.
Used as a building block for multi-precision arithmetic.

(sec:aritheq)=
## ArithEq

The {src}`ArithEq AIR <zisk/precompiles/arith_eq/src/arith_eq.rs#ArithEqSM>` ($2^{20}$ {src}`rows <zisk/pil/zisk.pil:75>`) provides 256-bit modular arithmetic
for elliptic curve operations over secp256k1 and BN254.
Supports:

- 256-bit modular addition, subtraction, and multiplication.
- secp256k1 point addition and doubling.
- BN254 curve operations (addition, doubling, complex field arithmetic).

Uses the ArithEq Lt Table (bus ID 5002) for field comparison lookups.

(sec:aritheq384)=
## ArithEq384

The {src}`ArithEq384 AIR <zisk/precompiles/arith_eq_384/src/arith_eq_384.rs#ArithEq384SM>` ($2^{20}$ {src}`rows <zisk/pil/zisk.pil:76>`) extends ArithEq to 384-bit fields,
supporting BLS12-381 elliptic curve operations.

(sec:keccakf)=
## Keccakf

The {src}`Keccakf AIR <zisk/precompiles/keccakf/src/keccakf.rs#KeccakfSM>` ($2^{17}$ {src}`rows <zisk/pil/zisk.pil:79>`) implements the Keccak-f[1600] permutation,
the core of the Keccak/SHA-3 hash function.
Each invocation processes a 1600-bit state through 24 rounds.
Memory operations for reading/writing the state use the Memory Bus (10).
Uses the Keccakf Table (bus ID 126) for round constant lookups.

(sec:sha256f)=
## Sha256f

The {src}`Sha256f AIR <zisk/precompiles/sha256f/src/sha256f.rs#Sha256fSM>` ($2^{18}$ {src}`rows <zisk/pil/zisk.pil:82>`) implements the SHA-256 compression function.
Each invocation processes a 512-bit message block with a 256-bit state.
Memory operations use the Memory Bus (10).
