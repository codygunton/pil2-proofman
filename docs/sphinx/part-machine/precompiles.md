(sec:precompiles)=
# Precompiles

Precompile AIRs provide accelerated circuits for cryptographic operations.
All four precompile AIRs require the Compressor stage in the recursion
pipeline due to their large verifier circuits.

(sec:add256)=
## Add256

The Add256 AIR ($2^{20}$ rows) provides 256-bit unsigned addition.
Used as a building block for multi-precision arithmetic.

(sec:aritheq)=
## ArithEq

The ArithEq AIR ($2^{20}$ rows) provides 256-bit modular arithmetic
for elliptic curve operations over secp256k1 and BN254.
Supports:

- 256-bit modular addition, subtraction, and multiplication.
- secp256k1 point addition and doubling.
- BN254 curve operations (addition, doubling, complex field arithmetic).

Uses the ArithEq Lt Table (bus ID 5002) for field comparison lookups.

(sec:aritheq384)=
## ArithEq384

The ArithEq384 AIR ($2^{20}$ rows) extends ArithEq to 384-bit fields,
supporting BLS12-381 elliptic curve operations.

(sec:keccakf)=
## Keccakf

The Keccakf AIR ($2^{17}$ rows) implements the Keccak-f[1600] permutation,
the core of the Keccak/SHA-3 hash function.
Each invocation processes a 1600-bit state through 24 rounds.
Memory operations for reading/writing the state use the Memory Bus (10).
Uses the Keccakf Table (bus ID 126) for round constant lookups.

(sec:sha256f)=
## Sha256f

The Sha256f AIR ($2^{18}$ rows) implements the SHA-256 compression function.
Each invocation processes a 512-bit message block with a 256-bit state.
Memory operations use the Memory Bus (10).
