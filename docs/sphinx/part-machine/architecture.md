(sec:architecture)=
# Architecture Overview

ZisK is a zero-knowledge virtual machine that proves correct execution
of RISC-V programs.
It decomposes computation into a single *airgroup* named "ZisK"
containing 21 specialized AIRs (Algebraic Intermediate Representations),
each responsible for a different aspect of execution:
instruction dispatch, memory, arithmetic, bitwise operations,
cryptographic precompiles, and lookup tables.

The AIRs communicate via *buses*---shared lookup and permutation
arguments that enforce consistency between components.
The central interconnect is the *operation bus*: the Main CPU AIR
dispatches operations to coprocessors (Binary, Arith, etc.) via lookup
assumes, and each coprocessor proves correctness via lookup proves on
the same bus.

(sec:airgroup)=
## Airgroup Structure

All 21 AIRs belong to a single airgroup ("ZisK").
The aggregation type is **sum** (logup) at stage 2,
meaning the global constraint checks that the sum of all $\mathrm{gsum}$
boundary values across all AIRs equals zero.

Configuration parameters:

- Lattice size: $L = 368$ (no elliptic-curve mode).
- Transcript arity: $a = 4$ (Poseidon2 sponge width $= 16$).
- Number of public inputs: 68
  (4 for `rom_root` $+$ 64 for `inputs`).
- Stage-2 challenges: 2 ($\alpha, \gamma$).
- Proof values: 2 at stage 1
  (`enable_input_data`, `enable_rom_data`).

(sec:air-inventory)=
## AIR Inventory

Each AIR is implemented as a Rust state machine in `zisk/state-machines/`.

| ID | Name              | Trace size | Role                                          | Source | Compressor? |
|----|-------------------|------------|-----------------------------------------------|--------|-------------|
| 0  | Main              | $2^{22}$   | CPU instruction dispatch                      | {src}`zisk/state-machines/main/src/main_sm.rs:1` | No          |
| 1  | Rom               | $2^{22}$   | Program ROM lookup table                      | {src}`zisk/state-machines/rom/src/rom_sm.rs:1` | No          |
| 2  | Mem               | $2^{22}$   | Main memory (sorted by addr+step)             | {src}`zisk/state-machines/mem/src/mem.rs:1` | No          |
| 3  | RomData           | $2^{21}$   | Immutable ROM data region                     | {src}`zisk/state-machines/mem/src/rom_data_sm.rs:1` | No          |
| 4  | InputData         | $2^{21}$   | Free input data region                        | {src}`zisk/state-machines/mem/src/input_data_sm.rs:1` | No          |
| 5  | MemAlign          | $2^{21}$   | Unaligned memory access logic                 | {src}`zisk/state-machines/mem/src/mem_align_sm.rs:1` | No          |
| 6  | MemAlignByte      | $2^{22}$   | Byte-level memory alignment                   | {src}`zisk/state-machines/mem/src/mem_align_byte_sm.rs:1` | No          |
| 7  | MemAlignReadByte  | $2^{22}$   | Read-side byte alignment                      | {src}`zisk/state-machines/mem/src/mem_align_read_byte_instance.rs:1` | No          |
| 8  | MemAlignWriteByte | $2^{22}$   | Write-side byte alignment                     | {src}`zisk/state-machines/mem/src/mem_align_write_byte_instance.rs:1` | No          |
| 9  | Arith             | $2^{21}$   | 64-bit multiply/divide                        | {src}`zisk/state-machines/arith/src/arith.rs:1` | No          |
| 10 | Binary            | $2^{22}$   | Bitwise AND, OR, XOR, comparisons             | {src}`zisk/state-machines/binary/src/binary.rs:1` | No          |
| 11 | BinaryAdd         | $2^{22}$   | Dedicated 64-bit addition                     | {src}`zisk/state-machines/binary/src/binary_add.rs:1` | No          |
| 12 | BinaryExtension   | $2^{22}$   | Shifts, sign-extension                        | {src}`zisk/state-machines/binary/src/binary_extension.rs:1` | No          |
| 13 | Add256            | $2^{20}$   | 256-bit addition                              | {src}`zisk/precompiles/big_int/src/add256.rs:1` | No          |
| 14 | ArithEq           | $2^{20}$   | 256-bit field arithmetic (secp256k1, BN254)   | {src}`zisk/precompiles/arith_eq/src/arith_eq.rs:1` | Yes         |
| 15 | ArithEq384        | $2^{20}$   | 384-bit field arithmetic (BLS12-381)          | {src}`zisk/precompiles/arith_eq_384/src/arith_eq_384.rs:1` | Yes         |
| 16 | Keccakf           | $2^{17}$   | Keccak-f[1600] permutation                    | {src}`zisk/precompiles/keccakf/src/keccakf.rs:1` | Yes         |
| 17 | Sha256f           | $2^{18}$   | SHA-256 compression function                  | {src}`zisk/precompiles/sha256f/src/sha256f.rs:1` | Yes         |
| 18 | SpecifiedRanges   | $2^{20}$   | Range check lookup table                      | {src}`zisk/state-machines/frequent-ops/src/lib.rs:1` | No          |
| 19 | VirtualTable0     | $2^{21}$   | Packed lookup tables (7 tables)               | {src}`zisk/state-machines/frequent-ops/src/lib.rs:1` | No          |
| 20 | VirtualTable1     | $2^{21}$   | Packed lookup tables (3 tables)               | {src}`zisk/state-machines/frequent-ops/src/lib.rs:1` | No          |

AIRs marked "Compressor = Yes" have STARK verifier circuits exceeding
$2^{17}$ rows, requiring the optional Compressor stage in the recursion
pipeline (see the *Recursion Pipeline*).

(sec:air-params)=
## STARK Parameters per AIR

Each AIR defines a STARK instance with concrete parameters.
All AIRs share: blowup factor $\beta = 2$, Merkle arity $a = 4$,
quotient degree $d = 2$ (except Rom with $d = 1$), and cubic extension
$\Fext$ ($q_{\mathrm{dim}} = 3$).

| Name              | $n$ | Witness | Intmd | Const | Eval pts | FRI rounds |
|-------------------|-----|---------|-------|-------|----------|------------|
| Main              | 22  |  38     |  8    |   3   |   61     | 7          |
| Rom               | 22  |   1     |  2    |   1   |   18     | 7          |
| Mem               | 22  |  13     |  3    |   2   |   29     | 7          |
| RomData           | 21  |   6     |  3    |   2   |   19     | 7          |
| InputData         | 21  |   9     |  6    |   2   |   27     | 7          |
| MemAlign          | 21  |  29     |  6    |   2   |   59     | 7          |
| MemAlignByte      | 22  |  16     |  4    |   1   |   25     | 7          |
| MemAlignReadByte  | 22  |  10     |  3    |   1   |   18     | 7          |
| MemAlignWriteByte | 22  |  14     |  4    |   1   |   23     | 7          |
| Arith             | 21  |  44     | 15    |   1   |   64     | 7          |
| Binary            | 22  |  39     |  5    |   1   |   49     | 7          |
| BinaryAdd         | 22  |  10     |  3    |   1   |   18     | 7          |
| BinaryExtension   | 22  |  29     |  6    |   1   |   40     | 7          |
| Add256            | 20  |  47     | 17    |   1   |   69     | 6          |
| ArithEq           | 20  |  39     | 14    |   2   |  434     | 6          |
| ArithEq384        | 20  |  33     | 14    |   2   |  536     | 6          |
| Keccakf           | 17  | 2137    | 293   |   2   | 4065     | 5          |
| Sha256f           | 18  | 102     |  7    |   2   | 1265     | 6          |
| SpecifiedRanges   | 20  |  33     | 17    |  34   |   88     | 6          |
| VirtualTable0     | 21  |   8     |  5    |  52   |   69     | 7          |
| VirtualTable1     | 21  |   8     |  5    |  73   |   90     | 7          |

**Columns:**
$n$ = trace size exponent ($N = 2^n$),
Witness = stage-1 committed columns,
Intmd = stage-2 intermediate columns,
Const = constant (setup) columns,
Eval pts = evaluation map entries (polynomial openings in the FRI batching),
FRI rounds = number of folding rounds.
The number of FRI queries ranges from 217 (Keccakf) to 232 (ArithEq384),
targeting approximately 100 bits of security.

**Notable outliers.**
Keccakf has by far the most columns (2137 witness $+$ 293 intermediate)
because each Keccak-f round requires extensive bit-level decomposition.
ArithEq384 has the most evaluation points (536) due to the large number
of constraint polynomials in its 384-bit modular arithmetic verification.
The lookup table AIRs (SpecifiedRanges, VirtualTable0, VirtualTable1)
have many constant columns (up to 73) because the precomputed table values
are committed as constant polynomials during setup.
