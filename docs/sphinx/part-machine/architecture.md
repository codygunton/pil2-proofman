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

| ID | Name              | Trace size | Role                                          | Compressor? |
|----|-------------------|------------|-----------------------------------------------|-------------|
| 0  | {src}`Main <zisk/state-machines/main/src/main_sm.rs#MainSM>`              | {src}`$2^{22}$ <zisk/pil/zisk.pil:40>`   | CPU instruction dispatch                      | No          |
| 1  | {src}`Rom <zisk/state-machines/rom/src/rom.rs#RomSM>`               | {src}`$2^{22}$ <zisk/pil/zisk.pil:41>`   | Program ROM lookup table                      | No          |
| 2  | {src}`Mem <zisk/state-machines/mem/src/mem.rs#Mem>`               | {src}`$2^{22}$ <zisk/pil/zisk.pil:44>`   | Main memory (sorted by addr+step)             | No          |
| 3  | {src}`RomData <zisk/state-machines/mem/src/rom_data_sm.rs#RomDataSM>`           | {src}`$2^{21}$ <zisk/pil/zisk.pil:45>`   | Immutable ROM data region                     | No          |
| 4  | {src}`InputData <zisk/state-machines/mem/src/input_data_sm.rs#InputDataSM>`         | {src}`$2^{21}$ <zisk/pil/zisk.pil:46>`   | Free input data region                        | No          |
| 5  | {src}`MemAlign <zisk/state-machines/mem/src/mem_align_sm.rs#MemAlignSM>`          | {src}`$2^{21}$ <zisk/pil/zisk.pil:48>`   | Unaligned memory access logic                 | No          |
| 6  | {src}`MemAlignByte <zisk/state-machines/mem/src/mem_align_byte_sm.rs#MemAlignByteSM>`      | {src}`$2^{22}$ <zisk/pil/zisk.pil:49>`   | Byte-level memory alignment                   | No          |
| 7  | {src}`MemAlignReadByte <zisk/state-machines/mem/src/mem_align_read_byte_instance.rs#MemAlignReadByteInstance>`  | {src}`$2^{22}$ <zisk/pil/zisk.pil:50>`   | Read-side byte alignment                      | No          |
| 8  | {src}`MemAlignWriteByte <zisk/state-machines/mem/src/mem_align_write_byte_instance.rs#MemAlignWriteByteInstance>` | {src}`$2^{22}$ <zisk/pil/zisk.pil:51>`   | Write-side byte alignment                     | No          |
| 9  | {src}`Arith <zisk/state-machines/arith/src/arith.rs#ArithSM>`             | {src}`$2^{21}$ <zisk/pil/zisk.pil:56>`   | 64-bit multiply/divide                        | No          |
| 10 | {src}`Binary <zisk/state-machines/binary/src/binary.rs#BinarySM>`            | {src}`$2^{22}$ <zisk/pil/zisk.pil:62>`   | Bitwise AND, OR, XOR, comparisons             | No          |
| 11 | {src}`BinaryAdd <zisk/state-machines/binary/src/binary_add.rs#BinaryAddSM>`         | {src}`$2^{22}$ <zisk/pil/zisk.pil:63>`   | Dedicated 64-bit addition                     | No          |
| 12 | {src}`BinaryExtension <zisk/state-machines/binary/src/binary_extension.rs#BinaryExtensionSM>`   | {src}`$2^{22}$ <zisk/pil/zisk.pil:65>`   | Shifts, sign-extension                        | No          |
| 13 | {src}`Add256 <zisk/precompiles/big_int/src/add256.rs#Add256SM>`            | {src}`$2^{20}$ <zisk/pil/zisk.pil:74>`   | 256-bit addition                              | No          |
| 14 | {src}`ArithEq <zisk/precompiles/arith_eq/src/arith_eq.rs#ArithEqSM>`           | {src}`$2^{20}$ <zisk/pil/zisk.pil:75>`   | 256-bit field arithmetic (secp256k1, BN254)   | Yes         |
| 15 | {src}`ArithEq384 <zisk/precompiles/arith_eq_384/src/arith_eq_384.rs#ArithEq384SM>`        | {src}`$2^{20}$ <zisk/pil/zisk.pil:76>`   | 384-bit field arithmetic (BLS12-381)          | Yes         |
| 16 | {src}`Keccakf <zisk/precompiles/keccakf/src/keccakf.rs#KeccakfSM>`           | {src}`$2^{17}$ <zisk/pil/zisk.pil:79>`   | Keccak-f[1600] permutation                    | Yes         |
| 17 | {src}`Sha256f <zisk/precompiles/sha256f/src/sha256f.rs#Sha256fSM>`           | {src}`$2^{18}$ <zisk/pil/zisk.pil:82>`   | SHA-256 compression function                  | Yes         |
| 18 | {src}`SpecifiedRanges <zisk/state-machines/frequent-ops/src/frequent_ops_table.rs#FrequentOpsTable>`   | $2^{20}$   | Range check lookup table                      | No          |
| 19 | {src}`VirtualTable0 <zisk/state-machines/frequent-ops/src/frequent_ops_table.rs#FrequentOpsTable>`     | $2^{21}$   | Packed lookup tables (7 tables)               | No          |
| 20 | {src}`VirtualTable1 <zisk/state-machines/frequent-ops/src/frequent_ops_table.rs#FrequentOpsTable>`     | $2^{21}$   | Packed lookup tables (3 tables)               | No          |

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
