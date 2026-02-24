(sec:coprocessors)=
# Computation Coprocessors

Each coprocessor proves operations on the Operation Bus (5000).
The Main AIR assumes tuples of the form
$(\mathrm{opcode}, a_1, a_2, \ldots, a_k)$,
and the coprocessor proves matching tuples with the computed result.

(sec:binary)=
## Binary

The Binary AIR ({src}`zisk/state-machines/binary/src/binary.rs#BinarySM`, $2^{22}$ rows) handles bitwise operations:
AND, OR, XOR, and unsigned/signed comparisons (LTU, LT).
Operations are decomposed into byte-level lookups via the
Binary Table (bus ID 125).

(sec:binaryadd)=
## BinaryAdd

The BinaryAdd AIR ({src}`zisk/state-machines/binary/src/binary_add.rs#BinaryAddSM`, $2^{22}$ rows) provides dedicated 64-bit addition.
Separated from the Binary AIR for constraint degree optimization.

(sec:binaryext)=
## BinaryExtension

The BinaryExtension AIR ({src}`zisk/state-machines/binary/src/binary_extension.rs#BinaryExtensionSM`, $2^{22}$ rows) handles shifts
(logical left/right, arithmetic right) and sign-extension operations.
Uses the Binary Extension Table (bus ID 124) for byte-level decomposition.

(sec:arith)=
## Arith

The Arith AIR ({src}`zisk/state-machines/arith/src/arith.rs#ArithSM`, $2^{21}$ rows) handles 64-bit multiplication and division.
Operands are decomposed into 16-bit chunks, and the multiplication
is verified via a schoolbook decomposition with carry propagation.
Uses the Arith Table (bus ID 331) and Arith Range Table (bus ID 330)
for chunk-level lookups.
