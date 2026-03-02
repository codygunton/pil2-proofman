(sec:coprocessors)=
# Computation Coprocessors

Each coprocessor proves operations on the Operation Bus (5000).
The Main AIR assumes tuples of the form
$(\mathrm{opcode}, a_1, a_2, \ldots, a_k)$,
and the coprocessor proves matching tuples with the computed result.

(sec:binary)=
## Binary

The {src}`Binary AIR <zisk/state-machines/binary/src/binary.rs#BinarySM>` ($2^{22}$ {src}`rows <zisk/pil/zisk.pil:62>`) handles bitwise operations:
AND, OR, XOR, and unsigned/signed comparisons (LTU, LT).
Operations are decomposed into byte-level lookups via the
Binary Table (bus ID 125).

(sec:binaryadd)=
## BinaryAdd

The {src}`BinaryAdd AIR <zisk/state-machines/binary/src/binary_add.rs#BinaryAddSM>` ($2^{22}$ {src}`rows <zisk/pil/zisk.pil:63>`) provides dedicated 64-bit addition.
Separated from the Binary AIR for constraint degree optimization.

(sec:binaryext)=
## BinaryExtension

The {src}`BinaryExtension AIR <zisk/state-machines/binary/src/binary_extension.rs#BinaryExtensionSM>` ($2^{22}$ {src}`rows <zisk/pil/zisk.pil:65>`) handles shifts
(logical left/right, arithmetic right) and sign-extension operations.
Uses the Binary Extension Table (bus ID 124) for byte-level decomposition.

(sec:arith)=
## Arith

The {src}`Arith AIR <zisk/state-machines/arith/src/arith.rs#ArithSM>` ($2^{21}$ {src}`rows <zisk/pil/zisk.pil:56>`) handles 64-bit multiplication and division.
Operands are decomposed into 16-bit chunks, and the multiplication
is verified via a schoolbook decomposition with carry propagation.
Uses the Arith Table (bus ID 331) and Arith Range Table (bus ID 330)
for chunk-level lookups.
