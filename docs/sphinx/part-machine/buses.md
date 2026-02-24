(sec:buses)=
# Bus Architecture

(sec:bus-types)=
## Bus Types

ZisK uses three types of {src}`inter-AIR communication <zisk/data-bus/src/data_bus.rs#DataBusTrait>`:

- **Lookup (logup sum-check).**
  One side *proves* rows (provides entries with multiplicities),
  the other side *assumes* rows (consumes entries with selectors).
  The logup argument ensures every assumed tuple was proved.

- **Permutation (multiset equality).**
  Two sides prove/assume with $1{:}1$ matching.
  The grand product argument ensures the multisets are identical.

- **Direct update.**
  Degree-0 constraints for segment chaining and global anchors.
  Used for continuation across execution segments.

(sec:bus-inventory)=
## Bus Inventory

| ID   | Name                      | Type        | Description                      |
|------|---------------------------|-------------|----------------------------------|
| 5000 | Operation Bus             | Lookup      | CPU $\leftrightarrow$ coprocessors |
| 7890 | ROM Bus                   | Lookup      | Main $\leftrightarrow$ Rom       |
| 10   | Memory Bus                | Permutation | Memory subsystem interconnect    |
| 88   | Dual Byte Table           | Lookup      | Byte-pair decomposition          |
| 125  | Binary Table              | Lookup      | Binary operation lookup          |
| 124  | Binary Extension Table    | Lookup      | Shift/extension lookup           |
| 126  | Keccakf Table             | Lookup      | Keccak round constant lookup     |
| 133  | MemAlign ROM              | Lookup      | Memory alignment microcode       |
| 330  | Arith Range Table         | Lookup      | Arithmetic range check           |
| 331  | Arith Table               | Lookup      | Arithmetic operation lookup      |
| 5002 | ArithEq Lt Table          | Lookup      | Field comparison lookup          |
| 5010 | Arith Frops Table         | Lookup      | Arith frequent operations        |
| 5011 | Binary Frops Table        | Lookup      | Binary frequent operations       |
| 5012 | BinaryExt Frops Table     | Lookup      | BinaryExt frequent operations    |

(sec:bus-diagram)=
## Bus Interconnection Summary

The central bus topology is:

1. **Main CPU** assumes operations on the *Operation Bus* (5000).
   Every coprocessor (Binary, BinaryAdd, BinaryExtension, Arith,
   Add256, ArithEq, ArithEq384, Keccakf, Sha256f) proves on this bus.

2. **Main CPU** assumes instruction fetches on the *ROM Bus* (7890).
   The **Rom** AIR proves instruction tuples.
   **RomData** also assumes on the ROM Bus for data reads.

3. **Memory operations** use the *Memory Bus* (10) with permutation arguments.
   Main, Mem, RomData, InputData, MemAlign, and the MemAlign byte variants
   all participate.

4. **Lookup tables** (SpecifiedRanges, VirtualTable0, VirtualTable1)
   prove on their respective table buses;
   computation AIRs assume range checks and operation tables.
