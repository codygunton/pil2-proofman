(sec:memory)=
# Memory Subsystem

(sec:mem)=
## Mem AIR

The Mem AIR ($2^{22}$ rows) implements the main read/write memory.
Memory accesses are sorted by $(address, step)$ pairs,
enabling transition constraints that verify temporal consistency:

- A write at step $t$ stores a value.
- A read at step $t' > t$ at the same address returns the most recently written value.

Mem supports both 1-byte and 8-byte (aligned) accesses.
The memory bus uses a permutation argument (bus ID 10) to match
loads/stores from the Main AIR and MemAlign subsystem.

(sec:romdata)=
## RomData AIR

The RomData AIR ($2^{21}$ rows) holds immutable program data.
It follows a *first-write-then-read-only* pattern:

- Data is written once during initialization.
- All subsequent accesses are reads that return the initialized value.
- Proved via both the Memory Bus (10) and ROM Bus (7890).

Gated by the `enable_rom_data` proof value.

(sec:inputdata)=
## InputData AIR

The InputData AIR ($2^{21}$ rows) provides free input to the computation.
It follows a *first-read-determines-value* pattern:

- The first read at an address determines the value (prover's free input).
- Subsequent reads return the same value.
- Connected via the Memory Bus (10).

Gated by the `enable_input_data` proof value.

(sec:memalign)=
## MemAlign Subsystem

The MemAlign AIR ($2^{21}$ rows) and its three byte-level variants
(MemAlignByte, MemAlignReadByte, MemAlignWriteByte, each $2^{22}$ rows)
form a microprocessor for unaligned memory accesses.

When the Main AIR encounters a memory access that is not naturally aligned,
it delegates to the MemAlign subsystem, which:

1. Decomposes the unaligned access into aligned sub-accesses.
2. Performs byte-level read and write operations.
3. Reassembles the result for the Main AIR.

The MemAlign ROM (bus ID 133) provides microcode for the decomposition.
