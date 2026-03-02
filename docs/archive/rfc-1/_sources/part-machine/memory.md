(sec:memory)=
# Memory Subsystem

(sec:mem)=
## Mem AIR

The {src}`Mem AIR <zisk/state-machines/mem/src/mem.rs#Mem>` ($2^{22}$ {src}`rows <zisk/pil/zisk.pil:44>`) implements the main read/write memory.
Memory accesses are sorted by $(address, step)$ pairs,
enabling transition constraints that verify temporal consistency:

- A write at step $t$ stores a value.
- A read at step $t' > t$ at the same address returns the most recently written value.

Mem supports both 1-byte and 8-byte (aligned) accesses.
The memory bus uses a permutation argument (bus ID 10) to match
loads/stores from the Main AIR and MemAlign subsystem.

(sec:romdata)=
## RomData AIR

The {src}`RomData AIR <zisk/state-machines/mem/src/rom_data_sm.rs#RomDataSM>` ($2^{21}$ {src}`rows <zisk/pil/zisk.pil:45>`) holds immutable program data.
It follows a *first-write-then-read-only* pattern:

- Data is written once during initialization.
- All subsequent accesses are reads that return the initialized value.
- Proved via both the Memory Bus (10) and ROM Bus (7890).

Gated by the `enable_rom_data` proof value.

(sec:inputdata)=
## InputData AIR

The {src}`InputData AIR <zisk/state-machines/mem/src/input_data_sm.rs#InputDataSM>` ($2^{21}$ {src}`rows <zisk/pil/zisk.pil:46>`) provides free input to the computation.
It follows a *first-read-determines-value* pattern:

- The first read at an address determines the value (prover's free input).
- Subsequent reads return the same value.
- Connected via the Memory Bus (10).

Gated by the `enable_input_data` proof value.

(sec:memalign)=
## MemAlign Subsystem

The {src}`MemAlign AIR <zisk/state-machines/mem/src/mem_align_sm.rs#MemAlignSM>` ($2^{21}$ {src}`rows <zisk/pil/zisk.pil:48>`) and its three byte-level variants
({src}`MemAlignByte <zisk/state-machines/mem/src/mem_align_byte_sm.rs#MemAlignByteSM>`, {src}`MemAlignReadByte <zisk/state-machines/mem/src/mem_align_read_byte_instance.rs#MemAlignReadByteInstance>`, {src}`MemAlignWriteByte <zisk/state-machines/mem/src/mem_align_write_byte_instance.rs#MemAlignWriteByteInstance>`, each $2^{22}$ {src}`rows <zisk/pil/zisk.pil:49>`)
form a microprocessor for unaligned memory accesses.

When the Main AIR encounters a memory access that is not naturally aligned,
it delegates to the MemAlign subsystem, which:

1. Decomposes the unaligned access into aligned sub-accesses.
2. Performs byte-level read and write operations.
3. Reassembles the result for the Main AIR.

The MemAlign ROM (bus ID 133) provides microcode for the decomposition.
