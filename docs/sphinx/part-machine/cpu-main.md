(sec:main)=
# CPU: Main AIR

The {src}`Main AIR <zisk/state-machines/main/src/main_sm.rs#MainSM>` ($2^{22}$ {src}`rows <zisk/pil/zisk.pil:40>`) is the central instruction dispatch unit.
It processes RISC-V instructions ({src}`main_planner <zisk/state-machines/main/src/main_planner.rs#MainPlanner>`),
dispatches operations to coprocessors via the Operation Bus,
and maintains the program counter and register state.

Constraints are evaluated via the
{class}`~constraints.base.ConstraintModule` interface;
Main uses the {class}`~constraints.bytecode_adapter.BytecodeConstraintModule`
backed by compiled expression bytecode from the proving key.

(sec:main-execution)=
## Instruction Execution

Each row of the Main trace represents one clock cycle.
The Main AIR decodes the current instruction and dispatches the operation
to the appropriate coprocessor via the Operation Bus.
It does not perform computation directly---all arithmetic, bitwise,
and cryptographic operations are delegated.

(sec:main-buses)=
## Bus Interactions

- **Operation Bus (5000), assumes.**
  Dispatches operations with the tuple
  $(\mathrm{opcode},\; \mathrm{step},\; 0,\; \mathrm{addr},\; 0,\; \ldots)$.
  The coprocessor that handles this opcode proves the matching tuple.

- **ROM Bus (7890), assumes.**
  Fetches instruction words from the Rom AIR.
  The tuple includes program counter, immediate values,
  and operand encodings.

- **Memory Bus (10), permutation.**
  Issues memory loads and stores.
  The Mem AIR proves the corresponding memory operations.

- **Operation Bus (5000), direct update.**
  Provides continuation anchoring: the initial state (boot address)
  and final state (end address) are published as direct global updates,
  checked by the global constraints.
