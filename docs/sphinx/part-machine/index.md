(part:machine)=
# ZisK Machine

````{only} html
ZisK instantiates 21 AIRs, bus interconnections, memory layout, coprocessors,
precompile circuits, lookup tables, and global constraints to prove RISC-V execution with precompiles to accelerate proving Ethereum.

The Main state machine ({src}`zisk/state-machines/main/src/main_sm.rs#MainSM`) orchestrates RISC-V instruction execution.
````

```{toctree}
:maxdepth: 2
:hidden:

architecture
buses
cpu-main
memory
coprocessors
precompiles
global-constraints
```
