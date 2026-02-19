(sec:tables)=
# Lookup Tables

(sec:specified-ranges)=
## SpecifiedRanges

The SpecifiedRanges AIR ($2^{20}$ rows) provides range check lookups.
It proves that values fall within specified ranges,
used by various AIRs for constraint verification.

(sec:vt0)=
## VirtualTable0

The VirtualTable0 AIR ($2^{21}$ rows) packs 7 lookup tables into a
single AIR for efficiency:

| Bus ID | Table                   | Consumer                |
|--------|-------------------------|-------------------------|
| 331    | Arith Table             | Arith                   |
| 330    | Arith Range Table       | Arith                   |
| 5002   | ArithEq Lt Table        | ArithEq, ArithEq384     |
| 124    | Binary Extension Table  | BinaryExtension         |
| 125    | Binary Table            | Binary                  |
| 133    | MemAlign ROM            | MemAlign                |
| 126    | Keccakf Table           | Keccakf                 |

(sec:vt1)=
## VirtualTable1

The VirtualTable1 AIR ($2^{21}$ rows) packs 3 frequent-operation
tables:

| Bus ID | Table                     | Consumer        |
|--------|---------------------------|-----------------|
| 5010   | Arith Frops Table         | Arith           |
| 5011   | Binary Frops Table        | Binary          |
| 5012   | BinaryExt Frops Table     | BinaryExtension |

These "frequent operations" tables precompute common sub-expressions
used by the computation coprocessors to reduce constraint degree.

(sec:zisk-global-constraints)=
# Global Constraints

After all per-AIR proofs are generated, the system must verify
*cross-AIR consistency*: that buses balance, that the execution
begins and ends at the correct state, and that public inputs match.
This verification is performed by the VadcopFinal circuit
(see the *Recursion Pipeline*), which encodes the
global constraints as a single compiled constraint expression.

(sec:bus-balance)=
## Bus Balance Equations

Each bus connects two or more AIRs via a logup or permutation argument.
Each participating AIR accumulates a running sum ($\mathrm{gsum}$) or
running product ($\mathrm{gprod}$) during its own STARK proof.
The *boundary value* $\mathrm{gsum}^{(a)}[N^{(a)}-1]$
(the final row of the running sum for AIR $a$) is exported as an
*airgroup value* and carried through the Recursive2 aggregation tree.

For each bus, the global constraint checks that the boundary values
from all participating AIRs cancel:

- **Lookup buses** (Operation Bus, ROM Bus, all table buses):

  $$
  \sum_{a \in \mathrm{bus}(b)}
  \mathrm{gsum}^{(a)}[N^{(a)} - 1] = 0.
  $$

  Providers contribute positive multiplicities and consumers
  contribute negative selectors; if every consumed tuple was
  provided, the sum is zero.

- **Permutation buses** (Memory Bus):

  $$
  \prod_{a \in \mathrm{bus}(b)}
  \mathrm{gprod}^{(a)}[N^{(a)} - 1] = 1.
  $$

  The two sides form identical multisets;
  the grand product ratio equals one.

Concretely, ZisK has 14 buses ({ref}`sec:bus-inventory`),
producing 14 balance equations that the global constraint must enforce.
The single compiled global constraint expression (53,890 bytecode
operations) evaluates all 14 balance equations simultaneously,
verifying the entire bus fabric in one check.

(sec:continuation)=
## Continuation Anchoring

Direct-update constraints anchor the execution to known boundary values:

- **Main continuation.**
  The initial program counter equals the boot address.
  The final program counter equals the designated end address.
  Published via direct global updates on the Operation Bus.

- **Memory continuation.**
  Memory base addresses and final states are anchored.

- **Public output.**
  The 64 public input/output values (`inputs[0..63]`) are
  published via direct global updates, binding the execution trace
  to the claimed public inputs.

(sec:agg-values)=
## Airgroup Value Aggregation

The single airgroup uses sum-type aggregation at stage 2.
During recursive aggregation (see *Recursion Pipeline*, Recursive2),
per-AIR $\mathrm{gsum}$ boundary values are added together.
VadcopFinal checks that the final aggregated sum equals zero
for each bus, confirming cross-AIR consistency.

The aggregation flow is:

1. Each AIR computes $\mathrm{gsum}^{(a)}[N-1] \in \Fext$
   as a boundary value of its running logup sum.
2. Recursive2 adds boundary values from child proofs:

   $$
   \mathrm{gsum}_{\mathrm{agg}} = \sum_{a \in \mathrm{children}}
   \mathrm{gsum}^{(a)}.
   $$

3. VadcopFinal receives the fully aggregated sum and verifies:

   $$
   \mathrm{gsum}_{\mathrm{agg}} = 0 \quad\text{(for each bus)}.
   $$
