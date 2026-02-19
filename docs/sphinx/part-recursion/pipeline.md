(sec:pipeline)=
# Pipeline Overview

A multi-AIR computation produces $A$ independent STARK proofs,
one per AIR instance.
The aggregation pipeline transforms these into a single proof
through five stages:

| Stage | Name | Input | Output |
|-------|------|-------|--------|
| 1 | Basic | AIR witness | Per-AIR STARK proof |
| 2 | Compressor | Basic STARK proof | Compressed STARK proof |
| 3 | Recursive1 | Basic/Compressor | Normalized SNARK proof |
| 4 | Recursive2 | $\leq 3$ Recursive1/2 | Aggregated SNARK proof |
| 5 | VadcopFinal | One R2 per airgroup | Cross-AIR verified STARK proof |

All stages operate over the Goldilocks field $\F$ with Poseidon2 hashing.
The VadcopFinal STARK proof is submitted directly to the
ethproofs aggregation service.

````{only} html
```{mermaid}
:caption: "VADCOP recursive aggregation pipeline. Each per-AIR Basic proof is optionally compressed, normalized by Recursive1, then aggregated via a Recursive2 tree within each airgroup. VadcopFinal verifies the global challenge and cross-AIR constraints."

graph TD
    subgraph airgroup ["Airgroup &laquo;ZisK&raquo; (21 AIRs)"]
        direction TB

        subgraph stage1 ["Stage 1: Basic"]
            B1[Main] ; B2[Rom] ; B3[Mem] ; B4[Binary] ; B5[Keccakf] ; Bdots["..."]
        end

        subgraph stage2 ["Stage 2: Compressor (optional)"]
            C5[Compr.]
        end

        subgraph stage3 ["Stage 3: Recursive1"]
            R1a[R1] ; R1b[R1] ; R1c[R1] ; R1d[R1] ; R1e[R1] ; R1dots["..."]
        end

        subgraph stage4 ["Stage 4: Recursive2"]
            R2a[Recursive2] ; R2b[Recursive2]
            R2final[Recursive2]
        end

        B1 --> R1a
        B2 --> R1b
        B3 --> R1c
        B4 --> R1d
        B5 --> C5 --> R1e
        Bdots -.-> R1dots

        R1a --> R2a ; R1b --> R2a ; R1c --> R2a
        R1d --> R2b ; R1e --> R2b ; R1dots -.-> R2b

        R2a --> R2final ; R2b --> R2final
    end

    R2final --> VF["<b>VadcopFinal</b><br/>global challenge + constraints"]

    classDef basic fill:#e8f0fe,stroke:#666
    classDef comp fill:#fce8d0,stroke:#666
    classDef r1 fill:#e0f0e0,stroke:#666
    classDef r2 fill:#ece0f0,stroke:#666
    classDef final fill:#ffe0e0,stroke:#666,font-weight:bold

    class B1,B2,B3,B4,B5,Bdots basic
    class C5 comp
    class R1a,R1b,R1c,R1d,R1e,R1dots r1
    class R2a,R2b,R2final r2
    class VF final
```
````

````{only} latex
```{figure} /_static/pipeline.png
:name: fig-pipeline
:width: 90%

VADCOP recursive aggregation pipeline.
```
````

(sec:proof-types)=
## Proof Type Table

| Type | System | Description |
|------|--------|-------------|
| Basic | STARK | Per-AIR STARK proof (see the *STARK Protocol*) |
| Compressor | STARK | Optional compression for large Basic proofs |
| Recursive1 | Circom + STARK | Verifies one Basic/Compressor STARK inside a Circom (R1CS) circuit, proved with a STARK |
| Recursive2 | Circom + STARK | Aggregates $\leq 3$ proofs of the same airgroup into 1 (tree reduction) |
| VadcopFinal | STARK | Combines one Recursive2 per airgroup; verifies global challenge and global constraints |

(sec:field-transitions)=
## Field

All five stages operate over the Goldilocks field
$\F = \mathbb{F}_{2^{64} - 2^{32} + 1}$
with Poseidon2 hashing and cubic extension $\Fext$.
