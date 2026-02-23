# Sphinx + MyST Documentation for Zisk Prover Specification

## Context

The Zisk Prover Specification currently lives as ~2,400 lines of LaTeX across 4 body files, producing a single PDF. We want to migrate to Sphinx + MyST so that the same source produces **both a website and a PDF**, with code excerpts pulled from the actual Python executable spec via `literalinclude`. The LaTeX build remains functional during migration.

## Executive Summary

- **Problem**: LaTeX-only docs can't serve a website or link to source code
- **Solution**: Sphinx + MyST in `docs/sphinx/`, converting LaTeX → MyST markdown
- **Key features**: Dual output (HTML + PDF), `literalinclude` from `executable-spec/`, shared math macros, autodoc API reference
- **Theme**: `sphinx-book-theme` (math-friendly, clean, widely used for specs)
- **Deps managed via**: `uv` dependency group in `executable-spec/pyproject.toml`

## Solution Overview

### Directory Structure

```
docs/
├── (existing LaTeX files preserved during migration)
└── sphinx/                    # NEW Sphinx project
    ├── conf.py                # Extensions, macros, theme, autodoc
    ├── index.md               # Top-level toctree
    ├── Makefile
    ├── part-stark/            # 7 files: notation → appendix-batching
    ├── part-machine/          # 7 files: architecture → global-constraints
    ├── part-recursion/        # 9 files: pipeline → distributed
    ├── api/                   # 4 files: autodoc for each package
    ├── _static/
    │   ├── custom.css
    │   └── tikz-pipeline.svg  # Pre-rendered TikZ diagram
    └── _build/                # gitignored
```

### Key Design Decisions

1. **Convert LaTeX → MyST** for prose, math, and simple tables. All inline/display math, cross-refs, and data tables converted to native MyST so both HTML and PDF work.
2. **LaTeX figures are the single source of truth** for complex visuals. The 2 protocol tables (prover/verifier longtables) and 1 TikZ pipeline diagram stay as `.tex` files. A `render-figures.sh` script pre-renders them to SVG for the website. MathJax cannot handle longtable or TikZ — only math-mode content.
3. **`literalinclude` with marker comments** for code excerpts. Whole functions use `:pyobject:`. Sub-function excerpts use `:start-after:` / `:end-before:` with `# docs:start:name` / `# docs:end:name` markers in the Python source. Separate `api/` section has full autodoc.
4. **16 custom macros** defined once in `conf.py`, shared by MathJax (HTML) and LaTeX (PDF). `\textsf` → `\mathsf` for MathJax compat.
5. **Mock FFI imports** — `autodoc_mock_imports = ["poseidon2_ffi", "galois"]` avoids build-time Rust/galois dependency.
6. **Flexible inline vs standalone docs** — no rigid rule. Some docs can live in Python docstrings (pulled by autodoc), some as standalone `.md` files. Feel it out per module.

### Expected Outcomes

- `make html` serves a browsable website with math rendering and code links
- `make latexpdf` produces a PDF equivalent to the current protocol-spec.pdf
- Code excerpts stay in sync (pulled from actual `.py` files at build time)
- API reference with `[source]` links to syntax-highlighted Python

## Implementation Tasks

### Visual Dependency Tree

```
docs/sphinx/
├── conf.py                         (Task #0: Sphinx config)
├── Makefile                        (Task #0: Build system)
├── index.md                        (Task #0: Top-level toctree)
├── _static/custom.css              (Task #0: Protocol table CSS)
├── _static/tikz-pipeline.svg       (Task #4: Pre-rendered diagram)
├── render-tikz.sh                  (Task #4: TikZ → SVG script)
│
├── part-stark/
│   ├── notation.md                 (Task #1: Fields, domains, key quantities)
│   ├── building-blocks.md          (Task #1: Merkle, transcript)
│   ├── commitment-phase.md         (Task #1: Stages 1/2/Q, protocol table)
│   ├── query-phase.md              (Task #1: FRI queries, batch opening)
│   ├── challenge-binding.md        (Task #1: Multi-AIR challenges)
│   ├── appendix-constraints.md     (Task #1: Constraint structure)
│   └── appendix-batching.md        (Task #1: FRI batching formula)
│
├── part-machine/
│   ├── architecture.md             (Task #2: AIR inventory, STARK params)
│   ├── buses.md                    (Task #2: Bus types and inventory)
│   ├── cpu-main.md                 (Task #2: Main AIR)
│   ├── memory.md                   (Task #2: Mem, RomData, InputData)
│   ├── coprocessors.md             (Task #2: Binary, Arith)
│   ├── precompiles.md              (Task #2: Keccak, SHA256, etc.)
│   └── global-constraints.md       (Task #2: Cross-AIR constraints)
│
├── part-recursion/
│   ├── pipeline.md                 (Task #3: Overview, proof types, TikZ)
│   ├── basic-stage.md              (Task #3: Stage 1)
│   ├── compressor.md               (Task #3: Stage 2)
│   ├── recursive1.md               (Task #3: Stage 3)
│   ├── recursive2.md               (Task #3: Stage 4)
│   ├── vadcop-final.md             (Task #3: Stage 5)
│   ├── recursivef.md               (Task #3: Stage 6, not deployed)
│   ├── fflonk.md                   (Task #3: Stage 7, not deployed)
│   └── distributed.md              (Task #3: Distributed proving)
│
├── api/
│   ├── protocol.md                 (Task #5: autodoc protocol/)
│   ├── primitives.md               (Task #5: autodoc primitives/)
│   ├── constraints.md              (Task #5: autodoc constraints/)
│   └── witness.md                  (Task #5: autodoc witness/)
│
executable-spec/
└── pyproject.toml                  (Task #0: Add docs dep group)
```

### Execution Plan

#### Group A: Foundation (parallel)

- [ ] **Task #0a**: Create `docs/sphinx/conf.py`
  - All extensions: `myst_parser`, `sphinx.ext.autodoc`, `sphinx.ext.viewcode`, `sphinx_copybutton`, `sphinx_design`
  - `myst_enable_extensions`: `dollarmath`, `amsmath`, `deflist`, `colon_fence`
  - 16 custom math macros in shared `_MACROS` dict → `mathjax3_config` + `latex_elements`
  - `autodoc_mock_imports = ["poseidon2_ffi", "galois"]`
  - `sys.path.insert(0, os.path.abspath("../../executable-spec"))`
  - Theme: `sphinx-book-theme`
  - `numfig = True` for numbered cross-refs

- [ ] **Task #0b**: Create `docs/sphinx/index.md` with toctree
  - 4 sections: STARK Protocol, Zisk Machine, Recursion Pipeline, API Reference
  - Brief abstract matching the existing LaTeX abstract

- [ ] **Task #0c**: Create `docs/sphinx/Makefile`
  - Targets: `html`, `latexpdf`, `serve` (python http.server on 8000), `clean`
  - Uses `uv run --group docs sphinx-build`

- [ ] **Task #0d**: Create `docs/sphinx/_static/custom.css`
  - Protocol table grid styling (prover/arrow/verifier 3-column layout)

- [ ] **Task #0e**: Add `docs` dependency group to `executable-spec/pyproject.toml`
  - Under `[dependency-groups]`: `docs = ["sphinx>=7.0", "myst-parser>=3.0", "sphinx-book-theme>=1.1", "sphinx-copybutton>=0.5", "sphinx-design>=0.6"]`

#### Group B: STARK Protocol conversion (parallel with C, D after A)

- [ ] **Task #1a**: Convert `part-stark/notation.md` + `building-blocks.md`
  - From `stark-body.tex` sections 1-2 (~300 lines)
  - `literalinclude` of `primitives/field.py` type aliases (`:pyobject:` or `:lines:`)
  - `literalinclude` of `Transcript` class docstring
  - `literalinclude` of `MerkleTree.build` or `MerkleVerifier`
  - Convert all `\label{}`/`\Cref{}` to `(target)=`/`` {ref}`target` ``

- [ ] **Task #1b**: Convert `part-stark/commitment-phase.md`
  - From `stark-body.tex` section 3 (~400 lines) — the densest section
  - Protocol table (longtable) → `sphinx-design` grid or `{list-table}`
  - 7 stage subsections with display equations
  - `literalinclude` of `FRI.fold` (`:pyobject: FRI.fold`), `stages.py` module docstring, `fri_polynomial.py` docstring

- [ ] **Task #1c**: Convert `part-stark/query-phase.md` + `challenge-binding.md`
  - From `stark-body.tex` sections 4-5 (~250 lines)
  - Second protocol table (query phase)
  - `literalinclude` of `stark_verify` signature, `derive_global_challenge`

- [ ] **Task #1d**: Convert `part-stark/appendix-constraints.md` + `appendix-batching.md`
  - From `stark-appendix.tex` (102 lines)
  - `literalinclude` of `ConstraintModule` ABC from `constraints/base.py`

#### Group C: Machine conversion (parallel with B, D after A)

- [ ] **Task #2a**: Convert `part-machine/architecture.md` + `buses.md`
  - From `machine-body.tex` sections 1-2 (~250 lines)
  - AIR inventory table (21 rows), STARK params table, bus inventory table
  - Mostly tables and prose, minimal math

- [ ] **Task #2b**: Convert `part-machine/cpu-main.md` through `global-constraints.md`
  - From `machine-body.tex` sections 3-8 (~330 lines)
  - Per-AIR descriptions, bus interactions, global constraint equations

#### Group D: Recursion conversion (parallel with B, C after A)

- [ ] **Task #3a**: Convert `part-recursion/pipeline.md`
  - From `recursion-body.tex` section 1 (~150 lines)
  - Pipeline overview table, proof types, field transitions
  - TikZ figure placeholder (reference SVG from Task #4)

- [ ] **Task #3b**: Convert `part-recursion/basic-stage.md` through `distributed.md`
  - From `recursion-body.tex` sections 2-9 (~420 lines)
  - 8 separate files, one per stage + distributed proving
  - Note "not deployed" markers on stages 6-7

#### Group E: TikZ rendering + API reference (after A; parallel with B/C/D)

- [ ] **Task #4**: Pre-render TikZ pipeline diagram
  - Extract TikZ from `recursion-body.tex` into standalone `tikz-pipeline.tex`
  - Create `render-tikz.sh`: `pdflatex tikz-pipeline.tex && pdf2svg tikz-pipeline.pdf _static/tikz-pipeline.svg`
  - Store SVG in `_static/`

- [ ] **Task #5**: Create API reference pages
  - `api/protocol.md`: `automodule:: protocol.verifier`, `protocol.fri`, `protocol.prover`, `protocol.stages`
  - `api/primitives.md`: `automodule:: primitives.field`, `primitives.transcript`, `primitives.merkle_verifier`
  - `api/constraints.md`: `automodule:: constraints.base`
  - `api/witness.md`: `automodule:: witness.base`

#### Group F: CI + cleanup (after all above)

- [ ] **Task #6**: Update gitignore and add build docs to top-level
  - Add `docs/sphinx/_build/` to `docs/.gitignore`
  - Verify `make html` and `make latexpdf` both succeed
  - Verify `make serve` works on localhost:8000

### Critical Files

| File | Role |
|------|------|
| `docs/preamble.tex` | Source of 16 custom commands → translate to `conf.py` macros |
| `docs/stark-body.tex` | Largest body (1,123 lines), heaviest math, 2 protocol tables |
| `docs/recursion-body.tex` | Contains TikZ diagram (110 lines) |
| `executable-spec/pyproject.toml` | Add `docs` dependency group |
| `executable-spec/protocol/fri.py` | Highest-value `literalinclude` target (FRI fold) |
| `executable-spec/protocol/verifier.py` | `stark_verify` — referenced from query phase section |
| `executable-spec/primitives/field.py` | Type aliases referenced from notation section |
| `executable-spec/constraints/base.py` | `ConstraintModule` ABC referenced from appendix |

### Key Conversion Patterns

**LaTeX → MyST cheatsheet:**
| LaTeX | MyST |
|-------|------|
| `\section{Foo}` | `## Foo` |
| `\label{sec:foo}` | `(sec:foo)=` on line before heading |
| `\Cref{sec:foo}` | `` {ref}`sec:foo` `` |
| `\eqref{eq:foo}` | `` {eq}`eq-foo` `` |
| `$x^2$` | `$x^2$` (same) |
| `\[ x^2 \]` | `$$x^2$$` |
| `\begin{equation}\label{eq:foo}` | ```` ```{math}\n:label: eq-foo ```` |
| `\begin{itemize}[nosep]` | `- item` (MyST list) |
| `\begin{enumerate}[label=(\roman*)]` | `1. item` (numbered list) |
| `\textbf{Bold}` | `**Bold**` |
| `\emph{Italic}` | `*Italic*` |
| `\paragraph{Title.}` | `**Title.** ` (bold inline) |

## Verification

1. `cd docs/sphinx && uv run --group docs make html` → builds without errors, site at `_build/html/index.html`
2. `cd docs/sphinx && uv run --group docs make latexpdf` → produces PDF
3. `cd docs/sphinx && uv run --group docs make serve` → viewable at localhost:8000
4. All 16 custom macros render correctly in both HTML (MathJax) and PDF
5. `literalinclude` excerpts show actual code from `executable-spec/`
6. Cross-references (`{ref}`, `{eq}`) resolve without warnings
7. API reference pages show autodoc output with `[source]` links

## Implementation Workflow

This plan file is the authoritative checklist for implementation. When implementing:

### Required Process
1. **Load Plan**: Read this entire plan file before starting
2. **Sync Tasks**: Create TodoWrite tasks matching the checkboxes above
3. **Execute & Update**: For each task, mark `[ ]` → `[x]` when complete
4. **Maintain Sync**: Keep this file and TodoWrite synchronized

### Critical Rules
- Update checkboxes in real-time as work progresses
- Tasks in Groups B/C/D can all run in parallel after Group A
- Use `:pyobject:` not `:lines:` in `literalinclude` for resilience
- Test `make html` after each group completes
