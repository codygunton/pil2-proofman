# Code Anchor System for Sphinx Documentation References

## Executive Summary

**Problem:** The current `{src}` role in Sphinx docs uses hardcoded line numbers (e.g., `{src}\`protocol/prover.py:202\``), which are brittle and break whenever code is refactored. Every code change requires manually updating dozens of line numbers in documentation.

**Proposed Solution:** Implement a two-tier anchor system:
1. **Function/class references** - `{src}\`protocol.prover.gen_proof\`` links to function definition automatically
2. **Code anchors** - Special comments `# <doc-anchor id="witness-commit">` mark specific algorithm steps, resolved to line numbers at build time

**Technical Approach:**
- Extend the existing `_src_role` function in `docs/sphinx/conf.py`
- Add a pre-build scanner that extracts anchor positions from Python files
- Generate an anchor→line mapping cached for the build
- Support both anchor syntax and fallback to existing line number syntax

**Expected Outcomes:**
- Documentation references survive code refactoring
- Self-documenting code (anchors show which lines are referenced in docs)
- Reduced maintenance burden (no manual line number updates)
- Backwards compatible with existing {src} line number references

## Goals & Objectives

### Primary Goals
- **Eliminate line number brittleness** - 100% of {src} references use anchors or function refs, zero hardcoded line numbers
- **Zero breaking changes** - Existing {src}\`path:line\`` syntax continues to work during transition

### Secondary Objectives
- **Self-documenting codebase** - Anchor comments make it obvious which code is referenced in documentation
- **Build-time validation** - Warn on missing anchors or broken references
- **Developer experience** - Easy to add new anchors, clear error messages when anchors not found

## Solution Overview

### Approach

Replace brittle line numbers with two ref types:

1. **Symbol references** (for function/class definitions):
   ```markdown
   {src}`protocol.prover.gen_proof`
   ```
   Uses Python's AST to find the definition automatically.

2. **Code anchors** (for mid-function algorithm steps):
   ```python
   # <doc-anchor id="witness-commit">
   r1 = merkelize(witness)
   ```
   ```markdown
   {src}`protocol.prover#witness-commit`
   ```
   Scanner finds anchors and builds line number mapping at build time.

### Key Components

1. **Anchor Scanner** (`docs/sphinx/_ext/anchor_scanner.py`)
   - Scans `executable-spec/**/*.py` for anchor comments
   - Builds `{file: {anchor_id: line_number}}` mapping
   - Uses AST to extract function/class definitions
   - Caches results for fast incremental builds

2. **Extended _src_role** (`docs/sphinx/conf.py`)
   - Detects ref format: `path#anchor`, `module.symbol`, or legacy `path:line`
   - Resolves anchors/symbols to line numbers using scanner cache
   - Generates viewcode links with line numbers
   - Clear error messages for missing anchors

3. **Code Anchors** (`executable-spec/**/*.py`)
   - Lightweight comment syntax: `# <doc-anchor id="anchor-id">`
   - Added at ~100 critical algorithm steps currently using line refs
   - Self-documenting (developers see what's referenced in docs)

### Architecture Diagram

```
┌─────────────────┐
│  Sphinx Build   │
│     Start       │
└────────┬────────┘
         │
         v
┌─────────────────────────────────┐
│  Pre-build: anchor_scanner.py  │
│  - Scan executable-spec/*.py   │
│  - Extract doc-anchor comments │
│  - Parse AST for symbols       │
│  - Build anchor→line mapping   │
│  - Cache to _anchor_cache.pkl  │
└────────┬────────────────────────┘
         │
         v
┌─────────────────────────────────┐
│   Doc parsing: _src_role()     │
│   - Read {src}`ref` from .md   │
│   - Detect format (anchor/sym) │
│   - Look up line number         │
│   - Generate viewcode link     │
└────────┬────────────────────────┘
         │
         v
┌─────────────────┐
│  HTML Output    │
│  Clickable link │
│  to exact line  │
└─────────────────┘
```

### Data Flow

```
Python Source                    Sphinx Docs
─────────────                    ───────────
protocol/prover.py               commitment-phase.md
├─ # <doc-anchor id="foo">       ├─ {src}`protocol.prover#foo`
├─ def gen_proof():              └─ {src}`protocol.prover.gen_proof`

         │                              │
         v                              v
    Scanner reads                  _src_role parses
    extracts anchors               detects ref type
         │                              │
         v                              v
    {file: {id: line}}            Looks up in cache
    cached to disk                resolves to line number
         │                              │
         └──────────┬───────────────────┘
                    v
           viewcode link generated
           _modules/protocol/prover.html#line-202
```

### Expected Outcomes

- All ~150+ `{src}` references in STARK spec use anchors or symbols (zero hardcoded line numbers after migration)
- Code refactoring no longer breaks documentation links
- Developers can identify doc-referenced code via anchor comments
- Build system warns if anchor is missing or documentation reference is stale
- Backwards compatible - existing `{src}\`path:line\`` syntax works during transition

## Implementation Tasks

### CRITICAL IMPLEMENTATION RULES
1. **NO PLACEHOLDER CODE**: Full working implementation, not stubs
2. **BACKWARDS COMPATIBLE**: Existing {src}\`path:line\`` must continue to work
3. **COMPLETE IMPLEMENTATIONS**: Each task fully functional, tested with real references
4. **DETAILED SPECIFICATIONS**: Exact function signatures, error handling, caching strategy
5. **CONTEXT AWARENESS**: Scanner integrates with Sphinx build, _src_role uses scanner output

### Research Findings

**Current state (from research agent ad3313a):**
- **74 total {src} references** across 10 markdown files in docs/sphinx/part-stark/
- **21 function-level refs (28%)** - can use symbol resolution
- **53 mid-function refs (72%)** - need code anchors
- **Top referenced files:**
  - protocol/verifier.py (20 refs)
  - protocol/prover.py (10 refs)
  - protocol/stages.py (10 refs)
  - protocol/fri_polynomial.py (9 refs)
  - primitives/transcript.py (6 refs)
- **Current implementation:** conf.py lines 158-178, simple regex line number parsing

### Visual Dependency Tree

```
docs/sphinx/
├── conf.py (Task #2: Extend _src_role to support all 3 syntaxes)
│
├── _ext/
│   └── anchor_scanner.py (Task #1: NEW - Build anchor scanner with AST + comment parsing)
│
└── part-stark/
    ├── commitment-phase.md (Task #4: Migrate 15 refs)
    ├── query-phase.md (Task #4: Migrate 14 refs)
    ├── building-blocks.md (Task #4: Migrate 10 refs)
    ├── full-protocol.md (Task #4: Migrate 9 refs)
    ├── appendix-constraints.md (Task #4: Migrate 6 refs)
    └── ... (5 more files)

executable-spec/
├── protocol/
│   ├── verifier.py (Task #3: Add ~15 anchors for mid-function refs)
│   ├── prover.py (Task #3: Add ~8 anchors)
│   ├── stages.py (Task #3: Add ~8 anchors)
│   ├── fri_polynomial.py (Task #3: Add ~7 anchors)
│   └── fri.py (Task #3: Add ~4 anchors)
│
└── primitives/
    ├── transcript.py (Task #3: Add ~5 anchors)
    ├── merkle_tree.py (Task #3: Add ~3 anchors)
    └── ... (others as needed)
```

### Execution Plan

#### Group A: Foundation (Execute in parallel)

- [x] **Task #1**: Build anchor scanner extension
  - **File**: `docs/sphinx/_ext/anchor_scanner.py` (NEW)
  - **Imports**:
    ```python
    import ast
    import re
    from pathlib import Path
    from typing import Dict, Tuple
    import pickle
    ```
  - **Implements**:
    - `scan_python_files(base_path: Path) -> Dict[str, Dict[str, int]]`
      - Walks `base_path` recursively for `*.py` files
      - For each file: extract anchors + AST symbols
      - Returns: `{relative_path: {anchor_id: line_number}}`
    - `extract_anchors(source: str) -> Dict[str, int]`
      - Regex: `# <doc-anchor id="([^"]+)">`
      - Returns: `{anchor_id: line_number}` (1-indexed)
    - `extract_symbols(source: str, filepath: str) -> Dict[str, int]`
      - Use `ast.parse()` to find all `FunctionDef`, `AsyncFunctionDef`, `ClassDef`
      - Build dotted names: `module.Class.method`
      - Returns: `{symbol_name: line_number}`
    - `build_anchor_cache(base_path: Path, cache_path: Path) -> Dict[str, Dict[str, int]]`
      - Combines anchors + symbols for all Python files
      - Saves to pickle cache
      - Returns combined mapping
    - `load_anchor_cache(cache_path: Path) -> Dict[str, Dict[str, int]]`
      - Loads from pickle if exists and fresh
      - Otherwise rebuilds
  - **Cache strategy**:
    - Save to `docs/sphinx/_anchor_cache.pkl`
    - Invalidate if any `.py` file mtime > cache mtime
  - **Error handling**:
    - Duplicate anchor IDs in same file → warning with line numbers
    - Invalid Python syntax → skip file with warning
    - Missing base_path → raise clear error
  - **Integration**: Called from `conf.py` during Sphinx setup
  - **Testing**: Can test standalone with `python -m docs.sphinx._ext.anchor_scanner`

- [x] **Task #2**: Extend _src_role to support new syntax
  - **File**: `docs/sphinx/conf.py` (MODIFY lines 158-178)
  - **Current code** (lines 158-178):
    ```python
    def _src_role(name, rawtext, text, lineno, inliner, options={}, content=[]):
        # Current implementation parses `path:line` format
        # Generates viewcode links
    ```
  - **New implementation**:
    - Detect reference format via regex:
      - `path:line` → legacy (keep existing code path)
      - `module.symbol` → symbol lookup
      - `path#anchor` → anchor lookup
    - Load anchor cache once during setup (store in `app.env`)
    - **Symbol resolution**:
      ```python
      if '.' in ref and ':' not in ref and '#' not in ref:
          # Symbol format: protocol.prover.gen_proof
          module_path = ref.replace('.', '/') + '.py'
          symbol_parts = ref.split('.')
          # Look up in cache: cache[module_path][symbol_name]
      ```
    - **Anchor resolution**:
      ```python
      if '#' in ref:
          # Anchor format: protocol/prover.py#witness-commit
          file_path, anchor_id = ref.split('#', 1)
          if not file_path.endswith('.py'):
              file_path += '.py'
          # Look up: cache[file_path][anchor_id]
      ```
    - **Error messages**:
      - "Anchor '{anchor_id}' not found in {file_path}"
      - "Symbol '{symbol}' not found in {module_path}"
      - "Invalid reference format: {ref}"
    - **Backwards compatibility**: Existing `:line` syntax unchanged
  - **Integration**: Sphinx build calls this for every `{src}` role
  - **Setup hook**: Add `setup(app)` code to build cache on sphinx-build start:
    ```python
    def setup(app):
        from ._ext.anchor_scanner import build_anchor_cache
        cache = build_anchor_cache(
            base_path=Path('executable-spec'),
            cache_path=Path('docs/sphinx/_anchor_cache.pkl')
        )
        app.env.anchor_cache = cache
        app.add_role('src', _src_role)
    ```

#### Group B: Code Anchors (Execute after Group A, tasks run in parallel)

**Note**: Only add anchors for mid-function algorithm steps. Function/class definitions will use symbol refs.

- [x] **Task #3a**: Add anchors to protocol/verifier.py
  - **File**: `executable-spec/protocol/verifier.py`
  - **Add ~15 anchors** for mid-function algorithm steps currently referenced
  - **Anchor naming convention**: `{action}-{subject}` (kebab-case)
    - Examples: `transcript-seed`, `compute-vanishing`, `fri-fold-check`
  - **Placement**: Line immediately before the referenced code
  - **Format**: `# <doc-anchor id="anchor-id">`
  - **Top candidates** (based on current line refs):
    - Line 382: `# <doc-anchor id="transcript-reconstruct">`
    - Line 724: `# <doc-anchor id="constraint-check">`
    - Line 742: `# <doc-anchor id="compute-constraint">`
    - Line 747: `# <doc-anchor id="compute-vanishing">`
    - Line 686: `# <doc-anchor id="quotient-reconstruct">`
    - Line 753: `# <doc-anchor id="verify-quotient-div">`
    - Line 90: `# <doc-anchor id="grinding-check">`
    - Line 964: `# <doc-anchor id="degree-check">`
    - Line 982: `# <doc-anchor id="final-poly-intt">`
    - Line 987: `# <doc-anchor id="degree-bound">`
    - Line 989: `# <doc-anchor id="check-high-coeffs">`
    - Line 95: `# <doc-anchor id="derive-queries">`
    - Line 98: `# <doc-anchor id="squeeze-indices">`
    - Line 803: `# <doc-anchor id="stage-merkle-check">`
    - Line 879: `# <doc-anchor id="fri-merkle-check">`

- [x] **Task #3b**: Add anchors to protocol/prover.py
  - **File**: `executable-spec/protocol/prover.py`
  - **Added 9 anchors**
  - **Completed anchors**:
    - Line 201: `witness-commit` - Stage 1 witness commitment
    - Line 208: `transcript-seed-vadcop` - VADCOP transcript seeding
    - Line 231: `transcript-seed-standalone` - Standalone transcript seeding
    - Line 247: `derive-stage2-challenges` - Stage 2 challenge derivation
    - Line 275: `intermediate-commit` - Stage 2 commitment
    - Line 285: `derive-stageq-challenges` - Quotient stage challenge derivation
    - Line 313: `quotient-commit` - Quotient polynomial commitment
    - Line 321: `derive-eval-challenges` - Evaluation challenge derivation
    - Line 418: `collect-query-proofs` - Query proof collection

- [x] **Task #3c**: Add anchors to protocol/stages.py
  - **File**: `executable-spec/protocol/stages.py`
  - **Added 10 anchors**
  - **Completed anchors**:
    - Line 320: `calc-witness` - Calculate witness polynomials
    - Line 353: `compute-intermediates` - Compute intermediate columns
    - Line 357: `compute-grand-sums` - Compute grand sum columns
    - Line 427: `extend-to-coset` - Extend polynomial to coset domain
    - Line 507: `quotient-split` - Quotient polynomial splitting
    - Line 532: `intt-to-coeffs` - INTT to coefficient form
    - Line 565: `ntt-quotient-pieces` - NTT quotient pieces
    - Line 573: `calc-constraint-polynomial` - Calculate constraint polynomial
    - Line 615: `divide-by-zerofier` - Divide by zerofier
    - Line 728: `compute-evals` - Compute polynomial evaluations

- [x] **Task #3d**: Add anchors to protocol/fri_polynomial.py
  - **File**: `executable-spec/protocol/fri_polynomial.py`
  - **Added 7 anchors**
  - **Completed anchors**:
    - Line 129: `batching-prover` - FRI batching prover entry point
    - Line 183: `compute-denominators` - Compute denominator inverses
    - Line 191: `group-by-opening` - Group polynomials by opening position
    - Line 205: `horner-within-groups` - Horner's method within groups
    - Line 240: `horner-between-groups` - Horner's method between groups
    - Line 251: `batching-formula` - FRI batching verifier formula
    - Line 327: `horner-verifier-groups` - Verifier Horner accumulation

- [x] **Task #3e**: Add anchors to primitives files
  - **Files**:
    - `primitives/transcript.py` (~5 anchors)
    - `primitives/merkle_tree.py` (~3 anchors)
    - `primitives/merkle_prover.py` (~2 anchors)
    - `primitives/merkle_verifier.py` (~2 anchors)
    - `primitives/ntt.py` (~2 anchors)
  - **Top candidates**:
    - transcript.py line 30: `# <doc-anchor id="transcript-init">`
    - transcript.py line 50: `# <doc-anchor id="absorb">`
    - transcript.py line 56: `# <doc-anchor id="squeeze">`
    - transcript.py line 70: `# <doc-anchor id="squeeze-indices">`
    - merkle_tree.py line 48: `# <doc-anchor id="form-row">`
    - merkle_tree.py line 90: `# <doc-anchor id="build-tree">`
    - merkle_tree.py line 152: `# <doc-anchor id="merkle-root">`
    - merkle_tree.py line 164: `# <doc-anchor id="opening-proof">`
    - merkle_prover.py line 72: `# <doc-anchor id="gen-proof">`
    - merkle_verifier.py line 242: `# <doc-anchor id="verify-proof">`
    - ntt.py line 95: `# <doc-anchor id="intt-extend-ntt">`

#### Group C: Migration (Execute after Groups A & B, can run docs in parallel)

- [x] **Task #4a**: Migrate commitment-phase.md references (16 refs)
  - **File**: `docs/sphinx/part-stark/commitment-phase.md`
  - **Strategy**:
    - Function/class refs → symbol syntax: `{src}\`protocol.prover.gen_proof\``
    - Mid-function steps → anchor syntax: `{src}\`protocol/verifier.py#transcript-seed\``
  - **Test**: Build docs, verify all links work
  - **Status**: COMPLETE - All 16 references migrated (14 anchors + 2 symbols), Sphinx build succeeds, all links functional

- [x] **Task #4b**: Migrate query-phase.md references (14 refs)
  - **File**: `docs/sphinx/part-stark/query-phase.md`
  - **Apply same strategy**

- [x] **Task #4c**: Migrate building-blocks.md references (10 refs)
  - **File**: `docs/sphinx/part-stark/building-blocks.md`
  - **Apply same strategy**

- [x] **Task #4d**: Migrate remaining 7 files (35 refs total)
  - **Files**:
    - full-protocol.md (45 refs) ✓
    - appendix-constraints.md (6 refs) ✓
    - challenge-binding.md (5 refs) ✓
    - appendix-batching.md (3 refs) ✓
    - notation.md (3 refs) ✓
  - **Status**: All files migrated successfully
  - **Result**: Zero line number references remaining across all documentation

#### Group D: Validation (Execute after Group C)

- [x] **Task #5**: Validate and test the complete system
  - **Tests**:
    - Build docs: `cd docs/sphinx && make clean && make html` ✓
    - Verify all 105 references resolve correctly ✓
    - Check for orphaned line number refs (should be zero) ✓
  - **Results**:
    - Total references: 105
    - Anchor-based: 77 (73%)
    - Symbol-based: 28 (27%)
    - Line numbers: 0 (0%) ✓
  - **Success criteria**:
    - Zero line number refs remaining (all use symbols or anchors) ✓
    - All docs build without anchor resolution errors ✓
    - Documentation successfully generated

## Implementation Workflow

This plan file serves as the authoritative checklist for implementation. When implementing:

### Required Process
1. **Load Plan**: Read this entire plan file before starting
2. **Sync Tasks**: Create tasks matching the checkboxes below
3. **Execute & Update**: For each task:
   - Mark task as `in_progress` when starting
   - Update checkbox `[ ]` to `[x]` when completing
   - Mark task as `completed` when done
4. **Maintain Sync**: Keep this file synchronized throughout

### Critical Rules
- This plan file is the source of truth for progress
- Update checkboxes in real-time as work progresses
- Mark tasks complete only when fully implemented (no placeholders)
- Tasks should be run in parallel where possible

### Progress Tracking
The checkboxes represent the authoritative status of each task.
