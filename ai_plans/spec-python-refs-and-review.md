# STARK Spec: Python References & Review Fixes

## Executive Summary

The STARK protocol specification (`docs/sphinx/part-stark/`) is well-written prose with
thorough mathematical formulas. However:

1. **Python code references are unevenly distributed** — the commitment phase and
   full-protocol table have systematic `{src}` links, but notation, building blocks,
   query phase, challenge binding, and both appendices have **zero** Python references.

2. **Structural review feedback** from `my-notes/spec-review-notes-1.md` identifies
   TOC reorganization, section renames, and content merges that need to happen.

This plan addresses both: add systematic Python `{src}` references throughout every
section of Part I, and implement all review feedback items.

## Goals & Objectives

### Primary Goals
- Every mathematical formula and algorithm step in Part I has a `{src}` link to the
  implementing Python code
- All structural review feedback from spec-review-notes-1.md is addressed

### Secondary Objectives
- Verify that notation in the spec matches Python variable/function names
- Remove spec notation that doesn't appear in the Python code (`squeeze_indices`)
- Add galois library context to the primitives section

## Solution Overview

### Current State of Python References

| Section | File | Has `{src}` links? |
|---------|------|---------------------|
| Notation | `notation.md` | **None** |
| Building Blocks | `building-blocks.md` | **None** |
| Commitment Phase | `commitment-phase.md` | Yes (thorough) |
| Query Phase | `query-phase.md` | **None** |
| Challenge Binding | `challenge-binding.md` | **None** |
| Appendix: Constraints | `appendix-constraints.md` | **None** |
| Appendix: Batching | `appendix-batching.md` | **None** |
| Full Protocol | `full-protocol.md` | Yes (thorough) |

6 out of 8 files need Python references added.

### Review Notes Inventory

From `my-notes/spec-review-notes-1.md`:

| # | Feedback | Section | Action |
|---|----------|---------|--------|
| R1 | Rename "Notation and Algebraic Setup" to "Primitives" | `notation.md` | Rename heading |
| R2 | Add refs to Python, explaining galois dep and what our fork adds | `notation.md` | Add paragraph |
| R3 | Merge "Key Quantities" + "Notation Conventions" into "Glossary of Notation" | `notation.md` | Merge sections |
| R4 | Glossary should be last subsection of STARK Protocol section, not nested | `notation.md` | Move/restructure |
| R5 | Key Quantities should say what N is | `notation.md` | Add N to table |
| R6 | Double-check quantities match Python spec names | `notation.md` | Audit + report |
| R7 | Include Field in Notation Conventions | `notation.md` | Add row |
| R8 | Check if `squeeze_indices` is directly used in Python; if not, remove | `notation.md` | Audit |
| R9 | Building Blocks needs refs to Python | `building-blocks.md` | Add `{src}` links |
| R10 | Fiat-Shamir Transcript needs refs to Python | `building-blocks.md` | Add `{src}` links |
| R11 | TOC should reflect 5-phase structure, not flat list | `index.md` | Restructure |

### Audit Results (Pre-computed)

**R6 — Notation vs Python names:**

| Spec Symbol | Spec Meaning | Python Name | Match? |
|-------------|-------------|-------------|--------|
| $N = 2^n$ | Trace size | `2 ** stark_info.stark_struct.n_bits` | Yes (n = `n_bits`) |
| $N_{ext} = 2^{n_{ext}}$ | Extended domain | `2 ** stark_info.stark_struct.n_bits_ext` | Yes |
| $\omega$ | Primitive Nth root | `get_omega(n_bits)` in `field.py` | Yes |
| $g = 7$ | Coset shift | `SHIFT` in `field.py` | Yes |
| $Z_H(X)$ | Vanishing poly | `ProverHelpers.zi` (zerofier = 1/Z_H) | Close — note inverse |
| $J$ | Number of constraints | Implicit (length of constraint list) | OK |
| $d$ | Q split degree | `stark_info.q_deg` | Yes |
| $K$ | FRI rounds | `len(stark_info.stark_struct.fri_fold_steps)` | Yes |
| $Q_{queries}$ | FRI queries | `stark_info.stark_struct.n_queries` | Yes |
| $b_{pow}$ | Grinding bits | `stark_info.stark_struct.pow_bits` | Yes |
| $a$ | Merkle arity | `stark_info.stark_struct.merkle_tree_arity` | Yes |
| $\xi$ | Eval challenge | `xi` (in verifier/prover) | Yes |
| $v_1, v_2$ | Batching challenges | `vf1, vf2` (in fri_polynomial.py) | Diff name — note |
| $v_c$ | Constraint challenge | Derived from challenges array | OK |
| $\alpha, \gamma$ | Lookup challenges | `alpha, gamma` in constraint modules | Yes |

**R8 — `squeeze_indices` in Python:**
The spec notation `\T.\sqidx(q, b)` expands to `\mathsf{squeeze\_indices}` in rendered output.
In Python, this is `transcript.get_permutations(n, n_bits)`. The name `squeeze_indices`
does NOT appear anywhere in the Python code — it's called `get_permutations`. The spec
should note this mapping. Since the notation is otherwise clear and used in multiple
places (query derivation, full protocol), we keep the math notation `\sqidx` but add a
Python cross-reference showing the actual method name.

## Implementation Tasks

### Visual Dependency Tree

```
docs/sphinx/part-stark/
├── index.md              (Task #4: Restructure TOC with 5-phase grouping)
├── notation.md           (Task #1: Rename, add Python refs, merge tables, add N)
├── building-blocks.md    (Task #2: Add Python {src} refs throughout)
├── commitment-phase.md   (already has refs — no changes)
├── query-phase.md        (Task #3: Add Python {src} refs throughout)
├── challenge-binding.md  (Task #3: Add Python {src} refs throughout)
├── appendix-constraints.md (Task #3: Add Python {src} refs throughout)
├── appendix-batching.md  (Task #3: Add Python {src} refs throughout)
└── full-protocol.md      (already has refs — no changes)
```

### Execution Plan

#### Group A: Independent file edits (Execute all in parallel)

- [x] **Task #1**: Restructure `notation.md` — rename, merge, add Python refs
  - File: `docs/sphinx/part-stark/notation.md`
  - Changes:
    - **R1**: Rename top heading from "Notation and Algebraic Setup" to "Primitives"
    - **R2**: Add a new paragraph after the heading (before Fields) explaining:
      - The Python executable spec uses the `galois` library for field arithmetic
      - Link to `primitives/field.py` via `{src}`
      - Mention what the fork adds (FF3 cubic extension cache via `ff3_cache.pkl`)
      - Note that `FF` = `GF(p)` and `FF3` = `GF(p^3)` are the Python types
    - **R5**: Add row for $N$ to Key Quantities table: `$N = 2^n$` | Trace size (number of rows) — note it's already defined in Domains but should also appear in the table for quick reference
    - **R7**: Add row for $\F, \Fext$ to Notation Conventions table
    - **R3**: Merge "Key Quantities" and "Notation Conventions" into a single section called "Glossary of Notation"
      - Combine both tables into one, organized with quantities first then notation conventions
      - Add a "Python name" column showing the corresponding Python identifier where applicable
    - **R8**: In the merged glossary, for `\sqidx`, add note that Python name is `Transcript.get_permutations()`
    - **R6**: Add Python name column to glossary table mapping spec symbols to Python identifiers (see audit table above)
    - Add `{src}` links:
      - Fields section: `{src}\`primitives/field.py:39\`` for GOLDILOCKS_PRIME, `{src}\`primitives/field.py:43\`` for FF, `{src}\`primitives/field.py:47\`` for FF3
      - Domains section: `{src}\`primitives/field.py\`` for `get_omega()`, `SHIFT`
      - Polynomials section: reference to `protocol/stark_info.py` (PolMap)
  - Context: This is the first section readers encounter; Python refs here set the pattern

- [x] **Task #2**: Add Python `{src}` references to `building-blocks.md`
  - File: `docs/sphinx/part-stark/building-blocks.md`
  - Changes (R9, R10):
    - **Polynomial Commitment via Merkle Trees:**
      - Step 1 (INTT + NTT extend): `{src}\`primitives/ntt.py:95\`` (extend_pol), `{src}\`protocol/stages.py:424\`` (extendAndMerkelize)
      - Step 2a (row formation): `{src}\`primitives/merkle_tree.py:47\`` (transpose_for_merkle)
      - Step 2b (hash each row): `{src}\`primitives/merkle_tree.py:89\`` (MerkleTree.merkelize)
      - Step 2c (Merkle tree build): `{src}\`primitives/merkle_tree.py:60\`` (MerkleTree class)
      - Step 3 (output root): `{src}\`primitives/merkle_tree.py\`` (get_root)
      - Opening proof: `{src}\`primitives/merkle_tree.py\`` (get_query_proof)
      - Verification: `{src}\`primitives/merkle_verifier.py:70\`` (MerkleVerifier class)
      - Also mention MerkleProver: `{src}\`primitives/merkle_prover.py:16\``
    - **Fiat-Shamir Transcript:**
      - Transcript class: `{src}\`primitives/transcript.py:27\`` (Transcript class)
      - `\T.\abs`: `{src}\`primitives/transcript.py:49\`` (put method)
      - `\T.\sq`: `{src}\`primitives/transcript.py:54\`` (get_field method)
      - `\T.\sqidx`: `{src}\`primitives/transcript.py:68\`` (get_permutations method)
        - Add parenthetical: "(called `get_permutations` in the Python spec)"
  - Context: These are the two building blocks used throughout the protocol

- [x] **Task #3**: Add Python `{src}` references to query-phase, challenge-binding, and appendices
  - Files:
    - `docs/sphinx/part-stark/query-phase.md`
    - `docs/sphinx/part-stark/challenge-binding.md`
    - `docs/sphinx/part-stark/appendix-constraints.md`
    - `docs/sphinx/part-stark/appendix-batching.md`
  - Changes for **query-phase.md**:
    - Transcript Reconstruction: `{src}\`protocol/verifier.py:382\`` (_reconstruct_transcript)
    - Constraint Check:
      - Evaluate C(xi): `{src}\`protocol/verifier.py:742\`` (_verify_evaluations)
      - Z_H(xi): `{src}\`protocol/verifier.py:747\``
      - Q(xi) reconstruction: `{src}\`protocol/verifier.py:686\``
      - Final check: `{src}\`protocol/verifier.py:753\``
    - Grinding Check: `{src}\`protocol/verifier.py\`` (grinding verification)
    - Degree Check: `{src}\`protocol/verifier.py:964\`` (_verify_final_polynomial)
      - INTT: `{src}\`protocol/verifier.py:982\``
      - Degree bound: `{src}\`protocol/verifier.py:987\``
      - Coefficient check: `{src}\`protocol/verifier.py:989\``
    - Query Derivation: `{src}\`protocol/verifier.py:94\``
      - sqidx call: `{src}\`protocol/verifier.py:98\``
    - Merkle Tree Verification: `{src}\`protocol/verifier.py:803\`` (_verify_stage_merkle)
      - Also: `{src}\`protocol/verifier.py:829\`` (_verify_const_merkle)
      - Also: `{src}\`protocol/verifier.py:879\`` (_verify_fri_merkle_tree)
    - FRI Polynomial Consistency: `{src}\`protocol/verifier.py:758\`` (_verify_fri_consistency)
      - FRI polynomial verifier: `{src}\`protocol/fri_polynomial.py:246\`` (compute_fri_polynomial_verifier)
    - FRI Folding Verification: `{src}\`protocol/verifier.py:905\`` (_verify_fri_folding)
      - FRI verify_fold: `{src}\`protocol/fri.py:86\``
  - Changes for **challenge-binding.md**:
    - Per-AIR Contributions: `{src}\`tests/challenge_utils.py\`` (derive_global_challenge_multi_air)
      - Note: challenge derivation is currently only in test utilities, not in a protocol module
    - Lattice expansion: reference the chain-hash loop in challenge_utils.py
    - Global challenge derivation: `{src}\`tests/challenge_utils.py\`` (transcript squeeze)
  - Changes for **appendix-constraints.md**:
    - ConstraintModule ABC: `{src}\`constraints/base.py:43\`` (ConstraintContext)
    - constraint_polynomial method: `{src}\`constraints/base.py\`` (ConstraintModule)
    - Horner combination: note that the Python spec uses per-AIR modules (e.g., `{src}\`constraints/simple_left.py\``) or the bytecode adapter (`{src}\`constraints/bytecode_adapter.py\``)
    - Compress function: `{src}\`constraints/base.py:32\`` (compress_2col)
  - Changes for **appendix-batching.md**:
    - Prover batching: `{src}\`protocol/fri_polynomial.py:129\`` (compute_fri_polynomial)
    - Verifier batching: `{src}\`protocol/fri_polynomial.py:246\`` (compute_fri_polynomial_verifier)
    - Intra-group Horner: reference the inner loop in fri_polynomial.py
    - Inter-group Horner: reference the outer loop in fri_polynomial.py
    - DEEP quotient denominator: `{src}\`protocol/verifier.py:634\`` (_compute_x_div_x_sub)
  - Context: These four files currently have zero Python references

#### Group B: TOC restructuring (After Group A, since it may affect cross-references)

- [x] **Task #4**: Restructure `index.md` TOC to reflect 5-phase protocol
  - File: `docs/sphinx/part-stark/index.md`
  - Changes (R11):
    - The review notes say the TOC should reflect the 5-phase structure:
      setup → commit stages → evaluation → FRI fold → query
    - Current toctree is a flat list. The intro text should be updated to frame
      the 5-phase structure, then the toctree entries can be annotated.
    - Note: MyST toctree doesn't support nested grouping headers natively,
      so the restructuring would be done via the intro text and/or section
      renaming rather than toctree nesting.
    - Options:
      a. Add a brief paragraph listing the 5 phases with forward-refs
      b. Rename sections to include phase numbers (e.g., "Commitment Phase (Phases 1-3)")
      c. Both
    - **R4**: Move the merged "Glossary of Notation" so it's the last subsection
      before the appendices (or make it a standalone page in the toctree).
      Currently Key Quantities and Notation Conventions are sub-subsections of
      notation.md. After renaming to Primitives and merging to Glossary, the
      Glossary should either:
      - Stay as a subsection within Primitives (simplest)
      - Become its own toctree entry (more visible, but adds a file)
      Recommendation: keep it in Primitives as the last subsection — simpler.

---

## Implementation Workflow

This plan file serves as the authoritative checklist for implementation. When implementing:

### Required Process
1. **Load Plan**: Read this entire plan file before starting
2. **Sync Tasks**: Create TaskCreate tasks matching the checkboxes above
3. **Execute & Update**: For each task:
   - Mark task as `in_progress` when starting
   - Update checkbox `[ ]` to `[x]` when completing
   - Mark task as `completed` when done
4. **Maintain Sync**: Keep this file and task list synchronized throughout

### Critical Rules
- This plan file is the source of truth for progress
- Update checkboxes in real-time as work progresses
- Tasks in Group A can run in parallel (they edit different files)
- Task #4 should run after Group A since TOC changes may interact with renames
- After all edits, build the Sphinx docs to verify no broken references:
  `cd docs/sphinx && uv run --group docs make html`
- Verify `{src}` links resolve correctly in the built HTML

### Line Number Verification
**Important**: The line numbers in this plan are from the research phase. Before adding
`{src}` links, verify current line numbers by reading the actual Python files — they
may have shifted since the audit.

### Progress Tracking
The checkboxes above represent the authoritative status of each task.
