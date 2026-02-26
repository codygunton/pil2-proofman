# Spec Sync Guardian Memory

## Sync Checkpoint File
- Location: `/home/cody/pil2-proofman/SPEC_SYNC.md` (root of repo)
- Current checkpoint: `d601eaf4` (2026-02-26, second pass)

## Key Markdown Spec Files (priority order)

### Primary spec (contain {src} code references)
- `/home/cody/pil2-proofman/docs/sphinx/part-stark/building-blocks.md`
- `/home/cody/pil2-proofman/docs/sphinx/part-stark/commitment-phase.md`
- `/home/cody/pil2-proofman/docs/sphinx/part-stark/full-protocol.md`
- `/home/cody/pil2-proofman/docs/sphinx/part-stark/query-phase.md`
- `/home/cody/pil2-proofman/docs/sphinx/part-stark/appendix-constraints.md`
- `/home/cody/pil2-proofman/docs/sphinx/part-stark/challenge-binding.md`
- `/home/cody/pil2-proofman/executable-spec/README.md`

### API RST docs (also contain stale symbol references)
- `/home/cody/pil2-proofman/docs/sphinx/api/protocol/prover/index.rst`
- `/home/cody/pil2-proofman/docs/sphinx/api/protocol/simple_pilout/index.rst`
- `/home/cody/pil2-proofman/docs/sphinx/api/protocol/verifier/index.rst`
- (all files under `docs/sphinx/api/` — NOT auto-generated; must be updated manually)

### Secondary (user-facing docs, no Python code refs)
- `/home/cody/pil2-proofman/CLAUDE.md` — project instructions, package structure
- `/home/cody/pil2-proofman/executable-spec/NOTES.md` — dev notes on transcript modes
- `/home/cody/pil2-proofman/docs/sphinx/part-machine/` — ZisK machine docs (Rust refs, not Python)
- `/home/cody/pil2-proofman/docs/sphinx/part-recursion/` — recursion pipeline docs (JS/Rust refs)

## {src} Reference Conventions
- Two formats used interchangeably:
  - Path+anchor: `{src}\`protocol/stages.py#calc-witness\`` — links to `# <doc-anchor id="calc-witness">` comment in the file
  - Dotted symbol: `{src}\`protocol.verifier._verify_fri_consistency\`` — links to Python symbol by dotted import path
- Both formats are used in the same doc. Neither has line numbers.
- **Important**: The RST API docs under `docs/sphinx/api/` are NOT auto-generated — they are hand-maintained and drift just like the markdown spec files. Always include them in sync checks.

## Outstanding Stale References (pre-existing, not yet fixed)
1. `docs/sphinx/part-stark/building-blocks.md` line 14: `` `calculate_witness_with_module` `` — renamed to `calculate_witness`. The `{src}` anchor `protocol/stages.py#calc-witness` is still valid; only the function name in prose needs updating.
2. `docs/sphinx/part-stark/full-protocol.md` line 163: `{src}\`protocol.verifier.verify\`` — function is named `stark_verify`, not `verify`. Symbol `verify` does not exist in the module.
3. `executable-spec/README.md`: `proof_context.py` / `ProofContext` references — file deleted in `77b716ba`. Already fixed in directory tree and key abstractions table; check if any prose remains.

## Resolved Stale References (d601eaf4 sync pass)
- `full-protocol.md` line 33: removed dead `#transcript-seed-standalone` anchor (Mode 3 deleted)
- `commitment-phase.md` lines 33–53: replaced two-mode (Standalone + VADCOP) section with VADCOP-only
- `api/protocol/prover/index.rst`: removed `global_challenge` and `compute_global_challenge` params from `gen_proof()` signature
- `api/protocol/simple_pilout/index.rst`: updated module docstring, usage example, and autoapisummary listings to reflect `prove_simple_pilout()` / `AIRProveData` as primary API

## High-Drift Python Modules (most likely to cause spec drift)
- `protocol/stages.py` — PolynomialCommitter class, all doc-anchors for stage ops
- `protocol/prover.py` — gen_proof() signature, doc-anchors for transcript modes; also `api/protocol/prover/index.rst`
- `protocol/simple_pilout.py` — multi-AIR API surface; also `api/protocol/simple_pilout/index.rst`
- `protocol/verifier.py` — stark_verify(), all verification doc-anchors; also `api/protocol/verifier/index.rst`
- `constraints/base.py` — ConstraintContext ABC, public API

## Protocol State (as of d601eaf4)
- `gen_proof()` signature: `(air_config, trace, const_pols, const_pols_extended, public_inputs=None)`
- Modes 1 (external VADCOP) and 3 (standalone) deleted; only Mode 2 (internal VADCOP) remains
- Multi-AIR primary API: `prove_simple_pilout(air_data: dict[str, AIRProveData]) -> dict[str, dict]`
- `_commit_stage1()` and `_gen_proof_stage2_plus()` are private helpers (not spec-visible)
- `prove_simple_pilout_stage1()` / `AIRStage1Data` still exist as lower-level API (not deleted)

## Recommended Fixes (still outstanding)
1. `docs/sphinx/part-stark/building-blocks.md` line 14: Change `` `calculate_witness_with_module` `` to `` `calculate_witness` `` (the {src} anchor is correct)
2. `docs/sphinx/part-stark/full-protocol.md` line 163: Change `{src}\`protocol.verifier.verify\`` to `{src}\`protocol.verifier.stark_verify\``
