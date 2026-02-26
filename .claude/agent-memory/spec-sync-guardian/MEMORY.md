# Spec Sync Guardian Memory

## Sync Checkpoint File
- Location: `/home/cody/pil2-proofman/SPEC_SYNC.md` (root of repo)
- No prior checkpoint existed; this file was created on 2026-02-26

## Key Markdown Spec Files (priority order)

### Primary spec (contain {src} code references)
- `/home/cody/pil2-proofman/docs/sphinx/part-stark/building-blocks.md`
- `/home/cody/pil2-proofman/docs/sphinx/part-stark/commitment-phase.md`
- `/home/cody/pil2-proofman/docs/sphinx/part-stark/full-protocol.md`
- `/home/cody/pil2-proofman/docs/sphinx/part-stark/query-phase.md`
- `/home/cody/pil2-proofman/docs/sphinx/part-stark/appendix-constraints.md`
- `/home/cody/pil2-proofman/docs/sphinx/part-stark/challenge-binding.md`
- `/home/cody/pil2-proofman/executable-spec/README.md`

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

## Known Pre-Existing Stale References (before af14b0d)
1. `executable-spec/README.md` lines 30, 76, 83: References `protocol/proof_context.py` and `ProofContext` — file was deleted in commit `77b716ba`. Two-layer model description is now wrong (ProofContext layer no longer exists; protocol internals use numpy arrays directly).
2. `docs/sphinx/part-stark/full-protocol.md` line 163: `{src}\`protocol.verifier.verify\`` — function is named `stark_verify`, not `verify`. The symbol `verify` does not exist in the module.

## Stale References Introduced Since af14b0d
3. `docs/sphinx/part-stark/building-blocks.md` line 14: `\`calculate_witness_with_module\`` — renamed to `calculate_witness` in commit `33ec379a`. The `{src}` anchor `protocol/stages.py#calc-witness` is still valid.

## Undocumented Protocol Changes Since af14b0d (not in any spec markdown)
1. **New AIRs added** (Simple pilout multi-AIR): `SimpleRight`, `U8Air`, `U16Air`, `SpecifiedRanges` — new witness modules in `witness/`. No spec coverage needed (implementation detail), but `executable-spec/README.md` supported AIRs table only lists 3 AIRs.
2. **`ProverData.constants` key changed**: Was `dict[str, FFPoly]` keyed by name. Now `dict[tuple[str, int], FFPoly]` keyed by (name, index) to support AIRs with multiple same-named constants. Data model docstring in `protocol/data.py` was updated. No sphinx spec doc references this internal format.
3. **`ConstraintContext.const/next_const/prev_const` API changed**: Added `index: int = 0` parameter. Not referenced directly in sphinx spec.
4. **`gen_proof` signature simplified**: Removed `skip_challenge_derivation` and `injected_challenges` params (testing scaffolding). Also renamed `root1`→`stage1_commitment`, `computed_roots`→`commitments`. Not referenced in sphinx spec.
5. **`AirConfig` gained `expressions_bin` field**: Auto-detected sibling `.bin` file. Used for bytecode fallback when hand-written modules defer Stage-2.
6. **`get_constraint_module`/`get_witness_module` gained `expressions_bin` param**: Prevents cross-pilout naming collisions (e.g., SpecifiedRanges in both Simple and Zisk pilouts).
7. **Proof dict now includes `"global_challenge"` key**: Contains transcript seed (Modes 1 and 2) or None (Mode 3). Enables verifier to reconstruct transcript without re-deriving.

## High-Drift Python Modules (most likely to cause spec drift)
- `protocol/stages.py` — PolynomialCommitter class, all doc-anchors for stage ops
- `protocol/prover.py` — gen_proof() signature, doc-anchors for transcript modes
- `protocol/verifier.py` — stark_verify(), all verification doc-anchors
- `constraints/base.py` — ConstraintContext ABC, public API

## Recommended Fixes (apply when authorized)
1. `docs/sphinx/part-stark/building-blocks.md` line 14: Change `\`calculate_witness_with_module\`` to `\`calculate_witness\`` (the {src} anchor is correct)
2. `executable-spec/README.md` lines 30, 76, 83: Remove `proof_context.py` row from directory tree and key abstractions table; update "two-layer data model" section to reflect current architecture (numpy arrays for protocol internals, ProverData/VerifierData for modules)
3. `docs/sphinx/part-stark/full-protocol.md` line 163: Change `{src}\`protocol.verifier.verify\`` to `{src}\`protocol.verifier.stark_verify\``
