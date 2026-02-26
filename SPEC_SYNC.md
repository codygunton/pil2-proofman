# Spec Sync History

## 2026-02-26 (second pass)

- **Commit checked**: `d601eaf454d78577b2040993e311d59b19d2e493`
- **Diffed from**: `5c8265595c882ff84643146f9f3fd218e9e25c3c`
- **Checked by**: spec-sync-guardian agent
- **Python files changed since last sync**: protocol/prover.py, protocol/simple_pilout.py, protocol/verifier.py (+ style/perf-only changes)
- **Issues found**: 4 stale references
- **Issues resolved**: 4 (all applied)
- **Notes**: Mode 3 (standalone) and Modes 1/external-VADCOP removed from prover.py; gen_proof() signature simplified (removed global_challenge, compute_global_challenge params); prove_simple_pilout() + AIRProveData added as primary multi-AIR API. Fixed: (1) full-protocol.md line 33 dead #transcript-seed-standalone anchor, (2) commitment-phase.md standalone mode section, (3) api/protocol/prover/index.rst gen_proof() signature, (4) api/protocol/simple_pilout/index.rst module docstring and API surface.

## 2026-02-26

- **Commit checked**: `5c8265595c882ff84643146f9f3fd218e9e25c3c`
- **Diffed from**: `af14b0d526bd928cbc639a32e2ef56f2fc739d66`
- **Checked by**: spec-sync-guardian agent
- **Python files changed since last sync**: 8 modified + 6 new (executable-spec/)
- **Issues found**: 3 stale references (all pre-existing before this diff), 2 undocumented protocol changes
- **Issues resolved**: 0 (no spec edits authorized yet — report delivered to user)
- **Notes**: Main changes were Starks→PolynomialCommitter rename (already reflected in README.md and executable-spec/README.md), calculate_witness_with_module→calculate_witness (building-blocks.md stale), new Simple pilout AIRs added (U8Air, U16Air, SimpleRight, SpecifiedRanges), ProverData.constants key changed to tuple[str,int], expressions_bin param added to AirConfig/gen_proof. Two pre-existing stale refs identified: proof_context.py in executable-spec/README.md, protocol.verifier.verify (should be stark_verify) in full-protocol.md.
