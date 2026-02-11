# Zisk AIR Support: Hybrid Bytecode + Hand-Written Plan

> Groups A-E COMPLETE. All 12 Zisk AIRs pass (including Rom). Group F remains (future).

## Executive Summary

Reinstate the bytecode interpreter **strictly behind the existing ConstraintModule/WitnessModule ABCs** as a fallback for AIRs without hand-written Python. A registry dict controls which backend each AIR uses, allowing side-by-side validation. Zero changes to `protocol/` files for bytecode support.

**Phases**: Test AIRs (validate bytecode == hand-written) -> Protocol gaps only when Zisk needs them -> Zisk RISC-V AIRs -> Consider transpiler bootstrapping.

---

## Architecture

### Hard Rule: No Protocol Pollution

The following files **must not change** for bytecode support:
- `protocol/prover.py`
- `protocol/verifier.py`
- `protocol/stages.py`
- `protocol/fri.py`, `protocol/pcs.py`

All bytecode machinery lives in `primitives/expression_bytecode/` package. Wrappers live in `constraints/` and `witness/`. The toggle lives in the registries.

### Package Layout

```
executable-spec/
  primitives/
    expression_bytecode/                (bytecode interpreter, isolated)
      __init__.py
      expressions_bin.py                (recovered from git, adapted)
      expression_evaluator.py           (recovered from git, adapted)
      witness_generation.py             (recovered from git, adapted)

  constraints/
    __init__.py                         (MODIFIED - add toggle + bytecode fallback)
    base.py                             (UNCHANGED)
    bytecode_adapter.py                 (BytecodeConstraintModule wrapper)
    simple_left.py                      (UNCHANGED)
    lookup2_12.py                       (UNCHANGED)
    permutation1_6.py                   (UNCHANGED)

  witness/
    __init__.py                         (MODIFIED - add toggle + bytecode fallback)
    base.py                             (UNCHANGED)
    bytecode_adapter.py                 (BytecodeWitnessModule wrapper)
    simple_left.py                      (UNCHANGED)
    lookup2_12.py                       (UNCHANGED)
    permutation1_6.py                   (UNCHANGED)

  protocol/                             (UNCHANGED for bytecode. Protocol gaps are
                                         separate work, not bytecode-related.)
```

### Toggle Mechanism

```python
# constraints/__init__.py
CONSTRAINT_REGISTRY: dict[str, type[ConstraintModule]] = {
    'SimpleLeft': SimpleLeftConstraints,        # hand-written
    'Lookup2_12': Lookup2_12Constraints,        # hand-written
    'Permutation1_6': Permutation1_6Constraints, # hand-written
}

# AIRs that should use bytecode interpreter instead of hand-written modules.
BYTECODE_AIRS: dict[str, str] = {
    # 'SimpleLeft': '/path/to/SimpleLeft.bin',   # uncomment to use bytecode
    # 'SomeZiskAir': '/path/to/SomeZiskAir.bin', # no hand-written module exists
}

def get_constraint_module(air_name: str) -> ConstraintModule:
    if air_name in BYTECODE_AIRS:
        from constraints.bytecode_adapter import BytecodeConstraintModule
        return BytecodeConstraintModule(BYTECODE_AIRS[air_name])
    if air_name in CONSTRAINT_REGISTRY:
        return CONSTRAINT_REGISTRY[air_name]()
    raise KeyError(f"No constraint module for AIR '{air_name}'")
```

Same pattern for `witness/__init__.py`. `BYTECODE_AIRS` checked first so you can override a hand-written module with bytecode for validation.

---

## Critical Design Detail: cExpId Computes Q(x), Not C(x)

The C++ compiled bytecode expression `cExpId` computes **Q(x) = C(x)/Z_H(x)** directly — the zerofier division is baked into the bytecode. The hand-written Python modules compute **C(x)** (the raw constraint polynomial).

The adapter bridges this gap:
- **Prover path**: `C(x) = Q(x) * Z_H(x)` where `Z_H(x) = batch_inverse(zi)` and `zi = 1/Z_H(x)` from ProverHelpers
- **Verifier path**: `C(xi) = Q(xi) * (xi^N - 1)` computed directly

This creates a conceptual round-trip (adapter undoes division, stages.py redoes it), but maintains the clean ConstraintModule interface.

---

## Implementation Tasks

### Group A: Recover and Isolate Bytecode Interpreter — COMPLETE ✓

#### Task #1: Recover expression binary parser ✓
- Recovered from `git show 731d33f4~1:executable-spec/protocol/expressions_bin.py`
- Destination: `primitives/expression_bytecode/expressions_bin.py`

#### Task #2: Recover bytecode interpreter ✓
- Recovered from `git show 731d33f4~1:executable-spec/protocol/expression_evaluator.py`
- Destination: `primitives/expression_bytecode/expression_evaluator.py`

#### Task #3: Recover hint-driven witness generation ✓
- Recovered from `git show 731d33f4~1:executable-spec/protocol/witness_generation.py`
- Destination: `primitives/expression_bytecode/witness_generation.py`

#### Task #4: Recover parser tests ✓
- Recovered from `git show 731d33f4~1:executable-spec/tests/test_expressions_bin.py`
- Destination: `tests/test_expressions_bin.py`

### Group B: Build Adapter Wrappers — COMPLETE ✓

#### Task #5: BytecodeConstraintModule adapter ✓
- File: `constraints/bytecode_adapter.py`
- Key fix: cExpId returns Q(x), adapter multiplies by Z_H to recover C(x)

#### Task #6: BytecodeWitnessModule adapter ✓
- File: `witness/bytecode_adapter.py`

#### Task #7: Registry toggle wiring ✓
- BYTECODE_AIRS dicts in `constraints/__init__.py` and `witness/__init__.py`

### Group C: Validate Bytecode == Hand-Written — COMPLETE ✓

#### Task #8: Bytecode equivalence tests ✓
- File: `tests/test_bytecode_equivalence.py`
- All 3 test AIRs pass: bytecode produces identical constraint evaluations

#### Task #9: Full E2E with bytecode toggle ✓
- All 171 tests pass with bytecode-only configuration
- Byte-identical proofs confirmed
- Toggle reverted to hand-written default

---

### Group D: Zisk Build Artifacts and Infrastructure — COMPLETE ✓

**Approach taken** (diverged from original plan): Used existing `zisk/provingKey` (22 AIRs,
zksyncos branch) rather than rebuilding from `zisk-for-spec/` at v0.15.0. This proved
sufficient for verifier E2E testing. The original detailed plan is preserved in
`zisk-e2e-fixture-generation.md` for reference.

#### Task #10: Zisk AIR auto-discovery ✓
- `_discover_zisk_airs()` in `constraints/__init__.py` and `witness/__init__.py`
- Reads `pilout.globalInfo.json` from `ZISK_PROVING_KEY` env var
- Dynamically populates `BYTECODE_AIRS` dict: 22 AIRs discovered
- No manual enumeration needed — purely data-driven

#### Task #11: Zisk fixture generation ✓
- `generate-zisk-test-vectors.sh`: Runs `cargo-zisk prove` against the test ELF,
  then converts JSON proofs to binary via `tests/json-proof-to-bin.py`
- Produces per-AIR `.proof.bin` files in `tests/test-data/zisk/`
- 13 AIRs exercised by the test ELF (others have 0 rows, no proofs generated)

#### Task #12: BYTECODE_AIRS registry ✓
- Auto-discovery handles this — no manual registry entries needed
- Each discovered AIR maps to its `.bin` bytecode file path

#### Task #13: Protocol gaps ✓
- **Public inputs** (68 values): Transcript seeding verified correct
- **Custom commits**: `_verify_custom_commit_merkle()` implemented in `verifier.py`
- **Custom commit eval loading**: `EvMap.Type.custom` case added to
  `_build_buffers_from_verifier_data()` in `constraints/bytecode_adapter.py`
- Only Rom AIR uses custom commits (11 polynomials, `qDeg=1`)

### Group E: Zisk Verifier E2E — COMPLETE ✓

#### Task #14: Zisk verifier E2E tests ✓
- Test file: `tests/test_zisk_verifier_e2e.py`
- 12 AIR test cases (Fibonacci ELF doesn't exercise Arith), parametrized
- **ALL 12 AIRs PASS** (including Rom!) — no xfails
- Fixtures: CPU-generated proofs from Fibonacci(10) guest on zisk-for-spec v0.15.0
- Module-level skip gate: `pytestmark = pytest.mark.skipif` on `ZISK_PROVING_KEY`
- Full test suite: 320+ passed in ~2 min (excluding Zisk); Zisk E2E ~17 min

**Rom xfail — RESOLVED:**
Previously Rom failed with evaluation check errors. Root cause was stale/invalid
proof fixtures from an earlier prover run. Regenerating fixtures with the CPU prover
(`generate-zisk-test-vectors.sh`) using a fresh Fibonacci(10) ELF on zisk-for-spec
v0.15.0 resolved the issue. Commit `8808bc99`.

### Group F: Transpiler Bootstrapping (Future)

#### Task #15: Consider transpiler for readability
- Once Zisk works via bytecode, evaluate whether a transpiler is worth building
- Bytecode adapter stays as permanent fallback

---

## Verification

| After | Command | Expected |
|-------|---------|----------|
| Group A | `uv run pytest tests/test_expressions_bin.py -v` | Parser tests pass ✓ |
| Group A | `uv run ruff check .` | No lint errors ✓ |
| Group B | `./run-tests.sh` (hand-written default) | All tests pass ✓ |
| Group C | `uv run pytest tests/test_bytecode_equivalence.py -v` | Bytecode == hand-written ✓ |
| Group C | Toggle to bytecode, `./run-tests.sh` | 171 tests pass byte-identically ✓ |
| Group D | `ZISK_PROVING_KEY=... python -c "from constraints import ..."` | 22 AIRs discovered ✓ |
| Group E | `./run-tests.sh zisk` | 12 Zisk AIRs pass ✓ |
| Group E | `./run-tests.sh e2e` | 19 E2E tests pass (~35s) ✓ |

## Execution Order

```
Group A (#1-4) ──seq──> Group B (#5-7) ──> Group C (#8-9)  ← ALL COMPLETE
                                                │
                                      Group D (#10-13) ← COMPLETE (auto-discovery approach)
                                                │
                                      Group E (#14) ← COMPLETE (12/12 pass, Rom fixed)
                                                │
                                      Group F (#15) ← FUTURE
```

---

## Progress Checklist

### Group A: Recover Bytecode Interpreter
- [x] #1 Recover expression binary parser (`primitives/expression_bytecode/expressions_bin.py`)
- [x] #2 Recover bytecode interpreter (`primitives/expression_bytecode/expression_evaluator.py`)
- [x] #3 Recover witness generation (`primitives/expression_bytecode/witness_generation.py`)
- [x] #4 Recover parser tests (`tests/test_expressions_bin.py`)

### Group B: Build Adapter Wrappers
- [x] #5 BytecodeConstraintModule adapter (`constraints/bytecode_adapter.py`)
- [x] #6 BytecodeWitnessModule adapter (`witness/bytecode_adapter.py`)
- [x] #7 Registry toggle in `constraints/__init__.py` and `witness/__init__.py`

### Group C: Validate Bytecode == Hand-Written
- [x] #8 Equivalence tests (`tests/test_bytecode_equivalence.py`) — all 3 AIRs match
- [x] #9 Full E2E with bytecode toggle — 171 tests pass, byte-identical proofs

### Group C+: Readability Cleanup (from agent reviews)

Findings from zksnark-python-style and human-simplicity-enforcer reviews.
Can be done before or after Group D — correctness is not affected.

**Adapter files** (`constraints/bytecode_adapter.py`, `witness/bytecode_adapter.py`):
- [x] #C+1 Extract repeated index computation to shared helper (`bytecode_utils.py`)
- [x] #C+2 Split `_build_buffers_from_prover_data()` into named phases
- [x] #C+3 Split `_build_buffers_from_witness_data()` similarly
- [x] #C+4 Extract Z_H correction into `_recover_constraint_from_quotient_{prover,verifier}()`
- [x] #C+5 Extract `_ensure_buffers()` / `_run_witness_computation()` in BytecodeWitnessModule

**Recovered interpreter files** (`primitives/expression_bytecode/`):
- [x] #C+6 Named buffer type offset constants (PUBLIC_INPUTS_OFFSET..EVALS_OFFSET)
- [x] #C+7 Expanded dense comprehensions to explicit loops with named intermediates
- [x] #C+8 Extracted hint parsing into `_parse_hint()`, `_parse_hint_field()`, `_parse_hint_field_value()`
- [x] #C+9 Added mathematical variable citations in docstrings

### Group D: Zisk Build Artifacts — COMPLETE ✓
(Approach changed from original plan: used existing `zisk/provingKey` with 22 AIRs
from zksyncos branch instead of building v0.15.0 from scratch via `zisk-for-spec/`.
See `zisk-e2e-fixture-generation.md` for the original detailed plan, now superseded.)

- [x] #10 Zisk AIR auto-discovery (`_discover_zisk_airs()` in constraints/\_\_init\_\_.py)
  - Reads `pilout.globalInfo.json` from `ZISK_PROVING_KEY` env var
  - Discovers 22 AIRs (including U256Delegation from zksyncos)
- [x] #11 Fixture generation via `cargo-zisk prove` + `generate-zisk-test-vectors.sh`
  - Binary proofs generated for 13 exercised AIRs (of 22 discovered)
  - JSON-to-binary converter: `tests/json-proof-to-bin.py`
- [x] #12 BYTECODE_AIRS registry wired via auto-discovery (no manual wiring needed)
- [x] #13 Protocol gaps:
  - Public inputs: 68 values, seeded into transcript correctly
  - Custom commits: `_verify_custom_commit_merkle()` implemented in verifier.py
  - Custom commit eval loading: `EvMap.Type.custom` handling in bytecode_adapter.py

### Group E: Zisk Verifier E2E — COMPLETE ✓
(Verifier-only E2E. Prover E2E deferred — Zisk AIRs too large for JSON witness traces.)

- [x] #14a 12 Zisk AIRs exercised by Fibonacci(10) ELF (no Arith)
- [x] #14b Binary proof fixtures generated via `generate-zisk-test-vectors.sh`
- [x] #14c Python verifier validates C++ proofs: **12/12 pass** (including Rom)
- [ ] ~~#14d VADCOP coordination validation~~ (deferred — single-AIR verification scope)
- [x] #14e Test file: `tests/test_zisk_verifier_e2e.py`
  - **All passing**: Main, MemAlign, RomData, InputData, Mem, BinaryExtension,
    BinaryAdd, Binary, SpecifiedRanges, VirtualTable0, VirtualTable1, Rom
  - Rom xfail RESOLVED — was caused by stale fixtures (commit `8808bc99`)

### Group F: Transpiler (Future)
- [ ] #15 Evaluate transpiler vs bytecode-only for readability
