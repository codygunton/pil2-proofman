# Zisk AIR Support: Hybrid Bytecode + Hand-Written Plan

> Groups A-C completed. Groups D-F remain.

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

### Group D: Zisk Build Artifacts and Infrastructure

#### Task #10: Generate Zisk build artifacts
- Follow `zisk-for-spec/tools/test-env/build_setup.sh`:
  1. Generate fixed data: `cargo run --release --bin arith_frops_fixed_gen` (etc.)
  2. Compile PIL: `node pil2-compiler/src/pil.js pil/zisk.pil -I ... -o pil/zisk.pilout`
  3. Generate setup: `node pil2-proofman-js/src/main_setup.js -a ./pil/zisk.pilout -b build -s starkstructs.json`
- Output: per-AIR directories under `build/provingKey/` each containing:
  - `*.starkinfo.json` (AIR spec)
  - `*.bin` (compiled expression bytecode)
  - `*.const` (constant polynomial values)
  - `*.consttree` (Merkle tree over constant polynomials)
- **Dependencies**: `pil2-compiler` and `pil2-proofman-js` as sibling repos, Rust toolchain for cargo builds

#### Task #11: Generate Zisk witness traces
- The Zisk prover (`cargo-zisk`) generates witness traces by running a RISC-V program
- We need to capture the witness trace data per AIR for use as Python test inputs
- Start with the simplest ELF program available in `zisk-for-spec/witness-computation/rom/zisk.elf`

#### Task #12: Wire Zisk AIRs into BYTECODE_AIRS registry
- Enumerate all AIR directories from the build output
- Add each to `BYTECODE_AIRS` with its `.bin` path
- No hand-written modules needed — bytecode adapter handles all of them

#### Task #13: Protocol gaps (public inputs + custom commits)
- Only needed here because Zisk exercises them; no standalone test possible
- **Public inputs** (68 in Zisk):
  - Audit transcript seeding code in `prover.py` and `verifier.py`
  - Validate against Zisk reference data
- **Custom commits** (Zisk Rom uses `commit stage(0) public(rom_root) rom`):
  - Implement `_verify_custom_commit_merkle()` in `verifier.py` (currently returns `True`)
  - Implement `_load_evmap_poly()` for custom type in `stages.py` (currently `NotImplementedError`)
  - Reference: `pil2-stark/src/starkpil/stark_verify.hpp` line 504

### Group E: Zisk E2E Integration

#### Task #14: Per-AIR unit tests and full proof comparison
- 14a: Identify simplest Zisk AIRs (DualByte, ArithTable likely)
- 14b: Generate per-AIR reference data from Rust prover
- 14c: Per-AIR Python proving with bytecode adapter
- 14d: VADCOP coordination validation
- 14e: Full proof comparison (Python verifier accepts Rust proofs)

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
| Group E | Per-AIR Zisk tests | Bytecode adapter handles Zisk AIRs |

## Execution Order

```
Group A (#1-4) ──seq──> Group B (#5-7) ──> Group C (#8-9)  ← ALL COMPLETE
                                                │
                                      Group D (#10-13) ──> Group E (#14a-14e)
                                                                    │
                                                              Group F (#15)
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

### Group D: Zisk Build Artifacts
- [ ] #10 Generate Zisk build artifacts (PIL compile + setup)
- [ ] #11 Generate Zisk witness traces (run Rust prover, capture per-AIR data)
- [ ] #12 Wire Zisk AIRs into BYTECODE_AIRS registry
- [ ] #13 Protocol gaps: public inputs + custom commits

### Group E: Zisk E2E Integration
- [ ] #14a Identify simplest Zisk AIRs
- [ ] #14b Generate per-AIR reference data from Rust prover
- [ ] #14c Per-AIR Python proving with bytecode adapter
- [ ] #14d VADCOP coordination validation
- [ ] #14e Full proof comparison (Python verifier accepts Rust proofs)

### Group F: Transpiler (Future)
- [ ] #15 Evaluate transpiler vs bytecode-only for readability
