# Zisk AIR Support: Interpreter-First Implementation Plan

## Executive Summary

Get the full Zisk RISC-V AIR system working in the Python executable spec by **reinstating the previously-deleted expression binary interpreter** behind the existing `ConstraintModule`/`WitnessModule` API. This gives us immediate support for all ~25 Zisk AIRs without per-AIR Python code. Then, incrementally convert individual AIRs from bytecode interpretation to readable Python, one at a time, maintaining byte-identical test invariants throughout.

**Strategy**: "Make it work" first (interpreter), "make it readable" later (per-AIR Python conversion).

**Why not transpiler-first?** A transpiler requires building a new tool, debugging it, and handling edge cases — all before testing a single Zisk AIR. The interpreter is ~1,875 lines of proven code that already worked. It gets us to a running system in days, not weeks.

## Goals & Objectives

### Primary Goals
- Reinstate expression interpreter behind the existing module API, validate on 3 test AIRs
- Fix protocol gaps (public inputs, custom commits) needed for Zisk
- Full Zisk E2E proving with byte-identical proof comparison

### Secondary Objectives
- Hybrid system: hand-written Python modules coexist with bytecode interpreter
- Incremental conversion path: upgrade AIRs one at a time from bytecode → readable Python
- No protocol code pollution: interpreter details stay behind module API boundary

## Solution Overview

### Architecture

```
ConstraintModule (ABC)
├── SimpleLeftConstraints          (existing hand-written Python)
├── Lookup2_12Constraints          (existing hand-written Python)
├── Permutation1_6Constraints      (existing hand-written Python)
└── BytecodeConstraintModule       (reinstated interpreter, wrapped)
    └── Fallback for any AIR without a hand-written module

WitnessModule (ABC)
├── SimpleLeftWitness              (existing hand-written Python)
├── Lookup2_12Witness              (existing hand-written Python)
├── Permutation1_6Witness          (existing hand-written Python)
└── BytecodeWitnessModule          (reinstated interpreter, wrapped)
    └── Fallback for any AIR without a hand-written module
```

### Registry Lookup (hybrid)
```python
def get_constraint_module(air_name, air_dir=None):
    if air_name in CONSTRAINT_REGISTRY:
        return CONSTRAINT_REGISTRY[air_name]()       # hand-written Python
    else:
        return BytecodeConstraintModule(air_dir)      # bytecode interpreter
```

### Key Design Principle: No Protocol Pollution

The `BytecodeConstraintModule` and `BytecodeWitnessModule` wrappers implement the same ABCs as hand-written modules. Protocol code (`prover.py`, `verifier.py`, `stages.py`) never knows which implementation is being used. The interpreter's buffer-based internals are completely encapsulated.

### Data Flow

```
Existing 3 test AIRs:
  starkinfo.json → hand-written Python modules → protocol layer

Zisk AIRs (and any new AIR):
  starkinfo.json + expressions.bin → BytecodeConstraintModule/BytecodeWitnessModule → protocol layer
                                     (same API as hand-written)

Later conversion (per AIR, incremental):
  BytecodeConstraintModule → hand-written or transpiled Python → register in CONSTRAINT_REGISTRY
```

## Source Code to Reinstate

Three files were deleted in commit `731d33f4` (Feb 3, 2026):

| File | Lines | Purpose |
|------|-------|---------|
| `protocol/expressions_bin.py` | 832 | Binary parser: `.bin` file format, `ParserParams`, hints (`im_col`, `gsum_col`, `gprod_col`) |
| `protocol/expression_evaluator.py` | 627 | Bytecode interpreter: `ExpressionsPack.calculate_expressions()`, operand loading, arithmetic dispatch |
| `protocol/witness_generation.py` | 416 | Hint-driven witness: `calculate_witness_std()`, im_cluster/gsum/gprod computation |

Also deleted: test files `test_expressions_bin.py` (330 lines) and `test_witness_comparison.py` (310 lines).

**Total: ~1,875 lines of interpreter + 640 lines of tests to reinstate.**

### API Adaptation Required

The old code operated directly on `ProofContext` flat buffers. The current API uses `ConstraintContext` with named dictionary access. The adaptation:

1. `BytecodeConstraintModule` wrapper receives the same inputs as hand-written modules (via `ConstraintContext`)
2. Internally, it reconstructs the buffer layout the interpreter expects from `ProofContext`
3. The interpreter runs on buffers, produces the result
4. The wrapper returns the result through the standard API

This keeps the interpreter mostly intact and isolates buffer details behind the module boundary.

---

## Implementation Tasks

### Visual Dependency Tree

```
executable-spec/
├── primitives/
│   ├── expressions_bin.py           (Task #1: Reinstate binary parser)
│   └── expression_evaluator.py      (Task #2: Reinstate bytecode interpreter)
│
├── protocol/
│   ├── witness_generation.py        (Task #3: Reinstate hint-driven witness)
│   ├── prover.py                    (Task #6: Public inputs in transcript)
│   ├── verifier.py                  (Task #6: Public inputs; Task #7: custom commits)
│   └── stages.py                    (Task #7: custom commit prover support)
│
├── constraints/
│   ├── base.py                      (KEEP unchanged)
│   ├── __init__.py                  (Task #4: Add bytecode fallback to registry)
│   ├── bytecode_module.py           (Task #4: BytecodeConstraintModule wrapper)
│   ├── simple_left.py               (KEEP)
│   ├── lookup2_12.py                (KEEP)
│   └── permutation1_6.py            (KEEP)
│
├── witness/
│   ├── base.py                      (KEEP unchanged)
│   ├── __init__.py                  (Task #4: Add bytecode fallback to registry)
│   ├── bytecode_module.py           (Task #4: BytecodeWitnessModule wrapper)
│   ├── simple_left.py               (KEEP)
│   ├── lookup2_12.py                (KEEP)
│   └── permutation1_6.py            (KEEP)
│
└── tests/
    ├── test_expressions_bin.py      (Task #5: Reinstate parser tests)
    ├── test_bytecode_equivalence.py (Task #5: Bytecode vs hand-written comparison)
    └── test_zisk_e2e.py             (Task #9: Zisk integration tests)
```

### Execution Plan

#### Group A: Reinstate Interpreter (Execute in sequence)

- [ ] **Task #1**: Reinstate expression binary parser
  - Recover `expressions_bin.py` from commit `731d33f4~1` (the commit before deletion)
  - Place in `primitives/` (not `protocol/`) to respect the separation: parser is a primitive, not protocol logic
  - Key classes: `BinFileReader`, `ExpressionsBin`, `OpType` enum, `Hint`/`HintField`/`HintFieldValue`
  - Key API: `ExpressionsBin.from_file(path)`, `.get_expression(exp_id)`, `.get_hint_ids_by_name(name)`, `.get_hint_field(hint_id, field_name)`
  - Verify it still parses the existing test AIR `.bin` files:
    - `/home/cody/pil2-proofman/pil2-components/test/simple/build/provingKey/build/Simple/airs/SimpleLeft/air/SimpleLeft.bin`
  - Adapt to any API changes since deletion (field types, imports)

- [ ] **Task #2**: Reinstate bytecode interpreter
  - Recover `expression_evaluator.py` from same commit
  - Place in `primitives/` — it's a primitive computation engine, not protocol logic
  - Key classes: `ExpressionsCtx`, `ExpressionsPack`
  - Key API: `calculate_expressions(params, dest, domain_size, extended)`, `_load_operand()`, `_apply_op()`
  - The interpreter uses `ProofContext` buffers internally — this is fine as long as it stays inside the wrapper
  - Adapt to any changes in `ProofContext`, field types, or buffer layout since deletion
  - Must handle both prover mode (full domain evaluation) and verifier mode (single-point evaluation)

- [ ] **Task #3**: Reinstate hint-driven witness generation
  - Recover `witness_generation.py` from same commit
  - Place in `primitives/` or keep in `protocol/` (TBD based on coupling analysis)
  - Key API: `calculate_witness_std(stark_info, expressions_bin, params, expressions_ctx, prod=False)`
  - Handles: `im_col` hints (intermediate columns), `gsum_col` (running sum), `gprod_col` (running product)
  - Uses `ExpressionsPack` for evaluating sub-expressions referenced by hints

#### Group B: API Wrappers (After Group A)

- [ ] **Task #4**: Create BytecodeConstraintModule and BytecodeWitnessModule wrappers
  - `constraints/bytecode_module.py`:
    ```python
    class BytecodeConstraintModule(ConstraintModule):
        def __init__(self, air_dir: str):
            # Load .bin and starkinfo.json from air_dir
            self.expressions_bin = ExpressionsBin.from_file(...)
            self.stark_info = StarkInfo(...)

        def constraint_polynomial(self, ctx: ConstraintContext) -> FF3Poly | FF3:
            # Reconstruct buffer layout from ctx
            # Delegate to ExpressionsPack.calculate_expressions()
            # Return result through standard API
    ```
  - `witness/bytecode_module.py`:
    ```python
    class BytecodeWitnessModule(WitnessModule):
        def __init__(self, air_dir: str):
            self.expressions_bin = ExpressionsBin.from_file(...)

        def compute_intermediates(self, ctx) -> dict[str, dict[int, FF3Poly]]:
            # Delegate to calculate_witness_std() for im_col hints

        def compute_grand_sums(self, ctx) -> dict[str, FF3Poly]:
            # Delegate to calculate_witness_std() for gsum_col/gprod_col hints
    ```
  - Update `constraints/__init__.py` and `witness/__init__.py`:
    - Existing registry stays for hand-written modules
    - Add fallback: if `air_name` not in registry, create `BytecodeConstraintModule(air_dir)`
    - `get_constraint_module()` and `get_witness_module()` gain an optional `air_dir` parameter
  - **Critical**: Protocol code (`prover.py`, `verifier.py`, `stages.py`) must NOT change its module lookup pattern. The `air_dir` parameter flows from `AirConfig` which already knows the proving key path.

#### Group C: Validate Bytecode == Hand-Written (After Group B)

- [ ] **Task #5**: Validation tests
  - Reinstate `test_expressions_bin.py` — binary parser unit tests
  - New `test_bytecode_equivalence.py`:
    - For each of the 3 test AIRs, run both hand-written and bytecode modules
    - Assert identical constraint polynomial results (prover: array equality, verifier: scalar equality)
    - Assert identical witness columns (im_cluster, gsum, gprod)
  - Run full test suite (`./run-tests.sh`) with bytecode modules swapped in — all 164 tests must pass
  - This proves the reinstated interpreter produces byte-identical results

#### Group D: Protocol Gaps (After Group B, parallel with C)

- [ ] **Task #6**: Public inputs support
  - Zisk has 68 public inputs; current test AIRs have 0
  - Code paths exist in transcript but are untested
  - Verify public inputs flow correctly through Fiat-Shamir transcript
  - May need a minimal test case (no existing pil2-components tests exercise nPublics > 0)
  - Add `public` operand type handling if not already in the reinstated interpreter

- [ ] **Task #7**: Custom commits support
  - Zisk's Rom uses `commit stage(0) public(rom_root) rom`
  - `protocol/stages.py` line 821: `_load_evmap_poly()` raises `NotImplementedError` for `custom` type
  - `protocol/verifier.py` line 745: `_verify_custom_commit_merkle()` returns `True` (stub)
  - Implement: separate Merkle tree for custom-committed polynomials, root as public output
  - The reinstated interpreter already handles `custom` operand type (OpType enum had it)

#### Group E: Zisk Integration (After Groups C + D)

- [ ] **Task #8**: Generate Zisk build artifacts
  - Prerequisites: `pil2-compiler` at `/home/cody/pil2-compiler`, `pil2-proofman-js` at `/home/cody/pil2-proofman-js`
  - Follow `/home/cody/pil2-proofman/zisk-for-spec/tools/test-env/build_setup.sh`:
    1. Generate fixed data (cargo run Rust binaries)
    2. Compile PIL (`pil2-compiler` on `zisk.pil`)
    3. Generate setup (`pil2-proofman-js main_setup.js`)
  - Output: per-AIR `.starkinfo.json` + `.bin` + `.const` + `.consttree` under `build/provingKey/`

- [ ] **Task #9**: Per-Zisk-AIR unit tests
  - Start with simplest AIRs: DualByte (2 fixed + 1 witness, 1 lookup), ArithTable (128 rows)
  - For each AIR: load .bin, create BytecodeConstraintModule, compare intermediate values against Rust prover
  - Test vector generation from Rust prover (extend `generate-test-vectors.sh` pattern)
  - Incrementally add more AIRs

- [ ] **Task #10**: Full Zisk E2E integration
  - Select a small Zisk program (simple addition) that exercises a subset of AIRs
  - Generate reference proof from Rust prover
  - Python proves each AIR independently via bytecode interpreter
  - Byte-identical proof comparison per AIR
  - Python verifier accepts Rust-generated proofs

#### Group F: Incremental Readability (After Group E, ongoing)

- [ ] **Task #11**: Build TAC-to-Python transpiler (as a conversion tool)
  - Same transpiler design from the original plan (see `ai_plans/zisk-air-transpiler.md`)
  - But now it's a convenience tool, not a prerequisite
  - Used to bootstrap readable Python for individual AIRs
  - Generated code is then manually simplified

- [ ] **Task #12**: Convert AIRs one at a time
  - For each Zisk AIR, in order of simplicity:
    1. Transpile (or hand-write) constraint + witness Python module
    2. Register in CONSTRAINT_REGISTRY / WITNESS_REGISTRY
    3. Run tests — byte-identical results vs bytecode interpreter
    4. Simplify the Python for readability
  - The bytecode interpreter remains as fallback for unconverted AIRs

---

## Key Files Reference

### Code to reinstate (from git history)
| Source commit | File | Lines | Destination |
|--------------|------|-------|-------------|
| `731d33f4~1` | `protocol/expressions_bin.py` | 832 | `primitives/expressions_bin.py` |
| `731d33f4~1` | `protocol/expression_evaluator.py` | 627 | `primitives/expression_evaluator.py` |
| `731d33f4~1` | `protocol/witness_generation.py` | 416 | `protocol/witness_generation.py` or `primitives/` |
| `731d33f4~1` | `tests/test_expressions_bin.py` | 330 | `tests/test_expressions_bin.py` |

### Existing code (unchanged)
| File | Role |
|------|------|
| `constraints/base.py` | ConstraintModule ABC, ConstraintContext — wrappers implement this |
| `witness/base.py` | WitnessModule ABC — wrappers implement this |
| `protocol/stark_info.py` | StarkInfo parser — already fully generic |
| `protocol/proof_context.py` | Buffer management — used internally by interpreter |
| `protocol/prover.py` | Prover entry — calls modules through ABC, no changes needed for interpreter |
| `protocol/verifier.py` | Verifier — calls modules through ABC |

### Test AIR .bin files (existing)
| Path |
|------|
| `.../SimpleLeft/air/SimpleLeft.bin` |
| `.../Lookup2_12/air/Lookup2_12.bin` |
| `.../Permutation1_6/air/Permutation1_6.bin` |

---

## Verification

- **After Group A-C**: `cd executable-spec && ./run-tests.sh` — all 164 tests pass with both hand-written AND bytecode modules
- **After Group D**: Public inputs and custom commits tests pass
- **After Group E**: Zisk per-AIR tests pass, E2E byte-identical proofs
- **Linter**: `cd executable-spec && uv run ruff check .`

## Implementation Workflow

This plan file serves as the authoritative checklist. When implementing:
1. Read this plan before starting
2. Mark `[ ]` → `[x]` as tasks complete
3. Run tests after each group
4. Tasks should be run in parallel within groups where possible
