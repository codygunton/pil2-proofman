# Remove Expression Binaries - Progress Tracker

Last updated: 2026-02-03

## 🎉 PRIMARY GOAL ACHIEVED 🎉

**Expression binary machinery has been completely removed.**

The Python executable spec is now self-contained with no dependency on C++ expression bytecode.
All AIR-specific operations use readable Python constraint and witness modules.

- **164 tests pass**
- **Byte-identical proofs to C++ implementation**
- **3,002 lines of dead code removed**

---

## Phase 1: Infrastructure ✅

- [x] **Task 1.1**: Create ProverData and VerifierData dataclasses
- [x] **Task 1.2**: Create ConstraintContext ABC and implementations
- [x] **Task 1.3**: Create WitnessModule ABC
- [x] **Task 1.4**: Add name mapping helpers to StarkInfo

## Phase 2: SimpleLeft AIR ✅

- [x] **Task 2.1**: Implement SimpleLeft constraint module
- [x] **Task 2.2**: Implement SimpleLeft witness module

## Phase 3: Lookup2_12 AIR ✅

- [x] **Task 3.1**: Implement Lookup2_12 constraint module
- [x] **Task 3.2**: Implement Lookup2_12 witness module

## Phase 4: Permutation1_6 AIR ✅

- [x] **Task 4.1**: Implement Permutation1_6 constraint module
- [x] **Task 4.2**: Implement Permutation1_6 witness module

## Phase 5: Prover Integration ✅

- [x] **Task 5.1**: Wire constraint modules into prover
- [x] **Task 5.2**: Wire witness modules into prover

## Phase 6: Verifier Integration ✅

- [x] **Task 6.1**: Wire constraint modules into verifier
- [x] **Task 6.2**: Debug and fix verifier constraint module issues

## Phase 7: Cleanup ✅

- [x] **Task 7.1**: Remove expression binary machinery (7ba71491)
  - Deleted `expression_evaluator.py` (627 lines)
  - Deleted `expressions_bin.py` (832 lines)
  - Deleted `witness_generation.py` (416 lines)
  - Deleted `test_expressions_bin.py` (330 lines)
  - Deleted `test_witness_comparison.py` (310 lines)
  - All 164 tests pass

---

## Additional Cleanup ✅

- [x] **Task 7.2**: ProofContext architecture review
  - Assessed full migration to ProverData/VerifierData
  - Determined current two-layer design is appropriate:
    - ProofContext: buffer-based, efficient for protocol operations
    - ProverData/VerifierData: dict-based, readable for AIR code
  - Added comprehensive architecture documentation
  - Cleaned up type annotations
- [x] **Task 7.3**: Final test verification
  - All 164 tests pass
  - Byte-identical proofs to C++ implementation

---

## Summary

### What Was Removed

| File | Lines | Purpose |
|------|-------|---------|
| `expression_evaluator.py` | 627 | C++ bytecode interpreter |
| `expressions_bin.py` | 832 | Binary format parser |
| `witness_generation.py` | 416 | Hint-based witness computation |
| `test_expressions_bin.py` | 330 | Unit tests for parser |
| `test_witness_comparison.py` | 310 | Debugging comparison tests |
| **Total** | **3,002** | |

### What Replaced It

| Operation | New Implementation |
|-----------|-------------------|
| Constraint Polynomial | `constraints/*.py` modules |
| Witness Generation | `witness/*.py` modules |
| FRI Polynomial | `fri_polynomial.py` (direct computation) |

### Current Architecture

```
executable-spec/
├── constraints/           # Per-AIR constraint evaluation
│   ├── simple_left.py
│   ├── lookup2_12.py
│   └── permutation1_6.py
├── witness/               # Per-AIR witness generation
│   ├── simple_left.py
│   ├── lookup2_12.py
│   └── permutation1_6.py
└── protocol/              # STARK protocol (AIR-agnostic)
    ├── prover.py
    ├── verifier.py
    ├── fri_polynomial.py
    └── stages.py
```

## How to Verify

```bash
# Run all tests
cd executable-spec && uv run pytest tests/ -v

# Verify byte-identical proofs
uv run pytest tests/test_stark_e2e.py::TestFullBinaryComparison -v

# Check no expression binary imports
grep -r "expression_evaluator\|expressions_bin" protocol/
```
