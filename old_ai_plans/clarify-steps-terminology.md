# Clarify "Steps" Terminology Implementation Plan

## Executive Summary

The executable-spec codebase conflates three fundamentally different concepts under the name "steps":

1. **FRI Steps** - Recursive folding layers in the FRI protocol (e.g., `starkStruct.steps`, iteration counter)
2. **Proof Stages** - Phases of polynomial generation (stage 1 witness, stage 2 intermediate, quotient, FRI)
3. **StepsParams** - Container for all working buffers (poorly named; should be ProofContext)

This confusion makes the code harder to read and reason about. The fix is straightforward renaming to expose the semantic boundaries:
- `StepsParams` → `ProofContext` (eliminates the "steps" misnomer for working state)
- `StepStruct` → `FriFoldStep` (clarifies it's FRI-specific)
- `starkStruct.steps` → `starkStruct.friFoldSteps` (makes FRI context explicit)
- Loop variable `step` → `fold_step` in FRI code (distinguishes from proof stages)

## Goals & Objectives

### Primary Goals
- **Eliminate naming ambiguity** between FRI folding iterations, proof stages, and working state
- **Improve code readability** by making semantic boundaries explicit in names
- **Maintain 100% correctness** - purely mechanical renaming, no behavioral changes
- **Achieve full test compatibility** - all existing tests pass without modification

### Secondary Objectives
- Establish naming conventions for future development
- Make the distinction clear for new contributors
- Set foundation for clarifying expression evaluation parameters

## Solution Overview

### Approach

Three parallel renaming groups with minimal cross-file dependencies:

**Group A: Type/Class Definitions** (rename the core names)
- `StepsParams` → `ProofContext` in `steps_params.py` (rename file + class)
- `StepStruct` → `FriFoldStep` in `stark_info.py` (rename class)
- Update corresponding docstrings

**Group B: Data Structure References** (update array/field names)
- `starkStruct.steps` → `starkStruct.friFoldSteps` across 12 files
- `StepStruct.nBits` → `FriFoldStep.domainBits` (semantic clarity)
- Update constructor calls in JSON parsing

**Group C: Variable Names** (rename local variables for clarity)
- FRI loops: `step` → `fold_step` (4 files, ~15 instances)
- FRI parameters: `step` → `fri_layer` in function signatures (2 files)

All groups execute in parallel after Group A (independent updates).

### Key Components

1. **ProofContext** (renamed from StepsParams): Working state container holding trace, auxiliary buffers, challenges, evaluations, and constants. Used by prover, verifier, stages, and expression evaluator.

2. **FriFoldStep** (renamed from StepStruct): Configuration for one FRI folding layer, specifying domain size reduction.

3. **friFoldSteps array** (renamed from steps): Array of FRI fold configurations in StarkStruct.

4. **Consistent loop variables**: `fold_step` in FRI folding code to distinguish from proof stage numbers.

### Expected Outcomes

- Code readers can immediately distinguish FRI concepts from proof stage concepts from working state
- No runtime behavior change - purely clarifying renames
- All 142 tests pass after refactoring
- Reduced cognitive load when reading proof generation and FRI logic

## Implementation Tasks

### Visual Dependency Tree

```
protocol/
├── steps_params.py (Task #1: Rename StepsParams → ProofContext)
├── stark_info.py (Task #2: Rename StepStruct → FriFoldStep, update steps → friFoldSteps)
├── prover.py (Task #3: Update imports, types, StepsParams→ProofContext, steps→friFoldSteps)
├── verifier.py (Task #4: Update imports, types, construction, steps→friFoldSteps)
├── stages.py (Task #5: Update types, parameter names, step variables in loops)
├── witness_generation.py (Task #6: Update import, function parameters)
├── expression_evaluator.py (Task #7: Update import, function parameters, docstrings)
├── pcs.py (Task #8: Update loop variables step→fold_step, fri_steps→fri_fold_steps)
├── fri.py (Task #9: Update function parameters step→fri_layer)
├── proof.py (Task #10: Update references steps→friFoldSteps in parsing/serialization)
└── __init__.py (Task #11: Update re-exports if applicable)

tests/
├── test_stark_e2e.py (Task #12: Update StepsParams→ProofContext construction)
├── test_verifier_e2e.py (Task #13: Update construction)
├── test_fri.py (Task #14: Update loop variables if any)
└── test_stark_info.py (Task #15: Update StepStruct→FriFoldStep references)
```

### Execution Plan

#### Group A: Core Type Definitions (Execute in parallel)

- [x] **Task #1**: Rename StepsParams to ProofContext
  - File: `protocol/steps_params.py` → `protocol/proof_context.py`
  - Changes:
    - Rename file (steps_params.py → proof_context.py)
    - Rename class `StepsParams` → `ProofContext`
    - Update docstring: "Container for all prover/verifier working data" (clarify it's proof state)
    - Update C++ reference comment: `pil2-stark/src/starkpil/steps.hpp::StepsParams` → same (no change in C++)
    - Rename helper methods: `get_challenge()`, `set_challenge()` stay same (already clear)
    - No field renames needed (fields are self-documenting with comments)
  - Exports: `class ProofContext` with all 12 fields and 2 helper methods
  - Integration: All 8 consumer files import and use `ProofContext` instead of `StepsParams`

- [x] **Task #2**: Rename StepStruct to FriFoldStep in stark_info.py
  - File: `protocol/stark_info.py`
  - Changes:
    - Line 22-24: Rename `class StepStruct` → `class FriFoldStep`
    - Update docstring: "FRI recursive folding layer configuration"
    - Line 24: Rename field `nBits: int` → `domainBits: int` (semantic: 2^domainBits = domain size)
    - Line 34: Update `steps: List[StepStruct]` → `friFoldSteps: List[FriFoldStep]`
    - Line 174: Update JSON parsing: `for s in ss["steps"]: FriFoldStep(nBits=s["nBits"])` → `FriFoldStep(domainBits=s["nBits"])`
    - Update docstring for StarkStruct.friFoldSteps: "FRI folding layer configurations (domain size reduction at each fold)"
  - Exports: `class FriFoldStep` with field `domainBits`
  - Integration: StarkInfo now exposes `starkStruct.friFoldSteps` instead of `starkStruct.steps`

#### Group B: Update Data Structure References (Execute all in parallel after Group A)

- [x] **Task #3**: Update prover.py - imports, types, and friFoldSteps references
  - File: `protocol/prover.py`
  - Imports:
    - Line 14: `from protocol.steps_params import StepsParams` → `from protocol.proof_context import ProofContext`
  - Changes:
    - Line 28: Function param: `params: StepsParams` → `params: ProofContext`
    - Line 44: `params: StepsParams` → `params: ProofContext`
    - Line 119: `n_fri_elements = 1 << stark_info.starkStruct.steps[0].nBits` → `n_fri_elements = 1 << stark_info.starkStruct.friFoldSteps[0].domainBits`
    - Line 126: `n_bits_ext=stark_info.starkStruct.steps[0].nBits` → `n_bits_ext=stark_info.starkStruct.friFoldSteps[0].domainBits`
    - Line 127: `fri_steps=[step.nBits for step in stark_info.starkStruct.steps]` → `fri_fold_steps=[step.domainBits for step in stark_info.starkStruct.friFoldSteps]`
    - Variable rename: All `params` variables stay as `params` (or could rename to `context` but that's cosmetic)
  - Exports: None (module-level)
  - Integration: Consistent with ProofContext and FriFoldStep changes

- [x] **Task #4**: Update verifier.py - imports, construction, friFoldSteps references
  - File: `protocol/verifier.py`
  - Imports:
    - Line 5: `from protocol.steps_params import StepsParams` → `from protocol.proof_context import ProofContext`
  - Changes:
    - Line 28: Function param: `params: StepsParams` → `params: ProofContext`
    - Line 84: `StepsParams(` → `ProofContext(`
    - All references to `stark_info.starkStruct.steps[i].nBits` → `stark_info.starkStruct.friFoldSteps[i].domainBits`
      - Line 502: `stark_info.starkStruct.steps[0].nBits` → `stark_info.starkStruct.friFoldSteps[0].domainBits`
      - Line 622-623: array indexing with `steps` → `friFoldSteps`
      - Line 640, 644, 668, 671, 685-686, 694, 720: All similar replacements
  - Exports: None (module-level)
  - Integration: Consistent with ProofContext and FriFoldStep changes

- [x] **Task #5**: Update stages.py - types, parameter names, variable consistency
  - File: `protocol/stages.py`
  - Imports:
    - Line 9: `from protocol.steps_params import StepsParams` → `from protocol.proof_context import ProofContext`
  - Changes:
    - Line 97: Function param: `def commitStage(self, step: int, params: StepsParams, ...)` → `def commitStage(self, stage: int, context: ProofContext, ...)`
    - Line 100: `if step <= self.setupCtx.stark_info.nStages:` → `if stage <= self.setupCtx.stark_info.nStages:`
    - Line 142: Function signature and body params: `def calculateQuotientPolynomial(self, params: StepsParams, ...)` → `(self, context: ProofContext, ...)`
    - Line 233: `params.auxTrace` → `context.auxTrace`
    - Similar updates for other methods: `calculateImPolsExpressions`, `calculateFRIPolynomial`, etc. (replace `params` with `context`)
    - Docstring updates to clarify "stage" is a proof generation stage, not FRI folding step
  - Exports: Class Starks (no type changes)
  - Integration: Consistent parameter naming with prover, verifier

- [x] **Task #6**: Update witness_generation.py - import and parameter types
  - File: `protocol/witness_generation.py`
  - Imports:
    - Line 4: `from protocol.steps_params import StepsParams` → `from protocol.proof_context import ProofContext`
  - Changes:
    - Line 16: `def calculate_witness_std(params: StepsParams, ...)` → `(context: ProofContext, ...)`
    - Line 268: `expressions_ctx.calculate_expressions(params, ...)` → `(context, ...)`
    - Line 361: Similar parameter passing
    - Update all internal references from `params.` to `context.` (grep will show exact locations)
  - Exports: Function `calculate_witness_std`
  - Integration: Called from prover, receives ProofContext instead of StepsParams

- [x] **Task #7**: Update expression_evaluator.py - import and parameter types
  - File: `protocol/expression_evaluator.py`
  - Imports:
    - Line 8: `from protocol.steps_params import StepsParams` → `from protocol.proof_context import ProofContext`
  - Changes:
    - Line 213: `def calculate_expressions(self, params: StepsParams, ...)` → `(self, context: ProofContext, ...)`
    - Line 167: `def calculate_expression(self, params: StepsParams, ...)` → `(self, context: ProofContext, ...)`
    - Update all internal references `params.` → `context.` in _load_operand and related methods
    - Update docstrings: "params:" → "context:" parameter documentation
  - Exports: Class ExpressionsPack (type signature changes)
  - Integration: Called from stages and verifier with ProofContext

#### Group C: FRI-Specific Variable Names (Execute all in parallel after Group A)

- [x] **Task #8**: Update pcs.py - loop variables and configuration
  - File: `protocol/pcs.py`
  - Imports: None (no ProofContext used here)
  - Changes:
    - Line 59: `n_fri_folds = len(cfg.fri_steps) - 1` (update comment if exists)
    - Line 70: `for step in range(n_fri_folds):` → `for fold_step in range(n_fri_folds):`
    - Line 78-79: `cfg.fri_steps[step]` → `cfg.fri_steps[fold_step]` and `cfg.fri_steps[step + 1]` → `cfg.fri_steps[fold_step + 1]`
    - Line 119, 127: Similar replacements in any other loops using `step` as FRI iteration
    - Line 143-144: Any FRI-specific step variable references
  - Note: FriPcsConfig still uses `fri_steps` (from prover line 127) - no rename needed there since it's just extracting nBits values
  - Exports: Class FriPcs (no type changes)
  - Integration: Internal loop variable clarity only

- [x] **Task #9**: Update fri.py - function parameter names for clarity
  - File: `protocol/fri.py`
  - Imports: None
  - Changes:
    - Line 20-27: `def fold(step: int, ...)` → `def fold(fri_layer: int, ...)`
    - Update all docstrings referencing `step` parameter to `fri_layer`
    - Update internal usage: `step` → `fri_layer` within the function
    - Line 15-19: Similar check for `merkelize` and other FRI functions
  - Exports: All FRI functions with updated parameter names
  - Integration: Called from pcs.py with `fold_step` now matching semantically

- [x] **Task #10**: Update proof.py - friFoldSteps array references
  - File: `protocol/proof.py`
  - Imports: None (no ProofContext used)
  - Changes:
    - Line 258: `len(stark_info.starkStruct.steps)` → `len(stark_info.starkStruct.friFoldSteps)`
    - Line 259, 264-267: Similar array access updates
    - Line 295: `stark_info.starkStruct.steps[-1].nBits` → `stark_info.starkStruct.friFoldSteps[-1].domainBits`
    - Line 419: `stark_info.starkStruct.steps[0].nBits` → similar
    - Line 472-473, 611-612, 689: Any other friFoldSteps references
  - Exports: None (module-level functions)
  - Integration: Consistent with StarkInfo changes

#### Group D: Test File Updates (Execute all in parallel after Group A)

- [x] **Task #11**: Update test_stark_e2e.py - ProofContext construction
  - File: `tests/test_stark_e2e.py`
  - Imports:
    - Line 11 (estimate): `from protocol.steps_params import StepsParams` → `from protocol.proof_context import ProofContext`
  - Changes:
    - Line 170 (estimate): `params = StepsParams(...)` → `context = ProofContext(...)`
    - Update all references to `params` as `context` within test code
    - Update assertions and comments if they reference StepsParams
  - Exports: None (test file)
  - Integration: Tests execute with ProofContext

- [x] **Task #12**: Update test_verifier_e2e.py - ProofContext construction
  - File: `tests/test_verifier_e2e.py`
  - Imports:
    - Line 9 (estimate): `from protocol.steps_params import StepsParams` → `from protocol.proof_context import ProofContext`
  - Changes:
    - Line 120 (estimate): `StepsParams(` → `ProofContext(`
    - Update all references throughout test
  - Exports: None (test file)
  - Integration: Tests execute with ProofContext

- [x] **Task #13**: Update test_fri.py - loop variable naming if applicable
  - File: `tests/test_fri.py`
  - Imports: None typically
  - Changes:
    - Check for any `step` loop variables in FRI tests
    - Rename to `fold_step` if testing FRI folding iterations
    - Likely no changes if tests don't iterate FRI steps directly
  - Exports: None (test file)
  - Integration: Minor - only if loop variables exist

- [x] **Task #14**: Update test_stark_info.py - StepStruct references
  - File: `tests/test_stark_info.py`
  - Imports: Likely none for StepsParams, but check for StepStruct
  - Changes:
    - Any direct references to `StepStruct` → `FriFoldStep`
    - Any references to `steps` array → `friFoldSteps`
    - Update assertions on FriFoldStep.domainBits if checking nBits
  - Exports: None (test file)
  - Integration: Tests of StarkInfo still pass with renamed fields

---

## Implementation Workflow

This plan file serves as the authoritative checklist for implementation. When implementing:

### Required Process

1. **Load Plan**: Read this entire plan file before starting any task
2. **Execute Groups Sequentially**:
   - Execute all Group A tasks in parallel (they only depend on existing code)
   - Once all Group A tasks complete, execute all Group B tasks in parallel (depend on Group A)
   - Once Group B completes, execute all Group C tasks in parallel (independent of Group B)
   - Once Groups A, B, C complete, execute all Group D tasks in parallel (depend on A, B, C)
3. **Update Checkboxes**: Mark checkbox `[x]` when each task completes
4. **Verify Tests**: After all tasks complete, run `cd executable-spec && uv run python -m pytest tests/ -v` to confirm all 142 tests pass

### Critical Rules

- This plan file is the source of truth for progress
- Update checkboxes in real-time as work progresses
- Mark tasks complete only when fully implemented and verified
- All renaming must be mechanical - no logic changes
- All tests must pass after group completion

### Success Criteria

- All 14 tasks marked complete `[x]`
- `pytest` runs successfully with all 142 tests passing
- No functional behavior changed - purely mechanical renaming
- Code diffs show only name replacements, no logic changes
