# C++ Reference Annotations Implementation Plan

## Executive Summary

Add reference comments to all classes and functions in 12 new Python executable-spec files, mapping them to their equivalent C++ implementations in pil2-stark. This creates a clear traceability between the Python spec and the production C++ code.

### Annotation Format
```python
# C++: pil2-stark/src/starkpil/stark_info.hpp::StarkInfo (lines 137-217)
class StarkInfo:
    ...

# C++: pil2-stark/src/goldilocks/src/ntt_goldilocks.hpp::NTT_Goldilocks::NTT (lines 211-260)
def ntt(self, pol: list[int]) -> list[int]:
    ...

# C++: No direct equivalent (Python-specific utility)
def some_helper():
    ...
```

### Expected Outcomes
- Every class and function in the 12 files has a C++ reference comment
- Developers can quickly navigate between Python spec and C++ implementation
- Clear indication when Python code has no C++ equivalent

## Implementation Tasks

### CRITICAL IMPLEMENTATION RULES
1. Add comment IMMEDIATELY BEFORE each class/function definition
2. Use format: `# C++: <relative-path>::<class>::<method> (lines X-Y)` or `# C++: No direct equivalent`
3. Preserve all existing code and comments
4. Do not modify any logic, only add annotation comments

### Visual Dependency Tree

```
executable-spec/
├── primitives/
│   ├── ntt.py           (Task #1: NTT class with 9 methods)
│   └── pol_map.py       (Task #2: 5 dataclasses)
│
└── protocol/
    ├── expression_evaluator.py  (Task #3: Operation enum, Params, Dest, ExpressionsCtx, ExpressionsPack)
    ├── expressions_bin.py       (Task #4: OpType, ParserParams, ParserArgs, HintFieldValue, HintField, Hint, BinFileReader, ExpressionsBin)
    ├── proof.py                 (Task #5: MerkleProof, ProofTree, FriProof, STARKProof, FRIProofFull + 8 functions)
    ├── prover.py                (Task #6: gen_proof function)
    ├── setup_ctx.py             (Task #7: ProverHelpers, SetupCtx)
    ├── stages.py                (Task #8: Starks class with 12 methods)
    ├── stark_info.py            (Task #9: StepStruct, StarkStruct, StarkInfo)
    ├── steps_params.py          (Task #10: StepsParams dataclass)
    ├── verifier.py              (Task #11: stark_verify + 11 helper functions)
    └── witness_generation.py    (Task #12: 19 functions)
```

### Execution Plan

**PARALLELIZATION STRATEGY**: All 12 tasks are fully independent. Execute using 3 parallel batches of 4 subtasks each to maximize throughput while managing context.

#### Batch 1: Execute 4 subtasks in parallel
| Task | File | Complexity |
|------|------|------------|
| #1 | `primitives/ntt.py` | 1 class, 9 methods |
| #2 | `primitives/pol_map.py` | 5 dataclasses |
| #3 | `protocol/expression_evaluator.py` | 5 classes, 12 methods |
| #4 | `protocol/expressions_bin.py` | 8 classes, 12 methods |

#### Batch 2: Execute 4 subtasks in parallel (after Batch 1)
| Task | File | Complexity |
|------|------|------------|
| #5 | `protocol/proof.py` | 5 classes, 8 functions |
| #6 | `protocol/prover.py` | 1 function |
| #7 | `protocol/setup_ctx.py` | 2 classes, 9 methods |
| #8 | `protocol/stages.py` | 1 class, 12 methods |

#### Batch 3: Execute 4 subtasks in parallel (after Batch 2)
| Task | File | Complexity |
|------|------|------------|
| #9 | `protocol/stark_info.py` | 3 classes, 8 methods |
| #10 | `protocol/steps_params.py` | 1 dataclass |
| #11 | `protocol/verifier.py` | 12 functions |
| #12 | `protocol/witness_generation.py` | 19 functions |

---

### Task Details

---

- [x] **Task #1**: Annotate `executable-spec/primitives/ntt.py`
  - File: `executable-spec/primitives/ntt.py`
  - Annotations to add:
    ```
    class NTT:
      # C++: pil2-stark/src/goldilocks/src/ntt_goldilocks.hpp::NTT_Goldilocks

      __init__:
        # C++: NTT_Goldilocks::NTT_Goldilocks (ntt_goldilocks.cpp lines 66-162)

      _log2:
        # C++: No direct equivalent (inline in C++)

      _precompute_roots:
        # C++: NTT_Goldilocks constructor (precomputes roots, lines 66-162)

      _precompute_pow_two_inv:
        # C++: NTT_Goldilocks constructor (precomputes inverses, lines 66-162)

      _compute_r:
        # C++: NTT_Goldilocks::computeR (ntt_goldilocks.cpp lines 48-60)

      ntt:
        # C++: NTT_Goldilocks::NTT (ntt_goldilocks.cpp lines 211-260)

      intt:
        # C++: NTT_Goldilocks::INTT (ntt_goldilocks.cpp lines 188-191)

      extend_pol:
        # C++: NTT_Goldilocks::extendPol (ntt_goldilocks.cpp lines 369-404)

      _reshape_input:
        # C++: No direct equivalent (handled inline in C++)
    ```

---

- [x] **Task #2**: Annotate `executable-spec/primitives/pol_map.py`
  - File: `executable-spec/primitives/pol_map.py`
  - Annotations to add:
    ```
    class PolMap:
      # C++: pil2-stark/src/starkpil/stark_info.hpp::PolMap (lines 93-106)

    class EvMap:
      # C++: pil2-stark/src/starkpil/stark_info.hpp::EvMap (lines 108-135)

      class Type (enum):
        # C++: stark_info.hpp::EvMap::eType (lines 109-114)

      type_from_string:
        # C++: stark_info.hpp::EvMap::setType (lines 124-134)

    class ChallengeMap:
      # C++: No direct equivalent (challenge info embedded in StarkInfo)

    class CustomCommits:
      # C++: pil2-stark/src/starkpil/stark_info.hpp::CustomCommits (lines 52-58)

    class Boundary:
      # C++: pil2-stark/src/starkpil/stark_info.hpp::Boundary (lines 60-66)
    ```

---

- [x] **Task #3**: Annotate `executable-spec/protocol/expression_evaluator.py`
  - File: `executable-spec/protocol/expression_evaluator.py`
  - Annotations to add:
    ```
    class Operation (enum):
      # C++: pil2-stark/src/starkpil/expressions_ctx.hpp (operation constants)

    class Params:
      # C++: pil2-stark/src/starkpil/expressions_ctx.hpp::Params (lines 53-80)

    class Dest:
      # C++: pil2-stark/src/starkpil/expressions_ctx.hpp::Dest (lines 82-123)

      __post_init__:
        # C++: Dest constructor logic

    class ExpressionsCtx:
      # C++: pil2-stark/src/starkpil/expressions_ctx.hpp::ExpressionsCtx

      __init__:
        # C++: ExpressionsCtx constructor

      set_xi:
        # C++: ExpressionsCtx::setXi

      calculate_expression:
        # C++: ExpressionsCtx::calculateExpression

      calculate_expressions:
        # C++: ExpressionsCtx::calculateExpressions

    class ExpressionsPack:
      # C++: pil2-stark/src/starkpil/expressions_pack.hpp::ExpressionsPack

      __init__:
        # C++: ExpressionsPack constructor

      calculate_expressions:
        # C++: ExpressionsPack::calculateExpressions

      _load:
        # C++: ExpressionsPack load operations (inline)

      _get_inverse_polynomial:
        # C++: ExpressionsPack inverse polynomial handling

      _multiply_polynomials:
        # C++: ExpressionsPack polynomial multiplication

      _store_polynomial:
        # C++: ExpressionsPack store operations (inline)

      _goldilocks_op_pack:
        # C++: ExpressionsPack Goldilocks operations

      _goldilocks3_op_pack:
        # C++: ExpressionsPack Goldilocks3 operations

      _goldilocks3_op_31_pack:
        # C++: ExpressionsPack Goldilocks3x1 operations
    ```

---

- [x] **Task #4**: Annotate `executable-spec/protocol/expressions_bin.py`
  - File: `executable-spec/protocol/expressions_bin.py`
  - Annotations to add:
    ```
    class OpType (enum):
      # C++: pil2-stark/src/starkpil/stark_info.hpp::opType (lines 30-49)

    optype_from_string (function):
      # C++: No direct equivalent (C++ uses enum directly)

    class ParserParams:
      # C++: pil2-stark/src/starkpil/expressions_bin.hpp::ParserParams (lines 53-69)

    class ParserArgs:
      # C++: pil2-stark/src/starkpil/expressions_bin.hpp::ParserArgs (lines 71-77)

    class HintFieldValue:
      # C++: pil2-stark/src/starkpil/expressions_bin.hpp::HintFieldValue (lines 30-39)

    class HintField:
      # C++: pil2-stark/src/starkpil/expressions_bin.hpp::HintField (lines 41-44)

    class Hint:
      # C++: pil2-stark/src/starkpil/expressions_bin.hpp::Hint (lines 47-51)

    class BinFileReader:
      # C++: No direct equivalent (C++ uses direct file I/O in expressions_bin.cpp)

      __init__, read_bytes, read_u8_le, read_u16_le, read_u32_le, read_u64_le, read_string:
        # C++: Inline file reading in ExpressionsBin::load methods

      start_read_section, end_read_section:
        # C++: Section reading in expressions_bin.cpp

    class ExpressionsBin:
      # C++: pil2-stark/src/starkpil/expressions_bin.hpp::ExpressionsBin (lines 79-145)

      __init__:
        # C++: ExpressionsBin constructor

      from_file:
        # C++: ExpressionsBin::load (expressions_bin.cpp)

      _load_expressions_bin:
        # C++: ExpressionsBin::loadExpressionsBin

      _load_verifier_bin:
        # C++: ExpressionsBin::loadVerifierBin

      _load_global_bin:
        # C++: ExpressionsBin::loadGlobalBin

      get_expression:
        # C++: ExpressionsBin::getExpression

      get_hint_ids_by_name:
        # C++: ExpressionsBin::getHintIdsByName

      get_number_hint_ids_by_name:
        # C++: ExpressionsBin::getNumberHintIdsByName

      get_hint_field:
        # C++: ExpressionsBin::getHintField
    ```

---

- [x] **Task #5**: Annotate `executable-spec/protocol/proof.py`
  - File: `executable-spec/protocol/proof.py`
  - Annotations to add:
    ```
    class MerkleProof:
      # C++: pil2-stark/src/starkpil/proof_stark.hpp::MerkleProof<ElementType> (lines 39-69)

    class ProofTree:
      # C++: pil2-stark/src/starkpil/proof_stark.hpp::ProofTree<ElementType> (lines 71-95)

    class FriProof:
      # C++: pil2-stark/src/starkpil/proof_stark.hpp::Fri<ElementType> (lines 97-125)

    class STARKProof:
      # C++: pil2-stark/src/starkpil/proof_stark.hpp::Proofs<ElementType> (lines 127-537)

    class FRIProofFull:
      # C++: No direct equivalent (Python-specific wrapper with metadata)

    proof_to_json (function):
      # C++: No direct equivalent (Python-specific serialization)

    load_proof_from_json (function):
      # C++: No direct equivalent (Python-specific deserialization)

    load_proof_from_binary (function):
      # C++: Proofs::loadProof methods in proof_stark.hpp

    proof_to_pointer_layout (function):
      # C++: Proofs pointer/offset layout methods

    to_bytes_partial (function):
      # C++: Proofs::toBytes methods

    to_bytes_full (function):
      # C++: Proofs::toBytesFull methods

    to_bytes_full_from_dict (function):
      # C++: No direct equivalent (Python-specific)

    validate_proof_structure (function):
      # C++: No direct equivalent (Python-specific validation)
    ```

---

- [x] **Task #6**: Annotate `executable-spec/protocol/prover.py`
  - File: `executable-spec/protocol/prover.py`
  - Annotations to add:
    ```
    gen_proof (function):
      # C++: pil2-stark/src/starkpil/gen_proof.hpp::genProof (lines 47-465)
    ```

---

- [x] **Task #7**: Annotate `executable-spec/protocol/setup_ctx.py`
  - File: `executable-spec/protocol/setup_ctx.py`
  - Annotations to add:
    ```
    class ProverHelpers:
      # C++: pil2-stark/src/starkpil/setup_ctx.hpp::ProverHelpers (lines 8-91)

      __init__:
        # C++: ProverHelpers constructor

      from_stark_info:
        # C++: ProverHelpers initialization from StarkInfo

      from_challenge:
        # C++: ProverHelpers::setFromChallenge

      compute_x:
        # C++: ProverHelpers::computeX

      compute_zerofier:
        # C++: ProverHelpers::computeZerofier

      build_zh_inv:
        # C++: ProverHelpers::buildZHInv

      build_one_row_zerofier_inv:
        # C++: ProverHelpers::buildOneRowZerofierInv

      build_frame_zerofier_inv:
        # C++: ProverHelpers::buildFrameZerofierInv

    class SetupCtx:
      # C++: pil2-stark/src/starkpil/setup_ctx.hpp::SetupCtx (implicit container)

      __init__:
        # C++: SetupCtx constructor

      from_files:
        # C++: SetupCtx::load methods
    ```

---

- [x] **Task #8**: Annotate `executable-spec/protocol/stages.py`
  - File: `executable-spec/protocol/stages.py`
  - Annotations to add:
    ```
    class Starks:
      # C++: pil2-stark/src/starkpil/starks.hpp::Starks<ElementType> (lines 24-112)

      __init__:
        # C++: Starks constructor

      build_const_tree:
        # C++: Starks::buildConstTree

      get_const_query_proof:
        # C++: Starks::getConstQueryProof

      extendAndMerkelize:
        # C++: Starks::extendAndMerkelize (line 90)

      get_stage_query_proof:
        # C++: Starks::getStageQueryProof

      get_stage_tree:
        # C++: Starks::getStageTree

      commitStage:
        # C++: Starks::commitStage (line 92)

      computeFriPol:
        # C++: Starks::computeFriPol

      calculateImPolsExpressions:
        # C++: Starks::calculateImPolsExpressions (line 95)

      calculateQuotientPolynomial:
        # C++: Starks::calculateQuotientPolynomial (line 96)

      calculateFRIPolynomial:
        # C++: Starks::calculateFRIPolynomial (line 97)

      computeLEv:
        # C++: Starks::computeLEv

      computeEvals:
        # C++: Starks::computeEvals (line 100)

      evmap:
        # C++: Starks::evmap
    ```

---

- [x] **Task #9**: Annotate `executable-spec/protocol/stark_info.py`
  - File: `executable-spec/protocol/stark_info.py`
  - Annotations to add:
    ```
    class StepStruct:
      # C++: pil2-stark/src/starkpil/stark_info.hpp::StepStruct (lines 68-72)

    class StarkStruct:
      # C++: pil2-stark/src/starkpil/stark_info.hpp::StarkStruct (lines 74-88)

    class StarkInfo:
      # C++: pil2-stark/src/starkpil/stark_info.hpp::StarkInfo (lines 137-217)

      __init__:
        # C++: StarkInfo constructor

      from_json:
        # C++: StarkInfo::load (stark_info.cpp)

      _load:
        # C++: StarkInfo::load internal parsing

      _get_proof_size:
        # C++: StarkInfo::getProofSize

      _set_map_offsets:
        # C++: StarkInfo::setMapOffsets

      _get_num_nodes_mt:
        # C++: StarkInfo::getNumNodesMT

      get_offset:
        # C++: StarkInfo::getOffset

      get_n_cols:
        # C++: StarkInfo::getNCols
    ```

---

- [x] **Task #10**: Annotate `executable-spec/protocol/steps_params.py`
  - File: `executable-spec/protocol/steps_params.py`
  - Annotations to add:
    ```
    class StepsParams:
      # C++: pil2-stark/src/starkpil/steps.hpp::StepsParams (lines 6-20)

      __post_init__:
        # C++: StepsParams initialization logic
    ```

---

- [x] **Task #11**: Annotate `executable-spec/protocol/verifier.py`
  - File: `executable-spec/protocol/verifier.py`
  - Annotations to add:
    ```
    stark_verify (function):
      # C++: pil2-stark/src/starkpil/stark_verify.hpp::starkVerify (lines 22-695)

    _parse_root (function):
      # C++: stark_verify.hpp root parsing (inline)

    _compute_x_div_x_sub (function):
      # C++: stark_verify.hpp::computeXDivXSub

    _parse_trace_values (function):
      # C++: stark_verify.hpp trace value parsing

    _verify_evaluations (function):
      # C++: stark_verify.hpp evaluation verification section

    _verify_fri_consistency (function):
      # C++: stark_verify.hpp FRI consistency checks

    _verify_stage_merkle_tree (function):
      # C++: stark_verify.hpp stage Merkle verification

    _verify_constant_merkle_tree (function):
      # C++: stark_verify.hpp constant Merkle verification

    _verify_custom_commit_merkle_tree (function):
      # C++: stark_verify.hpp custom commit Merkle verification

    _verify_fri_folding_merkle_tree (function):
      # C++: stark_verify.hpp FRI folding Merkle verification

    _verify_fri_folding (function):
      # C++: stark_verify.hpp FRI folding verification

    _verify_final_polynomial (function):
      # C++: stark_verify.hpp final polynomial degree check
    ```

---

- [x] **Task #12**: Annotate `executable-spec/protocol/witness_generation.py`
  - File: `executable-spec/protocol/witness_generation.py`
  - Annotations to add:
    ```
    _goldilocks3_add (function):
      # C++: pil2-stark/src/goldilocks/src/goldilocks_cubic_extension.hpp::add

    _goldilocks3_mul (function):
      # C++: goldilocks_cubic_extension.hpp::mul

    _goldilocks3_inv (function):
      # C++: goldilocks_cubic_extension.hpp::inv

    _goldilocks_inv (function):
      # C++: goldilocks_base_field.hpp::inv

    _field_mul_scalar (function):
      # C++: Inline Goldilocks multiplication

    _field_inverse_scalar (function):
      # C++: Goldilocks::inv

    _field_mul_columns (function):
      # C++: No direct equivalent (Python batch operation)

    _field_inverse_column (function):
      # C++: Batch inverse computation

    evaluate_hint_field_with_expressions (function):
      # C++: pil2-stark/src/starkpil/hints.cpp hint evaluation

    _build_param_from_hint_field (function):
      # C++: hints.cpp parameter building

    _get_polynomial_column (function):
      # C++: hints.cpp polynomial access

    _get_const_polynomial (function):
      # C++: hints.cpp constant polynomial access

    _fetch_operand_value (function):
      # C++: hints.cpp operand fetching

    get_hint_field_values (function):
      # C++: pil2-stark/src/starkpil/hints.cpp::getHintFieldValues

    _set_polynomial_column (function):
      # C++: hints.cpp polynomial writing

    _set_hint_field (function):
      # C++: hints.cpp::setHintField

    multiply_hint_fields (function):
      # C++: pil2-stark/src/starkpil/hints.cpp::multiplyHintFields

    acc_mul_hint_fields (function):
      # C++: hints.cpp::accMulHintFields

    update_airgroup_value (function):
      # C++: hints.cpp::updateAirgroupValue

    calculate_witness_std (function):
      # C++: pil2-stark/src/starkpil/gen_proof.hpp::calculateWitnessSTD (lines 4-45)
    ```

---

## Implementation Workflow

This plan file serves as the authoritative checklist for implementation. When implementing:

### Required Process
1. **Load Plan**: Read this entire plan file before starting
2. **Execute in Parallel Batches**:
   - **Batch 1**: Launch 4 parallel Task subtasks for Tasks #1-4
   - Wait for Batch 1 completion
   - **Batch 2**: Launch 4 parallel Task subtasks for Tasks #5-8
   - Wait for Batch 2 completion
   - **Batch 3**: Launch 4 parallel Task subtasks for Tasks #9-12
3. **Update Checkboxes**: After each batch completes, update `[ ]` to `[x]` for completed tasks

### Subtask Prompt Template
Each subtask should receive:
```
Annotate the file {FILE_PATH} with C++ reference comments.

Format: Add a comment IMMEDIATELY BEFORE each class/function definition:
- `# C++: pil2-stark/path/to/file.hpp::ClassName::methodName (lines X-Y)`
- `# C++: No direct equivalent (reason)`

Specific annotations for this file:
{PASTE TASK DETAILS FROM PLAN}

Rules:
1. Preserve all existing code and comments
2. Only add annotation comments, do not modify any logic
3. Comment goes on the line immediately before `def` or `class`
```

### Critical Rules
- This plan file is the source of truth for progress
- **Use parallel subtasks** - do NOT annotate files sequentially
- Update checkboxes after each batch completes
- Each subtask is self-contained with all needed C++ mappings

### Progress Tracking
The checkboxes above represent the authoritative status of each task. Keep them updated as you work.
