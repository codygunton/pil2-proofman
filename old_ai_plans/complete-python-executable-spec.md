# Complete Python Executable Spec Implementation Plan

## Executive Summary

### Problem Statement
The Python executable spec for pil2-proofman is 98% complete but cannot pass full end-to-end tests because it's missing the **witness STD computation** - the algorithm that computes running sum/product polynomials (`gsum`/`gprod`) for lookup and permutation arguments.

Currently:
- **25 tests pass** (FRI protocol, NTT, polynomial evaluations for cm1/const)
- **5 tests fail** due to stage 2 polynomials (`gsum`) being zeros

### Proposed Solution
Implement the witness STD computation in Python, following the C++ implementation in `pil2-stark/src/starkpil/hints.cpp` and `gen_proof.hpp`. This involves:

1. **Hint field evaluation** - Fetching values from hints (polynomials, challenges, etc.)
2. **Intermediate column computation** - Computing `im_col` products
3. **Running accumulation** - Computing `gsum`/`gprod` via running sum/product
4. **Airgroup value updates** - Aggregating direct components

### Technical Approach
The witness STD computation uses a **hint-driven** approach:
- Hints define which polynomials to multiply and accumulate
- The algorithm fetches hint field values, computes products with inversions, and accumulates

```
calculateWitnessSTD(prod=False):  # for gsum
├── Get "gsum_col" hint ID
├── IF im_col hints exist:
│   └── multiplyHintFields() → compute intermediate products
├── accMulHintFields() → running sum of (numerator * denominator^-1)
└── updateAirgroupValue() → add direct components to aggregation
```

### Data Flow
```
Inputs:
  witness_trace (N rows) ──┐
  const_pols ──────────────┤
  challenges (stage 2) ────┼──► calculateWitnessSTD() ──► gsum polynomial (stage 2)
  hints (expressions.bin) ─┘                              airgroupValues

gsum polynomial flows into:
  └──► commitStage(2) ──► root2 ──► quotient polynomial ──► FRI ──► proof
```

### Expected Outcomes
- All 5 failing e2e tests will pass
- Full proof output matches C++ byte-for-byte
- Python spec becomes a standalone reference implementation

---

## Goals & Objectives

### Primary Goals
- **Complete witness STD implementation** matching C++ algorithm exactly
- **Pass all e2e tests** with full proof comparison against C++ golden values
- **Validate 27/27 polynomial evaluations** (currently 17/27)

### Secondary Objectives
- Clean, readable Python code suitable as reference specification
- Comprehensive test coverage for intermediate computations
- Documentation of the witness STD algorithm

---

## Solution Overview

### Approach
Implement witness STD as a new module `witness_std.py` with three core functions mirroring C++:
1. `multiply_hint_fields()` - Compute intermediate column products
2. `acc_mul_hint_fields()` - Accumulate running sum/product
3. `update_airgroup_value()` - Update aggregation with direct components

Integrate into `gen_proof.py` between challenge derivation and stage 2 commitment.

### Key Components

1. **`witness_std.py`**: New module containing the witness STD algorithm
2. **`expressions_bin.py`**: Already has hint parsing - add helper methods
3. **`gen_proof.py`**: Add call to `calculate_witness_std()`
4. **`create-test-vectors.py`**: Capture full proof outputs
5. **`test_stark_e2e.py`**: Add comprehensive proof comparison tests

### Architecture Diagram
```
┌─────────────────────────────────────────────────────────────────┐
│                     gen_proof.py                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Stage 1: commitStage(1)                                        │
│      │                                                          │
│      ▼                                                          │
│  Stage 2: derive challenges                                     │
│      │                                                          │
│      ├──► calculateImPolsExpressions(2)  [existing - imPol=True]│
│      │                                                          │
│      ├──► calculate_witness_std()  ◄── NEW                      │
│      │        │                                                 │
│      │        ├── multiply_hint_fields()                        │
│      │        ├── acc_mul_hint_fields()  ──► gsum polynomial    │
│      │        └── update_airgroup_value() ──► airgroupValues    │
│      │                                                          │
│      └──► commitStage(2)                                        │
│                                                                 │
│  Stage Q: calculateQuotientPolynomial()                         │
│  ...                                                            │
└─────────────────────────────────────────────────────────────────┘
```

---

## Implementation Tasks

### CRITICAL IMPLEMENTATION RULES
1. **NO PLACEHOLDER CODE**: Every implementation must be production-ready
2. **MATCH C++ EXACTLY**: Field arithmetic must match C++ bit-for-bit
3. **TEST INCREMENTALLY**: Add tests for each component as implemented
4. **COMPLETE IMPLEMENTATIONS**: Each task fully implements its feature

### Visual Dependency Tree

```
executable-spec/
├── witness_std.py (Task #1-3: Core witness STD algorithm)
│   ├── get_hint_field_values()     (Task #1)
│   ├── multiply_hint_fields()      (Task #2)
│   ├── acc_mul_hint_fields()       (Task #2)
│   ├── update_airgroup_value()     (Task #2)
│   └── calculate_witness_std()     (Task #3)
│
├── expressions_bin.py (Task #0: Helper methods)
│   └── get_hint_field()            (Task #0)
│
├── gen_proof.py (Task #4: Integration)
│   └── Add calculate_witness_std() call
│
├── create-test-vectors.py (Task #5: Update test vector capture)
│   └── Capture full proof outputs
│
├── test-data/*.json (Task #5: Regenerated test vectors)
│   ├── simple-left.json
│   ├── lookup2-12.json
│   └── permutation1-6.json
│
└── test_stark_e2e.py (Task #6: Comprehensive tests)
    └── test_full_proof_matches_cpp[]
```

### Execution Plan

#### Group A: Foundation (Execute in parallel)

- [ ] **Task #0**: Add hint field accessor to ExpressionsBin
  - **Folder**: `executable-spec/`
  - **File**: `expressions_bin.py`
  - **Implements**:
    ```python
    def get_hint_field(self, hint_id: int, field_name: str) -> HintField:
        """Get a specific field from a hint by name.

        Args:
            hint_id: Index into self.hints
            field_name: Name of field (e.g., "numerator", "denominator", "reference")

        Returns:
            HintField containing the field values

        Raises:
            ValueError: If field not found
        """
        hint = self.hints[hint_id]
        for field in hint.fields:
            if field.name == field_name:
                return field
        raise ValueError(f"Field '{field_name}' not found in hint '{hint.name}'")
    ```
  - **Exports**: Method on ExpressionsBin class
  - **Context**: Used by witness_std.py to access hint fields

#### Group B: Core Algorithm (Execute sequentially after Group A)

- [ ] **Task #1**: Implement hint field value fetching
  - **Folder**: `executable-spec/`
  - **File**: `witness_std.py` (new file)
  - **Imports**:
    ```python
    import numpy as np
    from typing import Optional, Tuple
    from expressions_bin import ExpressionsBin, HintFieldValue, OpType
    from stark_info import StarkInfo
    from steps_params import StepsParams
    from field import FF, goldilocks_inverse, goldilocks3_inverse
    ```
  - **Implements**:
    ```python
    FIELD_EXTENSION = 3

    def get_hint_field_values(
        stark_info: StarkInfo,
        expressions_bin: ExpressionsBin,
        params: StepsParams,
        hint_id: int,
        field_name: str,
        inverse: bool = False
    ) -> np.ndarray:
        """Fetch values for a hint field.

        Resolves hint field operands to actual values from params buffers.
        Handles: cm (witness), const, challenge, number, tmp (expression result),
                 airgroupvalue, airvalue, custom.

        Args:
            stark_info: Stark configuration
            expressions_bin: Parsed expressions binary
            params: Working buffers
            hint_id: Index of hint in expressions_bin.hints
            field_name: Name of field to fetch
            inverse: If True, compute multiplicative inverse

        Returns:
            np.ndarray of field values (N rows for columns, single value for scalars)
        """
        N = 1 << stark_info.starkStruct.nBits
        hint_field = expressions_bin.get_hint_field(hint_id, field_name)

        # Aggregate values from all hint field values
        result = None
        for hfv in hint_field.values:
            val = _fetch_operand_value(stark_info, params, hfv, N)
            if result is None:
                result = val
            else:
                # Multiply multiple values together
                result = _field_mul(result, val)

        if inverse:
            result = _field_inverse(result)

        return result

    def _fetch_operand_value(
        stark_info: StarkInfo,
        params: StepsParams,
        hfv: HintFieldValue,
        N: int
    ) -> np.ndarray:
        """Fetch value for a single hint field operand."""
        if hfv.operand == OpType.cm:
            # Committed polynomial
            pol_info = stark_info.cmPolsMap[hfv.id]
            return _get_polynomial_column(stark_info, params, pol_info, hfv.row_offset_index)
        elif hfv.operand == OpType.const_:
            # Constant polynomial
            pol_info = stark_info.constPolsMap[hfv.id]
            return _get_const_polynomial(params, pol_info, N)
        elif hfv.operand == OpType.challenge:
            # Challenge value (single element, but dim=3)
            idx = hfv.id * FIELD_EXTENSION
            return params.challenges[idx:idx + FIELD_EXTENSION].copy()
        elif hfv.operand == OpType.number:
            # Literal number
            return np.array([hfv.value], dtype=np.uint64)
        elif hfv.operand == OpType.airgroupvalue:
            # Airgroup value
            idx = hfv.id * FIELD_EXTENSION
            return params.airgroupValues[idx:idx + FIELD_EXTENSION].copy()
        elif hfv.operand == OpType.airvalue:
            # Air value
            return params.airValues[hfv.id * FIELD_EXTENSION:(hfv.id + 1) * FIELD_EXTENSION].copy()
        else:
            raise NotImplementedError(f"Operand type {hfv.operand} not implemented")

    def _get_polynomial_column(
        stark_info: StarkInfo,
        params: StepsParams,
        pol_info,
        row_offset_index: int
    ) -> np.ndarray:
        """Extract a polynomial column from trace buffer."""
        N = 1 << stark_info.starkStruct.nBits
        stage = pol_info.stage
        dim = pol_info.dim

        if stage == 1:
            # Stage 1 is in params.trace
            section = "cm1"
            n_cols = stark_info.mapSectionsN[section]
            buffer = params.trace
        else:
            # Stage 2+ is in params.auxTrace
            section = f"cm{stage}"
            n_cols = stark_info.mapSectionsN[section]
            offset = stark_info.mapOffsets[(section, False)]
            buffer = params.auxTrace[offset:]

        row_offset = stark_info.openingPoints[row_offset_index] if row_offset_index < len(stark_info.openingPoints) else 0

        result = np.zeros(N * dim, dtype=np.uint64)
        for j in range(N):
            l = (j + row_offset) % N
            result[j * dim:(j + 1) * dim] = buffer[l * n_cols + pol_info.stagePos:l * n_cols + pol_info.stagePos + dim]

        return result
    ```
  - **Exports**: `get_hint_field_values`, helper functions
  - **Context**: Core building block for witness STD - fetches data that hints reference

- [ ] **Task #2**: Implement multiply and accumulate functions
  - **Folder**: `executable-spec/`
  - **File**: `witness_std.py` (continue)
  - **Implements**:
    ```python
    def multiply_hint_fields(
        stark_info: StarkInfo,
        expressions_bin: ExpressionsBin,
        params: StepsParams,
        hint_ids: list,
        dest_field: str,
        field1: str,
        field2: str,
        field2_inverse: bool = True
    ) -> None:
        """Compute products for intermediate columns.

        For each hint in hint_ids:
            dest = field1 * field2^(-1)  (if field2_inverse=True)

        Results stored back into committed polynomial referenced by dest_field.

        C++ reference: hints.cpp multiplyHintFields() lines 479-523
        """
        N = 1 << stark_info.starkStruct.nBits

        for hint_id in hint_ids:
            # Get operand values
            val1 = get_hint_field_values(stark_info, expressions_bin, params, hint_id, field1, inverse=False)
            val2 = get_hint_field_values(stark_info, expressions_bin, params, hint_id, field2, inverse=field2_inverse)

            # Compute product
            result = _field_mul_columns(val1, val2, N)

            # Store in destination
            _set_hint_field(stark_info, expressions_bin, params, hint_id, dest_field, result)

    def acc_mul_hint_fields(
        stark_info: StarkInfo,
        expressions_bin: ExpressionsBin,
        params: StepsParams,
        hint_id: int,
        dest_field: str,
        airgroup_val_field: str,
        field1: str,
        field2: str,
        add: bool
    ) -> None:
        """Accumulate running sum/product of field multiplications.

        Computes:
            vals[0] = field1[0] * field2[0]^(-1)
            for i in 1..N-1:
                if add:
                    vals[i] = vals[i] + vals[i-1]  (running sum)
                else:
                    vals[i] = vals[i] * vals[i-1]  (running product)

        Stores result in dest_field polynomial and airgroup_val_field.

        C++ reference: hints.cpp accMulHintFields() lines 581-625
        """
        N = 1 << stark_info.starkStruct.nBits

        # Get destination polynomial info for dimension
        hint = expressions_bin.hints[hint_id]
        dest_hf = expressions_bin.get_hint_field(hint_id, dest_field)
        dest_pol_id = dest_hf.values[0].id
        dim = stark_info.cmPolsMap[dest_pol_id].dim

        # Get operand values
        val1 = get_hint_field_values(stark_info, expressions_bin, params, hint_id, field1, inverse=False)
        val2 = get_hint_field_values(stark_info, expressions_bin, params, hint_id, field2, inverse=True)

        # Compute element-wise product: vals[i] = val1[i] * val2[i]
        vals = _field_mul_columns(val1, val2, N)

        # Running accumulation
        if dim == 1:
            for i in range(1, N):
                if add:
                    vals[i] = FF(vals[i]) + FF(vals[i - 1])
                else:
                    vals[i] = FF(vals[i]) * FF(vals[i - 1])
        else:
            # Field extension (dim=3)
            for i in range(1, N):
                if add:
                    vals[i * FIELD_EXTENSION:(i + 1) * FIELD_EXTENSION] = _goldilocks3_add(
                        vals[i * FIELD_EXTENSION:(i + 1) * FIELD_EXTENSION],
                        vals[(i - 1) * FIELD_EXTENSION:i * FIELD_EXTENSION]
                    )
                else:
                    vals[i * FIELD_EXTENSION:(i + 1) * FIELD_EXTENSION] = _goldilocks3_mul(
                        vals[i * FIELD_EXTENSION:(i + 1) * FIELD_EXTENSION],
                        vals[(i - 1) * FIELD_EXTENSION:i * FIELD_EXTENSION]
                    )

        # Store in destination polynomial
        _set_hint_field(stark_info, expressions_bin, params, hint_id, dest_field, vals)

        # Store final value in airgroup value (if specified)
        if airgroup_val_field:
            final_val = vals[(N - 1) * FIELD_EXTENSION:(N) * FIELD_EXTENSION] if dim == 3 else vals[N - 1:N]
            _set_hint_field(stark_info, expressions_bin, params, hint_id, airgroup_val_field, final_val)

    def update_airgroup_value(
        stark_info: StarkInfo,
        expressions_bin: ExpressionsBin,
        params: StepsParams,
        hint_id: int,
        airgroup_val_field: str,
        field1: str,
        field2: str,
        add: bool
    ) -> None:
        """Update airgroup value with direct components.

        Computes: airgroupValue += (or *=) field1 * field2^(-1)

        C++ reference: hints.cpp updateAirgroupValue() lines 627-664
        """
        if not airgroup_val_field:
            return

        # Get values (single elements, not columns)
        val1 = get_hint_field_values(stark_info, expressions_bin, params, hint_id, field1, inverse=False)
        val2 = get_hint_field_values(stark_info, expressions_bin, params, hint_id, field2, inverse=True)

        # Compute product
        result = _field_mul(val1, val2)

        # Get airgroup value location
        airgroup_hf = expressions_bin.get_hint_field(hint_id, airgroup_val_field)
        airgroup_id = airgroup_hf.values[0].id
        idx = airgroup_id * FIELD_EXTENSION

        # Update: add or multiply
        current = params.airgroupValues[idx:idx + FIELD_EXTENSION]
        if add:
            params.airgroupValues[idx:idx + FIELD_EXTENSION] = _goldilocks3_add(current, result)
        else:
            params.airgroupValues[idx:idx + FIELD_EXTENSION] = _goldilocks3_mul(current, result)
    ```
  - **Exports**: `multiply_hint_fields`, `acc_mul_hint_fields`, `update_airgroup_value`
  - **Context**: Core accumulation logic matching C++ hints.cpp

- [ ] **Task #3**: Implement main calculate_witness_std function
  - **Folder**: `executable-spec/`
  - **File**: `witness_std.py` (continue)
  - **Implements**:
    ```python
    def calculate_witness_std(
        stark_info: StarkInfo,
        expressions_bin: ExpressionsBin,
        params: StepsParams,
        prod: bool
    ) -> None:
        """Calculate witness STD columns (gsum or gprod).

        This is the main entry point for witness STD computation.
        Computes running sum (gsum) or running product (gprod) polynomials
        for lookup and permutation arguments.

        C++ reference: gen_proof.hpp calculateWitnessSTD() lines 4-45

        Args:
            stark_info: Stark configuration
            expressions_bin: Parsed expressions binary with hints
            params: Working buffers (trace, auxTrace, challenges, etc.)
            prod: If True, compute gprod (running product)
                  If False, compute gsum (running sum)
        """
        name = "gprod_col" if prod else "gsum_col"

        # Check if hints exist for this type
        hint_ids = expressions_bin.get_hint_ids_by_name(name)
        if len(hint_ids) == 0:
            return

        hint_id = hint_ids[0]

        # Handle intermediate column hints (im_col and im_airval)
        im_col_hints = expressions_bin.get_hint_ids_by_name("im_col")
        im_airval_hints = expressions_bin.get_hint_ids_by_name("im_airval")

        if len(im_col_hints) + len(im_airval_hints) > 0:
            all_im_hints = im_col_hints + im_airval_hints
            multiply_hint_fields(
                stark_info, expressions_bin, params,
                all_im_hints,
                dest_field="reference",
                field1="numerator",
                field2="denominator",
                field2_inverse=True
            )

        # Determine if we have airgroup values
        airgroup_val_field = "result" if len(stark_info.airgroupValuesMap) > 0 else ""

        # Accumulate main computation
        # Note: !prod means add=True for gsum, add=False for gprod
        acc_mul_hint_fields(
            stark_info, expressions_bin, params,
            hint_id,
            dest_field="reference",
            airgroup_val_field=airgroup_val_field,
            field1="numerator_air",
            field2="denominator_air",
            add=not prod  # gsum uses addition, gprod uses multiplication
        )

        # Update with direct components
        update_airgroup_value(
            stark_info, expressions_bin, params,
            hint_id,
            airgroup_val_field=airgroup_val_field,
            field1="numerator_direct",
            field2="denominator_direct",
            add=not prod
        )
    ```
  - **Also implements field arithmetic helpers**:
    ```python
    def _field_mul(a: np.ndarray, b: np.ndarray) -> np.ndarray:
        """Multiply two field elements (dim 1 or 3)."""
        if len(a) == 1 and len(b) == 1:
            return np.array([int(FF(a[0]) * FF(b[0]))], dtype=np.uint64)
        elif len(a) == 3 and len(b) == 3:
            return _goldilocks3_mul(a, b)
        else:
            raise ValueError(f"Dimension mismatch: {len(a)} vs {len(b)}")

    def _field_inverse(a: np.ndarray) -> np.ndarray:
        """Compute multiplicative inverse."""
        if len(a) == 1:
            return goldilocks_inverse(a)
        elif len(a) == 3:
            return goldilocks3_inverse(a)
        elif len(a) % 3 == 0:
            # Column of Goldilocks3 elements
            N = len(a) // 3
            result = np.zeros_like(a)
            for i in range(N):
                result[i*3:(i+1)*3] = goldilocks3_inverse(a[i*3:(i+1)*3])
            return result
        else:
            N = len(a)
            result = np.zeros_like(a)
            for i in range(N):
                result[i:i+1] = goldilocks_inverse(a[i:i+1])
            return result

    def _goldilocks3_add(a: np.ndarray, b: np.ndarray) -> np.ndarray:
        """Add two Goldilocks3 elements."""
        from field import FF
        return np.array([
            int(FF(a[0]) + FF(b[0])),
            int(FF(a[1]) + FF(b[1])),
            int(FF(a[2]) + FF(b[2]))
        ], dtype=np.uint64)

    def _goldilocks3_mul(a: np.ndarray, b: np.ndarray) -> np.ndarray:
        """Multiply two Goldilocks3 elements.

        Using irreducible polynomial x^3 - x - 1.
        C++ reference: goldilocks_cubic_extension.hpp mul() lines 232-245
        """
        from field import FF
        a0, a1, a2 = FF(a[0]), FF(a[1]), FF(a[2])
        b0, b1, b2 = FF(b[0]), FF(b[1]), FF(b[2])

        A = (a0 + a1) * (b0 + b1)
        B = (a0 + a2) * (b0 + b2)
        C = (a1 + a2) * (b1 + b2)
        D = a0 * b0
        E = a1 * b1
        F = a2 * b2
        G = D - E

        r0 = int((C + G) - F)
        r1 = int((((A + C) - E) - E) - D)
        r2 = int(B - G)

        return np.array([r0, r1, r2], dtype=np.uint64)

    def _set_hint_field(
        stark_info: StarkInfo,
        expressions_bin: ExpressionsBin,
        params: StepsParams,
        hint_id: int,
        field_name: str,
        values: np.ndarray
    ) -> None:
        """Store values into the polynomial referenced by a hint field."""
        hint_field = expressions_bin.get_hint_field(hint_id, field_name)
        hfv = hint_field.values[0]

        if hfv.operand == OpType.cm:
            pol_info = stark_info.cmPolsMap[hfv.id]
            _set_polynomial_column(stark_info, params, pol_info, values)
        elif hfv.operand == OpType.airgroupvalue:
            idx = hfv.id * FIELD_EXTENSION
            params.airgroupValues[idx:idx + len(values)] = values
        else:
            raise NotImplementedError(f"Cannot set hint field with operand type {hfv.operand}")

    def _set_polynomial_column(
        stark_info: StarkInfo,
        params: StepsParams,
        pol_info,
        values: np.ndarray
    ) -> None:
        """Store values into a polynomial column in trace buffer."""
        N = 1 << stark_info.starkStruct.nBits
        stage = pol_info.stage
        dim = pol_info.dim

        section = f"cm{stage}"
        n_cols = stark_info.mapSectionsN[section]

        if stage == 1:
            buffer = params.trace
            offset = 0
        else:
            offset = stark_info.mapOffsets[(section, False)]
            buffer = params.auxTrace

        for j in range(N):
            buffer[offset + j * n_cols + pol_info.stagePos:offset + j * n_cols + pol_info.stagePos + dim] = values[j * dim:(j + 1) * dim]
    ```
  - **Exports**: `calculate_witness_std` (main entry point)
  - **Context**: Complete witness STD implementation matching C++

#### Group C: Integration (After Group B)

- [ ] **Task #4**: Integrate witness STD into gen_proof.py
  - **Folder**: `executable-spec/`
  - **File**: `gen_proof.py`
  - **Changes**:
    1. Add import at top:
       ```python
       from witness_std import calculate_witness_std
       ```
    2. After line 158 (after `calculateImPolsExpressions`), add:
       ```python
       # Calculate witness STD columns for grand product arguments
       # C++: Lines 136-142 in gen_proof.hpp
       # This computes gsum (running sum) and gprod (running product) polynomials
       # for lookup and permutation arguments
       calculate_witness_std(
           setup_ctx.stark_info,
           setup_ctx.expressions_bin,
           params,
           prod=True   # gprod first
       )
       calculate_witness_std(
           setup_ctx.stark_info,
           setup_ctx.expressions_bin,
           params,
           prod=False  # then gsum
       )
       ```
  - **Context**: Integrates witness STD into proof generation flow

#### Group D: Testing Infrastructure (Execute in parallel after Group C)

- [ ] **Task #5**: Update test vector generation
  - **Folder**: `executable-spec/`
  - **File**: `create-test-vectors.py`
  - **Changes**:
    1. Add capture of full proof output:
       ```python
       # After proof generation completes, capture:
       "expected": {
           "evals": proof['evals'].tolist(),
           "airgroup_values": proof['airgroup_values'].tolist(),
           "air_values": proof['air_values'].tolist(),
           "nonce": proof['nonce'],
           "final_pol": proof['fri_proof'].final_pol.tolist(),
           "fri_queries": [...],  # FRI query responses
       }
       ```
    2. Add capture of stage 2 polynomial values for validation:
       ```python
       "intermediates": {
           ...
           "cm2_hash": hash_of_cm2_extended,
           "gsum_values": [...],  # First few gsum values for spot-checking
       }
       ```
  - **Then run**: `./generate-test-vectors.sh` to regenerate all test vectors
  - **Context**: Test vectors will include full proof for comparison

- [ ] **Task #6**: Add comprehensive e2e proof comparison tests
  - **Folder**: `executable-spec/`
  - **File**: `test_stark_e2e.py`
  - **Implements**:
    ```python
    @pytest.mark.parametrize("air_name", ["simple", "lookup", "permutation"])
    class TestFullProof:
        """Full end-to-end proof comparison tests."""

        def test_full_proof_matches_cpp(self, air_name, test_vectors, setup_ctx, params):
            """Verify complete proof matches C++ byte-for-byte."""
            proof = gen_proof(setup_ctx, params, ...)

            expected = test_vectors['expected']

            # Compare all polynomial evaluations
            assert np.allclose(proof['evals'], expected['evals']), \
                f"Evaluations mismatch"

            # Compare airgroup values
            assert np.allclose(proof['airgroup_values'], expected['airgroup_values']), \
                f"Airgroup values mismatch"

            # Compare FRI proof
            assert proof['nonce'] == expected['nonce'], \
                f"Nonce mismatch: {proof['nonce']} vs {expected['nonce']}"

            assert np.allclose(proof['fri_proof'].final_pol, expected['final_pol']), \
                f"Final polynomial mismatch"

        def test_all_evals_match(self, air_name, test_vectors, setup_ctx, params):
            """Verify all 27 polynomial evaluations match (cm1 + cm2 + const)."""
            proof = gen_proof(setup_ctx, params, ...)

            expected_evals = test_vectors['expected']['evals']
            actual_evals = proof['evals']

            # Count matches
            n_evals = len(expected_evals) // 3
            matches = 0
            for i in range(n_evals):
                if np.allclose(actual_evals[i*3:(i+1)*3], expected_evals[i*3:(i+1)*3]):
                    matches += 1

            assert matches == n_evals, \
                f"Only {matches}/{n_evals} evaluations match"

        def test_gsum_polynomial_computed(self, air_name, test_vectors, setup_ctx, params):
            """Verify gsum polynomial is non-zero after witness STD."""
            proof = gen_proof(setup_ctx, params, ...)

            # Check that cm2 section is populated
            cm2_offset = setup_ctx.stark_info.mapOffsets[("cm2", False)]
            cm2_size = setup_ctx.stark_info.mapSectionsN["cm2"]
            N = 1 << setup_ctx.stark_info.starkStruct.nBits

            cm2_data = params.auxTrace[cm2_offset:cm2_offset + N * cm2_size]

            # Should not be all zeros
            assert not np.all(cm2_data == 0), \
                "gsum polynomial is all zeros - witness STD not computed"
    ```
  - **Context**: Comprehensive tests validating full proof correctness

---

## Implementation Workflow

This plan file serves as the authoritative checklist for implementation. When implementing:

### Required Process
1. **Load Plan**: Read this entire plan file before starting
2. **Sync Tasks**: Create TodoWrite tasks matching the checkboxes above
3. **Execute & Update**: For each task:
   - Mark TodoWrite as `in_progress` when starting
   - Update checkbox `[ ]` to `[x]` when completing
   - Mark TodoWrite as `completed` when done
4. **Maintain Sync**: Keep this file and TodoWrite synchronized throughout

### Critical Rules
- This plan file is the source of truth for progress
- Update checkboxes in real-time as work progresses
- Never lose synchronization between plan file and TodoWrite
- Mark tasks complete only when fully implemented (no placeholders)
- Run tests after each task to verify correctness

### Testing Strategy
After each group:
- **Group A**: Run `pytest test_expressions_bin.py -v` to verify hint accessor
- **Group B**: Create unit tests for witness_std.py functions
- **Group C**: Run `pytest test_stark_e2e.py -v` to see improvement in e2e tests
- **Group D**: Regenerate test vectors and run full test suite

### Progress Tracking
The checkboxes above represent the authoritative status of each task. Keep them updated as you work.

---

## Risk Mitigation

### Potential Issues

1. **Field arithmetic precision**: Goldilocks3 multiplication must match C++ exactly
   - Mitigation: Verify against known test vectors element-by-element

2. **Hint field value fetching**: Complex operand resolution
   - Mitigation: Add debug logging, compare intermediate values

3. **Memory layout differences**: Python vs C++ buffer organization
   - Mitigation: Use existing mapOffsets consistently

### Validation Checkpoints

After implementing witness STD:
1. Verify `gsum` polynomial is non-zero
2. Compare first 10 `gsum` values against C++ captured values
3. Verify cm2 extended hash matches
4. Verify all 27 evaluations match
5. Verify full proof matches byte-for-byte
