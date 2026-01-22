"""Witness STD computation for lookup and permutation arguments.

Faithful translation from:
- pil2-stark/src/starkpil/gen_proof.hpp (calculateWitnessSTD, lines 4-45)
- pil2-stark/src/starkpil/hints.cpp (multiplyHintFields, accMulHintFields, updateAirgroupValue)

This module computes the running sum/product polynomials (gsum/gprod) that are
essential for lookup and permutation arguments in STARK proofs. These polynomials
accumulate evidence that lookups are valid or permutations are correct.

The algorithm uses a hint-driven approach:
1. Hints define which polynomials to multiply and accumulate
2. The algorithm fetches hint field values (polynomials, challenges, etc.)
3. Computes products with inversions (numerator * denominator^-1)
4. Accumulates via running sum (gsum) or running product (gprod)
"""

import numpy as np
from typing import Optional, List, TYPE_CHECKING

from protocol.expressions_bin import ExpressionsBin, HintFieldValue, OpType
from protocol.stark_info import StarkInfo
from protocol.steps_params import StepsParams
from primitives.field import FF, FF3, ff3, ff3_coeffs
from primitives.batch_inverse import batch_inverse_ff, batch_inverse_ff3, batch_inverse_ff_array, batch_inverse_ff3_array

if TYPE_CHECKING:
    from protocol.expression_evaluator import ExpressionsPack

# Field extension size (Goldilocks3)
FIELD_EXTENSION = 3


# =============================================================================
# Goldilocks3 Field Arithmetic
# =============================================================================

# C++: pil2-stark/src/goldilocks/src/goldilocks_cubic_extension.hpp::add
def _goldilocks3_add(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """Add two Goldilocks3 elements (component-wise mod p).

    Args:
        a: First element [a0, a1, a2]
        b: Second element [b0, b1, b2]

    Returns:
        Sum [a0+b0, a1+b1, a2+b2] mod p
    """
    # Use ff3 for correct Goldilocks3 addition
    a_ff3 = ff3([int(a[0]), int(a[1]), int(a[2])])
    b_ff3 = ff3([int(b[0]), int(b[1]), int(b[2])])
    result = a_ff3 + b_ff3
    return np.array(ff3_coeffs(result), dtype=np.uint64)


# C++: goldilocks_cubic_extension.hpp::mul
def _goldilocks3_mul(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """Multiply two Goldilocks3 elements.

    Using irreducible polynomial x^3 - x - 1.
    Uses galois library for correctness.

    Args:
        a: First element [a0, a1, a2]
        b: Second element [b0, b1, b2]

    Returns:
        Product in Goldilocks3
    """
    a_ff3 = ff3([int(a[0]), int(a[1]), int(a[2])])
    b_ff3 = ff3([int(b[0]), int(b[1]), int(b[2])])
    result = a_ff3 * b_ff3
    return np.array(ff3_coeffs(result), dtype=np.uint64)


# C++: goldilocks_cubic_extension.hpp::inv
def _goldilocks3_inv(a: np.ndarray) -> np.ndarray:
    """Compute multiplicative inverse in Goldilocks3.

    Uses the galois library's ff3 implementation for correctness.

    Args:
        a: Element [a0, a1, a2] to invert

    Returns:
        Inverse element such that a * inv(a) = 1
    """
    elem = ff3([int(a[0]), int(a[1]), int(a[2])])
    inv_elem = elem ** -1
    return np.array(ff3_coeffs(inv_elem), dtype=np.uint64)


# C++: goldilocks_base_field.hpp::inv
def _goldilocks_inv(a: int) -> int:
    """Compute multiplicative inverse in base Goldilocks field."""
    return int(FF(a) ** -1)


# =============================================================================
# Field Operations on Columns
# =============================================================================

# C++: Inline Goldilocks multiplication
def _field_mul_scalar(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """Multiply two field elements (dim 1 or 3).

    Args:
        a: First element (1 or 3 components)
        b: Second element (1 or 3 components)

    Returns:
        Product with same dimension
    """
    # Note: Must convert numpy uint64 to Python int before creating FF
    if len(a) == 1 and len(b) == 1:
        return np.array([int(FF(int(a[0])) * FF(int(b[0])))], dtype=np.uint64)
    elif len(a) == 3 and len(b) == 3:
        return _goldilocks3_mul(a, b)
    elif len(a) == 1 and len(b) == 3:
        # Scalar * extension = scale each component
        scalar = FF(int(a[0]))
        return np.array([int(scalar * FF(int(b[i]))) for i in range(3)], dtype=np.uint64)
    elif len(a) == 3 and len(b) == 1:
        scalar = FF(int(b[0]))
        return np.array([int(scalar * FF(int(a[i]))) for i in range(3)], dtype=np.uint64)
    else:
        raise ValueError(f"Dimension mismatch: {len(a)} vs {len(b)}")


# C++: Goldilocks::inv
def _field_inverse_scalar(a: np.ndarray) -> np.ndarray:
    """Compute multiplicative inverse of a field element."""
    if len(a) == 1:
        return np.array([_goldilocks_inv(int(a[0]))], dtype=np.uint64)
    elif len(a) == 3:
        return _goldilocks3_inv(a)
    else:
        raise ValueError(f"Invalid dimension for inverse: {len(a)}")


# C++: No direct equivalent (Python batch operation)
def _field_mul_columns(a: np.ndarray, b: np.ndarray, N: int, dim: int) -> np.ndarray:
    """Multiply two columns element-wise.

    Args:
        a: First column (N * dim elements)
        b: Second column (N * dim elements)
        N: Number of rows
        dim: Dimension per element (1 or 3)

    Returns:
        Product column (N * dim elements)
    """
    result = np.zeros(N * dim, dtype=np.uint64)

    # Note: Must convert numpy uint64 to Python int before creating FF
    if dim == 1:
        for i in range(N):
            result[i] = int(FF(int(a[i])) * FF(int(b[i])))
    else:
        for i in range(N):
            result[i * dim:(i + 1) * dim] = _goldilocks3_mul(
                a[i * dim:(i + 1) * dim],
                b[i * dim:(i + 1) * dim]
            )

    return result


# C++: Batch inverse computation (using Montgomery's trick)
def _field_inverse_column(a: np.ndarray, N: int, dim: int) -> np.ndarray:
    """Compute multiplicative inverse of each element in a column.

    Uses Montgomery batch inversion: N inversions → 3N-3 multiplications + 1 inversion.

    Args:
        a: Column (N * dim elements, AoS layout for dim=3)
        N: Number of rows
        dim: Dimension per element (1 or 3)

    Returns:
        Inverse column (N * dim elements)
    """
    result = np.zeros(N * dim, dtype=np.uint64)

    if dim == 1:
        # Convert to FF array for batch inversion
        ff_vals = FF(np.asarray(a[:N], dtype=np.uint64))
        ff_invs = batch_inverse_ff_array(ff_vals)
        result[:N] = np.asarray(ff_invs, dtype=np.uint64)
    else:
        # Convert from AoS layout to FF3 array for batch inversion
        # Input is [a0_c0, a0_c1, a0_c2, a1_c0, a1_c1, a1_c2, ...]
        # FF3 integer encoding: value = c0 + c1*p + c2*p^2
        from primitives.field import GOLDILOCKS_PRIME
        p = GOLDILOCKS_PRIME
        p2 = p * p
        # Extract coefficients via numpy slicing
        c0 = a[0::3][:N].tolist()  # [a0_c0, a1_c0, ...]
        c1 = a[1::3][:N].tolist()  # [a0_c1, a1_c1, ...]
        c2 = a[2::3][:N].tolist()  # [a0_c2, a1_c2, ...]
        ints = [c0[i] + c1[i] * p + c2[i] * p2 for i in range(N)]
        ff3_vals = FF3(ints)
        ff3_invs = batch_inverse_ff3_array(ff3_vals)
        # Convert back to AoS layout
        vecs = ff3_invs.vector()  # Shape (N, 3) in descending order [c2, c1, c0]
        result[0::3] = vecs[:, 2].view(np.ndarray).astype(np.uint64)  # c0
        result[1::3] = vecs[:, 1].view(np.ndarray).astype(np.uint64)  # c1
        result[2::3] = vecs[:, 0].view(np.ndarray).astype(np.uint64)  # c2

    return result


# =============================================================================
# Expression Evaluation for Hint Fields
# =============================================================================

# C++: pil2-stark/src/starkpil/hints.cpp hint evaluation
def evaluate_hint_field_with_expressions(
    stark_info: StarkInfo,
    expressions_bin: ExpressionsBin,
    params: StepsParams,
    expressions_ctx: 'ExpressionsPack',
    hint_id: int,
    field1_name: str,
    field2_name: str,
    field2_inverse: bool = True
) -> np.ndarray:
    """Evaluate hint field values using the expression evaluator.

    This is the main entry point for evaluating hint fields that contain
    expression (tmp) operands. It constructs a Dest structure with the
    two operands and uses calculateExpressions to compute the result.

    C++ reference: hints.cpp addHintField() + calculateExpressions()

    Args:
        stark_info: Stark configuration
        expressions_bin: Parsed expressions binary
        params: Working buffers
        expressions_ctx: Expression evaluator context
        hint_id: Hint index
        field1_name: Name of first field (numerator)
        field2_name: Name of second field (denominator)
        field2_inverse: If True, invert field2 before multiplication

    Returns:
        Result column (N * dim elements)
    """
    from protocol.expression_evaluator import Dest, Params

    N = 1 << stark_info.starkStruct.nBits

    # Get hint fields
    hint_field1 = expressions_bin.get_hint_field(hint_id, field1_name)
    hint_field2 = expressions_bin.get_hint_field(hint_id, field2_name)

    # Build Params for each field
    param1 = _build_param_from_hint_field(stark_info, hint_field1.values[0])
    param2 = _build_param_from_hint_field(stark_info, hint_field2.values[0])
    param2.inverse = field2_inverse

    # Determine output dimension
    dim = max(param1.dim, param2.dim)

    # Create destination buffer
    dest_buffer = np.zeros(N * dim, dtype=np.uint64)

    # Create Dest structure
    dest = Dest(
        dest=dest_buffer,
        dim=dim,
        domain_size=N,
        params=[param1, param2]
    )

    # Evaluate expressions
    expressions_ctx.calculate_expressions(
        params=params,
        dest=dest,
        domain_size=N,
        domain_extended=False,
        compilation_time=False
    )

    return dest_buffer


# C++: hints.cpp parameter building
def _build_param_from_hint_field(
    stark_info: StarkInfo,
    hfv: HintFieldValue
) -> 'Params':
    """Build a Params object from a HintFieldValue.

    Translates hint field value specification into expression parameter.

    Args:
        stark_info: Stark configuration
        hfv: Hint field value to convert

    Returns:
        Params object for expression evaluation
    """
    from protocol.expression_evaluator import Params

    if hfv.operand == OpType.tmp:
        # Expression reference
        exp_info = None
        # Get dimension from expression info if available
        dim = hfv.dim if hfv.dim > 0 else 3  # Default to extension field
        return Params(
            op="tmp",
            exp_id=hfv.id,
            dim=dim,
            row_offset_index=hfv.row_offset_index
        )

    elif hfv.operand == OpType.cm:
        # Committed polynomial
        pol_info = stark_info.cmPolsMap[hfv.id]
        return Params(
            op="cm",
            dim=pol_info.dim,
            stage=pol_info.stage,
            stage_pos=pol_info.stagePos,
            pols_map_id=hfv.id,
            row_offset_index=hfv.row_offset_index
        )

    elif hfv.operand == OpType.const_:
        # Constant polynomial
        pol_info = stark_info.constPolsMap[hfv.id]
        return Params(
            op="const",
            dim=pol_info.dim,
            stage_pos=pol_info.stagePos,
            row_offset_index=hfv.row_offset_index
        )

    elif hfv.operand == OpType.number:
        # Literal number
        return Params(
            op="number",
            dim=1,
            value=hfv.value
        )

    elif hfv.operand == OpType.challenge:
        # Challenge (handled via expression evaluation)
        return Params(
            op="challenge",
            dim=3,
            pols_map_id=hfv.id
        )

    elif hfv.operand == OpType.airgroupvalue:
        return Params(
            op="airgroupvalue",
            dim=3,
            pols_map_id=hfv.id
        )

    elif hfv.operand == OpType.airvalue:
        return Params(
            op="airvalue",
            dim=3,
            pols_map_id=hfv.id
        )

    else:
        raise NotImplementedError(f"Cannot build Params for operand type {hfv.operand}")


# =============================================================================
# Hint Field Value Fetching
# =============================================================================

# C++: hints.cpp polynomial access
def _get_polynomial_column(
    stark_info: StarkInfo,
    params: StepsParams,
    pol_info,
    row_offset_index: int
) -> np.ndarray:
    """Extract a polynomial column from trace buffer.

    C++ reference: hints.cpp getPolynomial() lines 6-18

    Args:
        stark_info: Stark configuration
        params: Working buffers
        pol_info: Polynomial map entry
        row_offset_index: Index into openingPoints for row offset

    Returns:
        Column values (N * dim elements)
    """
    N = 1 << stark_info.starkStruct.nBits
    stage = pol_info.stage
    dim = pol_info.dim

    section = f"cm{stage}"
    n_cols = stark_info.mapSectionsN.get(section, 0)

    if stage == 1:
        buffer = params.trace
        base_offset = 0
    else:
        offset_key = (section, False)
        base_offset = stark_info.mapOffsets.get(offset_key, 0)
        buffer = params.auxTrace

    row_offset = 0
    if row_offset_index < len(stark_info.openingPoints):
        row_offset = stark_info.openingPoints[row_offset_index]

    result = np.zeros(N * dim, dtype=np.uint64)
    for j in range(N):
        l = (j + row_offset) % N
        src_idx = base_offset + l * n_cols + pol_info.stagePos
        result[j * dim:(j + 1) * dim] = buffer[src_idx:src_idx + dim]

    return result


# C++: hints.cpp constant polynomial access
def _get_const_polynomial(
    stark_info: StarkInfo,
    params: StepsParams,
    pol_info,
    N: int
) -> np.ndarray:
    """Extract a constant polynomial column.

    Args:
        stark_info: Stark configuration
        params: Working buffers
        pol_info: Polynomial map entry
        N: Domain size

    Returns:
        Column values (N * dim elements)
    """
    dim = pol_info.dim
    n_cols = stark_info.nConstants

    result = np.zeros(N * dim, dtype=np.uint64)
    for j in range(N):
        src_idx = j * n_cols + pol_info.stagePos
        result[j * dim:(j + 1) * dim] = params.constPols[src_idx:src_idx + dim]

    return result


# C++: hints.cpp operand fetching
def _fetch_operand_value(
    stark_info: StarkInfo,
    params: StepsParams,
    hfv: HintFieldValue,
    N: int
) -> np.ndarray:
    """Fetch value for a single hint field operand.

    C++ reference: hints.cpp addHintField() and getHintFieldSizes()

    Args:
        stark_info: Stark configuration
        params: Working buffers
        hfv: Hint field value describing what to fetch
        N: Domain size

    Returns:
        Fetched values (column or scalar)
    """
    if hfv.operand == OpType.cm:
        # Committed polynomial column
        pol_info = stark_info.cmPolsMap[hfv.id]
        return _get_polynomial_column(stark_info, params, pol_info, hfv.row_offset_index)

    elif hfv.operand == OpType.const_:
        # Constant polynomial column
        pol_info = stark_info.constPolsMap[hfv.id]
        return _get_const_polynomial(stark_info, params, pol_info, N)

    elif hfv.operand == OpType.challenge:
        # Challenge value (single Goldilocks3 element)
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
        idx = hfv.id * FIELD_EXTENSION
        return params.airValues[idx:idx + FIELD_EXTENSION].copy()

    elif hfv.operand == OpType.tmp:
        # Temporary expression - needs to be evaluated
        # This is handled separately with expression evaluation
        raise ValueError("OpType.tmp must be evaluated with expressions context - use evaluate_expression_column()")

    elif hfv.operand == OpType.custom:
        # Custom commitment polynomial
        # For now, skip custom commits (not needed for basic tests)
        raise NotImplementedError(f"Custom commit operand not yet implemented")

    else:
        raise NotImplementedError(f"Operand type {hfv.operand} not implemented")


# C++: pil2-stark/src/starkpil/hints.cpp::getHintFieldValues
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
    If the hint field has multiple values, they are multiplied together.

    C++ reference: hints.cpp addHintField() lines 252-476

    Args:
        stark_info: Stark configuration
        expressions_bin: Parsed expressions binary
        params: Working buffers
        hint_id: Index of hint in expressions_bin.hints
        field_name: Name of field to fetch
        inverse: If True, compute multiplicative inverse of result

    Returns:
        np.ndarray of field values
    """
    N = 1 << stark_info.starkStruct.nBits
    hint_field = expressions_bin.get_hint_field(hint_id, field_name)

    # Aggregate values from all hint field values
    result = None
    result_dim = 1

    for hfv in hint_field.values:
        val = _fetch_operand_value(stark_info, params, hfv, N)

        # Track dimension
        if len(val) == 3:
            result_dim = 3
        elif len(val) > 3 and len(val) % 3 == 0:
            result_dim = 3

        if result is None:
            result = val
        else:
            # Multiply values together
            if len(result) == len(val):
                if len(result) <= 3:
                    result = _field_mul_scalar(result, val)
                else:
                    # Column multiplication
                    dim = 3 if len(result) % 3 == 0 and len(result) > 3 else 1
                    result = _field_mul_columns(result, val, len(result) // dim, dim)
            else:
                # Broadcasting: scalar * column
                if len(result) <= 3 and len(val) > 3:
                    # result is scalar, val is column
                    dim = 3 if len(val) % 3 == 0 else 1
                    col_N = len(val) // dim
                    new_result = np.zeros_like(val)
                    for i in range(col_N):
                        new_result[i * dim:(i + 1) * dim] = _field_mul_scalar(
                            result if len(result) == dim else np.array([result[0]] * dim, dtype=np.uint64)[:dim],
                            val[i * dim:(i + 1) * dim]
                        )
                    result = new_result
                elif len(val) <= 3 and len(result) > 3:
                    # val is scalar, result is column
                    dim = 3 if len(result) % 3 == 0 else 1
                    col_N = len(result) // dim
                    for i in range(col_N):
                        result[i * dim:(i + 1) * dim] = _field_mul_scalar(
                            result[i * dim:(i + 1) * dim],
                            val if len(val) == dim else np.array([val[0]] * dim, dtype=np.uint64)[:dim]
                        )

    if inverse and result is not None:
        if len(result) <= 3:
            result = _field_inverse_scalar(result)
        else:
            dim = 3 if len(result) % 3 == 0 else 1
            result = _field_inverse_column(result, len(result) // dim, dim)

    return result


# =============================================================================
# Hint Field Storage
# =============================================================================

# C++: hints.cpp polynomial writing
def _set_polynomial_column(
    stark_info: StarkInfo,
    params: StepsParams,
    pol_info,
    values: np.ndarray
) -> None:
    """Store values into a polynomial column in trace buffer.

    C++ reference: hints.cpp setPolynomial() lines 20-33

    Args:
        stark_info: Stark configuration
        params: Working buffers
        pol_info: Polynomial map entry
        values: Column values to store (N * dim elements)
    """
    N = 1 << stark_info.starkStruct.nBits
    stage = pol_info.stage
    dim = pol_info.dim

    section = f"cm{stage}"
    n_cols = stark_info.mapSectionsN.get(section, 0)

    if stage == 1:
        buffer = params.trace
        base_offset = 0
    else:
        offset_key = (section, False)
        base_offset = stark_info.mapOffsets.get(offset_key, 0)
        buffer = params.auxTrace

    for j in range(N):
        dst_idx = base_offset + j * n_cols + pol_info.stagePos
        buffer[dst_idx:dst_idx + dim] = values[j * dim:(j + 1) * dim]


# C++: hints.cpp::setHintField
def _set_hint_field(
    stark_info: StarkInfo,
    expressions_bin: ExpressionsBin,
    params: StepsParams,
    hint_id: int,
    field_name: str,
    values: np.ndarray
) -> None:
    """Store values into the polynomial referenced by a hint field.

    C++ reference: hints.cpp setHintField() lines 467-477

    Args:
        stark_info: Stark configuration
        expressions_bin: Parsed expressions binary
        params: Working buffers
        hint_id: Hint index
        field_name: Name of field to store into
        values: Values to store
    """
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


# =============================================================================
# Core Witness STD Functions
# =============================================================================

# C++: pil2-stark/src/starkpil/hints.cpp::multiplyHintFields
def multiply_hint_fields(
    stark_info: StarkInfo,
    expressions_bin: ExpressionsBin,
    params: StepsParams,
    expressions_ctx: 'ExpressionsPack',
    hint_ids: List[int],
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

    Args:
        stark_info: Stark configuration
        expressions_bin: Parsed expressions binary
        params: Working buffers
        expressions_ctx: Expression evaluator for tmp operands
        hint_ids: List of hint indices to process
        dest_field: Name of destination field
        field1: Name of first operand field
        field2: Name of second operand field
        field2_inverse: If True, invert field2 before multiplication
    """
    N = 1 << stark_info.starkStruct.nBits

    for hint_id in hint_ids:
        # Use expression evaluator to compute field1 * field2^(-1)
        result = evaluate_hint_field_with_expressions(
            stark_info, expressions_bin, params, expressions_ctx,
            hint_id, field1, field2, field2_inverse
        )

        # Store in destination
        _set_hint_field(stark_info, expressions_bin, params, hint_id, dest_field, result)


# C++: hints.cpp::accMulHintFields
def acc_mul_hint_fields(
    stark_info: StarkInfo,
    expressions_bin: ExpressionsBin,
    params: StepsParams,
    expressions_ctx: 'ExpressionsPack',
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

    Args:
        stark_info: Stark configuration
        expressions_bin: Parsed expressions binary
        params: Working buffers
        expressions_ctx: Expression evaluator for tmp operands
        hint_id: Hint index
        dest_field: Destination field name for accumulated values
        airgroup_val_field: Field name for final airgroup value (or empty)
        field1: Numerator field name
        field2: Denominator field name (inverted)
        add: If True, use running sum; if False, use running product
    """
    N = 1 << stark_info.starkStruct.nBits

    # Get destination polynomial info for dimension
    hint_field = expressions_bin.get_hint_field(hint_id, dest_field)
    dest_pol_id = hint_field.values[0].id
    dim = stark_info.cmPolsMap[dest_pol_id].dim

    # Use expression evaluator to compute field1 * field2^(-1) for all rows
    vals = evaluate_hint_field_with_expressions(
        stark_info, expressions_bin, params, expressions_ctx,
        hint_id, field1, field2, field2_inverse=True
    )

    # Running accumulation
    # Note: Must convert numpy uint64 to Python int before creating FF
    if dim == 1:
        for i in range(1, N):
            if add:
                vals[i] = int(FF(int(vals[i])) + FF(int(vals[i - 1])))
            else:
                vals[i] = int(FF(int(vals[i])) * FF(int(vals[i - 1])))
    else:
        # Field extension (dim=3)
        for i in range(1, N):
            if add:
                vals[i * dim:(i + 1) * dim] = _goldilocks3_add(
                    vals[i * dim:(i + 1) * dim],
                    vals[(i - 1) * dim:i * dim]
                )
            else:
                vals[i * dim:(i + 1) * dim] = _goldilocks3_mul(
                    vals[i * dim:(i + 1) * dim],
                    vals[(i - 1) * dim:i * dim]
                )

    # Store in destination polynomial
    _set_hint_field(stark_info, expressions_bin, params, hint_id, dest_field, vals)

    # Store final value in airgroup value (if specified)
    if airgroup_val_field:
        final_val = vals[(N - 1) * dim:N * dim]
        _set_hint_field(stark_info, expressions_bin, params, hint_id, airgroup_val_field, final_val)


# C++: hints.cpp::updateAirgroupValue
def update_airgroup_value(
    stark_info: StarkInfo,
    expressions_bin: ExpressionsBin,
    params: StepsParams,
    expressions_ctx: 'ExpressionsPack',
    hint_id: int,
    airgroup_val_field: str,
    field1: str,
    field2: str,
    add: bool
) -> None:
    """Update airgroup value with direct components.

    Computes: airgroupValue += (or *=) field1 * field2^(-1)

    C++ reference: hints.cpp updateAirgroupValue() lines 627-664

    Args:
        stark_info: Stark configuration
        expressions_bin: Parsed expressions binary
        params: Working buffers
        expressions_ctx: Expression evaluator (may be needed for tmp operands)
        hint_id: Hint index
        airgroup_val_field: Field name for airgroup value (or empty to skip)
        field1: Numerator field name
        field2: Denominator field name (inverted)
        add: If True, add to current value; if False, multiply
    """
    if not airgroup_val_field:
        return

    # Check operand types - direct components are usually number operands
    hint_field1 = expressions_bin.get_hint_field(hint_id, field1)
    hint_field2 = expressions_bin.get_hint_field(hint_id, field2)
    hfv1 = hint_field1.values[0]
    hfv2 = hint_field2.values[0]

    # For number operands, handle directly
    if hfv1.operand == OpType.number and hfv2.operand == OpType.number:
        val1 = hfv1.value
        val2 = hfv2.value
        # If denominator is 0, skip (C++ handles this by not updating)
        if val2 == 0:
            return
        # Compute val1 / val2 (in field)
        if val1 == 0:
            result = np.array([0, 0, 0], dtype=np.uint64)
        else:
            inv_val2 = _goldilocks_inv(val2)
            result_scalar = int(FF(val1) * FF(inv_val2))
            result = np.array([result_scalar, 0, 0], dtype=np.uint64)
    else:
        # Use expression evaluator for complex operands
        # Evaluate at row 0 only (direct components are scalars)
        from protocol.expression_evaluator import Dest, Params
        param1 = _build_param_from_hint_field(stark_info, hfv1)
        param2 = _build_param_from_hint_field(stark_info, hfv2)
        param2.inverse = True

        dest_buffer = np.zeros(FIELD_EXTENSION, dtype=np.uint64)
        dest = Dest(
            dest=dest_buffer,
            dim=FIELD_EXTENSION,
            domain_size=1,
            params=[param1, param2]
        )
        expressions_ctx.calculate_expressions(
            params=params,
            dest=dest,
            domain_size=1,
            domain_extended=False,
            compilation_time=False
        )
        result = dest_buffer

    # Get airgroup value location
    airgroup_hf = expressions_bin.get_hint_field(hint_id, airgroup_val_field)
    airgroup_id = airgroup_hf.values[0].id
    idx = airgroup_id * FIELD_EXTENSION

    # Update: add or multiply
    current = params.airgroupValues[idx:idx + FIELD_EXTENSION].copy()
    if add:
        params.airgroupValues[idx:idx + FIELD_EXTENSION] = _goldilocks3_add(current, result)
    else:
        params.airgroupValues[idx:idx + FIELD_EXTENSION] = _goldilocks3_mul(current, result)


# =============================================================================
# Main Entry Point
# =============================================================================

# C++: pil2-stark/src/starkpil/gen_proof.hpp::calculateWitnessSTD (lines 4-45)
def calculate_witness_std(
    stark_info: StarkInfo,
    expressions_bin: ExpressionsBin,
    params: StepsParams,
    expressions_ctx: 'ExpressionsPack',
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
        expressions_ctx: Expression evaluator for tmp operands in hints
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
            stark_info, expressions_bin, params, expressions_ctx,
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
        stark_info, expressions_bin, params, expressions_ctx,
        hint_id,
        dest_field="reference",
        airgroup_val_field=airgroup_val_field,
        field1="numerator_air",
        field2="denominator_air",
        add=not prod  # gsum uses addition, gprod uses multiplication
    )

    # Update with direct components
    update_airgroup_value(
        stark_info, expressions_bin, params, expressions_ctx,
        hint_id,
        airgroup_val_field=airgroup_val_field,
        field1="numerator_direct",
        field2="denominator_direct",
        add=not prod
    )

