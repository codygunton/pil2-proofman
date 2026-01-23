"""Witness STD computation for lookup and permutation arguments."""

import numpy as np
from typing import List, TYPE_CHECKING

from protocol.expressions_bin import ExpressionsBin, HintFieldValue, OpType
from protocol.stark_info import StarkInfo
from protocol.steps_params import StepsParams
from primitives.field import FF, FF3, ff3, ff3_coeffs, batch_inverse

if TYPE_CHECKING:
    from protocol.expression_evaluator import ExpressionsPack

# --- Constants ---

FIELD_EXTENSION = 3


# --- Conversion Helpers ---
# These convert between numpy coefficient storage and galois types.
# Storage uses interleaved coefficients [a0, a1, a2, b0, b1, b2, ...] as uint64.

def _np_to_ff3(arr: np.ndarray) -> FF3:
    """Convert numpy coefficient array (len 3) to FF3 scalar."""
    return ff3([int(arr[0]), int(arr[1]), int(arr[2])])


def _ff3_to_np(elem: FF3) -> np.ndarray:
    """Convert FF3 scalar to numpy coefficient array."""
    return np.array(ff3_coeffs(elem), dtype=np.uint64)


def _np_column_to_ff3_array(arr: np.ndarray, N: int) -> FF3:
    """Convert interleaved numpy column [a0,a1,a2,b0,b1,b2,...] to FF3 array."""
    from primitives.field import GOLDILOCKS_PRIME
    p, p2 = GOLDILOCKS_PRIME, GOLDILOCKS_PRIME ** 2
    c0, c1, c2 = arr[0::3][:N].tolist(), arr[1::3][:N].tolist(), arr[2::3][:N].tolist()
    ints = [c0[i] + c1[i] * p + c2[i] * p2 for i in range(N)]
    return FF3(ints)


def _ff3_array_to_np(arr: FF3, N: int) -> np.ndarray:
    """Convert FF3 array to interleaved numpy column."""
    result = np.zeros(N * 3, dtype=np.uint64)
    vecs = arr.vector()  # (N, 3) in descending [c2, c1, c0]
    result[0::3] = vecs[:, 2].view(np.ndarray).astype(np.uint64)
    result[1::3] = vecs[:, 1].view(np.ndarray).astype(np.uint64)
    result[2::3] = vecs[:, 0].view(np.ndarray).astype(np.uint64)
    return result


# --- Polynomial Buffer Access ---

def _get_poly_column(stark_info: StarkInfo, params: StepsParams, pol_info, row_offset_index: int) -> np.ndarray:
    """Read a committed polynomial column from trace buffer."""
    N = 1 << stark_info.starkStruct.nBits
    stage, dim = pol_info.stage, pol_info.dim
    section = f"cm{stage}"
    n_cols = stark_info.mapSectionsN.get(section, 0)

    if stage == 1:
        buffer, base_offset = params.trace, 0
    else:
        base_offset = stark_info.mapOffsets.get((section, False), 0)
        buffer = params.auxTrace

    row_offset = stark_info.openingPoints[row_offset_index] if row_offset_index < len(stark_info.openingPoints) else 0

    result = np.zeros(N * dim, dtype=np.uint64)
    for j in range(N):
        src_idx = base_offset + ((j + row_offset) % N) * n_cols + pol_info.stagePos
        result[j * dim:(j + 1) * dim] = buffer[src_idx:src_idx + dim]
    return result


def _get_const_poly(stark_info: StarkInfo, params: StepsParams, pol_info, N: int) -> np.ndarray:
    """Read a constant polynomial column."""
    dim, n_cols = pol_info.dim, stark_info.nConstants
    result = np.zeros(N * dim, dtype=np.uint64)
    for j in range(N):
        src_idx = j * n_cols + pol_info.stagePos
        result[j * dim:(j + 1) * dim] = params.constPols[src_idx:src_idx + dim]
    return result


def _set_poly_column(stark_info: StarkInfo, params: StepsParams, pol_info, values: np.ndarray) -> None:
    """Write values to a committed polynomial column."""
    N = 1 << stark_info.starkStruct.nBits
    stage, dim = pol_info.stage, pol_info.dim
    section = f"cm{stage}"
    n_cols = stark_info.mapSectionsN.get(section, 0)

    if stage == 1:
        buffer, base_offset = params.trace, 0
    else:
        base_offset = stark_info.mapOffsets.get((section, False), 0)
        buffer = params.auxTrace

    for j in range(N):
        dst_idx = base_offset + j * n_cols + pol_info.stagePos
        buffer[dst_idx:dst_idx + dim] = values[j * dim:(j + 1) * dim]


# --- Hint Field Access ---

def _fetch_operand(stark_info: StarkInfo, params: StepsParams, hfv: HintFieldValue, N: int) -> np.ndarray:
    """Fetch value for a hint field operand."""
    if hfv.operand == OpType.cm:
        return _get_poly_column(stark_info, params, stark_info.cmPolsMap[hfv.id], hfv.row_offset_index)
    elif hfv.operand == OpType.const_:
        return _get_const_poly(stark_info, params, stark_info.constPolsMap[hfv.id], N)
    elif hfv.operand == OpType.challenge:
        idx = hfv.id * FIELD_EXTENSION
        return params.challenges[idx:idx + FIELD_EXTENSION].copy()
    elif hfv.operand == OpType.number:
        return np.array([hfv.value], dtype=np.uint64)
    elif hfv.operand == OpType.airgroupvalue:
        idx = hfv.id * FIELD_EXTENSION
        return params.airgroupValues[idx:idx + FIELD_EXTENSION].copy()
    elif hfv.operand == OpType.airvalue:
        idx = hfv.id * FIELD_EXTENSION
        return params.airValues[idx:idx + FIELD_EXTENSION].copy()
    elif hfv.operand == OpType.tmp:
        raise ValueError("OpType.tmp requires expression evaluation")
    elif hfv.operand == OpType.custom:
        raise NotImplementedError("Custom commit operand not implemented")
    else:
        raise NotImplementedError(f"Operand type {hfv.operand} not implemented")


def _set_hint_field(
    stark_info: StarkInfo, expressions_bin: ExpressionsBin, params: StepsParams,
    hint_id: int, field_name: str, values: np.ndarray
) -> None:
    """Store values into polynomial/airgroup referenced by hint field."""
    hfv = expressions_bin.get_hint_field(hint_id, field_name).values[0]

    if hfv.operand == OpType.cm:
        _set_poly_column(stark_info, params, stark_info.cmPolsMap[hfv.id], values)
    elif hfv.operand == OpType.airgroupvalue:
        idx = hfv.id * FIELD_EXTENSION
        params.airgroupValues[idx:idx + len(values)] = values
    else:
        raise NotImplementedError(f"Cannot set hint field with operand type {hfv.operand}")


def _multiply_values(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """Multiply two field values using galois. Handles scalar and column cases."""
    len_a, len_b = len(a), len(b)

    # Scalar * scalar
    if len_a <= 3 and len_b <= 3:
        if len_a == 1 and len_b == 1:
            return np.array([int(FF(int(a[0])) * FF(int(b[0])))], dtype=np.uint64)
        elif len_a == 3 and len_b == 3:
            result = _np_to_ff3(a) * _np_to_ff3(b)
            return _ff3_to_np(result)
        elif len_a == 1 and len_b == 3:
            scalar = FF(int(a[0]))
            return np.array([int(scalar * FF(int(b[i]))) for i in range(3)], dtype=np.uint64)
        else:  # len_a == 3 and len_b == 1
            scalar = FF(int(b[0]))
            return np.array([int(scalar * FF(int(a[i]))) for i in range(3)], dtype=np.uint64)

    # Column * column (same size)
    if len_a == len_b:
        dim = 3 if len_a % 3 == 0 and len_a > 3 else 1
        N = len_a // dim
        if dim == 1:
            ff_a = FF(np.asarray(a, dtype=np.uint64))
            ff_b = FF(np.asarray(b, dtype=np.uint64))
            return np.asarray(ff_a * ff_b, dtype=np.uint64)
        else:
            ff3_a = _np_column_to_ff3_array(a, N)
            ff3_b = _np_column_to_ff3_array(b, N)
            return _ff3_array_to_np(ff3_a * ff3_b, N)

    # Scalar * column broadcast
    if len_a <= 3 and len_b > 3:
        dim = 3 if len_b % 3 == 0 else 1
        N = len_b // dim
        if dim == 1:
            scalar = FF(int(a[0]))
            ff_b = FF(np.asarray(b, dtype=np.uint64))
            return np.asarray(scalar * ff_b, dtype=np.uint64)
        else:
            scalar = _np_to_ff3(a) if len_a == 3 else ff3([int(a[0]), 0, 0])
            ff3_b = _np_column_to_ff3_array(b, N)
            return _ff3_array_to_np(scalar * ff3_b, N)

    # Column * scalar broadcast
    if len_b <= 3 and len_a > 3:
        dim = 3 if len_a % 3 == 0 else 1
        N = len_a // dim
        if dim == 1:
            scalar = FF(int(b[0]))
            ff_a = FF(np.asarray(a, dtype=np.uint64))
            return np.asarray(ff_a * scalar, dtype=np.uint64)
        else:
            scalar = _np_to_ff3(b) if len_b == 3 else ff3([int(b[0]), 0, 0])
            ff3_a = _np_column_to_ff3_array(a, N)
            return _ff3_array_to_np(ff3_a * scalar, N)

    raise ValueError(f"Cannot multiply arrays of size {len_a} and {len_b}")


def _invert_values(a: np.ndarray) -> np.ndarray:
    """Invert field values using galois. Handles scalar and column cases."""
    if len(a) == 1:
        return np.array([int(FF(int(a[0])) ** -1)], dtype=np.uint64)
    elif len(a) == 3:
        result = _np_to_ff3(a) ** -1
        return _ff3_to_np(result)
    else:
        dim = 3 if len(a) % 3 == 0 else 1
        N = len(a) // dim
        if dim == 1:
            ff_vals = FF(np.asarray(a, dtype=np.uint64))
            ff_invs = batch_inverse(ff_vals)
            return np.asarray(ff_invs, dtype=np.uint64)
        else:
            ff3_vals = _np_column_to_ff3_array(a, N)
            ff3_invs = batch_inverse(ff3_vals)
            return _ff3_array_to_np(ff3_invs, N)


def get_hint_field_values(
    stark_info: StarkInfo, expressions_bin: ExpressionsBin, params: StepsParams,
    hint_id: int, field_name: str, inverse: bool = False
) -> np.ndarray:
    """Fetch hint field values, multiplying multiple operands if present."""
    N = 1 << stark_info.starkStruct.nBits
    hint_field = expressions_bin.get_hint_field(hint_id, field_name)

    result = None

    for hfv in hint_field.values:
        val = _fetch_operand(stark_info, params, hfv, N)

        if result is None:
            result = val
        else:
            result = _multiply_values(result, val)

    if inverse and result is not None:
        result = _invert_values(result)

    return result


# --- Expression Evaluation Helpers ---

def _build_param_from_hint_field(stark_info: StarkInfo, hfv: HintFieldValue):
    """Convert HintFieldValue to expression Params."""
    from protocol.expression_evaluator import Params

    if hfv.operand == OpType.tmp:
        return Params(op="tmp", exp_id=hfv.id, dim=hfv.dim if hfv.dim > 0 else 3,
                      row_offset_index=hfv.row_offset_index)
    elif hfv.operand == OpType.cm:
        pol = stark_info.cmPolsMap[hfv.id]
        return Params(op="cm", dim=pol.dim, stage=pol.stage, stage_pos=pol.stagePos,
                      pols_map_id=hfv.id, row_offset_index=hfv.row_offset_index)
    elif hfv.operand == OpType.const_:
        pol = stark_info.constPolsMap[hfv.id]
        return Params(op="const", dim=pol.dim, stage_pos=pol.stagePos,
                      row_offset_index=hfv.row_offset_index)
    elif hfv.operand == OpType.number:
        return Params(op="number", dim=1, value=hfv.value)
    elif hfv.operand == OpType.challenge:
        return Params(op="challenge", dim=3, pols_map_id=hfv.id)
    elif hfv.operand == OpType.airgroupvalue:
        return Params(op="airgroupvalue", dim=3, pols_map_id=hfv.id)
    elif hfv.operand == OpType.airvalue:
        return Params(op="airvalue", dim=3, pols_map_id=hfv.id)
    else:
        raise NotImplementedError(f"Cannot build Params for operand type {hfv.operand}")


def evaluate_hint_field_with_expressions(
    stark_info: StarkInfo, expressions_bin: ExpressionsBin, params: StepsParams,
    expressions_ctx: 'ExpressionsPack', hint_id: int, field1_name: str, field2_name: str,
    field2_inverse: bool = True
) -> np.ndarray:
    """Evaluate field1 * field2^(-1) using expression evaluator."""
    from protocol.expression_evaluator import Dest

    N = 1 << stark_info.starkStruct.nBits
    hf1 = expressions_bin.get_hint_field(hint_id, field1_name)
    hf2 = expressions_bin.get_hint_field(hint_id, field2_name)

    param1 = _build_param_from_hint_field(stark_info, hf1.values[0])
    param2 = _build_param_from_hint_field(stark_info, hf2.values[0])
    param2.inverse = field2_inverse

    dim = max(param1.dim, param2.dim)
    dest_buffer = np.zeros(N * dim, dtype=np.uint64)
    dest = Dest(dest=dest_buffer, dim=dim, domain_size=N, params=[param1, param2])

    expressions_ctx.calculate_expressions(
        params=params, dest=dest, domain_size=N, domain_extended=False, compilation_time=False
    )
    return dest_buffer


# --- Core Witness STD Functions ---

def multiply_hint_fields(
    stark_info: StarkInfo, expressions_bin: ExpressionsBin, params: StepsParams,
    expressions_ctx: 'ExpressionsPack', hint_ids: List[int], dest_field: str,
    field1: str, field2: str, field2_inverse: bool = True
) -> None:
    """Compute dest = field1 * field2^(-1) for each hint."""
    for hint_id in hint_ids:
        result = evaluate_hint_field_with_expressions(
            stark_info, expressions_bin, params, expressions_ctx,
            hint_id, field1, field2, field2_inverse
        )
        _set_hint_field(stark_info, expressions_bin, params, hint_id, dest_field, result)


def acc_mul_hint_fields(
    stark_info: StarkInfo, expressions_bin: ExpressionsBin, params: StepsParams,
    expressions_ctx: 'ExpressionsPack', hint_id: int, dest_field: str,
    airgroup_val_field: str, field1: str, field2: str, add: bool
) -> None:
    """Compute running sum (add=True) or product (add=False) of field1 * field2^(-1)."""
    N = 1 << stark_info.starkStruct.nBits
    dest_pol_id = expressions_bin.get_hint_field(hint_id, dest_field).values[0].id
    dim = stark_info.cmPolsMap[dest_pol_id].dim

    vals = evaluate_hint_field_with_expressions(
        stark_info, expressions_bin, params, expressions_ctx,
        hint_id, field1, field2, field2_inverse=True
    )

    # Running accumulation using galois operations
    if dim == 1:
        ff_vals = FF(np.asarray(vals[:N], dtype=np.uint64))
        for i in range(1, N):
            if add:
                ff_vals[i] = ff_vals[i] + ff_vals[i - 1]
            else:
                ff_vals[i] = ff_vals[i] * ff_vals[i - 1]
        vals[:N] = np.asarray(ff_vals, dtype=np.uint64)
    else:
        ff3_vals = _np_column_to_ff3_array(vals, N)
        for i in range(1, N):
            if add:
                ff3_vals[i] = ff3_vals[i] + ff3_vals[i - 1]
            else:
                ff3_vals[i] = ff3_vals[i] * ff3_vals[i - 1]
        vals = _ff3_array_to_np(ff3_vals, N)

    _set_hint_field(stark_info, expressions_bin, params, hint_id, dest_field, vals)

    if airgroup_val_field:
        final_val = vals[(N - 1) * dim:N * dim]
        _set_hint_field(stark_info, expressions_bin, params, hint_id, airgroup_val_field, final_val)


def update_airgroup_value(
    stark_info: StarkInfo, expressions_bin: ExpressionsBin, params: StepsParams,
    expressions_ctx: 'ExpressionsPack', hint_id: int, airgroup_val_field: str,
    field1: str, field2: str, add: bool
) -> None:
    """Update airgroup value: airgroupValue op= field1 * field2^(-1)."""
    if not airgroup_val_field:
        return

    hfv1 = expressions_bin.get_hint_field(hint_id, field1).values[0]
    hfv2 = expressions_bin.get_hint_field(hint_id, field2).values[0]

    # Handle number operands directly using galois
    if hfv1.operand == OpType.number and hfv2.operand == OpType.number:
        if hfv2.value == 0:
            return
        if hfv1.value == 0:
            result = np.array([0, 0, 0], dtype=np.uint64)
        else:
            result_scalar = int(FF(hfv1.value) * (FF(hfv2.value) ** -1))
            result = np.array([result_scalar, 0, 0], dtype=np.uint64)
    else:
        # Use expression evaluator for complex operands
        from protocol.expression_evaluator import Dest

        param1 = _build_param_from_hint_field(stark_info, hfv1)
        param2 = _build_param_from_hint_field(stark_info, hfv2)
        param2.inverse = True

        dest_buffer = np.zeros(FIELD_EXTENSION, dtype=np.uint64)
        dest = Dest(dest=dest_buffer, dim=FIELD_EXTENSION, domain_size=1, params=[param1, param2])
        expressions_ctx.calculate_expressions(
            params=params, dest=dest, domain_size=1, domain_extended=False, compilation_time=False
        )
        result = dest_buffer

    # Update airgroup value using galois
    airgroup_id = expressions_bin.get_hint_field(hint_id, airgroup_val_field).values[0].id
    idx = airgroup_id * FIELD_EXTENSION
    current = _np_to_ff3(params.airgroupValues[idx:idx + FIELD_EXTENSION])
    result_ff3 = _np_to_ff3(result)

    if add:
        updated = current + result_ff3
    else:
        updated = current * result_ff3

    params.airgroupValues[idx:idx + FIELD_EXTENSION] = _ff3_to_np(updated)


# --- Main Entry Point ---

def calculate_witness_std(
    stark_info: StarkInfo, expressions_bin: ExpressionsBin, params: StepsParams,
    expressions_ctx: 'ExpressionsPack', prod: bool
) -> None:
    """Calculate gsum (prod=False) or gprod (prod=True) witness columns."""
    name = "gprod_col" if prod else "gsum_col"
    hint_ids = expressions_bin.get_hint_ids_by_name(name)
    if not hint_ids:
        return

    hint_id = hint_ids[0]

    # Process intermediate columns (im_col and im_airval hints)
    im_hints = expressions_bin.get_hint_ids_by_name("im_col") + expressions_bin.get_hint_ids_by_name("im_airval")
    if im_hints:
        multiply_hint_fields(
            stark_info, expressions_bin, params, expressions_ctx, im_hints,
            dest_field="reference", field1="numerator", field2="denominator", field2_inverse=True
        )

    airgroup_val_field = "result" if stark_info.airgroupValuesMap else ""

    # Main accumulation: gsum uses addition, gprod uses multiplication
    acc_mul_hint_fields(
        stark_info, expressions_bin, params, expressions_ctx, hint_id,
        dest_field="reference", airgroup_val_field=airgroup_val_field,
        field1="numerator_air", field2="denominator_air", add=not prod
    )

    # Update with direct components
    update_airgroup_value(
        stark_info, expressions_bin, params, expressions_ctx, hint_id,
        airgroup_val_field=airgroup_val_field,
        field1="numerator_direct", field2="denominator_direct", add=not prod
    )
