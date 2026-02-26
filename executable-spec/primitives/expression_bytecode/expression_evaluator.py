"""Expression bytecode evaluator for STARK constraint polynomials.

Recovered from git history (731d33f4~1) and adapted to current codebase.

Mathematical variables used throughout this module:
    N       -- domain size (number of trace rows, = 2^n_bits)
    N_ext   -- extended domain size (= 2^n_bits_ext), used for quotient evaluation
    xi      -- challenge evaluation point (random point from Fiat-Shamir transcript)
    zh/Z_H  -- vanishing polynomial Z_H(x) = x^N - 1
    zi      -- inverse vanishing polynomial 1/Z_H(x)
    o       -- row offset for shifted polynomial evaluation (from opening points)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import numpy as np

from primitives.expression_bytecode.expressions_bin import ExpressionsBin, ParserParams
from primitives.field import FIELD_EXTENSION_DEGREE
from primitives.goldilocks_jit import (
    ff3_batch_inverse,
    gl_add_vec,
    gl_inv_vec,
    gl_mul_vec,
    gl_sub_vec,
)

if TYPE_CHECKING:
    from protocol.air_config import ProverHelpers
    from protocol.stark_info import StarkInfo

# --- Type Aliases ---

# FastValue: a vectorized field element representing one batch of rows.
# Base field (FF):  np.ndarray of shape (batch_size,), dtype=uint64
#                   OR np.uint64 scalar (broadcast over the entire batch)
# Extension field (FF3): tuple (c0, c1, c2), each component as above
FastValue = np.ndarray | tuple  # FF column or (c0_col, c1_col, c2_col)

# --- Constants ---

NROWS_PACK = 1 << 16  # Rows per batch

# Buffer type indices beyond committed polynomial slots.
# Matches C++ expressions_bin.hpp layout: the scalar_params dict
# keys are buffer_commits_size + these offsets.
PUBLIC_INPUTS_OFFSET = 2
NUMBERS_OFFSET = 3
AIR_VALUES_OFFSET = 4
PROOF_VALUES_OFFSET = 5
AIRGROUP_VALUES_OFFSET = 6
CHALLENGES_OFFSET = 7
EVALS_OFFSET = 8


# --- Type Utilities ---

def _is_ff3(val: FastValue) -> bool:
    """Check if value is in the extension field FF3 (represented as a 3-tuple)."""
    return isinstance(val, tuple)


def _promote_ff_to_ff3(val: np.ndarray | np.uint64) -> tuple:
    """Lift a base-field value to the extension field (c1=c2=0)."""
    if isinstance(val, np.ndarray):
        zeros = np.zeros(len(val), dtype=np.uint64)
        return (val, zeros, zeros.copy())
    return (val, np.uint64(0), np.uint64(0))


def _ff3_mul_vecs(a: tuple, b: tuple) -> tuple:
    """Element-wise FF3 multiply: (a0,a1,a2) * (b0,b1,b2) using the relation x³ = x+1.

    Formula (derived from x³ = x+1):
        t  = a1*b2 + a2*b1
        c0 = a0*b0 + t
        c1 = a0*b1 + a1*b0 + t + a2*b2
        c2 = a0*b2 + a1*b1 + a2*b0 + a2*b2
    """
    a0, a1, a2 = a
    b0, b1, b2 = b

    t  = gl_add_vec(gl_mul_vec(a1, b2), gl_mul_vec(a2, b1))
    c0 = gl_add_vec(gl_mul_vec(a0, b0), t)

    a0_b1 = gl_mul_vec(a0, b1)
    a1_b0 = gl_mul_vec(a1, b0)
    a2_b2 = gl_mul_vec(a2, b2)
    c1 = gl_add_vec(gl_add_vec(gl_add_vec(a0_b1, a1_b0), t), a2_b2)

    a0_b2 = gl_mul_vec(a0, b2)
    a1_b1 = gl_mul_vec(a1, b1)
    a2_b0 = gl_mul_vec(a2, b0)
    c2 = gl_add_vec(gl_add_vec(gl_add_vec(a0_b2, a1_b1), a2_b0), a2_b2)

    return (c0, c1, c2)


def _format_fast_value_for_debug(v: FastValue) -> object:
    """Format a FastValue as a Python object suitable for debug tracing output."""
    if _is_ff3(v):
        c0, c1, c2 = v
        if isinstance(c0, np.uint64):
            return (int(c0), int(c1), int(c2))
        return list(zip(c0.tolist(), c1.tolist(), c2.tolist()))
    if isinstance(v, np.uint64):
        return int(v)
    return v.tolist() if hasattr(v, "tolist") else int(v)


# --- Buffer Container ---

@dataclass
class BufferSet:
    """Container for flat polynomial buffers used by the bytecode evaluator.

    This replaces the deleted ProofContext class with a minimal set of buffers
    needed by the expression interpreter.
    """
    trace: np.ndarray                # Stage 1 trace (base domain)
    aux_trace: np.ndarray            # Auxiliary trace (stages 2+ and extended)
    const_pols: np.ndarray           # Constant polynomials (base domain)
    const_pols_extended: np.ndarray  # Constant polynomials (extended domain)
    public_inputs: np.ndarray        # Public input values
    challenges: np.ndarray           # Challenge values (flat FF3 interleaved)
    evals: np.ndarray                # Evaluation values
    air_values: np.ndarray           # AIR-specific values
    airgroup_values: np.ndarray      # AIR group accumulated values
    proof_values: np.ndarray         # Proof values
    x_div_x_sub: np.ndarray | None = None   # For verifier mode
    custom_commits: np.ndarray | None = None  # Custom commit buffers


# --- Evaluation Parameters ---

@dataclass
class Params:
    """Operand specification for expression evaluation."""
    exp_id: int = 0
    dim: int = 1
    stage: int = 0
    stage_pos: int = 0
    pols_map_id: int = 0
    row_offset_index: int = 0
    inverse: bool = False
    batch: bool = True
    op: str = "tmp"  # "tmp", "cm", "const", "number", "airvalue"
    value: int = 0


@dataclass
class Dest:
    """Destination buffer for expression results."""
    dest: np.ndarray = None
    exp_id: int = -1
    offset: int = 0
    stage_pos: int = 0
    stage_cols: int = 0
    expr: bool = False
    dim: int = 1
    domain_size: int = 0
    params: list[Params] = None

    def __post_init__(self) -> None:
        if self.params is None:
            self.params = []


# --- Expression Context ---

class ExpressionsCtx:
    """Memory layout and stride mappings for polynomial access."""

    def __init__(self, stark_info: StarkInfo, prover_helpers: ProverHelpers | None = None,
                 n_queries: int | None = None, verify: bool = False) -> None:
        self.stark_info = stark_info
        self.prover_helpers = prover_helpers
        self.n_queries = n_queries
        self.verify = verify

        # Xi values for FRI (set via set_xi)
        self.xis: np.ndarray | None = None

        # Opening point strides
        n_opening_points = len(stark_info.opening_points)
        self.next_strides = np.zeros(n_opening_points, dtype=np.int64)
        self.next_strides_extended = np.zeros(n_opening_points, dtype=np.int64)

        # Section offsets: index 0=const, 1..nStages+1=cm1..cmN
        self.map_offsets = np.zeros(1 + stark_info.n_stages + 1, dtype=np.uint64)
        self.map_offsets_extended = np.zeros(1 + stark_info.n_stages + 1, dtype=np.uint64)
        self.map_sections_n = np.zeros(1 + stark_info.n_stages + 1, dtype=np.uint64)

        # Custom commit offsets
        n_custom = len(stark_info.custom_commits)
        self.map_offsets_custom_fixed = np.zeros(n_custom, dtype=np.uint64)
        self.map_offsets_custom_fixed_extended = np.zeros(n_custom, dtype=np.uint64)
        self.map_sections_n_custom_fixed = np.zeros(n_custom, dtype=np.uint64)

        # N = domain size (number of trace rows)
        N = 1 << stark_info.stark_struct.n_bits
        # N_ext = extended domain size for quotient polynomial evaluation
        N_extended = 1 << stark_info.stark_struct.n_bits_ext
        extend = 1 << (stark_info.stark_struct.n_bits_ext - stark_info.stark_struct.n_bits)

        # Row bounds for cyclic constraints
        self.min_row = 0
        self.max_row = N
        self.min_row_extended = 0
        self.max_row_extended = N_extended

        # Compute strides and row bounds from opening points
        for i in range(n_opening_points):
            if self.verify:
                self.next_strides[i] = 0
                self.next_strides_extended[i] = 0
            else:
                self.next_strides[i] = stark_info.opening_points[i]
                self.next_strides_extended[i] = stark_info.opening_points[i] * extend

            if stark_info.opening_points[i] < 0:
                self.min_row = max(self.min_row, abs(self.next_strides[i]))
                self.min_row_extended = max(self.min_row_extended, abs(self.next_strides_extended[i]))
            else:
                self.max_row = min(self.max_row, N - self.next_strides[i])
                self.max_row_extended = min(self.max_row_extended, N_extended - self.next_strides_extended[i])

        # Constant polynomials (index 0)
        self.map_offsets[0] = stark_info.map_offsets[("const", False)]
        self.map_offsets_extended[0] = stark_info.map_offsets.get(("const", True), 0)
        self.map_sections_n[0] = stark_info.map_sections_n["const"]

        # FRI polynomial offset
        self.map_offset_fri_pol = stark_info.map_offsets.get(("f", True), 0)

        # Committed polynomials (stages 1..nStages+1)
        verify_aux_offset = 0
        for i in range(stark_info.n_stages + 1):
            section_name = f"cm{i + 1}"
            self.map_sections_n[i + 1] = stark_info.map_sections_n[section_name]

            if self.verify and n_queries is not None and i >= 1:
                self.map_offsets[i + 1] = verify_aux_offset
                verify_aux_offset += n_queries * stark_info.map_sections_n[section_name]
            else:
                self.map_offsets[i + 1] = stark_info.map_offsets[(section_name, False)]

            self.map_offsets_extended[i + 1] = stark_info.map_offsets.get((section_name, True), 0)

        # Custom commits
        for i in range(n_custom):
            cc = stark_info.custom_commits[i]
            section_name = cc.name + "0"
            self.map_sections_n_custom_fixed[i] = stark_info.map_sections_n[section_name]
            self.map_offsets_custom_fixed[i] = stark_info.map_offsets[(section_name, False)]
            self.map_offsets_custom_fixed_extended[i] = stark_info.map_offsets.get((section_name, True), 0)

        # Buffer metadata
        self.buffer_commits_size = 1 + stark_info.n_stages + 3 + len(stark_info.custom_commits)
        self.n_stages = stark_info.n_stages
        self.n_publics = stark_info.n_publics
        self.n_challenges = len(stark_info.challenges_map)
        self.n_evals = len(stark_info.ev_map)
        self.rows_per_batch = min(NROWS_PACK, N)

    def set_xi(self, xis: np.ndarray) -> None:
        """Set xi evaluation points for FRI division.

        xi = challenge evaluation point (random point from Fiat-Shamir transcript).
        Used to compute x/(x - xi) for FRI opening checks.
        """
        self.xis = xis

    def calculate_expression(self, buffers: BufferSet, dest: np.ndarray,
                            expression_id: int, inverse: bool = False,
                            compilation_time: bool = False) -> None:
        """Evaluate a single expression into dest buffer."""

        # Determine domain configuration
        if compilation_time:
            domain_size = 1
            domain_extended = False
        elif expression_id in [self.stark_info.c_exp_id,
                               self.stark_info.fri_exp_id]:
            domain_size = 1 << self.stark_info.stark_struct.n_bits_ext
            domain_extended = True
            if expression_id in self._expressions_bin.expressions_info:
                self._expressions_bin.expressions_info[expression_id].dest_dim = FIELD_EXTENSION_DEGREE
        else:
            domain_size = 1 << self.stark_info.stark_struct.n_bits
            domain_extended = False

        dest_struct = Dest(dest=dest, domain_size=domain_size, offset=0, exp_id=expression_id)

        exp_info = self._expressions_bin.expressions_info[expression_id]
        param = Params(exp_id=expression_id, dim=exp_info.dest_dim, inverse=inverse, batch=True, op="tmp")
        dest_struct.params.append(param)
        dest_struct.dim = max(dest_struct.dim, exp_info.dest_dim)

        self.calculate_expressions(buffers, dest_struct, domain_size, domain_extended, compilation_time)

    def calculate_expressions(self, buffers: BufferSet, dest: Dest,
                             domain_size: int, domain_extended: bool,
                             compilation_time: bool = False,
                             verify_constraints: bool = False, debug: bool = False) -> None:
        """Evaluate expressions across domain. Overridden by ExpressionsPack."""
        raise NotImplementedError("Subclass must implement calculate_expressions")


# --- Arithmetic Operation Codes ---

# These mirror the C++ expressions_bin.hpp arith_op encoding.
_ARITH_OP_ADD      = 0
_ARITH_OP_SUB      = 1
_ARITH_OP_MUL      = 2
_ARITH_OP_SUB_SWAP = 3  # b - a (operand order swapped)


# --- Bytecode Evaluator ---

class ExpressionsPack(ExpressionsCtx):
    """Bytecode interpreter for constraint polynomial evaluation."""

    def __init__(self, stark_info: StarkInfo, expressions_bin: ExpressionsBin,
                 prover_helpers: ProverHelpers | None = None,
                 nrows_pack: int = NROWS_PACK, n_queries: int | None = None,
                 verify: bool = False) -> None:
        super().__init__(stark_info, prover_helpers, n_queries, verify=verify)
        self._expressions_bin = expressions_bin
        N = 1 << stark_info.stark_struct.n_bits
        self.rows_per_batch = min(nrows_pack, N)

    def calculate_expressions(self, buffers: BufferSet, dest: Dest,
                              domain_size: int, domain_extended: bool,
                              compilation_time: bool = False,
                              verify_constraints: bool = False, debug: bool = False) -> None:
        """Execute bytecode to evaluate constraint expressions."""
        nrows_pack = min(self.rows_per_batch, domain_size)

        # Select offset mappings for current domain
        map_offsets_exps = self.map_offsets_extended if domain_extended else self.map_offsets
        map_offsets_custom_exps = (self.map_offsets_custom_fixed_extended
                                   if domain_extended else self.map_offsets_custom_fixed)
        next_strides_exps = self.next_strides_extended if domain_extended else self.next_strides

        # Cyclic constraint row bounds
        if domain_extended:
            k_min = ((self.min_row_extended + nrows_pack - 1) // nrows_pack) * nrows_pack
            k_max = (self.max_row_extended // nrows_pack) * nrows_pack
        else:
            k_min = ((self.min_row + nrows_pack - 1) // nrows_pack) * nrows_pack
            k_max = (self.max_row // nrows_pack) * nrows_pack

        # Select bytecode stream
        parser_args = (self._expressions_bin.expressions_bin_args_constraints
                      if verify_constraints
                      else self._expressions_bin.expressions_bin_args_expressions)

        # Resolve expression metadata for each dest param
        parser_params_list: list[ParserParams | None] = []
        assert len(dest.params) in [1, 2], "dest.params must have 1 or 2 parameters"

        for k in range(len(dest.params)):
            if dest.params[k].op != "tmp":
                parser_params_list.append(None)
            elif verify_constraints:
                parser_params_list.append(
                    self._expressions_bin.constraints_info_debug[dest.params[k].exp_id])
            else:
                parser_params_list.append(
                    self._expressions_bin.expressions_info[dest.params[k].exp_id])

        # Scalar parameter lookup table
        scalar_params: dict[int, np.ndarray] = {
            self.buffer_commits_size + PUBLIC_INPUTS_OFFSET: buffers.public_inputs,
            self.buffer_commits_size + NUMBERS_OFFSET: parser_args.numbers,
            self.buffer_commits_size + AIR_VALUES_OFFSET: buffers.air_values,
            self.buffer_commits_size + PROOF_VALUES_OFFSET: buffers.proof_values,
            self.buffer_commits_size + AIRGROUP_VALUES_OFFSET: buffers.airgroup_values,
            self.buffer_commits_size + CHALLENGES_OFFSET: buffers.challenges,
            self.buffer_commits_size + EVALS_OFFSET: buffers.evals,
        }

        # Evaluate row batches
        for row in range(0, domain_size, nrows_pack):
            is_cyclic = (row < k_min) or (row >= k_max)

            # Temp storage for bytecode execution
            tmp1_g: dict[int, np.ndarray | np.uint64] = {}
            tmp3_g: dict[int, tuple] = {}

            param_results: list[FastValue | None] = [None, None]

            for k in range(len(dest.params)):
                p = dest.params[k]

                # Direct polynomial load (cm/const)
                if p.op in ["cm", "const"]:
                    result = self._load_direct_poly(
                        buffers, p, row, nrows_pack, domain_size,
                        domain_extended, map_offsets_exps, next_strides_exps)
                    if p.inverse:
                        if _is_ff3(result):
                            result = ff3_batch_inverse(*result)
                        else:
                            result = gl_inv_vec(result)
                    param_results[k] = result
                    continue

                # Literal number
                if p.op == "number":
                    param_results[k] = np.uint64(p.value)
                    continue

                # AIR value
                if p.op == "airvalue":
                    if p.dim == 1:
                        param_results[k] = np.uint64(int(buffers.air_values[p.pols_map_id]))
                    else:
                        c0 = np.uint64(int(buffers.air_values[p.pols_map_id]))
                        c1 = np.uint64(int(buffers.air_values[p.pols_map_id + 1]))
                        c2 = np.uint64(int(buffers.air_values[p.pols_map_id + 2]))
                        param_results[k] = (c0, c1, c2)
                    continue

                # Expression bytecode evaluation
                parser_params = parser_params_list[k]
                if parser_params is None:
                    continue

                ops = parser_args.ops[parser_params.ops_offset:]
                args = parser_args.args[parser_params.args_offset:]
                i_args = 0

                for op_idx in range(parser_params.n_ops):
                    op_type = ops[op_idx]
                    is_last = (op_idx == parser_params.n_ops - 1)
                    arith_op = args[i_args]
                    dest_slot = args[i_args + 1]

                    # Bytecode op_type: 0=FF*FF, 1=FF3*FF, 2=FF3*FF3
                    dim_a = FIELD_EXTENSION_DEGREE if op_type >= 1 else 1
                    dim_b = FIELD_EXTENSION_DEGREE if op_type == 2 else 1

                    if debug:
                        a_type = args[i_args + 2]
                        a_id = args[i_args + 3]
                        a_open = args[i_args + 4]
                        b_type = args[i_args + 5]
                        b_id = args[i_args + 6]
                        b_open = args[i_args + 7]
                        op_names = {
                            _ARITH_OP_ADD: "add",
                            _ARITH_OP_SUB: "sub",
                            _ARITH_OP_MUL: "mul",
                            _ARITH_OP_SUB_SWAP: "sub(swap)",
                        }
                        print(f"  [TRACE] op[{op_idx}]: type={op_type} "
                              f"arith={op_names.get(arith_op, arith_op)} dest={dest_slot} "
                              f"a=({a_type},{a_id},{a_open}) b=({b_type},{b_id},{b_open})")

                    a = self._load_operand(buffers, scalar_params, tmp1_g, tmp3_g, args,
                                           map_offsets_exps, map_offsets_custom_exps,
                                           next_strides_exps, i_args + 2, row, dim_a,
                                           domain_size, domain_extended, is_cyclic, nrows_pack)
                    b = self._load_operand(buffers, scalar_params, tmp1_g, tmp3_g, args,
                                           map_offsets_exps, map_offsets_custom_exps,
                                           next_strides_exps, i_args + 5, row, dim_b,
                                           domain_size, domain_extended, is_cyclic, nrows_pack)
                    result = self._apply_op(arith_op, a, b)

                    if debug:
                        print(f"         a={_format_fast_value_for_debug(a)}"
                              f" b={_format_fast_value_for_debug(b)}"
                              f" -> {_format_fast_value_for_debug(result)}")

                    if is_last:
                        param_results[k] = result
                    elif op_type == 0:
                        tmp1_g[dest_slot] = result
                    else:
                        tmp3_g[dest_slot] = result
                    i_args += 8

                assert i_args == parser_params.n_args, f"Args mismatch: {i_args} != {parser_params.n_args}"

                if p.inverse:
                    r = param_results[k]
                    param_results[k] = ff3_batch_inverse(*r) if _is_ff3(r) else gl_inv_vec(r)

            # Combine results if two params
            if len(dest.params) == 2:
                final_result = self._multiply_results(param_results[0], param_results[1])
            else:
                final_result = param_results[0]

            self._store_result(dest, final_result, row, nrows_pack)

    # --- Operand Loading ---

    def _load_direct_poly(self, buffers: BufferSet, param: Params, row: int,
                          nrows_pack: int, domain_size: int, domain_extended: bool,
                          map_offsets_exps: np.ndarray, next_strides_exps: np.ndarray
                          ) -> FastValue:
        """Load polynomial directly from cm/const buffers using vectorized numpy indexing."""
        o = int(next_strides_exps[param.row_offset_index])
        rows = (np.arange(nrows_pack, dtype=np.intp) + row + o) % domain_size

        if param.op == "const":
            n_cols = int(self.map_sections_n[0])
            buf = buffers.const_pols_extended if domain_extended else buffers.const_pols
            return np.asarray(buf[rows * n_cols + param.stage_pos], dtype=np.uint64)

        offset = int(map_offsets_exps[param.stage])
        n_cols = int(self.map_sections_n[param.stage])

        if param.stage == 1 and not domain_extended:
            return np.asarray(buffers.trace[rows * n_cols + param.stage_pos], dtype=np.uint64)

        base = offset + rows * n_cols + param.stage_pos
        if param.dim == 1:
            return np.asarray(buffers.aux_trace[base], dtype=np.uint64)

        # FF3: interleaved layout — c0, c1, c2 at positions base, base+1, base+2
        c0 = np.asarray(buffers.aux_trace[base],     dtype=np.uint64)
        c1 = np.asarray(buffers.aux_trace[base + 1], dtype=np.uint64)
        c2 = np.asarray(buffers.aux_trace[base + 2], dtype=np.uint64)
        return (c0, c1, c2)

    def _load_operand(self, buffers: BufferSet, scalar_params: dict[int, np.ndarray],
                      tmp1_g: dict[int, np.ndarray | np.uint64],
                      tmp3_g: dict[int, tuple],
                      args: np.ndarray, map_offsets_exps: np.ndarray,
                      map_offsets_custom_exps: np.ndarray, next_strides_exps: np.ndarray,
                      i_args: int, row: int, dim: int, domain_size: int,
                      domain_extended: bool, is_cyclic: bool, nrows_pack: int
                      ) -> FastValue:
        """Load operand from bytecode-specified source.

        Variables:
            o: row offset for shifted polynomial evaluation (from opening points)
            n_cols: number of columns in the section's flat buffer layout
            stage_pos: column position within the section
        """
        type_arg = args[i_args]

        # Type 0: Constant polynomials
        if type_arg == 0:
            stage_pos = args[i_args + 1]
            opening_idx = args[i_args + 2]
            # o = row offset for shifted polynomial evaluation
            o = int(next_strides_exps[opening_idx])
            n_cols = int(self.map_sections_n[0])

            # Verify mode: load from evals
            if self.verify and domain_size == 1:
                pol_id = None
                for idx, pol in enumerate(self.stark_info.const_pols_map):
                    if pol.stage_pos == stage_pos:
                        pol_id = idx
                        break
                if pol_id is not None:
                    # Deferred import to avoid circular dependency: pol_map → stark_info → expression_evaluator
                    from primitives.pol_map import EvMap
                    for idx, e in enumerate(self.stark_info.ev_map):
                        if e.type == EvMap.Type.const_ and e.id == pol_id and e.opening_pos == opening_idx:
                            base = idx * FIELD_EXTENSION_DEGREE
                            return (np.uint64(int(buffers.evals[base])),
                                    np.uint64(int(buffers.evals[base + 1])),
                                    np.uint64(int(buffers.evals[base + 2])))

            const_pols = buffers.const_pols_extended if domain_extended else buffers.const_pols
            rows = (np.arange(nrows_pack, dtype=np.intp) + row + o) % domain_size
            return np.asarray(const_pols[rows * n_cols + stage_pos], dtype=np.uint64)

        # Types 1..nStages+1: Committed polynomials
        if type_arg <= self.stark_info.n_stages + 1:
            stage_pos = args[i_args + 1]
            offset = int(map_offsets_exps[type_arg])
            n_cols = int(self.map_sections_n[type_arg])
            opening_idx = args[i_args + 2]
            # o = row offset for shifted polynomial evaluation
            o = int(next_strides_exps[opening_idx])

            # Verify mode: load from evals
            if self.verify and domain_size == 1:
                stage = type_arg
                pol_id = None
                for idx, pol in enumerate(self.stark_info.cm_pols_map):
                    if pol.stage == stage and pol.stage_pos == stage_pos:
                        pol_id = idx
                        break
                if pol_id is not None:
                    # Deferred import to avoid circular dependency: pol_map → stark_info → expression_evaluator
                    from primitives.pol_map import EvMap
                    for idx, e in enumerate(self.stark_info.ev_map):
                        if e.type == EvMap.Type.cm and e.id == pol_id and e.opening_pos == opening_idx:
                            base = idx * FIELD_EXTENSION_DEGREE
                            return (np.uint64(int(buffers.evals[base])),
                                    np.uint64(int(buffers.evals[base + 1])),
                                    np.uint64(int(buffers.evals[base + 2])))

            rows = (np.arange(nrows_pack, dtype=np.intp) + row + o) % domain_size
            if type_arg == 1 and not domain_extended:
                return np.asarray(buffers.trace[rows * n_cols + stage_pos], dtype=np.uint64)

            base_idx = offset + rows * n_cols + stage_pos
            if dim == 1:
                return np.asarray(buffers.aux_trace[base_idx], dtype=np.uint64)

            # FF3: interleaved layout — c0, c1, c2 at positions base, base+1, base+2
            c0 = np.asarray(buffers.aux_trace[base_idx],     dtype=np.uint64)
            c1 = np.asarray(buffers.aux_trace[base_idx + 1], dtype=np.uint64)
            c2 = np.asarray(buffers.aux_trace[base_idx + 2], dtype=np.uint64)
            return (c0, c1, c2)

        # Type nStages+2: Boundary values (x_n, zi)
        # zi = inverse vanishing polynomial 1/Z_H(x) where Z_H(x) = x^N - 1
        if type_arg == self.stark_info.n_stages + 2:
            boundary = args[i_args + 1]
            if self.verify:
                if boundary == 0:
                    c0 = np.uint64(int(self.prover_helpers.x_n[0]))
                    c1 = np.uint64(int(self.prover_helpers.x_n[1]))
                    c2 = np.uint64(int(self.prover_helpers.x_n[2]))
                    if dim == FIELD_EXTENSION_DEGREE:
                        return (np.full(nrows_pack, c0, dtype=np.uint64),
                                np.full(nrows_pack, c1, dtype=np.uint64),
                                np.full(nrows_pack, c2, dtype=np.uint64))
                    return np.full(nrows_pack, c0, dtype=np.uint64)
                else:
                    base = (boundary - 1) * FIELD_EXTENSION_DEGREE
                    c0 = np.uint64(int(self.prover_helpers.zi[base]))
                    c1 = np.uint64(int(self.prover_helpers.zi[base + 1]))
                    c2 = np.uint64(int(self.prover_helpers.zi[base + 2]))
                    return (np.full(nrows_pack, c0, dtype=np.uint64),
                            np.full(nrows_pack, c1, dtype=np.uint64),
                            np.full(nrows_pack, c2, dtype=np.uint64))
            else:
                if boundary == 0:
                    x_vals = self.prover_helpers.x if domain_extended else self.prover_helpers.x_n
                    return np.asarray(x_vals[row:row + nrows_pack], dtype=np.uint64)
                else:
                    ofs = (boundary - 1) * domain_size + row
                    return np.asarray(self.prover_helpers.zi[ofs:ofs + nrows_pack], dtype=np.uint64)

        # Type nStages+3: x/(x - xi) for FRI opening
        # xi = challenge evaluation point (random point from Fiat-Shamir transcript)
        if type_arg == self.stark_info.n_stages + 3:
            opening_point_idx = args[i_args + 1]
            if self.verify:
                n_openings = len(self.stark_info.opening_points)
                rows = np.arange(nrows_pack, dtype=np.intp) + row
                base_idx = (rows * n_openings + opening_point_idx) * FIELD_EXTENSION_DEGREE
                c0 = np.asarray(buffers.x_div_x_sub[base_idx],     dtype=np.uint64)
                c1 = np.asarray(buffers.x_div_x_sub[base_idx + 1], dtype=np.uint64)
                c2 = np.asarray(buffers.x_div_x_sub[base_idx + 2], dtype=np.uint64)
                return (c0, c1, c2)
            else:
                # xi = challenge evaluation point (from Fiat-Shamir)
                xi_base = opening_point_idx * FIELD_EXTENSION_DEGREE
                xi_c0 = np.uint64(int(self.xis[xi_base]))
                xi_c1 = np.uint64(int(self.xis[xi_base + 1]))
                xi_c2 = np.uint64(int(self.xis[xi_base + 2]))
                x_vals = np.asarray(self.prover_helpers.x[row:row + nrows_pack], dtype=np.uint64)
                # diff = x - xi in FF3: x lives in the base field, so x_ff3 = (x, 0, 0)
                zero_component = np.zeros(nrows_pack, dtype=np.uint64)
                diff_c0 = gl_sub_vec(x_vals, xi_c0)
                diff_c1 = gl_sub_vec(zero_component, xi_c1)
                diff_c2 = gl_sub_vec(zero_component, xi_c2)
                return ff3_batch_inverse(diff_c0, diff_c1, diff_c2)

        # Custom commits
        if (type_arg >= self.stark_info.n_stages + 4 and
            type_arg < len(self.stark_info.custom_commits) + self.stark_info.n_stages + 4):
            index = type_arg - (self.n_stages + 4)
            stage_pos = args[i_args + 1]
            opening_idx = args[i_args + 2]

            # Verify mode: load from evals
            if self.verify and domain_size == 1:
                # Deferred import to avoid circular dependency: pol_map → stark_info → expression_evaluator
                from primitives.pol_map import EvMap
                for idx, e in enumerate(self.stark_info.ev_map):
                    if (e.type == EvMap.Type.custom and e.id == stage_pos
                            and e.opening_pos == opening_idx and e.commit_id == index):
                        base = idx * FIELD_EXTENSION_DEGREE
                        return (np.uint64(int(buffers.evals[base])),
                                np.uint64(int(buffers.evals[base + 1])),
                                np.uint64(int(buffers.evals[base + 2])))

            offset = int(map_offsets_custom_exps[index])
            n_cols = int(self.map_sections_n_custom_fixed[index])
            # o = row offset for shifted polynomial evaluation
            o = int(next_strides_exps[opening_idx])
            rows = (np.arange(nrows_pack, dtype=np.intp) + row + o) % domain_size
            base_idx = offset + rows * n_cols + stage_pos
            return np.asarray(buffers.custom_commits[base_idx], dtype=np.uint64)

        # Temp registers
        if type_arg == self.buffer_commits_size:
            return tmp1_g[args[i_args + 1]]

        if type_arg == self.buffer_commits_size + 1:
            return tmp3_g[args[i_args + 1]]

        # Scalar values (publics, numbers, challenges, etc.)
        arr = scalar_params[type_arg]
        idx = args[i_args + 1]
        if dim == 1:
            return np.uint64(int(arr[idx]))
        return (np.uint64(int(arr[idx])),
                np.uint64(int(arr[idx + 1])),
                np.uint64(int(arr[idx + 2])))

    # --- Field Operations ---

    def _apply_op(self, op: int, a: FastValue, b: FastValue) -> FastValue:
        """Apply an arithmetic operation in GF(p) or GF(p³), promoting types as needed.

        Args:
            op: Arithmetic operation code (_ARITH_OP_ADD/SUB/MUL/SUB_SWAP).
            a: Left operand (base field or extension field column).
            b: Right operand (base field or extension field column).

        Returns:
            Result of the operation, in GF(p³) if either operand was in GF(p³).
        """
        a_is_extension = _is_ff3(a)
        b_is_extension = _is_ff3(b)
        if a_is_extension and not b_is_extension:
            b = _promote_ff_to_ff3(b)
        elif b_is_extension and not a_is_extension:
            a = _promote_ff_to_ff3(a)

        if not _is_ff3(a):
            if op == _ARITH_OP_ADD:
                return gl_add_vec(a, b)
            if op == _ARITH_OP_SUB:
                return gl_sub_vec(a, b)
            if op == _ARITH_OP_MUL:
                return gl_mul_vec(a, b)
            if op == _ARITH_OP_SUB_SWAP:
                return gl_sub_vec(b, a)
        else:
            a0, a1, a2 = a
            b0, b1, b2 = b
            if op == _ARITH_OP_ADD:
                return (gl_add_vec(a0, b0), gl_add_vec(a1, b1), gl_add_vec(a2, b2))
            if op == _ARITH_OP_SUB:
                return (gl_sub_vec(a0, b0), gl_sub_vec(a1, b1), gl_sub_vec(a2, b2))
            if op == _ARITH_OP_MUL:
                return _ff3_mul_vecs(a, b)
            if op == _ARITH_OP_SUB_SWAP:
                return (gl_sub_vec(b0, a0), gl_sub_vec(b1, a1), gl_sub_vec(b2, a2))
        raise ValueError(f"Invalid operation: {op}")

    def _multiply_results(self, a: FastValue, b: FastValue) -> FastValue:
        """Multiply two results, promoting to FF3 only if types mismatch."""
        a_ext, b_ext = _is_ff3(a), _is_ff3(b)
        if a_ext and not b_ext:
            b = _promote_ff_to_ff3(b)
        elif b_ext and not a_ext:
            a = _promote_ff_to_ff3(a)
        if not _is_ff3(a):
            return gl_mul_vec(a, b)
        return _ff3_mul_vecs(a, b)

    def _store_result(self, dest: Dest, result: FastValue, row: int, nrows_pack: int) -> None:
        """Store a batch result into the destination buffer.

        Args:
            dest: Destination specification including the output array and stride.
                  If dest.offset is zero, the stride is inferred from the result type
                  (FIELD_EXTENSION_DEGREE for FF3, 1 for base field).
            result: Computed column values for the current row batch.
            row: Starting row index of this batch.
            nrows_pack: Number of rows in this batch.
        """
        result_is_extension = _is_ff3(result)

        if dest.offset != 0:
            stride = dest.offset
        elif result_is_extension:
            stride = FIELD_EXTENSION_DEGREE
        else:
            stride = 1

        base_indices = (np.arange(nrows_pack, dtype=np.intp) + row) * stride

        if not result_is_extension:
            dest.dest[base_indices] = np.asarray(result, dtype=np.uint64)
        else:
            c0, c1, c2 = result
            dest.dest[base_indices]     = np.asarray(c0, dtype=np.uint64)
            dest.dest[base_indices + 1] = np.asarray(c1, dtype=np.uint64)
            dest.dest[base_indices + 2] = np.asarray(c2, dtype=np.uint64)
