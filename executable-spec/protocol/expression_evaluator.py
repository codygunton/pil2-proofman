"""Expression bytecode evaluator for STARK constraint polynomials."""

from dataclasses import dataclass
from typing import Dict, List, Optional, Union
import numpy as np

from protocol.setup_ctx import SetupCtx, ProverHelpers, FIELD_EXTENSION
from protocol.steps_params import StepsParams
from protocol.expressions_bin import ParserParams
from primitives.field import FF, FF3, ff3, ff3_coeffs, GOLDILOCKS_PRIME, batch_inverse

# --- Type Aliases ---

GaloisValue = Union[FF, FF3]  # Field element or extension element

# --- Constants ---

# Rows per batch - large enough for any test domain
NROWS_PACK = 1 << 16

# Operation codes for field arithmetic
OP_ADD = 0
OP_SUB = 1
OP_MUL = 2
OP_SUB_SWAP = 3  # b - a


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
    params: List[Params] = None

    def __post_init__(self):
        if self.params is None:
            self.params = []


# --- Expression Context ---

class ExpressionsCtx:
    """Memory layout and stride mappings for polynomial access."""

    def __init__(self, setup_ctx: SetupCtx, prover_helpers: Optional[ProverHelpers] = None,
                 n_queries: Optional[int] = None):
        self.setup_ctx = setup_ctx
        self.prover_helpers = prover_helpers
        self.n_queries = n_queries

        stark_info = setup_ctx.stark_info

        # Xi values for FRI (set via set_xi)
        self.xis: Optional[np.ndarray] = None

        # Opening point strides
        n_opening_points = len(stark_info.openingPoints)
        self.next_strides = np.zeros(n_opening_points, dtype=np.int64)
        self.next_strides_extended = np.zeros(n_opening_points, dtype=np.int64)

        # Section offsets: index 0=const, 1..nStages+1=cm1..cmN
        self.map_offsets = np.zeros(1 + stark_info.nStages + 1, dtype=np.uint64)
        self.map_offsets_extended = np.zeros(1 + stark_info.nStages + 1, dtype=np.uint64)
        self.map_sections_n = np.zeros(1 + stark_info.nStages + 1, dtype=np.uint64)

        # Custom commit offsets
        n_custom = len(stark_info.customCommits)
        self.map_offsets_custom_fixed = np.zeros(n_custom, dtype=np.uint64)
        self.map_offsets_custom_fixed_extended = np.zeros(n_custom, dtype=np.uint64)
        self.map_sections_n_custom_fixed = np.zeros(n_custom, dtype=np.uint64)

        # Domain sizes
        N = 1 << stark_info.starkStruct.nBits
        N_extended = 1 << stark_info.starkStruct.nBitsExt
        extend = 1 << (stark_info.starkStruct.nBitsExt - stark_info.starkStruct.nBits)

        # Row bounds for cyclic constraints
        self.min_row = 0
        self.max_row = N
        self.min_row_extended = 0
        self.max_row_extended = N_extended

        # Compute strides and row bounds from opening points
        for i in range(n_opening_points):
            if stark_info.verify:
                self.next_strides[i] = 0
                self.next_strides_extended[i] = 0
            else:
                self.next_strides[i] = stark_info.openingPoints[i]
                self.next_strides_extended[i] = stark_info.openingPoints[i] * extend

            if stark_info.openingPoints[i] < 0:
                self.min_row = max(self.min_row, abs(self.next_strides[i]))
                self.min_row_extended = max(self.min_row_extended, abs(self.next_strides_extended[i]))
            else:
                self.max_row = min(self.max_row, N - self.next_strides[i])
                self.max_row_extended = min(self.max_row_extended, N_extended - self.next_strides_extended[i])

        # Constant polynomials (index 0)
        self.map_offsets[0] = stark_info.mapOffsets[("const", False)]
        self.map_offsets_extended[0] = stark_info.mapOffsets.get(("const", True), 0)
        self.map_sections_n[0] = stark_info.mapSectionsN["const"]

        # FRI polynomial offset
        self.map_offset_fri_pol = stark_info.mapOffsets.get(("f", True), 0)

        # Committed polynomials (stages 1..nStages+1)
        verify_aux_offset = 0
        for i in range(stark_info.nStages + 1):
            section_name = f"cm{i + 1}"
            self.map_sections_n[i + 1] = stark_info.mapSectionsN[section_name]

            if stark_info.verify and n_queries is not None and i >= 1:
                self.map_offsets[i + 1] = verify_aux_offset
                verify_aux_offset += n_queries * stark_info.mapSectionsN[section_name]
            else:
                self.map_offsets[i + 1] = stark_info.mapOffsets[(section_name, False)]

            self.map_offsets_extended[i + 1] = stark_info.mapOffsets.get((section_name, True), 0)

        # Custom commits
        for i in range(n_custom):
            cc = stark_info.customCommits[i]
            section_name = cc.name + "0"
            self.map_sections_n_custom_fixed[i] = stark_info.mapSectionsN[section_name]
            self.map_offsets_custom_fixed[i] = stark_info.mapOffsets[(section_name, False)]
            self.map_offsets_custom_fixed_extended[i] = stark_info.mapOffsets.get((section_name, True), 0)

        # Buffer metadata
        self.buffer_commits_size = 1 + stark_info.nStages + 3 + len(stark_info.customCommits)
        self.n_stages = stark_info.nStages
        self.n_publics = stark_info.nPublics
        self.n_challenges = len(stark_info.challengesMap)
        self.n_evals = len(stark_info.evMap)
        self.nrows_pack_ = min(NROWS_PACK, N)

    def set_xi(self, xis: np.ndarray):
        """Set xi evaluation points for FRI division."""
        self.xis = xis

    def calculate_expression(self, params: StepsParams, dest: np.ndarray,
                            expression_id: int, inverse: bool = False,
                            compilation_time: bool = False):
        """Evaluate a single expression into dest buffer."""
        # Determine domain configuration
        if compilation_time:
            domain_size = 1
            domain_extended = False
        elif expression_id in [self.setup_ctx.stark_info.cExpId,
                               self.setup_ctx.stark_info.friExpId]:
            domain_size = 1 << self.setup_ctx.stark_info.starkStruct.nBitsExt
            domain_extended = True
            if expression_id in self.setup_ctx.expressions_bin.expressions_info:
                self.setup_ctx.expressions_bin.expressions_info[expression_id].dest_dim = 3
        else:
            domain_size = 1 << self.setup_ctx.stark_info.starkStruct.nBits
            domain_extended = False

        dest_struct = Dest(dest=dest, domain_size=domain_size, offset=0, exp_id=expression_id)

        exp_info = self.setup_ctx.expressions_bin.expressions_info[expression_id]
        param = Params(exp_id=expression_id, dim=exp_info.dest_dim, inverse=inverse, batch=True, op="tmp")
        dest_struct.params.append(param)
        dest_struct.dim = max(dest_struct.dim, exp_info.dest_dim)

        self.calculate_expressions(params, dest_struct, domain_size, domain_extended, compilation_time)

    def calculate_expressions(self, params: StepsParams, dest: Dest,
                             domain_size: int, domain_extended: bool,
                             compilation_time: bool = False,
                             verify_constraints: bool = False, debug: bool = False):
        """Evaluate expressions across domain. Overridden by ExpressionsPack."""
        raise NotImplementedError("Subclass must implement calculate_expressions")


# --- Bytecode Evaluator ---

class ExpressionsPack(ExpressionsCtx):
    """Bytecode interpreter for constraint polynomial evaluation."""

    def __init__(self, setup_ctx: SetupCtx, prover_helpers: Optional[ProverHelpers] = None,
                 nrows_pack: int = NROWS_PACK, n_queries: Optional[int] = None):
        super().__init__(setup_ctx, prover_helpers, n_queries)
        N = 1 << setup_ctx.stark_info.starkStruct.nBits
        self.nrows_pack_ = min(nrows_pack, N)

    def calculate_expressions(self, params: StepsParams, dest: Dest,
                              domain_size: int, domain_extended: bool,
                              compilation_time: bool = False,
                              verify_constraints: bool = False, debug: bool = False):
        """Execute bytecode to evaluate constraint expressions."""
        nrows_pack = min(self.nrows_pack_, domain_size)

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
        parser_args = (self.setup_ctx.expressions_bin.expressions_bin_args_constraints
                      if verify_constraints
                      else self.setup_ctx.expressions_bin.expressions_bin_args_expressions)

        # Resolve expression metadata for each dest param
        parser_params_list: List[Optional[ParserParams]] = []
        assert len(dest.params) in [1, 2], "dest.params must have 1 or 2 parameters"

        for k in range(len(dest.params)):
            if dest.params[k].op != "tmp":
                parser_params_list.append(None)
            elif verify_constraints:
                parser_params_list.append(
                    self.setup_ctx.expressions_bin.constraints_info_debug[dest.params[k].exp_id])
            else:
                parser_params_list.append(
                    self.setup_ctx.expressions_bin.expressions_info[dest.params[k].exp_id])

        # Scalar parameter lookup table
        scalar_params: Dict[int, np.ndarray] = {
            self.buffer_commits_size + 2: params.publicInputs,
            self.buffer_commits_size + 3: parser_args.numbers,
            self.buffer_commits_size + 4: params.airValues,
            self.buffer_commits_size + 5: params.proofValues,
            self.buffer_commits_size + 6: params.airgroupValues,
            self.buffer_commits_size + 7: params.challenges,
            self.buffer_commits_size + 8: params.evals,
        }

        # Evaluate row batches
        for row in range(0, domain_size, nrows_pack):
            is_cyclic = (row < k_min) or (row >= k_max)

            # Temp storage for bytecode execution
            tmp1_g: Dict[int, FF] = {}   # base field temps
            tmp3_g: Dict[int, FF3] = {}  # extension field temps

            param_results: List[GaloisValue] = [None, None]
            param_dims: List[int] = [1, 1]

            for k in range(len(dest.params)):
                p = dest.params[k]

                # Direct polynomial load (cm/const)
                if p.op in ["cm", "const"]:
                    result = self._load_direct_poly(
                        params, p, row, nrows_pack, domain_size,
                        domain_extended, map_offsets_exps, next_strides_exps)
                    if p.inverse:
                        result = batch_inverse(result)
                    param_results[k] = result
                    param_dims[k] = p.dim
                    continue

                # Literal number
                if p.op == "number":
                    param_results[k] = FF(p.value)
                    param_dims[k] = 1
                    continue

                # AIR value
                if p.op == "airvalue":
                    if p.dim == 1:
                        param_results[k] = FF(int(params.airValues[p.pols_map_id]))
                    else:
                        c = [int(params.airValues[p.pols_map_id + i]) for i in range(3)]
                        param_results[k] = ff3(c)
                    param_dims[k] = p.dim
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

                    # Bytecode format: op_type determines operand dimensions
                    #   0: dim1 x dim1 -> dim1
                    #   1: dim3 x dim1 -> dim3
                    #   2: dim3 x dim3 -> dim3
                    if op_type == 0:
                        a = self._load_operand(params, scalar_params, tmp1_g, tmp3_g, args,
                                               map_offsets_exps, map_offsets_custom_exps,
                                               next_strides_exps, i_args + 2, row, 1,
                                               domain_size, domain_extended, is_cyclic, nrows_pack)
                        b = self._load_operand(params, scalar_params, tmp1_g, tmp3_g, args,
                                               map_offsets_exps, map_offsets_custom_exps,
                                               next_strides_exps, i_args + 5, row, 1,
                                               domain_size, domain_extended, is_cyclic, nrows_pack)
                        result = self._apply_op(arith_op, a, b)
                        if is_last:
                            param_results[k] = result
                            param_dims[k] = 1
                        else:
                            tmp1_g[dest_slot] = result
                        i_args += 8

                    elif op_type == 1:
                        a = self._load_operand(params, scalar_params, tmp1_g, tmp3_g, args,
                                               map_offsets_exps, map_offsets_custom_exps,
                                               next_strides_exps, i_args + 2, row, 3,
                                               domain_size, domain_extended, is_cyclic, nrows_pack)
                        b = self._load_operand(params, scalar_params, tmp1_g, tmp3_g, args,
                                               map_offsets_exps, map_offsets_custom_exps,
                                               next_strides_exps, i_args + 5, row, 1,
                                               domain_size, domain_extended, is_cyclic, nrows_pack)
                        result = self._apply_op_ext_base(arith_op, a, b)
                        if is_last:
                            param_results[k] = result
                            param_dims[k] = 3
                        else:
                            tmp3_g[dest_slot] = result
                        i_args += 8

                    elif op_type == 2:
                        a = self._load_operand(params, scalar_params, tmp1_g, tmp3_g, args,
                                               map_offsets_exps, map_offsets_custom_exps,
                                               next_strides_exps, i_args + 2, row, 3,
                                               domain_size, domain_extended, is_cyclic, nrows_pack)
                        b = self._load_operand(params, scalar_params, tmp1_g, tmp3_g, args,
                                               map_offsets_exps, map_offsets_custom_exps,
                                               next_strides_exps, i_args + 5, row, 3,
                                               domain_size, domain_extended, is_cyclic, nrows_pack)
                        result = self._apply_op(arith_op, a, b)
                        if is_last:
                            param_results[k] = result
                            param_dims[k] = 3
                        else:
                            tmp3_g[dest_slot] = result
                        i_args += 8

                    else:
                        raise ValueError(f"Invalid operation type: {op_type}")

                assert i_args == parser_params.n_args, f"Args mismatch: {i_args} != {parser_params.n_args}"

                if p.inverse:
                    param_results[k] = batch_inverse(param_results[k])

            # Combine results if two params
            if len(dest.params) == 2:
                final_result = self._multiply_results(param_results[0], param_results[1],
                                                      param_dims[0], param_dims[1], dest.dim)
            else:
                final_result = param_results[0]

            self._store_result(dest, final_result, row, nrows_pack)

    # --- Operand Loading ---

    def _load_direct_poly(self, params: StepsParams, param: Params, row: int,
                          nrows_pack: int, domain_size: int, domain_extended: bool,
                          map_offsets_exps: np.ndarray, next_strides_exps: np.ndarray
                          ) -> GaloisValue:
        """Load polynomial directly from cm/const buffers."""
        o = int(next_strides_exps[param.row_offset_index])

        if param.op == "const":
            n_cols = int(self.map_sections_n[0])
            buf = params.constPolsExtended if domain_extended else params.constPols
            vals = [int(buf[(row + r + o) % domain_size * n_cols + param.stage_pos])
                    for r in range(nrows_pack)]
            return FF(vals)

        offset = int(map_offsets_exps[param.stage])
        n_cols = int(self.map_sections_n[param.stage])

        if param.stage == 1 and not domain_extended:
            vals = [int(params.trace[((row + r + o) % domain_size) * n_cols + param.stage_pos])
                    for r in range(nrows_pack)]
            return FF(vals)

        if param.dim == 1:
            vals = [int(params.auxTrace[offset + ((row + r + o) % domain_size) * n_cols + param.stage_pos])
                    for r in range(nrows_pack)]
            return FF(vals)

        # FF3 load
        p = GOLDILOCKS_PRIME
        p2 = p * p
        ints = []
        for r in range(nrows_pack):
            idx = (row + r + o) % domain_size
            c0 = int(params.auxTrace[offset + idx * n_cols + param.stage_pos])
            c1 = int(params.auxTrace[offset + idx * n_cols + param.stage_pos + 1])
            c2 = int(params.auxTrace[offset + idx * n_cols + param.stage_pos + 2])
            ints.append(c0 + c1 * p + c2 * p2)
        return FF3(ints)

    def _load_operand(self, params: StepsParams, scalar_params: Dict[int, np.ndarray],
                      tmp1_g: Dict[int, FF], tmp3_g: Dict[int, FF3],
                      args: np.ndarray, map_offsets_exps: np.ndarray,
                      map_offsets_custom_exps: np.ndarray, next_strides_exps: np.ndarray,
                      i_args: int, row: int, dim: int, domain_size: int,
                      domain_extended: bool, is_cyclic: bool, nrows_pack: int
                      ) -> GaloisValue:
        """Load operand from bytecode-specified source."""
        type_arg = args[i_args]
        p = GOLDILOCKS_PRIME
        p2 = p * p

        # Type 0: Constant polynomials
        if type_arg == 0:
            stage_pos = args[i_args + 1]
            opening_idx = args[i_args + 2]
            o = next_strides_exps[opening_idx]
            n_cols = int(self.map_sections_n[0])

            # Verify mode: load from evals
            if self.setup_ctx.stark_info.verify and domain_size == 1:
                pol_id = None
                for idx, pol in enumerate(self.setup_ctx.stark_info.constPolsMap):
                    if pol.stagePos == stage_pos:
                        pol_id = idx
                        break

                if pol_id is not None:
                    from primitives.pol_map import EvMap
                    for idx, e in enumerate(self.setup_ctx.stark_info.evMap):
                        if e.type == EvMap.Type.const_ and e.id == pol_id and e.openingPos == opening_idx:
                            base = idx * FIELD_EXTENSION
                            c0 = int(params.evals[base])
                            c1 = int(params.evals[base + 1])
                            c2 = int(params.evals[base + 2])
                            return ff3([c0, c1, c2])

            const_pols = params.constPolsExtended if domain_extended else params.constPols
            if is_cyclic:
                vals = [int(const_pols[((row + j + o) % domain_size) * self.setup_ctx.stark_info.nConstants + stage_pos])
                        for j in range(nrows_pack)]
            else:
                offset_col = (row + o) * n_cols + stage_pos
                vals = [int(const_pols[offset_col + j * n_cols]) for j in range(nrows_pack)]
            return FF(vals)

        # Types 1..nStages+1: Committed polynomials
        if type_arg <= self.setup_ctx.stark_info.nStages + 1:
            stage_pos = args[i_args + 1]
            offset = int(map_offsets_exps[type_arg])
            n_cols = int(self.map_sections_n[type_arg])
            opening_idx = args[i_args + 2]
            o = next_strides_exps[opening_idx]

            # Verify mode: load from evals
            if self.setup_ctx.stark_info.verify and domain_size == 1:
                stage = type_arg
                pol_id = None
                for idx, pol in enumerate(self.setup_ctx.stark_info.cmPolsMap):
                    if pol.stage == stage and pol.stagePos == stage_pos:
                        pol_id = idx
                        break

                if pol_id is not None:
                    from primitives.pol_map import EvMap
                    for idx, e in enumerate(self.setup_ctx.stark_info.evMap):
                        if e.type == EvMap.Type.cm and e.id == pol_id and e.openingPos == opening_idx:
                            base = idx * FIELD_EXTENSION
                            c0 = int(params.evals[base])
                            c1 = int(params.evals[base + 1])
                            c2 = int(params.evals[base + 2])
                            return ff3([c0, c1, c2])

            if type_arg == 1 and not domain_extended:
                if is_cyclic:
                    vals = [int(params.trace[((row + j + o) % domain_size) * n_cols + stage_pos])
                            for j in range(nrows_pack)]
                else:
                    offset_col = (row + o) * n_cols + stage_pos
                    vals = [int(params.trace[offset_col + j * n_cols]) for j in range(nrows_pack)]
                return FF(vals)

            if dim == 1:
                if is_cyclic:
                    vals = [int(params.auxTrace[offset + ((row + j + o) % domain_size) * n_cols + stage_pos])
                            for j in range(nrows_pack)]
                else:
                    offset_col = offset + (row + o) * n_cols + stage_pos
                    vals = [int(params.auxTrace[offset_col + j * n_cols]) for j in range(nrows_pack)]
                return FF(vals)

            # FF3
            ints = []
            if is_cyclic:
                for j in range(nrows_pack):
                    idx = (row + j + o) % domain_size
                    c0 = int(params.auxTrace[offset + idx * n_cols + stage_pos])
                    c1 = int(params.auxTrace[offset + idx * n_cols + stage_pos + 1])
                    c2 = int(params.auxTrace[offset + idx * n_cols + stage_pos + 2])
                    ints.append(c0 + c1 * p + c2 * p2)
            else:
                offset_col = offset + (row + o) * n_cols + stage_pos
                for j in range(nrows_pack):
                    c0 = int(params.auxTrace[offset_col + j * n_cols])
                    c1 = int(params.auxTrace[offset_col + j * n_cols + 1])
                    c2 = int(params.auxTrace[offset_col + j * n_cols + 2])
                    ints.append(c0 + c1 * p + c2 * p2)
            return FF3(ints)

        # Type nStages+2: Boundary values (x_n, zi)
        if type_arg == self.setup_ctx.stark_info.nStages + 2:
            boundary = args[i_args + 1]
            if self.setup_ctx.stark_info.verify:
                if boundary == 0:
                    c0 = int(self.prover_helpers.x_n[0])
                    c1 = int(self.prover_helpers.x_n[1])
                    c2 = int(self.prover_helpers.x_n[2])
                    scalar = ff3([c0, c1, c2])
                    return FF3([int(scalar)] * nrows_pack) if dim == 3 else FF([c0] * nrows_pack)
                else:
                    base = (boundary - 1) * FIELD_EXTENSION
                    c0 = int(self.prover_helpers.zi[base])
                    c1 = int(self.prover_helpers.zi[base + 1])
                    c2 = int(self.prover_helpers.zi[base + 2])
                    scalar = ff3([c0, c1, c2])
                    return FF3([int(scalar)] * nrows_pack)
            else:
                if boundary == 0:
                    x_vals = self.prover_helpers.x if domain_extended else self.prover_helpers.x_n
                    return FF(np.asarray(x_vals[row:row + nrows_pack], dtype=np.uint64))
                else:
                    ofs = (boundary - 1) * domain_size + row
                    return FF(np.asarray(self.prover_helpers.zi[ofs:ofs + nrows_pack], dtype=np.uint64))

        # Type nStages+3: Xi (x/(x-xi) for FRI)
        if type_arg == self.setup_ctx.stark_info.nStages + 3:
            o = args[i_args + 1]
            if self.setup_ctx.stark_info.verify:
                ints = []
                for k in range(nrows_pack):
                    base = ((row + k) * len(self.setup_ctx.stark_info.openingPoints) + o) * FIELD_EXTENSION
                    c0 = int(params.xDivXSub[base])
                    c1 = int(params.xDivXSub[base + 1])
                    c2 = int(params.xDivXSub[base + 2])
                    ints.append(c0 + c1 * p + c2 * p2)
                return FF3(ints)
            else:
                # Compute x/(x-xi)
                xi_c0 = int(self.xis[o * FIELD_EXTENSION])
                xi_c1 = int(self.xis[o * FIELD_EXTENSION + 1])
                xi_c2 = int(self.xis[o * FIELD_EXTENSION + 2])
                xi_val = ff3([xi_c0, xi_c1, xi_c2])

                x_vals = FF(np.asarray(self.prover_helpers.x[row:row + nrows_pack], dtype=np.uint64))
                x_ff3 = FF3(np.asarray(x_vals, dtype=np.uint64).tolist())
                diff = x_ff3 - xi_val
                return batch_inverse(diff)

        # Custom commits
        if (type_arg >= self.setup_ctx.stark_info.nStages + 4 and
            type_arg < len(self.setup_ctx.stark_info.customCommits) + self.setup_ctx.stark_info.nStages + 4):
            index = type_arg - (self.n_stages + 4)
            stage_pos = args[i_args + 1]
            offset = int(map_offsets_custom_exps[index])
            n_cols = int(self.map_sections_n_custom_fixed[index])
            o = next_strides_exps[args[i_args + 2]]

            if is_cyclic:
                vals = [int(params.customCommits[offset + ((row + j + o) % domain_size) * n_cols + stage_pos])
                        for j in range(nrows_pack)]
            else:
                offset_col = offset + (row + o) * n_cols + stage_pos
                vals = [int(params.customCommits[offset_col + j * n_cols]) for j in range(nrows_pack)]
            return FF(vals)

        # Temp registers
        if type_arg == self.buffer_commits_size:
            return tmp1_g[args[i_args + 1]]

        if type_arg == self.buffer_commits_size + 1:
            return tmp3_g[args[i_args + 1]]

        # Scalar values (publics, numbers, challenges, etc.)
        arr = scalar_params[type_arg]
        idx = args[i_args + 1]
        if dim == 1:
            return FF(int(arr[idx]))
        else:
            c0 = int(arr[idx])
            c1 = int(arr[idx + 1])
            c2 = int(arr[idx + 2])
            return ff3([c0, c1, c2])

    # --- Field Operations ---

    def _apply_op(self, op: int, a: GaloisValue, b: GaloisValue) -> GaloisValue:
        """Apply arithmetic operation, promoting to FF3 if needed."""
        # Check for field type mismatch
        a_ext = hasattr(a, '__class__') and '^3' in str(a.__class__)
        b_ext = hasattr(b, '__class__') and '^3' in str(b.__class__)

        if a_ext and not b_ext:
            b = FF3(int(b)) if hasattr(b, 'ndim') and b.ndim == 0 else FF3(np.asarray(b, dtype=np.uint64).tolist())
        elif b_ext and not a_ext:
            a = FF3(int(a)) if hasattr(a, 'ndim') and a.ndim == 0 else FF3(np.asarray(a, dtype=np.uint64).tolist())

        if op == OP_ADD:
            return a + b
        if op == OP_SUB:
            return a - b
        if op == OP_MUL:
            return a * b
        if op == OP_SUB_SWAP:
            return b - a
        raise ValueError(f"Invalid operation: {op}")

    def _apply_op_ext_base(self, op: int, a: FF3, b: GaloisValue) -> FF3:
        """Apply operation: FF3 x FF -> FF3 (embedding b as (b,0,0))."""
        if isinstance(b, FF):
            b = FF3(int(b)) if b.ndim == 0 else FF3(np.asarray(b, dtype=np.uint64).tolist())

        if op == OP_ADD:
            return a + b
        if op == OP_SUB:
            return a - b
        if op == OP_MUL:
            return a * b
        if op == OP_SUB_SWAP:
            return b - a
        raise ValueError(f"Invalid operation: {op}")

    def _multiply_results(self, a: GaloisValue, b: GaloisValue,
                          dim_a: int, dim_b: int, dest_dim: int) -> GaloisValue:
        """Multiply two results with proper field handling."""
        if dest_dim == 1:
            return a * b
        if dim_a == FIELD_EXTENSION and dim_b == FIELD_EXTENSION:
            return a * b
        if dim_a == FIELD_EXTENSION:
            return self._apply_op_ext_base(OP_MUL, a, b)
        return self._apply_op_ext_base(OP_MUL, b, a)

    def _store_result(self, dest: Dest, result: GaloisValue, row: int, nrows_pack: int):
        """Store result to destination buffer."""
        offset = dest.offset if dest.offset != 0 else (FIELD_EXTENSION if dest.dim == 3 else 1)

        if dest.dim == 1:
            if result.ndim == 0:
                val = int(result)
                for j in range(nrows_pack):
                    dest.dest[row * offset + j * offset] = val
            else:
                vals = np.asarray(result, dtype=np.uint64)
                for j in range(nrows_pack):
                    dest.dest[row * offset + j * offset] = vals[j]
        else:
            if result.ndim == 0:
                coeffs = ff3_coeffs(result)
                for j in range(nrows_pack):
                    base = row * offset + j * offset
                    dest.dest[base] = coeffs[0]
                    dest.dest[base + 1] = coeffs[1]
                    dest.dest[base + 2] = coeffs[2]
            else:
                # vector() returns [c2, c1, c0] (descending)
                vecs = result.vector()
                for j in range(nrows_pack):
                    base = row * offset + j * offset
                    dest.dest[base] = int(vecs[j, 2])
                    dest.dest[base + 1] = int(vecs[j, 1])
                    dest.dest[base + 2] = int(vecs[j, 0])
