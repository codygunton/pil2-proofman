"""Expression evaluation engine.

Faithful translation from:
- pil2-stark/src/starkpil/expressions_ctx.hpp
- pil2-stark/src/starkpil/expressions_pack.hpp

Evaluates compiled expression bytecode across polynomial domains.
This is the core constraint evaluation engine used by the STARK prover.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple
import numpy as np

from protocol.setup_ctx import SetupCtx, ProverHelpers, FIELD_EXTENSION
from protocol.steps_params import StepsParams
from protocol.expressions_bin import ParserParams, ParserArgs
from primitives.field import FF, FF3, ff3, ff3_coeffs, GOLDILOCKS_PRIME, batch_inverse
from typing import Union


# Number of rows to process in batch (C++ uses 128 for SIMD)
# Process entire domain at once for vectorization benefit
# The min() in calculate_expressions caps this to actual domain_size
NROWS_PACK = 1 << 16  # 65536, large enough for any test domain


# C++: pil2-stark/src/starkpil/expressions_ctx.hpp (operation constants)
class Operation(Enum):
    """Arithmetic operations.

    Corresponds to operation type values in args[i_args + 0].
    These are the same as CodeOperation::eOperation in expressions_info.hpp.
    """
    ADD = 0
    SUB = 1
    MUL = 2
    SUB_SWAP = 3


# C++: pil2-stark/src/starkpil/expressions_ctx.hpp::Params (lines 53-80)
@dataclass
class Params:
    """Expression evaluation parameters.

    Corresponds to C++ struct Params in expressions_ctx.hpp (lines 53-80).
    Used to specify operand sources in the calculateExpressions API.
    """
    exp_id: int = 0
    dim: int = 1
    stage: int = 0
    stage_pos: int = 0
    pols_map_id: int = 0
    row_offset_index: int = 0
    inverse: bool = False
    batch: bool = True
    op: str = "tmp"  # opType as string: "tmp", "cm", "const", "number", "airvalue"
    value: int = 0


# C++: pil2-stark/src/starkpil/expressions_ctx.hpp::Dest (lines 82-123)
@dataclass
class Dest:
    """Destination specification for expression evaluation.

    Corresponds to C++ struct Dest in expressions_ctx.hpp (lines 82-123).
    Specifies where to write evaluation results.
    """
    dest: np.ndarray = None  # Destination buffer
    exp_id: int = -1
    offset: int = 0
    stage_pos: int = 0
    stage_cols: int = 0
    expr: bool = False
    dim: int = 1
    domain_size: int = 0
    params: List[Params] = None

    # C++: Dest constructor logic
    def __post_init__(self):
        if self.params is None:
            self.params = []


# C++: pil2-stark/src/starkpil/expressions_ctx.hpp::ExpressionsCtx
class ExpressionsCtx:
    """Base context for expression evaluation.

    Corresponds to C++ class ExpressionsCtx in expressions_ctx.hpp (lines 125-244).

    Sets up memory layout mappings and stride calculations for accessing
    polynomial data during constraint evaluation.
    """

    # C++: ExpressionsCtx constructor
    def __init__(self, setup_ctx: SetupCtx, prover_helpers: Optional[ProverHelpers] = None,
                 n_queries: Optional[int] = None):
        """Initialize expressions context.

        Corresponds to C++ constructor (lines 152-207).

        Args:
            setup_ctx: Setup context with StarkInfo and ExpressionsBin
            prover_helpers: Precomputed prover helpers (zi, x, x_n)
            n_queries: Number of FRI queries (only used in verify mode)
        """
        self.setup_ctx = setup_ctx
        self.prover_helpers = prover_helpers
        self.n_queries = n_queries

        stark_info = setup_ctx.stark_info

        # Xi values for FRI division (set later via set_xi)
        self.xis: Optional[np.ndarray] = None

        # Stride calculations for opening points (lines 153-154)
        n_opening_points = len(stark_info.openingPoints)
        self.next_strides = np.zeros(n_opening_points, dtype=np.int64)
        self.next_strides_extended = np.zeros(n_opening_points, dtype=np.int64)

        # Offset mappings (lines 155-160)
        # Maps (section, extended) -> offset in aux_trace buffer
        # Index 0: const, 1..nStages+1: cm1..cmN
        self.map_offsets = np.zeros(1 + stark_info.nStages + 1, dtype=np.uint64)
        self.map_offsets_extended = np.zeros(1 + stark_info.nStages + 1, dtype=np.uint64)
        self.map_sections_n = np.zeros(1 + stark_info.nStages + 1, dtype=np.uint64)

        # Custom commit offsets (lines 157-160)
        n_custom = len(stark_info.customCommits)
        self.map_offsets_custom_fixed = np.zeros(n_custom, dtype=np.uint64)
        self.map_offsets_custom_fixed_extended = np.zeros(n_custom, dtype=np.uint64)
        self.map_sections_n_custom_fixed = np.zeros(n_custom, dtype=np.uint64)

        # Domain sizes (lines 162-165)
        N = 1 << stark_info.starkStruct.nBits
        N_extended = 1 << stark_info.starkStruct.nBitsExt
        extend = 1 << (stark_info.starkStruct.nBitsExt - stark_info.starkStruct.nBits)

        # Valid row ranges for cyclic constraints (lines 167-182)
        self.min_row = 0
        self.max_row = N
        self.min_row_extended = 0
        self.max_row_extended = N_extended

        # Compute strides for opening points (lines 172-182)
        for i in range(n_opening_points):
            # In verify mode, strides are 0 (verifier doesn't have full polynomials)
            if stark_info.verify:
                self.next_strides[i] = 0
                self.next_strides_extended[i] = 0
            else:
                self.next_strides[i] = stark_info.openingPoints[i]
                self.next_strides_extended[i] = stark_info.openingPoints[i] * extend

            # Adjust valid row range based on opening points
            if stark_info.openingPoints[i] < 0:
                self.min_row = max(self.min_row, abs(self.next_strides[i]))
                self.min_row_extended = max(self.min_row_extended, abs(self.next_strides_extended[i]))
            else:
                self.max_row = min(self.max_row, N - self.next_strides[i])
                self.max_row_extended = min(self.max_row_extended, N_extended - self.next_strides_extended[i])

        # Set up offset mappings (lines 184-194)
        # Constants (index 0)
        self.map_offsets[0] = stark_info.mapOffsets[("const", False)]
        # Extended offsets may not exist for all sections
        self.map_offsets_extended[0] = stark_info.mapOffsets.get(("const", True), 0)
        self.map_sections_n[0] = stark_info.mapSectionsN["const"]

        # FRI polynomial offset (line 188)
        # Not all AIRs have FRI polynomials (e.g., SimpleLeft has no FRI folding)
        self.map_offset_fri_pol = stark_info.mapOffsets.get(("f", True), 0)

        # Committed polynomials (stages 1..nStages+1)
        # In verify mode, compute offsets that don't overlap for n_queries entries
        verify_aux_offset = 0  # Running offset for verify mode aux_trace layout
        for i in range(stark_info.nStages + 1):
            section_name = f"cm{i + 1}"
            self.map_sections_n[i + 1] = stark_info.mapSectionsN[section_name]

            if stark_info.verify and n_queries is not None and i >= 1:
                # Verify mode: compute non-overlapping offsets for aux_trace (stages 2+)
                # Stage 1 (cm1) uses trace buffer directly, so offset doesn't matter
                self.map_offsets[i + 1] = verify_aux_offset
                verify_aux_offset += n_queries * stark_info.mapSectionsN[section_name]
            else:
                # Prover mode or cm1: use original offsets
                self.map_offsets[i + 1] = stark_info.mapOffsets[(section_name, False)]

            # Extended offsets may not exist for all sections
            self.map_offsets_extended[i + 1] = stark_info.mapOffsets.get((section_name, True), 0)

        # Custom commits (lines 196-200)
        for i in range(n_custom):
            cc = stark_info.customCommits[i]
            section_name = cc.name + "0"
            self.map_sections_n_custom_fixed[i] = stark_info.mapSectionsN[section_name]
            self.map_offsets_custom_fixed[i] = stark_info.mapOffsets[(section_name, False)]
            # Extended offsets may not exist for all sections
            self.map_offsets_custom_fixed_extended[i] = stark_info.mapOffsets.get((section_name, True), 0)

        # Buffer metadata (lines 202-206)
        self.buffer_commits_size = 1 + stark_info.nStages + 3 + len(stark_info.customCommits)
        self.n_stages = stark_info.nStages
        self.n_publics = stark_info.nPublics
        self.n_challenges = len(stark_info.challengesMap)
        self.n_evals = len(stark_info.evMap)

        # Pack size for batching (line 141 in expressions_pack.hpp)
        self.nrows_pack_ = min(NROWS_PACK, N)

    # C++: ExpressionsCtx::setXi
    def set_xi(self, xis: np.ndarray):
        """Set xi evaluation points for FRI division.

        Corresponds to C++ ExpressionsCtx::setXi() (lines 241-243).

        Args:
            xis: Xi values (n_opening_points × FIELD_EXTENSION)
        """
        self.xis = xis

    # C++: ExpressionsCtx::calculateExpression
    def calculate_expression(self, params: StepsParams, dest: np.ndarray,
                            expression_id: int, inverse: bool = False,
                            compilation_time: bool = False):
        """Calculate a single expression.

        Corresponds to C++ ExpressionsCtx::calculateExpression() (lines 222-239).

        This is a convenience wrapper that sets up a Dest struct and calls
        calculateExpressions().

        Args:
            params: Working parameters with all polynomial data
            dest: Destination buffer for results
            expression_id: Expression ID to evaluate
            inverse: Whether to invert the result
            compilation_time: Whether this is compilation-time evaluation
        """
        # Determine domain size and extension flag
        if compilation_time:
            domain_size = 1
            domain_extended = False
        elif expression_id in [self.setup_ctx.stark_info.cExpId,
                               self.setup_ctx.stark_info.friExpId]:
            # Constraint and FRI expressions use extended domain
            domain_size = 1 << self.setup_ctx.stark_info.starkStruct.nBitsExt
            domain_extended = True
            # Update dest_dim in expressions_info (C++ does this in-place)
            if expression_id in self.setup_ctx.expressions_bin.expressions_info:
                self.setup_ctx.expressions_bin.expressions_info[expression_id].dest_dim = 3
        else:
            domain_size = 1 << self.setup_ctx.stark_info.starkStruct.nBits
            domain_extended = False

        # Create Dest structure
        dest_struct = Dest(
            dest=dest,
            domain_size=domain_size,
            offset=0,
            exp_id=expression_id
        )

        # Add expression parameters
        exp_info = self.setup_ctx.expressions_bin.expressions_info[expression_id]
        param = Params(
            exp_id=expression_id,
            dim=exp_info.dest_dim,
            inverse=inverse,
            batch=True,
            op="tmp"
        )
        dest_struct.params.append(param)
        dest_struct.dim = max(dest_struct.dim, exp_info.dest_dim)

        # Call main evaluation
        self.calculate_expressions(params, dest_struct, domain_size, domain_extended, compilation_time)

    # C++: ExpressionsCtx::calculateExpressions
    def calculate_expressions(self, params: StepsParams, dest: Dest,
                             domain_size: int, domain_extended: bool,
                             compilation_time: bool = False,
                             verify_constraints: bool = False, debug: bool = False):
        """Evaluate expressions across domain.

        This is virtual in C++ (line 220). Overridden by ExpressionsPack.

        Args:
            params: Working parameters
            dest: Destination specification
            domain_size: Size of evaluation domain
            domain_extended: True for extended domain
            compilation_time: Compilation-time flag
            verify_constraints: Constraint verification mode
            debug: Debug output flag
        """
        raise NotImplementedError("Subclass must implement calculate_expressions")


# C++: pil2-stark/src/starkpil/expressions_pack.hpp::ExpressionsPack
class ExpressionsPack(ExpressionsCtx):
    """Expression evaluator with row batching.

    Corresponds to C++ class ExpressionsPack in expressions_pack.hpp (lines 9-511).

    Evaluates compiled expression bytecode across a polynomial domain,
    processing rows in batches for efficiency (though Python version uses batch=1).
    """

    # C++: ExpressionsPack constructor
    def __init__(self, setup_ctx: SetupCtx, prover_helpers: Optional[ProverHelpers] = None,
                 nrows_pack: int = NROWS_PACK, n_queries: Optional[int] = None):
        """Initialize expression pack evaluator.

        Corresponds to C++ constructor (lines 11-13).

        Args:
            setup_ctx: Setup context
            prover_helpers: Prover helpers
            nrows_pack: Number of rows to process per batch
            n_queries: Number of FRI queries (only used in verify mode)
        """
        super().__init__(setup_ctx, prover_helpers, n_queries)
        N = 1 << setup_ctx.stark_info.starkStruct.nBits
        self.nrows_pack_ = min(nrows_pack, N)

    # C++: ExpressionsPack::calculateExpressions (refactored to use native galois types)
    def calculate_expressions(self, params: StepsParams, dest: Dest,
                              domain_size: int, domain_extended: bool,
                              compilation_time: bool = False,
                              verify_constraints: bool = False, debug: bool = False):
        """Evaluate expressions across domain using native galois types.

        Refactored version that eliminates SoA layout - uses native FF/FF3 arrays
        throughout for cleaner code and potentially better performance.

        Args:
            params: Working parameters with all data
            dest: Destination specification
            domain_size: Evaluation domain size
            domain_extended: True for extended domain
            compilation_time: Compilation-time flag
            verify_constraints: Verify constraints mode
            debug: Debug flag
        """
        nrows_pack = min(self.nrows_pack_, domain_size)

        # Select offset mappings based on domain
        map_offsets_exps = self.map_offsets_extended if domain_extended else self.map_offsets
        map_offsets_custom_exps = (self.map_offsets_custom_fixed_extended
                                   if domain_extended else self.map_offsets_custom_fixed)
        next_strides_exps = self.next_strides_extended if domain_extended else self.next_strides

        # Compute valid row range for cyclic checks
        if domain_extended:
            k_min = ((self.min_row_extended + nrows_pack - 1) // nrows_pack) * nrows_pack
            k_max = (self.max_row_extended // nrows_pack) * nrows_pack
        else:
            k_min = ((self.min_row + nrows_pack - 1) // nrows_pack) * nrows_pack
            k_max = (self.max_row // nrows_pack) * nrows_pack

        # Select parser args
        parser_args = (self.setup_ctx.expressions_bin.expressions_bin_args_constraints
                      if verify_constraints
                      else self.setup_ctx.expressions_bin.expressions_bin_args_expressions)

        # Get parser params for each destination parameter
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

        # Scalar parameter arrays (for public inputs, numbers, etc.)
        scalar_params: Dict[int, np.ndarray] = {
            self.buffer_commits_size + 2: params.publicInputs,
            self.buffer_commits_size + 3: parser_args.numbers,
            self.buffer_commits_size + 4: params.airValues,
            self.buffer_commits_size + 5: params.proofValues,
            self.buffer_commits_size + 6: params.airgroupValues,
            self.buffer_commits_size + 7: params.challenges,
            self.buffer_commits_size + 8: params.evals,
        }

        # Main evaluation loop over rows
        for i in range(0, domain_size, nrows_pack):
            is_cyclic = (i < k_min) or (i >= k_max)

            # Native galois temp storage (replaces SoA buffers)
            tmp1_g: Dict[int, FF] = {}   # slot_id → FF array
            tmp3_g: Dict[int, FF3] = {}  # slot_id → FF3 array

            # Results for each dest param (up to 2)
            param_results: List[Union[FF, FF3, None]] = [None, None]
            param_dims: List[int] = [1, 1]

            # Process each destination parameter
            for k in range(len(dest.params)):
                # Handle direct polynomial access
                if dest.params[k].op in ["cm", "const"]:
                    result = self._load_direct_poly(
                        params, dest.params[k], i, nrows_pack, domain_size,
                        domain_extended, map_offsets_exps, next_strides_exps)
                    if dest.params[k].inverse:
                        result = self._get_inverse(result)
                    param_results[k] = result
                    param_dims[k] = dest.params[k].dim
                    continue

                # Handle number literals
                elif dest.params[k].op == "number":
                    param_results[k] = FF(dest.params[k].value)
                    param_dims[k] = 1
                    continue

                # Handle air values
                elif dest.params[k].op == "airvalue":
                    if dest.params[k].dim == 1:
                        param_results[k] = FF(int(params.airValues[dest.params[k].pols_map_id]))
                    else:
                        c0 = int(params.airValues[dest.params[k].pols_map_id])
                        c1 = int(params.airValues[dest.params[k].pols_map_id + 1])
                        c2 = int(params.airValues[dest.params[k].pols_map_id + 2])
                        param_results[k] = ff3([c0, c1, c2])
                    param_dims[k] = dest.params[k].dim
                    continue

                # Handle expression evaluation
                parser_params = parser_params_list[k]
                if parser_params is None:
                    continue

                ops = parser_args.ops[parser_params.ops_offset:]
                args = parser_args.args[parser_params.args_offset:]

                i_args = 0

                for kk in range(parser_params.n_ops):
                    op_type = ops[kk]
                    is_last = (kk == parser_params.n_ops - 1)

                    if op_type == 0:
                        # dim1 × dim1 → dim1
                        a = self._load_galois(params, scalar_params, tmp1_g, tmp3_g, args,
                                             map_offsets_exps, map_offsets_custom_exps,
                                             next_strides_exps, i_args + 2, i, 1,
                                             domain_size, domain_extended, is_cyclic, nrows_pack)
                        b = self._load_galois(params, scalar_params, tmp1_g, tmp3_g, args,
                                             map_offsets_exps, map_offsets_custom_exps,
                                             next_strides_exps, i_args + 5, i, 1,
                                             domain_size, domain_extended, is_cyclic, nrows_pack)
                        result = self._goldilocks_op(args[i_args], a, b)
                        if is_last:
                            param_results[k] = result
                            param_dims[k] = 1
                        else:
                            tmp1_g[args[i_args + 1]] = result
                        i_args += 8

                    elif op_type == 1:
                        # dim3 × dim1 → dim3
                        a = self._load_galois(params, scalar_params, tmp1_g, tmp3_g, args,
                                             map_offsets_exps, map_offsets_custom_exps,
                                             next_strides_exps, i_args + 2, i, 3,
                                             domain_size, domain_extended, is_cyclic, nrows_pack)
                        b = self._load_galois(params, scalar_params, tmp1_g, tmp3_g, args,
                                             map_offsets_exps, map_offsets_custom_exps,
                                             next_strides_exps, i_args + 5, i, 1,
                                             domain_size, domain_extended, is_cyclic, nrows_pack)
                        result = self._goldilocks3_op_31(args[i_args], a, b)
                        if is_last:
                            param_results[k] = result
                            param_dims[k] = 3
                        else:
                            tmp3_g[args[i_args + 1]] = result
                        i_args += 8

                    elif op_type == 2:
                        # dim3 × dim3 → dim3
                        a = self._load_galois(params, scalar_params, tmp1_g, tmp3_g, args,
                                             map_offsets_exps, map_offsets_custom_exps,
                                             next_strides_exps, i_args + 2, i, 3,
                                             domain_size, domain_extended, is_cyclic, nrows_pack)
                        b = self._load_galois(params, scalar_params, tmp1_g, tmp3_g, args,
                                             map_offsets_exps, map_offsets_custom_exps,
                                             next_strides_exps, i_args + 5, i, 3,
                                             domain_size, domain_extended, is_cyclic, nrows_pack)
                        result = self._goldilocks3_op(args[i_args], a, b)
                        if is_last:
                            param_results[k] = result
                            param_dims[k] = 3
                        else:
                            tmp3_g[args[i_args + 1]] = result
                        i_args += 8

                    else:
                        raise ValueError(f"Invalid operation type: {op_type}")

                assert i_args == parser_params.n_args, f"Args mismatch: {i_args} != {parser_params.n_args}"

                # Apply inverse if needed
                if dest.params[k].inverse:
                    param_results[k] = self._get_inverse(param_results[k])

            # Multiply two parameters if present
            if len(dest.params) == 2:
                final_result = self._multiply_galois(param_results[0], param_results[1],
                                                     param_dims[0], param_dims[1], dest.dim)
            else:
                final_result = param_results[0]

            # Store result to destination
            self._store_galois(dest, final_result, i, nrows_pack)

    def _load_direct_poly(self, params: StepsParams, param: Params, row: int,
                          nrows_pack: int, domain_size: int, domain_extended: bool,
                          map_offsets_exps: np.ndarray, next_strides_exps: np.ndarray
                          ) -> Union[FF, FF3]:
        """Load polynomial values directly from cm/const buffers.

        Returns native FF or FF3 galois array.
        """
        o = int(next_strides_exps[param.row_offset_index])

        if param.op == "const":
            n_cols = int(self.map_sections_n[0])
            const_buffer = params.constPolsExtended if domain_extended else params.constPols
            vals = [int(const_buffer[(row + r + o) % domain_size * n_cols + param.stage_pos])
                    for r in range(nrows_pack)]
            return FF(vals)
        else:
            offset = int(map_offsets_exps[param.stage])
            n_cols = int(self.map_sections_n[param.stage])

            if param.stage == 1 and not domain_extended:
                vals = [int(params.trace[((row + r + o) % domain_size) * n_cols + param.stage_pos])
                        for r in range(nrows_pack)]
                return FF(vals)
            elif param.dim == 1:
                vals = [int(params.auxTrace[offset + ((row + r + o) % domain_size) * n_cols + param.stage_pos])
                        for r in range(nrows_pack)]
                return FF(vals)
            else:
                # FF3 - load all three coefficients
                p = GOLDILOCKS_PRIME
                p2 = p * p
                ints = []
                for r in range(nrows_pack):
                    l = (row + r + o) % domain_size
                    c0 = int(params.auxTrace[offset + l * n_cols + param.stage_pos])
                    c1 = int(params.auxTrace[offset + l * n_cols + param.stage_pos + 1])
                    c2 = int(params.auxTrace[offset + l * n_cols + param.stage_pos + 2])
                    ints.append(c0 + c1 * p + c2 * p2)
                return FF3(ints)

    def _load_galois(self, params: StepsParams, scalar_params: Dict[int, np.ndarray],
                     tmp1_g: Dict[int, FF], tmp3_g: Dict[int, FF3],
                     args: np.ndarray, map_offsets_exps: np.ndarray,
                     map_offsets_custom_exps: np.ndarray, next_strides_exps: np.ndarray,
                     i_args: int, row: int, dim: int, domain_size: int,
                     domain_extended: bool, is_cyclic: bool, nrows_pack: int
                     ) -> Union[FF, FF3]:
        """Load operand as native galois type (FF or FF3).

        Replaces _load() with native galois return types.
        """
        type_arg = args[i_args]
        p = GOLDILOCKS_PRIME
        p2 = p * p


        # Type 0: Constant polynomials
        if type_arg == 0:
            stage_pos = args[i_args + 1]
            opening_idx = args[i_args + 2]
            o = next_strides_exps[opening_idx]
            n_cols = int(self.map_sections_n[0])

            # In verify mode with domain_size=1, load from evals
            if self.setup_ctx.stark_info.verify and domain_size == 1:
                # Find the polynomial id in constPolsMap by stagePos
                pol_id = None
                for idx, p in enumerate(self.setup_ctx.stark_info.constPolsMap):
                    if p.stagePos == stage_pos:
                        pol_id = idx
                        break

                if pol_id is not None:
                    # Find evMap entry for this constant polynomial and opening
                    opening_point = opening_idx
                    ev_id = None
                    from primitives.pol_map import EvMap
                    for idx, e in enumerate(self.setup_ctx.stark_info.evMap):
                        if e.type == EvMap.Type.const_ and e.id == pol_id and e.openingPos == opening_point:
                            ev_id = idx
                            break

                    if ev_id is not None:
                        # Read from evals - always return FF3
                        # In verify mode, evaluations at xi are field extension elements
                        # even for polynomials with dim=1.
                        base = ev_id * FIELD_EXTENSION
                        c0 = int(params.evals[base])
                        c1 = int(params.evals[base + 1])
                        c2 = int(params.evals[base + 2])
                        return ff3([c0, c1, c2])

            # Fallback: load from constPols buffer
            const_pols = params.constPolsExtended if domain_extended else params.constPols
            if is_cyclic:
                vals = [int(const_pols[((row + j + o) % domain_size) * self.setup_ctx.stark_info.nConstants + stage_pos])
                        for j in range(nrows_pack)]
            else:
                offset_col = (row + o) * n_cols + stage_pos
                vals = [int(const_pols[offset_col + j * n_cols]) for j in range(nrows_pack)]
            return FF(vals)

        # Types 1..nStages+1: Committed polynomials
        elif type_arg <= self.setup_ctx.stark_info.nStages + 1:
            stage_pos = args[i_args + 1]
            offset = int(map_offsets_exps[type_arg])
            n_cols = int(self.map_sections_n[type_arg])
            opening_idx = args[i_args + 2]
            o = next_strides_exps[opening_idx]

            # In verify mode with domain_size=1, load from evals instead of trace
            if self.setup_ctx.stark_info.verify and domain_size == 1:
                # Find the polynomial id in cmPolsMap by matching stage and stagePos
                stage = type_arg
                pol_id = None
                for idx, p in enumerate(self.setup_ctx.stark_info.cmPolsMap):
                    if p.stage == stage and p.stagePos == stage_pos:
                        pol_id = idx
                        break

                if pol_id is not None:
                    # Find evMap entry for this polynomial and opening
                    opening_point = opening_idx  # opening index in openingPoints
                    ev_id = None
                    from primitives.pol_map import EvMap
                    for idx, e in enumerate(self.setup_ctx.stark_info.evMap):
                        if e.type == EvMap.Type.cm and e.id == pol_id and e.openingPos == opening_point:
                            ev_id = idx
                            break

                    if ev_id is not None:
                        # Read from evals - always return FF3
                        # In verify mode, evaluations at xi are field extension elements
                        # even for polynomials with dim=1. The caller (_goldilocks3_op_31)
                        # handles FF3 inputs correctly.
                        base = ev_id * FIELD_EXTENSION
                        c0 = int(params.evals[base])
                        c1 = int(params.evals[base + 1])
                        c2 = int(params.evals[base + 2])
                        return ff3([c0, c1, c2])

                # Fallback: if not found in evMap, load from trace/auxTrace
                # This handles polynomials that aren't part of the opening

            if type_arg == 1 and not domain_extended:
                if is_cyclic:
                    vals = [int(params.trace[((row + j + o) % domain_size) * n_cols + stage_pos])
                            for j in range(nrows_pack)]
                else:
                    offset_col = (row + o) * n_cols + stage_pos
                    vals = [int(params.trace[offset_col + j * n_cols]) for j in range(nrows_pack)]
                return FF(vals)
            elif dim == 1:
                if is_cyclic:
                    vals = [int(params.auxTrace[offset + ((row + j + o) % domain_size) * n_cols + stage_pos])
                            for j in range(nrows_pack)]
                else:
                    offset_col = offset + (row + o) * n_cols + stage_pos
                    vals = [int(params.auxTrace[offset_col + j * n_cols]) for j in range(nrows_pack)]
                return FF(vals)
            else:
                # FF3
                ints = []
                if is_cyclic:
                    for j in range(nrows_pack):
                        l = (row + j + o) % domain_size
                        c0 = int(params.auxTrace[offset + l * n_cols + stage_pos])
                        c1 = int(params.auxTrace[offset + l * n_cols + stage_pos + 1])
                        c2 = int(params.auxTrace[offset + l * n_cols + stage_pos + 2])
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
        elif type_arg == self.setup_ctx.stark_info.nStages + 2:
            boundary = args[i_args + 1]
            if self.setup_ctx.stark_info.verify:
                if boundary == 0:
                    # x_n: C++ only loads first component for dim=1 case
                    c0 = int(self.prover_helpers.x_n[0])
                    c1 = int(self.prover_helpers.x_n[1])
                    c2 = int(self.prover_helpers.x_n[2])
                    scalar = ff3([c0, c1, c2])
                    return FF3([int(scalar)] * nrows_pack) if dim == 3 else FF([c0] * nrows_pack)
                else:
                    # zi: C++ always loads all FIELD_EXTENSION components in verify mode
                    # regardless of dim (expressions_pack.hpp lines 106-111)
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
                    offset = (boundary - 1) * domain_size + row
                    return FF(np.asarray(self.prover_helpers.zi[offset:offset + nrows_pack], dtype=np.uint64))

        # Type nStages+3: Xi values for FRI
        elif type_arg == self.setup_ctx.stark_info.nStages + 3:
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
                # Compute x/(x-xi) on the fly
                xi_c0 = int(self.xis[o * FIELD_EXTENSION])
                xi_c1 = int(self.xis[o * FIELD_EXTENSION + 1])
                xi_c2 = int(self.xis[o * FIELD_EXTENSION + 2])
                xi_val = ff3([xi_c0, xi_c1, xi_c2])

                x_vals = FF(np.asarray(self.prover_helpers.x[row:row + nrows_pack], dtype=np.uint64))
                # Embed x in FF3: (x, 0, 0)
                x_ff3 = FF3(np.asarray(x_vals, dtype=np.uint64).tolist())

                # Compute x - xi
                diff = x_ff3 - xi_val
                # Invert to get 1/(x - xi)
                return self._get_inverse(diff)

        # Custom commits
        elif (type_arg >= self.setup_ctx.stark_info.nStages + 4 and
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

        # tmp1 (scalar temps)
        elif type_arg == self.buffer_commits_size:
            return tmp1_g[args[i_args + 1]]

        # tmp3 (field extension temps)
        elif type_arg == self.buffer_commits_size + 1:
            return tmp3_g[args[i_args + 1]]

        # Scalar values (public inputs, numbers, air values, etc.)
        else:
            arr = scalar_params[type_arg]
            idx = args[i_args + 1]
            if dim == 1:
                return FF(int(arr[idx]))
            else:
                c0 = int(arr[idx])
                c1 = int(arr[idx + 1])
                c2 = int(arr[idx + 2])
                return ff3([c0, c1, c2])

    def _multiply_galois(self, a: Union[FF, FF3], b: Union[FF, FF3],
                         dim_a: int, dim_b: int, dest_dim: int) -> Union[FF, FF3]:
        """Multiply two galois values with proper type handling."""
        if dest_dim == 1:
            return a * b
        elif dim_a == FIELD_EXTENSION and dim_b == FIELD_EXTENSION:
            return a * b
        elif dim_a == FIELD_EXTENSION:
            return self._goldilocks3_op_31(Operation.MUL.value, a, b)
        else:
            return self._goldilocks3_op_31(Operation.MUL.value, b, a)

    def _store_galois(self, dest: Dest, result: Union[FF, FF3], row: int, nrows_pack: int):
        """Store galois result to destination buffer."""
        offset = dest.offset if dest.offset != 0 else (FIELD_EXTENSION if dest.dim == 3 else 1)

        if dest.dim == 1:
            if result.ndim == 0:
                # Scalar - broadcast to all rows
                val = int(result)
                for j in range(nrows_pack):
                    dest.dest[row * offset + j * offset] = val
            else:
                vals = np.asarray(result, dtype=np.uint64)
                for j in range(nrows_pack):
                    dest.dest[row * offset + j * offset] = vals[j]
        else:
            if result.ndim == 0:
                # Scalar FF3 - broadcast
                coeffs = ff3_coeffs(result)
                for j in range(nrows_pack):
                    base = row * offset + j * offset
                    dest.dest[base] = coeffs[0]
                    dest.dest[base + 1] = coeffs[1]
                    dest.dest[base + 2] = coeffs[2]
            else:
                vecs = result.vector()  # Shape (nrows_pack, 3), descending [c2, c1, c0]
                for j in range(nrows_pack):
                    base = row * offset + j * offset
                    dest.dest[base] = int(vecs[j, 2])      # c0
                    dest.dest[base + 1] = int(vecs[j, 1])  # c1
                    dest.dest[base + 2] = int(vecs[j, 0])  # c2

    # C++: ExpressionsPack inverse polynomial handling (native galois)
    def _get_inverse(self, vals: Union[FF, FF3]) -> Union[FF, FF3]:
        """Compute inverse of field values using Montgomery batch inversion.

        Args:
            vals: FF or FF3 scalar/array to invert

        Returns:
            Inverted values (same type as input)
        """
        return batch_inverse(vals)

    # C++: ExpressionsPack Goldilocks operations (native galois)
    def _goldilocks_op(self, op: int, a: Union[FF, FF3], b: Union[FF, FF3]) -> Union[FF, FF3]:
        """Execute Goldilocks field operation (vectorized).

        In verify mode, operands may be FF3 even when dim=1 is specified,
        because evaluations at xi are field extension elements. We promote
        FF operands to FF3 when needed.

        Args:
            op: Operation (0=add, 1=sub, 2=mul, 3=sub_swap)
            a: First operand (FF or FF3 scalar/array)
            b: Second operand (FF or FF3 scalar/array)

        Returns:
            FF or FF3 result
        """
        # Check if operands are in different fields (FF vs FF3)
        a_is_ext = hasattr(a, '__class__') and '^3' in str(a.__class__)
        b_is_ext = hasattr(b, '__class__') and '^3' in str(b.__class__)

        if a_is_ext and not b_is_ext:
            # Promote b to FF3
            if hasattr(b, 'ndim') and b.ndim == 0:
                b = FF3(int(b))
            else:
                b = FF3(np.asarray(b, dtype=np.uint64).tolist())
        elif b_is_ext and not a_is_ext:
            # Promote a to FF3
            if hasattr(a, 'ndim') and a.ndim == 0:
                a = FF3(int(a))
            else:
                a = FF3(np.asarray(a, dtype=np.uint64).tolist())

        if op == 0:   return a + b
        elif op == 1: return a - b
        elif op == 2: return a * b
        elif op == 3: return b - a
        else:
            raise ValueError(f"Invalid operation: {op}")

    # C++: ExpressionsPack Goldilocks3 operations (native galois)
    def _goldilocks3_op(self, op: int, a: FF3, b: FF3) -> FF3:
        """Execute Goldilocks3 field extension operation (dim3 × dim3, vectorized).

        Args:
            op: Operation (0=add, 1=sub, 2=mul, 3=sub_swap)
            a: First operand (FF3 scalar or array)
            b: Second operand (FF3 scalar or array)

        Returns:
            FF3 result
        """
        if op == 0:   return a + b
        elif op == 1: return a - b
        elif op == 2: return a * b
        elif op == 3: return b - a
        else:
            raise ValueError(f"Invalid operation: {op}")

    # C++: ExpressionsPack Goldilocks3x1 operations (native galois)
    def _goldilocks3_op_31(self, op: int, a: FF3, b: Union[FF, FF3]) -> FF3:
        """Execute Goldilocks3 operation: FF3 × FF → FF3.

        Operand a is FF3 (dim=3), operand b is FF (dim=1, embedded as (b,0,0)).

        Args:
            op: Operation (0=add, 1=sub, 2=mul, 3=sub_swap)
            a: First operand (FF3 scalar or array)
            b: Second operand (FF scalar/array, embedded in FF3 as (b,0,0))

        Returns:
            FF3 result
        """
        # Embed FF in FF3: for Goldilocks extension, FF3 integer encoding is c0 + c1*p + c2*p^2
        # When c1=c2=0, the integer value equals c0, so FF value can be used directly
        if isinstance(b, FF):
            # Convert FF to FF3 by using integer values directly (c1=c2=0 means int = c0)
            if b.ndim == 0:
                # Scalar FF → scalar FF3
                ff3_b = FF3(int(b))
            else:
                # Array FF → array FF3
                ff3_b = FF3(np.asarray(b, dtype=np.uint64).tolist())
        else:
            ff3_b = b

        if op == 0:   return a + ff3_b
        elif op == 1: return a - ff3_b
        elif op == 2: return a * ff3_b
        elif op == 3: return ff3_b - a
        else:
            raise ValueError(f"Invalid operation: {op}")
