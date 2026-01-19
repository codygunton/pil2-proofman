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

from tests.setup_ctx import SetupCtx, ProverHelpers, FIELD_EXTENSION
from tests.steps_params import StepsParams
from tests.expressions_bin import ParserParams, ParserArgs
from primitives.field import FF, FF3, ff3, ff3_coeffs


# Number of rows to process in batch (C++ uses 128 for SIMD)
# In Python without SIMD, we process row-by-row (set to 1)
NROWS_PACK = 1


class Operation(Enum):
    """Arithmetic operations.

    Corresponds to operation type values in args[i_args + 0].
    These are the same as CodeOperation::eOperation in expressions_info.hpp.
    """
    ADD = 0
    SUB = 1
    MUL = 2
    SUB_SWAP = 3


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

    def __post_init__(self):
        if self.params is None:
            self.params = []


class ExpressionsCtx:
    """Base context for expression evaluation.

    Corresponds to C++ class ExpressionsCtx in expressions_ctx.hpp (lines 125-244).

    Sets up memory layout mappings and stride calculations for accessing
    polynomial data during constraint evaluation.
    """

    def __init__(self, setup_ctx: SetupCtx, prover_helpers: Optional[ProverHelpers] = None):
        """Initialize expressions context.

        Corresponds to C++ constructor (lines 152-207).

        Args:
            setup_ctx: Setup context with StarkInfo and ExpressionsBin
            prover_helpers: Precomputed prover helpers (zi, x, x_n)
        """
        self.setup_ctx = setup_ctx
        self.prover_helpers = prover_helpers

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
        for i in range(stark_info.nStages + 1):
            section_name = f"cm{i + 1}"
            self.map_sections_n[i + 1] = stark_info.mapSectionsN[section_name]
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

    def set_xi(self, xis: np.ndarray):
        """Set xi evaluation points for FRI division.

        Corresponds to C++ ExpressionsCtx::setXi() (lines 241-243).

        Args:
            xis: Xi values (n_opening_points × FIELD_EXTENSION)
        """
        self.xis = xis

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


class ExpressionsPack(ExpressionsCtx):
    """Expression evaluator with row batching.

    Corresponds to C++ class ExpressionsPack in expressions_pack.hpp (lines 9-511).

    Evaluates compiled expression bytecode across a polynomial domain,
    processing rows in batches for efficiency (though Python version uses batch=1).
    """

    def __init__(self, setup_ctx: SetupCtx, prover_helpers: Optional[ProverHelpers] = None,
                 nrows_pack: int = NROWS_PACK):
        """Initialize expression pack evaluator.

        Corresponds to C++ constructor (lines 11-13).

        Args:
            setup_ctx: Setup context
            prover_helpers: Prover helpers
            nrows_pack: Number of rows to process per batch
        """
        super().__init__(setup_ctx, prover_helpers)
        N = 1 << setup_ctx.stark_info.starkStruct.nBits
        self.nrows_pack_ = min(nrows_pack, N)

    def calculate_expressions(self, params: StepsParams, dest: Dest,
                              domain_size: int, domain_extended: bool,
                              compilation_time: bool = False,
                              verify_constraints: bool = False, debug: bool = False):
        """Evaluate expressions across domain.

        Corresponds to C++ ExpressionsPack::calculateExpressions()
        (lines 312-510 of expressions_pack.hpp).

        Main evaluation algorithm:
        1. For each batch of rows:
           a. Determine if cyclic wrapping is needed
           b. For each destination parameter:
              - If it's a direct polynomial access (cm/const), load values
              - If it's a temporary expression, execute operation chain
           c. If two parameters, multiply them together
           d. Store result to destination

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

        # Select offset mappings based on domain (lines 315-317)
        map_offsets_exps = self.map_offsets_extended if domain_extended else self.map_offsets
        map_offsets_custom_exps = (self.map_offsets_custom_fixed_extended
                                   if domain_extended else self.map_offsets_custom_fixed)
        next_strides_exps = self.next_strides_extended if domain_extended else self.next_strides

        # Compute valid row range for cyclic checks (lines 319-324)
        if domain_extended:
            k_min = ((self.min_row_extended + nrows_pack - 1) // nrows_pack) * nrows_pack
            k_max = (self.max_row_extended // nrows_pack) * nrows_pack
        else:
            k_min = ((self.min_row + nrows_pack - 1) // nrows_pack) * nrows_pack
            k_max = (self.max_row // nrows_pack) * nrows_pack

        # Select parser args (expressions vs constraints) (line 327)
        parser_args = (self.setup_ctx.expressions_bin.expressions_bin_args_constraints
                      if verify_constraints
                      else self.setup_ctx.expressions_bin.expressions_bin_args_expressions)

        # Get parser params for each destination parameter (lines 328-346)
        parser_params_list: List[Optional[ParserParams]] = []
        max_temp1_size = 0
        max_temp3_size = 0

        assert len(dest.params) in [1, 2], "dest.params must have 1 or 2 parameters"

        for k in range(len(dest.params)):
            if dest.params[k].op != "tmp":
                parser_params_list.append(None)
                continue

            # Get parser params for this expression
            if verify_constraints:
                parser_params = self.setup_ctx.expressions_bin.constraints_info_debug[dest.params[k].exp_id]
            else:
                parser_params = self.setup_ctx.expressions_bin.expressions_info[dest.params[k].exp_id]

            parser_params_list.append(parser_params)

            # Track maximum temporary storage needed
            if parser_params.n_temp1 * nrows_pack > max_temp1_size:
                max_temp1_size = parser_params.n_temp1 * nrows_pack
            if parser_params.n_temp3 * nrows_pack * FIELD_EXTENSION > max_temp3_size:
                max_temp3_size = parser_params.n_temp3 * nrows_pack * FIELD_EXTENSION

        # Note: C++ reads offsets from mapOffsets for tmp1, tmp3, values buffers.
        # In Python, we allocate these fresh each row batch (lines 402-408 below).

        # Main evaluation loop over rows (line 352)
        # In C++, this is parallelized with OpenMP. In Python, we run sequentially.
        for i in range(0, domain_size, nrows_pack):
            # Check if we're in cyclic region (line 353)
            is_cyclic = (i < k_min) or (i >= k_max)

            # Set up expression parameter pointers (lines 354-362)
            # These map to different data sources
            expressions_params_size = self.buffer_commits_size + 9
            expressions_params: Dict[int, np.ndarray] = {}
            expressions_params[self.buffer_commits_size + 2] = params.publicInputs
            expressions_params[self.buffer_commits_size + 3] = parser_args.numbers
            expressions_params[self.buffer_commits_size + 4] = params.airValues
            expressions_params[self.buffer_commits_size + 5] = params.proofValues
            expressions_params[self.buffer_commits_size + 6] = params.airgroupValues
            expressions_params[self.buffer_commits_size + 7] = params.challenges
            expressions_params[self.buffer_commits_size + 8] = params.evals

            # Allocate values buffer for this row batch (line 364)
            # values[0..FIELD_EXTENSION*nrows_pack]: first operand
            # values[FIELD_EXTENSION*nrows_pack..2*FIELD_EXTENSION*nrows_pack]: second operand
            # values[2*FIELD_EXTENSION*nrows_pack..3*FIELD_EXTENSION*nrows_pack]: result buffer
            values = np.zeros(3 * FIELD_EXTENSION * nrows_pack, dtype=np.uint64)

            # Allocate temporary storage for this row batch
            tmp1 = np.zeros(max_temp1_size, dtype=np.uint64)
            tmp3 = np.zeros(max_temp3_size, dtype=np.uint64)
            expressions_params[self.buffer_commits_size] = tmp1
            expressions_params[self.buffer_commits_size + 1] = tmp3

            # Process each destination parameter (line 365)
            for k in range(len(dest.params)):
                # Handle direct polynomial access (lines 367-401)
                if dest.params[k].op in ["cm", "const"]:
                    opening_point_index = dest.params[k].row_offset_index
                    stage_pos = dest.params[k].stage_pos
                    o = int(next_strides_exps[opening_point_index])

                    if dest.params[k].op == "const":
                        # Load from constant polynomials (lines 372-376)
                        n_cols = int(self.map_sections_n[0])
                        # Use extended constants for extended domain
                        const_buffer = params.constPolsExtended if domain_extended else params.constPols
                        for r in range(nrows_pack):
                            l = (i + r + o) % domain_size
                            values[k * FIELD_EXTENSION * nrows_pack + r] = const_buffer[l * n_cols + stage_pos]
                    else:
                        # Load from committed polynomials (lines 377-395)
                        offset = int(map_offsets_exps[dest.params[k].stage])
                        n_cols = int(self.map_sections_n[dest.params[k].stage])

                        for r in range(nrows_pack):
                            l = (i + r + o) % domain_size

                            if dest.params[k].stage == 1 and not domain_extended:
                                # Stage 1 uses trace buffer (non-extended domain only)
                                values[k * FIELD_EXTENSION * nrows_pack + r] = params.trace[l * n_cols + stage_pos]
                            else:
                                # Other stages (and stage 1 in extended domain) use aux_trace
                                for d in range(dest.params[k].dim):
                                    values[k * FIELD_EXTENSION * nrows_pack + r + d * nrows_pack] = \
                                        params.aux_trace[offset + l * n_cols + stage_pos + d]

                    # Apply inverse if requested (lines 398-400)
                    if dest.params[k].inverse:
                        self._get_inverse_polynomial(nrows_pack,
                                                     values[k * FIELD_EXTENSION * nrows_pack:],
                                                     values[2 * FIELD_EXTENSION * nrows_pack:],
                                                     dest.params[k].batch, dest.params[k].dim)

                    continue

                # Handle number literals (lines 402-407)
                elif dest.params[k].op == "number":
                    values[k * FIELD_EXTENSION * nrows_pack] = dest.params[k].value
                    continue

                # Handle air values (lines 408-417)
                elif dest.params[k].op == "airvalue":
                    if dest.params[k].dim == 1:
                        values[k * FIELD_EXTENSION * nrows_pack] = params.airValues[dest.params[k].pols_map_id]
                    else:
                        values[k * FIELD_EXTENSION * nrows_pack] = params.airValues[dest.params[k].pols_map_id]
                        values[k * FIELD_EXTENSION * nrows_pack + nrows_pack] = params.airValues[dest.params[k].pols_map_id + 1]
                        values[k * FIELD_EXTENSION * nrows_pack + 2 * nrows_pack] = params.airValues[dest.params[k].pols_map_id + 2]
                    continue

                # Handle expression evaluation (lines 419-491)
                parser_params = parser_params_list[k]
                if parser_params is None:
                    continue

                # Get operation bytecode (lines 419-420)
                ops = parser_args.ops[parser_params.ops_offset:]
                args = parser_args.args[parser_params.args_offset:]

                # Execute operation chain (lines 427-483)
                value_a = values[FIELD_EXTENSION * nrows_pack:2 * FIELD_EXTENSION * nrows_pack]
                value_b = values[2 * FIELD_EXTENSION * nrows_pack:3 * FIELD_EXTENSION * nrows_pack]

                i_args = 0
                for kk in range(parser_params.n_ops):
                    op_type = ops[kk]

                    if op_type == 0:
                        # dim1 × dim1 → dim1 (lines 430-444)
                        a = self._load(params, expressions_params, args, map_offsets_exps,
                                      map_offsets_custom_exps, next_strides_exps,
                                      i_args + 2, i, 1, domain_size, domain_extended, is_cyclic,
                                      value_a, debug)
                        b = self._load(params, expressions_params, args, map_offsets_exps,
                                      map_offsets_custom_exps, next_strides_exps,
                                      i_args + 5, i, 1, domain_size, domain_extended, is_cyclic,
                                      value_b, debug)

                        is_constant_a = args[i_args + 2] > self.buffer_commits_size + 1
                        is_constant_b = args[i_args + 5] > self.buffer_commits_size + 1

                        # Result goes to final destination or temp buffer
                        if kk == parser_params.n_ops - 1:
                            res = values[k * FIELD_EXTENSION * nrows_pack:(k + 1) * FIELD_EXTENSION * nrows_pack]
                        else:
                            res_idx = args[i_args + 1] * nrows_pack
                            res = tmp1[res_idx:res_idx + nrows_pack]

                        self._goldilocks_op_pack(nrows_pack, args[i_args], res, a, is_constant_a, b, is_constant_b)
                        i_args += 8

                    elif op_type == 1:
                        # dim3 × dim1 → dim3 (lines 446-460)
                        a = self._load(params, expressions_params, args, map_offsets_exps,
                                      map_offsets_custom_exps, next_strides_exps,
                                      i_args + 2, i, 3, domain_size, domain_extended, is_cyclic,
                                      value_a, debug)
                        b = self._load(params, expressions_params, args, map_offsets_exps,
                                      map_offsets_custom_exps, next_strides_exps,
                                      i_args + 5, i, 1, domain_size, domain_extended, is_cyclic,
                                      value_b, debug)

                        is_constant_a = args[i_args + 2] > self.buffer_commits_size + 1
                        is_constant_b = args[i_args + 5] > self.buffer_commits_size + 1

                        if kk == parser_params.n_ops - 1:
                            res = values[k * FIELD_EXTENSION * nrows_pack:(k + 1) * FIELD_EXTENSION * nrows_pack]
                        else:
                            res_idx = args[i_args + 1] * nrows_pack
                            res = tmp3[res_idx:res_idx + FIELD_EXTENSION * nrows_pack]

                        self._goldilocks3_op_31_pack(nrows_pack, args[i_args], res, a, is_constant_a, b, is_constant_b)
                        i_args += 8

                    elif op_type == 2:
                        # dim3 × dim3 → dim3 (lines 462-476)
                        a = self._load(params, expressions_params, args, map_offsets_exps,
                                      map_offsets_custom_exps, next_strides_exps,
                                      i_args + 2, i, 3, domain_size, domain_extended, is_cyclic,
                                      value_a, debug)
                        b = self._load(params, expressions_params, args, map_offsets_exps,
                                      map_offsets_custom_exps, next_strides_exps,
                                      i_args + 5, i, 3, domain_size, domain_extended, is_cyclic,
                                      value_b, debug)

                        is_constant_a = args[i_args + 2] > self.buffer_commits_size + 1
                        is_constant_b = args[i_args + 5] > self.buffer_commits_size + 1

                        if kk == parser_params.n_ops - 1:
                            res = values[k * FIELD_EXTENSION * nrows_pack:(k + 1) * FIELD_EXTENSION * nrows_pack]
                        else:
                            res_idx = args[i_args + 1] * nrows_pack
                            res = tmp3[res_idx:res_idx + FIELD_EXTENSION * nrows_pack]

                        self._goldilocks3_op_pack(nrows_pack, args[i_args], res, a, is_constant_a, b, is_constant_b)
                        i_args += 8

                    else:
                        raise ValueError(f"Invalid operation type: {op_type}")

                # Verify all args consumed (lines 485-486)
                assert i_args == parser_params.n_args, \
                    f"Args mismatch: {i_args} != {parser_params.n_args}"

                # Apply inverse if needed (lines 488-490)
                if dest.params[k].inverse:
                    self._get_inverse_polynomial(nrows_pack,
                                                 values[k * FIELD_EXTENSION * nrows_pack:],
                                                 values[2 * FIELD_EXTENSION * nrows_pack:],
                                                 dest.params[k].batch, parser_params.dest_dim)

            # Multiply two parameters if present (lines 493-502)
            is_constant = False
            if len(dest.params) == 2:
                is_constant_a = dest.params[0].op in ["number", "airvalue"]
                is_constant_b = dest.params[1].op in ["number", "airvalue"]
                is_constant = is_constant_a and is_constant_b
                self._multiply_polynomials(nrows_pack, dest, values,
                                          is_constant_a, is_constant_b)
            else:
                is_constant = dest.params[0].op in ["number", "airvalue"]

            # Store result to destination (line 504)
            self._store_polynomial(nrows_pack, dest, values, i, is_constant)

    def _load(self, params: StepsParams, expressions_params: Dict[int, np.ndarray],
              args: np.ndarray, map_offsets_exps: np.ndarray,
              map_offsets_custom_exps: np.ndarray, next_strides_exps: np.ndarray,
              i_args: int, row: int, dim: int, domain_size: int,
              domain_extended: bool, is_cyclic: bool, value_buffer: np.ndarray,
              debug: bool = False) -> np.ndarray:
        """Load value(s) from appropriate buffer.

        Corresponds to C++ ExpressionsPack::load() (lines 15-195 of expressions_pack.hpp).

        This is the core dispatch function that loads operand values based on type.
        Type encoding (args[i_args]):
        - 0: constant polynomials
        - 1..nStages+1: committed polynomials (trace/aux_trace)
        - nStages+2: boundary values (x_n, zi)
        - nStages+3: xi values (for FRI)
        - nStages+4+: custom commits
        - buffer_commits_size: tmp1 (scalar temps)
        - buffer_commits_size+1: tmp3 (field extension temps)
        - buffer_commits_size+2+: public inputs, numbers, air_values, etc.

        Args:
            params: Working parameters
            expressions_params: Parameter buffers map
            args: Argument array
            map_offsets_exps: Offset mappings
            map_offsets_custom_exps: Custom commit offsets
            next_strides_exps: Opening point strides
            i_args: Argument index
            row: Current row
            dim: Dimension (1 or 3)
            domain_size: Domain size
            domain_extended: Extended domain flag
            is_cyclic: Cyclic region flag
            value_buffer: Temporary buffer for loading
            debug: Debug flag

        Returns:
            Pointer to loaded value(s)
        """
        nrows_pack = 1  # Python version processes one row at a time
        type_arg = args[i_args]

        # Type 0: Constant polynomials (lines 25-49)
        if type_arg == 0:
            if dim == FIELD_EXTENSION:
                raise ValueError("Constant polynomials cannot have dim=3")

            const_pols = params.constPolsExtended if domain_extended else params.constPols
            stage_pos = args[i_args + 1]
            o = next_strides_exps[args[i_args + 2]]
            n_cols = int(self.map_sections_n[0])

            if is_cyclic:
                for j in range(nrows_pack):
                    l = (row + j + o) % domain_size
                    value_buffer[j] = const_pols[l * self.setup_ctx.stark_info.nConstants + stage_pos]
            else:
                offset_col = (row + o) * n_cols + stage_pos
                for j in range(nrows_pack):
                    value_buffer[j] = const_pols[offset_col + j * n_cols]

            return value_buffer[:nrows_pack]

        # Types 1..nStages+1: Committed polynomials (lines 50-96)
        elif type_arg <= self.setup_ctx.stark_info.nStages + 1:
            stage_pos = args[i_args + 1]
            offset = int(map_offsets_exps[type_arg])
            n_cols = int(self.map_sections_n[type_arg])
            o = next_strides_exps[args[i_args + 2]]

            if is_cyclic:
                for j in range(nrows_pack):
                    l = (row + j + o) % domain_size
                    if type_arg == 1 and not domain_extended:
                        value_buffer[j] = params.trace[l * n_cols + stage_pos]
                    else:
                        for d in range(dim):
                            value_buffer[j + d * nrows_pack] = params.auxTrace[offset + l * n_cols + stage_pos + d]
            else:
                if type_arg == 1 and not domain_extended:
                    offset_col = (row + o) * n_cols + stage_pos
                    for j in range(nrows_pack):
                        value_buffer[j] = params.trace[offset_col + j * n_cols]
                else:
                    offset_col = offset + (row + o) * n_cols + stage_pos
                    for j in range(nrows_pack):
                        for d in range(dim):
                            value_buffer[j + d * nrows_pack] = params.auxTrace[offset_col + d + j * n_cols]

            return value_buffer[:dim * nrows_pack]

        # Type nStages+2: Boundary values (x_n, zi) (lines 97-127)
        elif type_arg == self.setup_ctx.stark_info.nStages + 2:
            boundary = args[i_args + 1]

            if self.setup_ctx.stark_info.verify:
                # Verifier mode: return constant value
                if boundary == 0:
                    for j in range(nrows_pack):
                        for e in range(FIELD_EXTENSION):
                            value_buffer[j + e * nrows_pack] = self.prover_helpers.x_n[e]
                else:
                    for j in range(nrows_pack):
                        for e in range(FIELD_EXTENSION):
                            value_buffer[j + e * nrows_pack] = self.prover_helpers.zi[(boundary - 1) * FIELD_EXTENSION + e]
            else:
                # Prover mode: return array slice
                if boundary == 0:
                    x_vals = self.prover_helpers.x if domain_extended else self.prover_helpers.x_n
                    return x_vals[row:row + nrows_pack]
                else:
                    offset = (boundary - 1) * domain_size + row
                    return self.prover_helpers.zi[offset:offset + nrows_pack]

            return value_buffer[:FIELD_EXTENSION * nrows_pack]

        # Type nStages+3: Xi values for FRI (lines 128-146)
        elif type_arg == self.setup_ctx.stark_info.nStages + 3:
            if dim == 1:
                raise ValueError("Xi values must have dim=3")

            o = args[i_args + 1]

            if self.setup_ctx.stark_info.verify:
                # Verifier mode: use precomputed x/(x-xi)
                for k in range(nrows_pack):
                    for e in range(FIELD_EXTENSION):
                        value_buffer[k + e * nrows_pack] = \
                            params.xDivXSub[((row + k) * len(self.setup_ctx.stark_info.openingPoints) + o) * FIELD_EXTENSION + e]
            else:
                # Prover mode: compute x/(x-xi) on the fly
                # This uses x from prover_helpers and xi from self.xis
                xdivxsub = params.auxTrace[self.map_offset_fri_pol + row * FIELD_EXTENSION:]

                # Compute x - xi (in place) using SUB_SWAP: result = b - a = x - xi
                xi_vals = self.xis[o * FIELD_EXTENSION:(o + 1) * FIELD_EXTENSION]
                x_val = self.prover_helpers.x[row]
                self._goldilocks3_op_31_pack(nrows_pack, Operation.SUB_SWAP.value, xdivxsub,
                                            xi_vals, True, np.array([x_val], dtype=np.uint64), False)

                # Invert to get 1/(x - xi)
                self._get_inverse_polynomial(nrows_pack, xdivxsub, value_buffer, True, 3)

                return xdivxsub[:FIELD_EXTENSION * nrows_pack]

            return value_buffer[:FIELD_EXTENSION * nrows_pack]

        # Types nStages+4+: Custom commits (lines 147-171)
        elif (type_arg >= self.setup_ctx.stark_info.nStages + 4 and
              type_arg < len(self.setup_ctx.stark_info.customCommits) + self.setup_ctx.stark_info.nStages + 4):
            index = type_arg - (self.n_stages + 4)
            stage_pos = args[i_args + 1]
            offset = int(map_offsets_custom_exps[index])
            n_cols = int(self.map_sections_n_custom_fixed[index])
            o = next_strides_exps[args[i_args + 2]]

            if is_cyclic:
                for j in range(nrows_pack):
                    l = (row + j + o) % domain_size
                    value_buffer[j] = params.customCommits[offset + l * n_cols + stage_pos]
            else:
                offset_col = offset + (row + o) * n_cols + stage_pos
                for j in range(nrows_pack):
                    value_buffer[j] = params.customCommits[offset_col + j * n_cols]

            return value_buffer[:nrows_pack]

        # Temporary buffers and scalar values (lines 172-194)
        elif type_arg == self.buffer_commits_size or type_arg == self.buffer_commits_size + 1:
            # tmp1 or tmp3
            idx = args[i_args + 1] * nrows_pack
            return expressions_params[type_arg][idx:idx + dim * nrows_pack]

        else:
            # Public inputs, numbers, air values, etc.
            return expressions_params[type_arg][args[i_args + 1]:args[i_args + 1] + dim]

    def _get_inverse_polynomial(self, nrows_pack: int, dest_vals: np.ndarray,
                                buff_helper: np.ndarray, batch: bool, dim: int):
        """Compute inverse of polynomial values.

        Corresponds to C++ ExpressionsPack::getInversePolinomial()
        (lines 197-221 of expressions_pack.hpp).

        Args:
            nrows_pack: Number of rows in pack
            dest_vals: Values to invert (in-place)
            buff_helper: Helper buffer for field extension operations
            batch: Use batch inversion (unused in Python)
            dim: Dimension (1 or 3)
        """
        if dim == 1:
            # Scalar inversion
            # Note: Must convert numpy uint64 to Python int before creating FF
            for i in range(nrows_pack):
                dest_vals[i] = int(FF(int(dest_vals[i])) ** -1)
        elif dim == FIELD_EXTENSION:
            # Field extension inversion
            # Copy to helper buffer in AoS layout
            for i in range(nrows_pack):
                for d in range(FIELD_EXTENSION):
                    buff_helper[i * FIELD_EXTENSION + d] = dest_vals[i + d * nrows_pack]

            # Invert
            for i in range(nrows_pack):
                val_ff3 = ff3([int(buff_helper[i * FIELD_EXTENSION + d]) for d in range(FIELD_EXTENSION)])
                inv_ff3 = val_ff3 ** -1
                inv_coeffs = ff3_coeffs(inv_ff3)
                for d in range(FIELD_EXTENSION):
                    buff_helper[i * FIELD_EXTENSION + d] = inv_coeffs[d]

            # Copy back to SoA layout
            for i in range(nrows_pack):
                for d in range(FIELD_EXTENSION):
                    dest_vals[i + d * nrows_pack] = buff_helper[i * FIELD_EXTENSION + d]

    def _multiply_polynomials(self, nrows_pack: int, dest: Dest, dest_vals: np.ndarray,
                             is_constant_a: bool, is_constant_b: bool):
        """Multiply two polynomial values.

        Corresponds to C++ ExpressionsPack::multiplyPolynomials()
        (lines 223-239 of expressions_pack.hpp).

        Multiplies values[0..n] * values[n..2n], stores in values[0..n].

        Args:
            nrows_pack: Number of rows in pack
            dest: Destination specification
            dest_vals: Values array
            is_constant_a: First operand is constant
            is_constant_b: Second operand is constant
        """
        if dest.dim == 1:
            # Scalar multiplication
            self._goldilocks_op_pack(nrows_pack, Operation.MUL.value, dest_vals,
                                    dest_vals, is_constant_a,
                                    dest_vals[FIELD_EXTENSION * nrows_pack:], is_constant_b)
        else:
            # Field extension multiplication
            buff_helper = np.zeros(FIELD_EXTENSION * nrows_pack, dtype=np.uint64)

            if dest.params[0].dim == FIELD_EXTENSION and dest.params[1].dim == FIELD_EXTENSION:
                # dim3 × dim3
                self._goldilocks3_op_pack(nrows_pack, Operation.MUL.value, buff_helper,
                                         dest_vals, is_constant_a,
                                         dest_vals[FIELD_EXTENSION * nrows_pack:], is_constant_b)
            elif dest.params[0].dim == FIELD_EXTENSION and dest.params[1].dim == 1:
                # dim3 × dim1
                self._goldilocks3_op_31_pack(nrows_pack, Operation.MUL.value, buff_helper,
                                            dest_vals, is_constant_a,
                                            dest_vals[FIELD_EXTENSION * nrows_pack:], is_constant_b)
            else:
                # dim1 × dim3
                self._goldilocks3_op_31_pack(nrows_pack, Operation.MUL.value, buff_helper,
                                            dest_vals[FIELD_EXTENSION * nrows_pack:], is_constant_b,
                                            dest_vals, is_constant_a)

            # Copy result back
            dest_vals[0:FIELD_EXTENSION * nrows_pack] = buff_helper[0:FIELD_EXTENSION * nrows_pack]

    def _store_polynomial(self, nrows_pack: int, dest: Dest, dest_vals: np.ndarray,
                         row: int, is_constant: int):
        """Store polynomial values to destination.

        Corresponds to C++ ExpressionsPack::storePolynomial()
        (lines 241-251 of expressions_pack.hpp).

        Args:
            nrows_pack: Number of rows in pack
            dest: Destination specification
            dest_vals: Values to store
            row: Row index
            is_constant: Constant flag
        """
        if dest.dim == 1:
            # Scalar storage
            offset = dest.offset if dest.offset != 0 else 1
            for j in range(nrows_pack):
                if is_constant:
                    dest.dest[row * offset] = dest_vals[0]
                else:
                    dest.dest[row * offset + j * offset] = dest_vals[j]
        else:
            # Field extension storage
            offset = dest.offset if dest.offset != 0 else FIELD_EXTENSION
            for j in range(nrows_pack):
                for d in range(FIELD_EXTENSION):
                    if is_constant:
                        dest.dest[row * offset + d] = dest_vals[d * nrows_pack]
                    else:
                        dest.dest[row * offset + j * offset + d] = dest_vals[j + d * nrows_pack]

    def _goldilocks_op_pack(self, nrows_pack: int, op: int, dest: np.ndarray,
                            a: np.ndarray, is_constant_a: bool,
                            b: np.ndarray, is_constant_b: bool):
        """Execute Goldilocks field operation.

        Corresponds to C++ Goldilocks::op_pack().

        Args:
            nrows_pack: Number of rows
            op: Operation (0=add, 1=sub, 2=mul, 3=sub_swap)
            dest: Destination buffer
            a: First operand
            is_constant_a: First operand is constant
            b: Second operand
            is_constant_b: Second operand is constant
        """
        # Note: Must convert numpy uint64 to Python int before creating FF
        for i in range(nrows_pack):
            a_val = FF(int(a[0]) if is_constant_a else int(a[i]))
            b_val = FF(int(b[0]) if is_constant_b else int(b[i]))

            if op == 0:  # ADD
                dest[i] = int(a_val + b_val)
            elif op == 1:  # SUB
                dest[i] = int(a_val - b_val)
            elif op == 2:  # MUL
                dest[i] = int(a_val * b_val)
            elif op == 3:  # SUB_SWAP
                dest[i] = int(b_val - a_val)

    def _goldilocks3_op_pack(self, nrows_pack: int, op: int, dest: np.ndarray,
                             a: np.ndarray, is_constant_a: bool,
                             b: np.ndarray, is_constant_b: bool):
        """Execute Goldilocks3 field extension operation (dim3 × dim3).

        Corresponds to C++ Goldilocks3::op_pack().

        Args:
            nrows_pack: Number of rows
            op: Operation
            dest: Destination buffer (SoA layout: [e0...e0, e1...e1, e2...e2])
            a: First operand (SoA layout)
            is_constant_a: First operand is constant
            b: Second operand (SoA layout)
            is_constant_b: Second operand is constant
        """
        for i in range(nrows_pack):
            if is_constant_a:
                a_val = ff3([int(a[0]), int(a[nrows_pack]), int(a[2 * nrows_pack])])
            else:
                a_val = ff3([int(a[i]), int(a[i + nrows_pack]), int(a[i + 2 * nrows_pack])])

            if is_constant_b:
                b_val = ff3([int(b[0]), int(b[nrows_pack]), int(b[2 * nrows_pack])])
            else:
                b_val = ff3([int(b[i]), int(b[i + nrows_pack]), int(b[i + 2 * nrows_pack])])

            if op == 0:  # ADD
                res = a_val + b_val
            elif op == 1:  # SUB
                res = a_val - b_val
            elif op == 2:  # MUL
                res = a_val * b_val
            elif op == 3:  # SUB_SWAP
                res = b_val - a_val
            else:
                raise ValueError(f"Invalid operation: {op}")

            res_coeffs = ff3_coeffs(res)
            dest[i] = res_coeffs[0]
            dest[i + nrows_pack] = res_coeffs[1]
            dest[i + 2 * nrows_pack] = res_coeffs[2]

    def _goldilocks3_op_31_pack(self, nrows_pack: int, op: int, dest: np.ndarray,
                                a: np.ndarray, is_constant_a: bool,
                                b: np.ndarray, is_constant_b: bool):
        """Execute Goldilocks3 field extension operation (dim3 × dim1).

        Corresponds to C++ Goldilocks3::op_31_pack().

        Args:
            nrows_pack: Number of rows
            op: Operation
            dest: Destination buffer (SoA layout)
            a: First operand (SoA layout, dim=3)
            is_constant_a: First operand is constant
            b: Second operand (scalar)
            is_constant_b: Second operand is constant
        """
        for i in range(nrows_pack):
            if is_constant_a:
                a_val = ff3([int(a[0]), int(a[nrows_pack]), int(a[2 * nrows_pack])])
            else:
                a_val = ff3([int(a[i]), int(a[i + nrows_pack]), int(a[i + 2 * nrows_pack])])

            b_val = FF(int(b[0]) if is_constant_b else int(b[i]))
            b_ff3 = ff3([int(b_val), 0, 0])

            if op == 0:  # ADD
                res = a_val + b_ff3
            elif op == 1:  # SUB
                res = a_val - b_ff3
            elif op == 2:  # MUL
                res = a_val * b_ff3
            elif op == 3:  # SUB_SWAP
                res = b_ff3 - a_val
            else:
                raise ValueError(f"Invalid operation: {op}")

            res_coeffs = ff3_coeffs(res)
            dest[i] = res_coeffs[0]
            dest[i + nrows_pack] = res_coeffs[1]
            dest[i + 2 * nrows_pack] = res_coeffs[2]
