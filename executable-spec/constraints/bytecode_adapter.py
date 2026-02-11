"""Bytecode-backed constraint module adapter.

Wraps the expression bytecode interpreter behind the ConstraintModule ABC,
allowing AIRs without hand-written Python to use compiled bytecode for
constraint evaluation.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import numpy as np

from bytecode_utils import compute_column_index
from primitives.expression_bytecode.expression_evaluator import (
    BufferSet,
    Dest,
    ExpressionsPack,
    Params,
)
from primitives.expression_bytecode.expressions_bin import ExpressionsBin
from primitives.field import (
    FF,
    FF3,
    FIELD_EXTENSION_DEGREE,
    FF3Poly,
    batch_inverse,
    ff3,
    ff3_from_interleaved_numpy,
    ff3_to_interleaved_numpy,
    ff3_to_numpy_coeffs,
)

from .base import (
    ConstraintContext,
    ConstraintModule,
    ProverConstraintContext,
    VerifierConstraintContext,
)

if TYPE_CHECKING:
    from protocol.air_config import ProverHelpers
    from protocol.stark_info import StarkInfo


# ---------------------------------------------------------------------------
# C+2: Named phases for _build_buffers_from_prover_data
# ---------------------------------------------------------------------------


def _determine_domain_size(ctx: ProverConstraintContext) -> int:
    """Determine domain size from the first column in ProverData.

    Raises:
        ValueError: If no columns are found
    """
    for _key, col in ctx._data.columns.items():
        return len(col)
    raise ValueError("No columns found in ProverData")


def _reconstruct_aux_trace(
    stark_info: StarkInfo,
    ctx: ProverConstraintContext,
    N: int,
) -> np.ndarray:
    """Reconstruct the flat aux_trace buffer from ProverData columns.

    Writes committed polynomial columns back into the interleaved layout
    expected by the bytecode evaluator on the extended domain.
    """
    data = ctx._data
    total_n = stark_info.map_total_n
    aux_trace = np.zeros(total_n, dtype=np.uint64)

    for pol_info in stark_info.cm_pols_map:
        name = pol_info.name
        stage = pol_info.stage
        dim = pol_info.dim
        stage_pos = pol_info.stage_pos

        index = compute_column_index(stark_info, name, stage_pos)
        key = (name, index)
        if key not in data.columns:
            continue

        col_val = data.columns[key]
        section = f"cm{stage}"
        n_cols = stark_info.map_sections_n.get(section, 0)
        offset = stark_info.map_offsets.get((section, True), 0)

        if dim == 1:
            values = np.asarray(col_val, dtype=np.uint64)
            for j in range(N):
                aux_trace[offset + j * n_cols + stage_pos] = values[j]
        else:
            interleaved = ff3_to_interleaved_numpy(col_val)
            for j in range(N):
                dst_idx = offset + j * n_cols + stage_pos
                aux_trace[dst_idx:dst_idx + dim] = interleaved[j * dim:(j + 1) * dim]

    return aux_trace


def _reconstruct_const_pols_extended(
    stark_info: StarkInfo,
    ctx: ProverConstraintContext,
    N: int,
) -> np.ndarray:
    """Reconstruct the flat const_pols_extended buffer from ProverData constants."""
    data = ctx._data
    n_const_cols = stark_info.n_constants
    const_pols_extended = np.zeros(N * n_const_cols, dtype=np.uint64)

    for pol_info in stark_info.const_pols_map:
        name = pol_info.name
        stage_pos = pol_info.stage_pos
        dim = pol_info.dim

        if name not in data.constants:
            continue

        const_val = data.constants[name]
        if dim == 1:
            values = np.asarray(const_val, dtype=np.uint64)
            for j in range(N):
                const_pols_extended[j * n_const_cols + stage_pos] = values[j]
        else:
            interleaved = ff3_to_interleaved_numpy(const_val)
            for j in range(N):
                dst_idx = j * n_const_cols + stage_pos
                const_pols_extended[dst_idx:dst_idx + dim] = interleaved[j * dim:(j + 1) * dim]

    return const_pols_extended


def _build_challenges_and_airgroup_values(
    stark_info: StarkInfo,
    ctx: ProverConstraintContext,
) -> tuple[np.ndarray, np.ndarray]:
    """Build flat interleaved challenges and airgroup_values arrays from ProverData."""
    data = ctx._data

    # Challenges
    n_challenges = len(stark_info.challenges_map)
    challenges = np.zeros(n_challenges * FIELD_EXTENSION_DEGREE, dtype=np.uint64)
    for ch_idx, ch_map in enumerate(stark_info.challenges_map):
        if ch_map.name in data.challenges:
            idx = ch_idx * FIELD_EXTENSION_DEGREE
            coeffs = ff3_to_numpy_coeffs(data.challenges[ch_map.name])
            challenges[idx:idx + FIELD_EXTENSION_DEGREE] = coeffs

    # Airgroup values
    n_agv = len(stark_info.airgroup_values_map)
    airgroup_values = np.zeros(n_agv * FIELD_EXTENSION_DEGREE, dtype=np.uint64)
    for i in range(n_agv):
        if i in data.airgroup_values:
            idx = i * FIELD_EXTENSION_DEGREE
            coeffs = ff3_to_numpy_coeffs(data.airgroup_values[i])
            airgroup_values[idx:idx + FIELD_EXTENSION_DEGREE] = coeffs

    return challenges, airgroup_values


def _build_buffers_from_prover_data(
    stark_info: StarkInfo,
    ctx: ProverConstraintContext,
) -> tuple[BufferSet, int]:
    """Reconstruct flat buffers from ProverData for bytecode evaluation.

    This reverses the conversion done by _build_prover_data_extended() in stages.py.
    The bytecode evaluator expects flat interleaved buffers indexed by section offsets,
    while ProverData stores named columns as galois arrays.

    Args:
        stark_info: StarkInfo with polynomial mappings
        ctx: ProverConstraintContext containing ProverData

    Returns:
        Tuple of (BufferSet, domain_size)
    """
    N = _determine_domain_size(ctx)
    aux_trace = _reconstruct_aux_trace(stark_info, ctx, N)
    const_pols_extended = _reconstruct_const_pols_extended(stark_info, ctx, N)
    challenges, airgroup_values = _build_challenges_and_airgroup_values(stark_info, ctx)

    buffers = BufferSet(
        trace=np.zeros(0, dtype=np.uint64),  # Not used on extended domain
        aux_trace=aux_trace,
        const_pols=np.zeros(0, dtype=np.uint64),
        const_pols_extended=const_pols_extended,
        public_inputs=np.zeros(stark_info.n_publics, dtype=np.uint64),
        challenges=challenges,
        evals=np.zeros(len(stark_info.ev_map) * FIELD_EXTENSION_DEGREE, dtype=np.uint64),
        air_values=np.zeros(stark_info.air_values_size, dtype=np.uint64),
        airgroup_values=airgroup_values,
        proof_values=np.zeros(0, dtype=np.uint64),
    )

    return buffers, N


# ---------------------------------------------------------------------------
# Verifier buffer construction (unchanged structure, uses C+1 helper)
# ---------------------------------------------------------------------------


def _build_buffers_from_verifier_data(
    stark_info: StarkInfo,
    ctx: VerifierConstraintContext,
) -> BufferSet:
    """Reconstruct flat buffers from VerifierData for bytecode evaluation.

    In verify mode, the bytecode evaluator loads values from evals instead
    of buffers, so we only need to populate evals and challenges.

    Args:
        stark_info: StarkInfo with polynomial mappings
        ctx: VerifierConstraintContext containing VerifierData

    Returns:
        BufferSet configured for verify mode
    """
    data = ctx._data

    # Build evals array from named evaluations
    n_evals = len(stark_info.ev_map)
    evals = np.zeros(n_evals * FIELD_EXTENSION_DEGREE, dtype=np.uint64)

    for idx, ev in enumerate(stark_info.ev_map):
        # Find the matching key in data.evals
        from primitives.pol_map import EvMap
        if ev.type == EvMap.Type.cm:
            pol_info = stark_info.cm_pols_map[ev.id]
            name = pol_info.name
            col_index = compute_column_index(stark_info, name, pol_info.stage_pos)
            key = (name, col_index, ev.row_offset)
        elif ev.type == EvMap.Type.const_:
            pol_info = stark_info.const_pols_map[ev.id]
            name = pol_info.name
            # Count same-name entries before this one (matching _build_verifier_data)
            const_index = 0
            for other in stark_info.const_pols_map[:ev.id]:
                if other.name == name:
                    const_index += 1
            key = (name, const_index, ev.row_offset)
        elif ev.type == EvMap.Type.custom:
            cc_pols = stark_info.custom_commits_map[ev.commit_id]
            pol_info = cc_pols[ev.id]
            name = pol_info.name
            custom_index = 0
            for other in cc_pols[:ev.id]:
                if other.name == name:
                    custom_index += 1
            key = (name, custom_index, ev.row_offset)
        else:
            continue

        if key in data.evals:
            base = idx * FIELD_EXTENSION_DEGREE
            coeffs = ff3_to_numpy_coeffs(data.evals[key])
            evals[base:base + FIELD_EXTENSION_DEGREE] = coeffs

    # Build challenges array
    n_challenges = len(stark_info.challenges_map)
    challenges = np.zeros(n_challenges * FIELD_EXTENSION_DEGREE, dtype=np.uint64)
    for ch_idx, ch_map in enumerate(stark_info.challenges_map):
        if ch_map.name in data.challenges:
            idx = ch_idx * FIELD_EXTENSION_DEGREE
            coeffs = ff3_to_numpy_coeffs(data.challenges[ch_map.name])
            challenges[idx:idx + FIELD_EXTENSION_DEGREE] = coeffs

    # Build airgroup_values array
    n_agv = len(stark_info.airgroup_values_map)
    airgroup_values = np.zeros(n_agv * FIELD_EXTENSION_DEGREE, dtype=np.uint64)
    for i in range(n_agv):
        if i in data.airgroup_values:
            idx = i * FIELD_EXTENSION_DEGREE
            coeffs = ff3_to_numpy_coeffs(data.airgroup_values[i])
            airgroup_values[idx:idx + FIELD_EXTENSION_DEGREE] = coeffs

    # Use actual publics/air_values/proof_values from VerifierData if available
    public_inputs = (
        np.asarray(data.publics_flat, dtype=np.uint64)
        if data.publics_flat is not None
        else np.zeros(stark_info.n_publics, dtype=np.uint64)
    )
    air_values = (
        data.air_values_flat
        if data.air_values_flat is not None
        else np.zeros(stark_info.air_values_size, dtype=np.uint64)
    )
    proof_values = (
        np.asarray(data.proof_values_flat, dtype=np.uint64)
        if data.proof_values_flat is not None
        else np.zeros(0, dtype=np.uint64)
    )

    return BufferSet(
        trace=np.zeros(0, dtype=np.uint64),
        aux_trace=np.zeros(0, dtype=np.uint64),
        const_pols=np.zeros(0, dtype=np.uint64),
        const_pols_extended=np.zeros(0, dtype=np.uint64),
        public_inputs=public_inputs,
        challenges=challenges,
        evals=evals,
        air_values=air_values,
        airgroup_values=airgroup_values,
        proof_values=proof_values,
    )


# ---------------------------------------------------------------------------
# C+4: Z_H correction functions
# ---------------------------------------------------------------------------


def _recover_constraint_from_quotient_prover(
    q_poly: FF3Poly,
    prover_helpers: ProverHelpers,
    N_ext: int,
) -> FF3Poly:
    """Recover C(x) from Q(x) on the extended domain (prover path).

    The bytecode computes Q(x) = C(x)/Z_H(x) directly (zerofier division
    baked into compiled bytecode). We multiply by Z_H(x) to recover C(x),
    matching the ConstraintModule interface.

    Z_H(x_i) = x_i^N - 1, and zi[:N_ext] contains 1/(x_i^N - 1).

    Args:
        q_poly: Q(x) in evaluation form on extended domain
        prover_helpers: ProverHelpers containing zi (inverse zerofier)
        N_ext: Extended domain size

    Returns:
        C(x) = Q(x) * Z_H(x) in evaluation form
    """
    zi = FF(np.asarray(prover_helpers.zi[:N_ext], dtype=np.uint64).tolist())
    zh = batch_inverse(zi)  # Z_H(x_i) = x_i^N - 1
    return q_poly * FF3(zh)


def _recover_constraint_from_quotient_verifier(
    q_xi: FF3,
    z: np.ndarray,
    n_bits: int,
) -> FF3:
    """Recover C(xi) from Q(xi) at a single point (verifier path).

    The bytecode evaluates Q(xi) = C(xi)/Z_H(xi) directly. We multiply
    by Z_H(xi) = xi^N - 1 to recover C(xi).

    Args:
        q_xi: Q(xi) scalar evaluation
        z: Challenge point z as flat numpy array [c0, c1, c2]
        n_bits: Log2 of domain size N

    Returns:
        C(xi) = Q(xi) * Z_H(xi)
    """
    xi = FF3.Vector([int(z[2]), int(z[1]), int(z[0])])
    N = 1 << n_bits
    xi_to_n = xi
    for _ in range(N - 1):
        xi_to_n = xi_to_n * xi
    zh_xi = xi_to_n - FF3(1)
    return q_xi * zh_xi


# ---------------------------------------------------------------------------
# BytecodeConstraintModule
# ---------------------------------------------------------------------------


class BytecodeConstraintModule(ConstraintModule):
    """Constraint module backed by compiled expression bytecode.

    Uses the expression bytecode interpreter to evaluate constraint polynomials,
    allowing AIRs without hand-written Python modules to be proven/verified.
    """

    def __init__(self, bin_path: str) -> None:
        """Initialize from expression binary file.

        Args:
            bin_path: Path to the .bin file (e.g., SimpleLeft.bin)
        """
        self._bin_path = bin_path
        self._expressions_bin = ExpressionsBin.from_file(bin_path)

        # Load adjacent starkinfo.json
        bin_dir = Path(bin_path).parent
        air_name = Path(bin_path).stem
        starkinfo_path = bin_dir / f"{air_name}.starkinfo.json"
        if not starkinfo_path.exists():
            # Try parent directory pattern
            starkinfo_path = bin_dir.parent / f"{air_name}.starkinfo.json"

        from protocol.stark_info import StarkInfo
        self._stark_info = StarkInfo.from_json(str(starkinfo_path))

    def constraint_polynomial(self, ctx: ConstraintContext) -> FF3Poly | FF3:
        """Evaluate constraint polynomial using bytecode interpreter.

        Detects prover vs verifier mode from the context type.
        """
        if isinstance(ctx, ProverConstraintContext):
            return self._constraint_polynomial_prover(ctx)
        elif isinstance(ctx, VerifierConstraintContext):
            return self._constraint_polynomial_verifier(ctx)
        else:
            raise TypeError(f"Unsupported context type: {type(ctx)}")

    def _constraint_polynomial_prover(self, ctx: ProverConstraintContext) -> FF3Poly:
        """Evaluate constraint polynomial in prover mode (array output).

        The bytecode expression cExpId computes Q(x) = C(x)/Z_H(x) directly
        (zerofier division baked into compiled bytecode). We multiply by Z_H(x)
        to recover C(x), matching the ConstraintModule interface.
        """
        stark_info = self._stark_info
        buffers, N_ext = _build_buffers_from_prover_data(stark_info, ctx)

        # Create expression evaluator
        from protocol.air_config import ProverHelpers
        prover_helpers = ProverHelpers.from_stark_info(stark_info)

        expr_pack = ExpressionsPack(
            stark_info, self._expressions_bin, prover_helpers=prover_helpers,
            nrows_pack=1,  # Row-by-row for correctness
        )

        # Evaluate constraint expression on extended domain -> Q(x)
        c_exp_id = stark_info.c_exp_id
        dest_buffer = np.zeros(N_ext * FIELD_EXTENSION_DEGREE, dtype=np.uint64)

        dest = Dest(
            dest=dest_buffer,
            domain_size=N_ext,
            dim=FIELD_EXTENSION_DEGREE,
            params=[Params(
                exp_id=c_exp_id,
                dim=FIELD_EXTENSION_DEGREE,
                op="tmp",
            )],
        )

        expr_pack.calculate_expressions(
            buffers=buffers,
            dest=dest,
            domain_size=N_ext,
            domain_extended=True,
        )

        # Convert interleaved result to FF3 array: Q(x) in evaluation form
        q_poly = ff3_from_interleaved_numpy(dest_buffer, N_ext)

        return _recover_constraint_from_quotient_prover(q_poly, prover_helpers, N_ext)

    def _constraint_polynomial_verifier(self, ctx: VerifierConstraintContext) -> FF3:
        """Evaluate constraint polynomial in verifier mode (scalar output)."""
        stark_info = self._stark_info
        buffers = _build_buffers_from_verifier_data(stark_info, ctx)

        # Extract challenge point z (std_xi) for ProverHelpers
        xi_idx = stark_info.get_challenge_index('std_xi')
        z = buffers.challenges[xi_idx * FIELD_EXTENSION_DEGREE:(xi_idx + 1) * FIELD_EXTENSION_DEGREE]

        from protocol.air_config import ProverHelpers
        prover_helpers = ProverHelpers.from_challenge(stark_info, z)

        # Create verifier-mode evaluator
        expr_pack = ExpressionsPack(
            stark_info, self._expressions_bin,
            prover_helpers=prover_helpers,
            nrows_pack=1,
            verify=True,
        )

        # Evaluate constraint expression at single point
        c_exp_id = stark_info.c_exp_id
        dest_buffer = np.zeros(FIELD_EXTENSION_DEGREE, dtype=np.uint64)

        dest = Dest(
            dest=dest_buffer,
            domain_size=1,
            dim=FIELD_EXTENSION_DEGREE,
            params=[Params(
                exp_id=c_exp_id,
                dim=FIELD_EXTENSION_DEGREE,
                op="tmp",
            )],
        )

        expr_pack.calculate_expressions(
            buffers=buffers,
            dest=dest,
            domain_size=1,
            domain_extended=False,
            compilation_time=True,
        )

        q_xi = ff3([int(dest_buffer[0]), int(dest_buffer[1]), int(dest_buffer[2])])

        return _recover_constraint_from_quotient_verifier(
            q_xi, z, stark_info.stark_struct.n_bits,
        )
