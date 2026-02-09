"""Bytecode-backed witness generation adapter.

Wraps the hint-driven witness computation behind the WitnessModule ABC,
allowing AIRs without hand-written Python to use compiled bytecode for
witness generation (intermediate columns and grand sums).
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import numpy as np

from bytecode_utils import compute_column_index
from primitives.expression_bytecode.expression_evaluator import BufferSet, ExpressionsPack
from primitives.expression_bytecode.expressions_bin import ExpressionsBin
from primitives.expression_bytecode.witness_generation import calculate_witness_std
from primitives.field import (
    FIELD_EXTENSION_DEGREE,
    FF3Poly,
    ff3_from_interleaved_numpy,
    ff3_to_interleaved_numpy,
    ff3_to_numpy_coeffs,
)

from .base import WitnessModule

if TYPE_CHECKING:
    from constraints.base import ConstraintContext, ProverConstraintContext
    from protocol.stark_info import StarkInfo


# ---------------------------------------------------------------------------
# C+3: Named phases for _build_buffers_from_witness_data
# ---------------------------------------------------------------------------


def _determine_domain_size(ctx: ProverConstraintContext) -> int:
    """Determine domain size from the first column in ProverData.

    Raises:
        ValueError: If no columns are found
    """
    for _key, col in ctx._data.columns.items():
        return len(col)
    raise ValueError("No columns found in ProverData")


def _reconstruct_trace_and_aux_trace(
    stark_info: StarkInfo,
    ctx: ProverConstraintContext,
    N: int,
) -> tuple[np.ndarray, np.ndarray]:
    """Reconstruct trace (stage 1) and aux_trace (stage 2+) buffers.

    Stage 1 columns go into the trace buffer, stage 2+ columns go into
    aux_trace. This is the key difference from the constraint adapter which
    puts everything into aux_trace (extended domain).
    """
    data = ctx._data

    n_cols_cm1 = stark_info.map_sections_n.get("cm1", 0)
    trace = np.zeros(N * n_cols_cm1, dtype=np.uint64)

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

        if stage == 1:
            buffer = trace
            base_offset = 0
        else:
            base_offset = stark_info.map_offsets.get((section, False), 0)
            buffer = aux_trace

        if dim == 1:
            values = np.asarray(col_val, dtype=np.uint64)
            for j in range(N):
                buffer[base_offset + j * n_cols + stage_pos] = values[j]
        else:
            interleaved = ff3_to_interleaved_numpy(col_val)
            for j in range(N):
                dst_idx = base_offset + j * n_cols + stage_pos
                buffer[dst_idx:dst_idx + dim] = interleaved[j * dim:(j + 1) * dim]

    return trace, aux_trace


def _reconstruct_const_pols(
    stark_info: StarkInfo,
    ctx: ProverConstraintContext,
    N: int,
) -> np.ndarray:
    """Reconstruct the flat const_pols buffer from ProverData constants.

    Witness computation uses base-domain const_pols (not const_pols_extended).
    """
    data = ctx._data
    n_const_cols = stark_info.n_constants
    const_pols = np.zeros(N * n_const_cols, dtype=np.uint64)

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
                const_pols[j * n_const_cols + stage_pos] = values[j]
        else:
            interleaved = ff3_to_interleaved_numpy(const_val)
            for j in range(N):
                dst_idx = j * n_const_cols + stage_pos
                const_pols[dst_idx:dst_idx + dim] = interleaved[j * dim:(j + 1) * dim]

    return const_pols


def _build_challenges(
    stark_info: StarkInfo,
    ctx: ProverConstraintContext,
) -> np.ndarray:
    """Build flat interleaved challenges array from ProverData."""
    data = ctx._data
    n_challenges = len(stark_info.challenges_map)
    challenges = np.zeros(n_challenges * FIELD_EXTENSION_DEGREE, dtype=np.uint64)
    for ch_idx, ch_map in enumerate(stark_info.challenges_map):
        if ch_map.name in data.challenges:
            idx = ch_idx * FIELD_EXTENSION_DEGREE
            coeffs = ff3_to_numpy_coeffs(data.challenges[ch_map.name])
            challenges[idx:idx + FIELD_EXTENSION_DEGREE] = coeffs
    return challenges


def _build_buffers_from_witness_data(
    stark_info: StarkInfo,
    ctx: ProverConstraintContext,
) -> tuple[BufferSet, int]:
    """Reconstruct flat buffers from ProverData for witness bytecode evaluation.

    Witness computation works on the base domain (not extended).
    Stage 1 columns go into trace buffer, stage 2 into aux_trace.

    Args:
        stark_info: StarkInfo with polynomial mappings
        ctx: ProverConstraintContext containing ProverData

    Returns:
        Tuple of (BufferSet, N) where N is the base domain size
    """
    N = _determine_domain_size(ctx)
    trace, aux_trace = _reconstruct_trace_and_aux_trace(stark_info, ctx, N)
    const_pols = _reconstruct_const_pols(stark_info, ctx, N)
    challenges = _build_challenges(stark_info, ctx)

    n_agv = len(stark_info.airgroup_values_map)
    airgroup_values = np.zeros(max(n_agv * FIELD_EXTENSION_DEGREE, 1), dtype=np.uint64)

    buffers = BufferSet(
        trace=trace,
        aux_trace=aux_trace,
        const_pols=const_pols,
        const_pols_extended=np.zeros(0, dtype=np.uint64),
        public_inputs=np.zeros(stark_info.n_publics, dtype=np.uint64),
        challenges=challenges,
        evals=np.zeros(len(stark_info.ev_map) * FIELD_EXTENSION_DEGREE, dtype=np.uint64),
        air_values=np.zeros(max(stark_info.air_values_size, 1), dtype=np.uint64),
        airgroup_values=airgroup_values,
        proof_values=np.zeros(0, dtype=np.uint64),
    )

    return buffers, N


# ---------------------------------------------------------------------------
# Buffer extraction helpers
# ---------------------------------------------------------------------------


def _extract_intermediates(
    stark_info: StarkInfo,
    buffers: BufferSet,
    N: int,
) -> dict[str, dict[int, FF3Poly]]:
    """Extract intermediate column values from flat buffers back to dict format.

    Args:
        stark_info: StarkInfo with polynomial mappings
        buffers: BufferSet containing computed witness values
        N: Domain size

    Returns:
        Dict like {'im_cluster': {0: poly0, 1: poly1, ...}}
    """
    result: dict[str, dict[int, FF3Poly]] = {}

    for pol_info in stark_info.cm_pols_map:
        name = pol_info.name
        if not name.startswith('im_'):
            continue

        stage = pol_info.stage
        dim = pol_info.dim
        stage_pos = pol_info.stage_pos

        section = f"cm{stage}"
        n_cols = stark_info.map_sections_n.get(section, 0)

        if stage == 1:
            buffer = buffers.trace
            base_offset = 0
        else:
            base_offset = stark_info.map_offsets.get((section, False), 0)
            buffer = buffers.aux_trace

        # Read values
        values = np.zeros(N * dim, dtype=np.uint64)
        for j in range(N):
            src_idx = base_offset + j * n_cols + stage_pos
            values[j * dim:(j + 1) * dim] = buffer[src_idx:src_idx + dim]

        index = compute_column_index(stark_info, name, stage_pos)

        if name not in result:
            result[name] = {}

        if dim == 1:
            from primitives.field import FF3
            result[name][index] = FF3(np.asarray(values, dtype=np.uint64))
        else:
            result[name][index] = ff3_from_interleaved_numpy(values, N)

    return result


def _extract_grand_sums(
    stark_info: StarkInfo,
    buffers: BufferSet,
    N: int,
) -> dict[str, FF3Poly]:
    """Extract gsum/gprod column values from flat buffers.

    Args:
        stark_info: StarkInfo with polynomial mappings
        buffers: BufferSet containing computed witness values
        N: Domain size

    Returns:
        Dict like {'gsum': gsum_poly} or {'gprod': gprod_poly}
    """
    result: dict[str, FF3Poly] = {}

    for pol_info in stark_info.cm_pols_map:
        name = pol_info.name
        if name not in ('gsum', 'gprod'):
            continue

        stage = pol_info.stage
        dim = pol_info.dim
        stage_pos = pol_info.stage_pos

        section = f"cm{stage}"
        n_cols = stark_info.map_sections_n.get(section, 0)

        if stage == 1:
            buffer = buffers.trace
            base_offset = 0
        else:
            base_offset = stark_info.map_offsets.get((section, False), 0)
            buffer = buffers.aux_trace

        values = np.zeros(N * dim, dtype=np.uint64)
        for j in range(N):
            src_idx = base_offset + j * n_cols + stage_pos
            values[j * dim:(j + 1) * dim] = buffer[src_idx:src_idx + dim]

        if dim == 1:
            from primitives.field import FF3
            result[name] = FF3(np.asarray(values, dtype=np.uint64))
        else:
            result[name] = ff3_from_interleaved_numpy(values, N)

    return result


# ---------------------------------------------------------------------------
# BytecodeWitnessModule
# ---------------------------------------------------------------------------


class BytecodeWitnessModule(WitnessModule):
    """Witness module backed by compiled expression bytecode.

    Uses the hint-driven witness computation to generate intermediate columns
    and grand sums, wrapping the result in the WitnessModule interface.
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
            starkinfo_path = bin_dir.parent / f"{air_name}.starkinfo.json"

        from protocol.stark_info import StarkInfo
        self._stark_info = StarkInfo.from_json(str(starkinfo_path))

    def _run_witness_computation(
        self, ctx: ProverConstraintContext,
    ) -> tuple[BufferSet, int]:
        """Run the full witness computation (intermediates + grand sums).

        Args:
            ctx: ProverConstraintContext containing ProverData

        Returns:
            Tuple of (populated BufferSet, domain_size)
        """
        stark_info = self._stark_info
        buffers, N = _build_buffers_from_witness_data(stark_info, ctx)

        expr_pack = ExpressionsPack(
            stark_info, self._expressions_bin,
            nrows_pack=1,
        )

        calculate_witness_std(
            stark_info, self._expressions_bin, buffers,
            expr_pack, prod=False
        )
        if self._expressions_bin.get_hint_ids_by_name("gprod_col"):
            calculate_witness_std(
                stark_info, self._expressions_bin, buffers,
                expr_pack, prod=True
            )

        return buffers, N

    def _ensure_buffers(self, ctx: ConstraintContext) -> tuple[BufferSet, int]:
        """Return cached buffers from compute_intermediates, or recompute.

        If compute_intermediates() was called first, its cached buffers are
        returned and the cache is cleared. Otherwise, a fresh witness
        computation is performed.

        Args:
            ctx: ConstraintContext (must be ProverConstraintContext)

        Returns:
            Tuple of (BufferSet, domain_size)
        """
        if hasattr(self, '_last_buffers'):
            buffers = self._last_buffers
            N = self._last_N
            del self._last_buffers
            del self._last_N
            return buffers, N

        # No cached buffers -- run full computation
        from constraints.base import ProverConstraintContext
        if not isinstance(ctx, ProverConstraintContext):
            raise TypeError("BytecodeWitnessModule only supports prover mode")
        return self._run_witness_computation(ctx)

    def compute_intermediates(self, ctx: ConstraintContext) -> dict[str, dict[int, FF3Poly]]:
        """Compute intermediate columns using bytecode interpreter.

        Runs im_col hints via calculate_witness_std(prod=False), extracts
        the intermediate columns from the buffer.
        """
        from constraints.base import ProverConstraintContext
        if not isinstance(ctx, ProverConstraintContext):
            raise TypeError("BytecodeWitnessModule only supports prover mode")

        buffers, N = self._run_witness_computation(ctx)

        # Store buffers for grand sums extraction
        self._last_buffers = buffers
        self._last_N = N

        return _extract_intermediates(self._stark_info, buffers, N)

    def compute_grand_sums(self, ctx: ConstraintContext) -> dict[str, FF3Poly]:
        """Extract grand sums from the witness computation.

        Must be called after compute_intermediates() which runs the full
        witness computation. The grand sums are already computed and stored
        in the buffers.
        """
        buffers, N = self._ensure_buffers(ctx)
        return _extract_grand_sums(self._stark_info, buffers, N)
