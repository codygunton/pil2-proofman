"""FRI polynomial computation.

The FRI polynomial F combines all committed polynomial evaluations into a single
polynomial for the FRI proximity test using polynomial batching.

**Batching formula (matching C++ bytecode):**

Within each opening position group g (with entries [e0, e1, ..., en] in evMap order):
    group_g = (vf2^n * (p0 - ev0) + vf2^{n-1} * (p1 - ev1) + ... + (pn - evn)) * xDivXSubXi[g]

First entry in group gets highest vf2 power, last entry gets vf2^0.

Between groups (with n_groups opening positions):
    F = vf1^{n_groups-1} * group_0 + vf1^{n_groups-2} * group_1 + ... + group_{n_groups-1}

First group gets highest vf1 power, last group gets vf1^0.

Where:
- vf1, vf2 are FRI verification challenges (std_vf1, std_vf2)
- xDivXSubXi[g] = 1/(x - xi * ω^openingPoints[g])
"""

from typing import TYPE_CHECKING

import numpy as np

from primitives.field import (
    FF,
    FF3,
    FIELD_EXTENSION_DEGREE,
    ff3_from_interleaved_numpy,
    ff3_to_interleaved_numpy,
)
from primitives.pol_map import EvMap

if TYPE_CHECKING:
    from protocol.air_config import ProverHelpers
    from protocol.stark_info import StarkInfo


def _get_polynomial_on_domain(
    stark_info: 'StarkInfo',
    trace: np.ndarray,
    aux_trace: np.ndarray,
    const_pols_extended: np.ndarray,
    ev_entry: EvMap,
    domain_size: int,
    extended: bool = True
) -> FF3:
    """Get polynomial values on evaluation domain.

    Args:
        stark_info: StarkInfo with polynomial mappings
        trace: Stage 1 trace buffer
        aux_trace: Auxiliary trace buffer
        const_pols_extended: Extended constant polynomials
        ev_entry: evMap entry with type, id, prime, openingPos
        domain_size: Size of evaluation domain
        extended: Whether using extended domain

    Returns:
        FF3 array of polynomial values
    """
    ev_type = ev_entry.type
    ev_id = ev_entry.id

    if ev_type == EvMap.Type.cm:
        # Committed polynomial
        pol_info = stark_info.cm_pols_map[ev_id]
        stage = pol_info.stage
        dim = pol_info.dim
        stage_pos = pol_info.stage_pos
        section = f"cm{stage}"
        n_cols = stark_info.map_sections_n.get(section, 0)

        if stage == 1 and not extended:
            # Non-extended: use original trace buffer
            buffer = trace
            base_offset = 0
        else:
            # Extended domain or stage > 1: use auxTrace with proper offset
            base_offset = stark_info.map_offsets.get((section, extended), 0)
            buffer = aux_trace

        # For FRI polynomial, read polynomial WITHOUT row offset
        # The row offset (prime) only determines which evaluation point and denominator to use,
        # not how to access the polynomial values
        result = np.zeros(domain_size * dim, dtype=np.uint64)
        for j in range(domain_size):
            src_row = j  # No row offset for polynomial access
            src_idx = base_offset + src_row * n_cols + stage_pos
            result[j * dim:(j + 1) * dim] = buffer[src_idx:src_idx + dim]

        if dim == 1:
            # Embed base field in extension field
            return FF3(np.asarray(result, dtype=np.uint64))
        else:
            return ff3_from_interleaved_numpy(result, domain_size)

    elif ev_type == EvMap.Type.const_:
        # Constant polynomial
        pol_info = stark_info.const_pols_map[ev_id]
        dim = pol_info.dim
        stage_pos = pol_info.stage_pos
        n_cols = stark_info.n_constants

        # Use extended constants buffer for extended domain
        const_buffer = const_pols_extended

        # For FRI polynomial, read constant polynomial WITHOUT row offset
        result = np.zeros(domain_size * dim, dtype=np.uint64)
        for j in range(domain_size):
            src_row = j  # No row offset for polynomial access
            src_idx = src_row * n_cols + stage_pos
            result[j * dim:(j + 1) * dim] = const_buffer[src_idx:src_idx + dim]

        if dim == 1:
            return FF3(np.asarray(result, dtype=np.uint64))
        else:
            return ff3_from_interleaved_numpy(result, domain_size)

    else:
        raise ValueError(f"Unknown evMap type: {ev_type}")


def compute_fri_polynomial(
    stark_info: 'StarkInfo',
    trace: np.ndarray,
    aux_trace: np.ndarray,
    const_pols_extended: np.ndarray,
    evals: np.ndarray,
    xi: FF3,
    vf1: FF3,
    vf2: FF3,
    domain_size: int,
    extended: bool = True,
    prover_helpers: 'ProverHelpers' = None
) -> np.ndarray:
    """Compute FRI polynomial on evaluation domain using polynomial batching.

    F(x) = Σ_i (vf1^i * vf2^openingPos[i]) * (poly_i(x) - eval_i) / (x - xi_i)

    Args:
        stark_info: StarkInfo with evMap and challenge mappings
        trace: Stage 1 trace buffer
        aux_trace: Auxiliary trace buffer
        const_pols_extended: Extended constant polynomials
        evals: Polynomial evaluations array
        xi: Evaluation point challenge
        vf1: FRI batching challenge 1
        vf2: FRI batching challenge 2
        domain_size: Size of evaluation domain
        extended: Whether using extended domain
        prover_helpers: ProverHelpers with x domain values (required for prover)

    Returns:
        FRI polynomial as interleaved numpy array (domain_size * 3)
    """
    from primitives.field import batch_inverse, get_omega

    # Compute xis[i] = xi * ω^opening_points[i] for each opening position
    w = FF(get_omega(stark_info.stark_struct.n_bits))
    xis = []
    for op in stark_info.opening_points:
        w_power = FF3([int(w ** op)]) if op >= 0 else FF3([int((w ** (-op)) ** -1)])
        xis.append(xi * w_power)

    # Get domain x values: x[j] = g^j * shift where g is the extended domain generator
    # For the extended domain, we need x values from prover_helpers
    if prover_helpers is not None:
        x_domain = FF3(np.asarray(prover_helpers.x[:domain_size], dtype=np.uint64))
    else:
        # Fall back to computing x values
        g_ext = FF(get_omega(stark_info.stark_struct.n_bits_ext))
        shift = FF(stark_info.stark_struct.power)
        x_vals = [int(shift * (g_ext ** j)) for j in range(domain_size)]
        x_domain = FF3(np.asarray(x_vals, dtype=np.uint64))

    # Precompute 1/(x - xi_i) for each opening position
    x_div_x_sub_xi = []
    for xi_val in xis:
        diff = x_domain - xi_val
        inv_diff = batch_inverse(diff)
        x_div_x_sub_xi.append(inv_diff)

    # Group ev_map entries by opening position index
    # ev_map[i].opening_pos is the INDEX into opening_points, not the actual value
    # Each group contains (ev_idx, ev_entry) pairs in ev_map order
    groups_by_opening_idx = {}
    for ev_idx, ev_entry in enumerate(stark_info.ev_map):
        opening_idx = ev_entry.opening_pos  # This is already an index
        if opening_idx not in groups_by_opening_idx:
            groups_by_opening_idx[opening_idx] = []
        groups_by_opening_idx[opening_idx].append((ev_idx, ev_entry))

    # Get ordered list of opening indices (sorted numerically)
    ordered_opening_indices = sorted(groups_by_opening_idx.keys())

    # Compute each group using Horner's method (first entry gets highest vf2 power)
    group_results = []
    for opening_idx in ordered_opening_indices:
        entries = groups_by_opening_idx[opening_idx]

        # Horner accumulation: result = 0
        # For each entry: result = result * vf2 + (poly - eval)
        # This gives first entry highest vf2 power
        group_acc = FF3(np.zeros(domain_size, dtype=np.uint64))

        for ev_idx, ev_entry in entries:
            # Get polynomial values on domain
            poly_vals = _get_polynomial_on_domain(
                stark_info, trace, aux_trace, const_pols_extended,
                ev_entry, domain_size, extended
            )

            # Get claimed evaluation for this polynomial
            eval_base = ev_idx * FIELD_EXTENSION_DEGREE
            eval_coeffs = [
                int(evals[eval_base]),
                int(evals[eval_base + 1]),
                int(evals[eval_base + 2])
            ]
            eval_val = FF3.Vector([eval_coeffs[2], eval_coeffs[1], eval_coeffs[0]])

            # Horner step: acc = acc * vf2 + (poly - eval)
            diff = poly_vals - eval_val
            group_acc = group_acc * vf2 + diff

        # Multiply by xDivXSubXi for this opening position
        group_acc = group_acc * x_div_x_sub_xi[opening_idx]
        group_results.append(group_acc)

    # Combine groups with vf1 powers (first group gets highest vf1 power)
    # Horner accumulation: result = 0
    # For each group: result = result * vf1 + group
    result = FF3(np.zeros(domain_size, dtype=np.uint64))
    for group_acc in group_results:
        result = result * vf1 + group_acc

    return ff3_to_interleaved_numpy(result)


def compute_fri_polynomial_verifier(
    stark_info: 'StarkInfo',
    trace: np.ndarray,
    aux_trace: np.ndarray,
    const_pols: np.ndarray,
    evals: np.ndarray,
    x_div_x_sub: np.ndarray,
    challenges: np.ndarray,
    n_queries: int
) -> np.ndarray:
    """Compute FRI polynomial at query points for verifier.

    The verifier computes:
    F(q) = Σ_i (vf1^i * vf2^openingPos[i]) * (poly_i(q) - eval_i) * xDivXSub[q][openingPos[i]]

    Where:
    - poly_i(q) are polynomial values at query point q (from trace/auxTrace)
    - eval_i are claimed evaluations at xi (from evals)
    - xDivXSub[q][i] = 1/(x_q - xi * ω^openingPoints[i])

    Args:
        stark_info: StarkInfo with evMap and polynomial mappings
        trace: Stage 1 trace buffer (query-sized)
        aux_trace: Auxiliary trace buffer (query-sized)
        const_pols: Constant polynomials
        evals: Polynomial evaluations from proof
        x_div_x_sub: Precomputed 1/(x - xi*w^k) values
        challenges: Challenge array (interleaved format)
        n_queries: Number of query points

    Returns:
        FRI polynomial values at query points as interleaved array (n_queries * 3)
    """
    from primitives.field import ff3_from_numpy_coeffs

    # Get vf1, vf2 challenges
    vf1_idx = next(
        i for i, cm in enumerate(stark_info.challenges_map)
        if cm.name == 'std_vf1'
    )
    vf2_idx = next(
        i for i, cm in enumerate(stark_info.challenges_map)
        if cm.name == 'std_vf2'
    )

    vf1 = ff3_from_numpy_coeffs(
        challenges[vf1_idx * FIELD_EXTENSION_DEGREE:(vf1_idx + 1) * FIELD_EXTENSION_DEGREE]
    )
    vf2 = ff3_from_numpy_coeffs(
        challenges[vf2_idx * FIELD_EXTENSION_DEGREE:(vf2_idx + 1) * FIELD_EXTENSION_DEGREE]
    )

    n_opening_points = len(stark_info.opening_points)

    # Helper to get polynomial values at query points
    def get_poly_vals_at_queries(ev_entry: EvMap) -> FF3 | None:
        ev_type = ev_entry.type
        ev_id = ev_entry.id

        if ev_type == EvMap.Type.cm:
            pol_info = stark_info.cm_pols_map[ev_id]
            stage = pol_info.stage
            dim = pol_info.dim
            stage_pos = pol_info.stage_pos
            section = f"cm{stage}"
            n_cols = stark_info.map_sections_n.get(section, 0)

            if stage == 1:
                buffer = trace
                base_offset = 0
            else:
                base_offset = 0
                for s in range(2, stage):
                    sec = f"cm{s}"
                    if sec in stark_info.map_sections_n:
                        base_offset += n_queries * stark_info.map_sections_n[sec]
                buffer = aux_trace

            poly_raw = np.zeros(n_queries * dim, dtype=np.uint64)
            for q in range(n_queries):
                src_idx = base_offset + q * n_cols + stage_pos
                poly_raw[q * dim:(q + 1) * dim] = buffer[src_idx:src_idx + dim]

            if dim == 1:
                return FF3(np.asarray(poly_raw, dtype=np.uint64))
            else:
                return ff3_from_interleaved_numpy(poly_raw, n_queries)

        elif ev_type == EvMap.Type.const_:
            pol_info = stark_info.const_pols_map[ev_id]
            dim = pol_info.dim
            stage_pos = pol_info.stage_pos
            n_cols = stark_info.n_constants

            poly_raw = np.zeros(n_queries * dim, dtype=np.uint64)
            for q in range(n_queries):
                src_idx = q * n_cols + stage_pos
                poly_raw[q * dim:(q + 1) * dim] = const_pols[src_idx:src_idx + dim]

            if dim == 1:
                return FF3(np.asarray(poly_raw, dtype=np.uint64))
            else:
                return ff3_from_interleaved_numpy(poly_raw, n_queries)
        else:
            return None

    # Helper to get xDivXSub for opening position at all queries
    def get_x_div_x_sub(opening_idx: int) -> FF3:
        x_div_raw = np.zeros(n_queries * FIELD_EXTENSION_DEGREE, dtype=np.uint64)
        for q in range(n_queries):
            base = (q * n_opening_points + opening_idx) * FIELD_EXTENSION_DEGREE
            x_div_raw[q * FIELD_EXTENSION_DEGREE:(q + 1) * FIELD_EXTENSION_DEGREE] = \
                x_div_x_sub[base:base + FIELD_EXTENSION_DEGREE]
        return ff3_from_interleaved_numpy(x_div_raw, n_queries)

    # Group ev_map entries by opening position index
    # ev_map[i].opening_pos is the INDEX into opening_points, not the actual value
    groups_by_opening_idx = {}
    for ev_idx, ev_entry in enumerate(stark_info.ev_map):
        opening_idx = ev_entry.opening_pos  # This is already an index
        if opening_idx not in groups_by_opening_idx:
            groups_by_opening_idx[opening_idx] = []
        groups_by_opening_idx[opening_idx].append((ev_idx, ev_entry))

    # Get ordered list of opening indices
    ordered_opening_indices = sorted(groups_by_opening_idx.keys())

    # Compute each group using Horner's method
    group_results = []
    for opening_idx in ordered_opening_indices:
        entries = groups_by_opening_idx[opening_idx]

        # Horner accumulation within group
        group_acc = FF3(np.zeros(n_queries, dtype=np.uint64))

        for ev_idx, ev_entry in entries:
            poly_vals = get_poly_vals_at_queries(ev_entry)
            if poly_vals is None:
                continue

            eval_base = ev_idx * FIELD_EXTENSION_DEGREE
            eval_coeffs = [
                int(evals[eval_base]),
                int(evals[eval_base + 1]),
                int(evals[eval_base + 2])
            ]
            eval_val = FF3.Vector([eval_coeffs[2], eval_coeffs[1], eval_coeffs[0]])

            diff = poly_vals - eval_val
            group_acc = group_acc * vf2 + diff

        # Multiply by xDivXSubXi for this opening position
        x_div_x_sub_val = get_x_div_x_sub(opening_idx)
        group_acc = group_acc * x_div_x_sub_val
        group_results.append(group_acc)

    # Combine groups with vf1 powers (Horner accumulation)
    result = FF3(np.zeros(n_queries, dtype=np.uint64))
    for group_acc in group_results:
        result = result * vf1 + group_acc

    return ff3_to_interleaved_numpy(result)
