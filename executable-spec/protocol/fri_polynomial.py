"""FRI polynomial computation.

The FRI polynomial F combines all committed polynomial evaluations into a single
polynomial for the FRI proximity test using polynomial batching.

**Naive formula (NOT USED BY BYTECODE):**
    F(x) = Σ_i (vf1^i * vf2^openingPos[i]) * (poly_i(x) - eval_i) / (x - xi_i)

**Actual bytecode formula (Horner's method grouped by opening position):**
The bytecode groups evaluations by opening position and uses Horner's method:

    For each openingPos group g:
        group_g = Σ_i (poly_i - eval_i) * vf2^(rank within group in reverse order)
        group_g = group_g * xDivXSubXi[g]

    F(x) = (group_0 + group_1) * vf1 + group_2

Where:
- vf1, vf2 are FRI verification challenges (std_vf1, std_vf2)
- xDivXSubXi[g] = 1/(x - xi * ω^openingPoints[g])
- Groups are combined with vf1 multiplier between them

Note: The compute_fri_polynomial function below implements the naive formula,
which produces different results from the bytecode. For correctness, use the
expression binary evaluator (expressionsCtx.calculate_expression with friExpId).
"""

import numpy as np
from typing import TYPE_CHECKING

from primitives.field import (
    FF, FF3, ff3,
    ff3_from_numpy_coeffs, ff3_to_interleaved_numpy,
    ff3_from_interleaved_numpy,
    FIELD_EXTENSION_DEGREE,
)
from primitives.pol_map import EvMap

if TYPE_CHECKING:
    from protocol.stark_info import StarkInfo
    from protocol.proof_context import ProofContext


def _get_polynomial_on_domain(
    stark_info: 'StarkInfo',
    params: 'ProofContext',
    ev_entry: EvMap,
    domain_size: int,
    extended: bool = True
) -> FF3:
    """Get polynomial values on evaluation domain.

    Args:
        stark_info: StarkInfo with polynomial mappings
        params: ProofContext with trace buffers
        ev_entry: evMap entry with type, id, prime, openingPos
        domain_size: Size of evaluation domain
        extended: Whether using extended domain

    Returns:
        FF3 array of polynomial values
    """
    ev_type = ev_entry.type
    ev_id = ev_entry.id
    opening_pos = ev_entry.openingPos
    prime = ev_entry.prime  # Row offset: -1, 0, or 1

    if ev_type == EvMap.Type.cm:
        # Committed polynomial
        pol_info = stark_info.cmPolsMap[ev_id]
        stage = pol_info.stage
        dim = pol_info.dim
        stage_pos = pol_info.stagePos
        section = f"cm{stage}"
        n_cols = stark_info.mapSectionsN.get(section, 0)

        if stage == 1 and not extended:
            # Non-extended: use original trace buffer
            buffer = params.trace
            base_offset = 0
        else:
            # Extended domain or stage > 1: use auxTrace with proper offset
            base_offset = stark_info.mapOffsets.get((section, extended), 0)
            buffer = params.auxTrace

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
        pol_info = stark_info.constPolsMap[ev_id]
        dim = pol_info.dim
        stage_pos = pol_info.stagePos
        n_cols = stark_info.nConstants

        # Use extended constants buffer for extended domain
        const_buffer = params.constPolsExtended if extended else params.constPols

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
    params: 'ProofContext',
    domain_size: int,
    extended: bool = True,
    prover_helpers: 'ProverHelpers' = None
) -> np.ndarray:
    """Compute FRI polynomial on evaluation domain using polynomial batching.

    F(x) = Σ_i (vf1^i * vf2^openingPos[i]) * (poly_i(x) - eval_i) / (x - xi_i)

    Args:
        stark_info: StarkInfo with evMap and challenge mappings
        params: ProofContext with trace buffers, challenges, and evals
        domain_size: Size of evaluation domain
        extended: Whether using extended domain
        prover_helpers: ProverHelpers with x domain values (required for prover)

    Returns:
        FRI polynomial as interleaved numpy array (domain_size * 3)
    """
    from primitives.field import batch_inverse, get_omega

    # Get vf1, vf2 challenges
    vf1_idx = next(
        i for i, cm in enumerate(stark_info.challengesMap)
        if cm.name == 'std_vf1'
    )
    vf2_idx = next(
        i for i, cm in enumerate(stark_info.challengesMap)
        if cm.name == 'std_vf2'
    )

    vf1 = ff3_from_numpy_coeffs(
        params.challenges[vf1_idx * FIELD_EXTENSION_DEGREE:(vf1_idx + 1) * FIELD_EXTENSION_DEGREE]
    )
    vf2 = ff3_from_numpy_coeffs(
        params.challenges[vf2_idx * FIELD_EXTENSION_DEGREE:(vf2_idx + 1) * FIELD_EXTENSION_DEGREE]
    )

    # Get xi challenge
    xi_idx = next(
        i for i, cm in enumerate(stark_info.challengesMap)
        if cm.stage == stark_info.nStages + 2 and cm.stageId == 0
    )
    xi = ff3_from_numpy_coeffs(
        params.challenges[xi_idx * FIELD_EXTENSION_DEGREE:(xi_idx + 1) * FIELD_EXTENSION_DEGREE]
    )

    # Compute xis[i] = xi * ω^openingPoints[i] for each opening position
    n_opening_points = len(stark_info.openingPoints)
    w = FF(get_omega(stark_info.starkStruct.nBits))
    xis = []
    for op in stark_info.openingPoints:
        if op >= 0:
            w_power = FF3([int(w ** op)])  # Embed in extension field
        else:
            w_power = FF3([int((w ** (-op)) ** -1)])
        xis.append(xi * w_power)

    # Get domain x values: x[j] = g^j * shift where g is the extended domain generator
    # For the extended domain, we need x values from prover_helpers
    if prover_helpers is not None:
        x_domain = FF3(np.asarray(prover_helpers.x[:domain_size], dtype=np.uint64))
    else:
        # Fall back to computing x values
        g_ext = FF(get_omega(stark_info.starkStruct.nBitsExt))
        shift = FF(stark_info.starkStruct.power)
        x_vals = [int(shift * (g_ext ** j)) for j in range(domain_size)]
        x_domain = FF3(np.asarray(x_vals, dtype=np.uint64))

    # Precompute 1/(x - xi_i) for each opening position
    x_div_x_sub_xi = []
    for xi_val in xis:
        diff = x_domain - xi_val
        inv_diff = batch_inverse(diff)
        x_div_x_sub_xi.append(inv_diff)

    # Precompute powers of vf2 for each openingPos
    vf2_powers = [ff3([1, 0, 0])]  # vf2^0
    for i in range(1, n_opening_points):
        vf2_powers.append(vf2_powers[-1] * vf2)

    # Initialize result to zero
    result = FF3(np.zeros(domain_size, dtype=np.uint64))

    # Process each evMap entry
    vf1_power = ff3([1, 0, 0])  # vf1^0

    for ev_idx, ev_entry in enumerate(stark_info.evMap):
        opening_pos = ev_entry.openingPos

        # Get polynomial values on domain
        poly_vals = _get_polynomial_on_domain(
            stark_info, params, ev_entry, domain_size, extended
        )

        # Get claimed evaluation for this polynomial
        eval_base = ev_idx * FIELD_EXTENSION_DEGREE
        eval_coeffs = [
            int(params.evals[eval_base]),
            int(params.evals[eval_base + 1]),
            int(params.evals[eval_base + 2])
        ]
        eval_val = ff3(eval_coeffs)

        # Compute (poly_vals - eval) * 1/(x - xi)
        diff = poly_vals - eval_val
        batched = diff * x_div_x_sub_xi[opening_pos]

        # Compute coefficient: vf1^i * vf2^openingPos
        coeff = vf1_power * vf2_powers[opening_pos]

        # Add to result: result += coeff * batched
        result = result + coeff * batched

        # Update vf1 power for next entry
        vf1_power = vf1_power * vf1

    return ff3_to_interleaved_numpy(result)


def compute_fri_polynomial_at_queries(
    stark_info: 'StarkInfo',
    params: 'ProofContext',
    query_indices: list[int],
    evals: np.ndarray
) -> np.ndarray:
    """Compute FRI polynomial at specific query points for verifier.

    Unlike the prover which computes on the full domain, the verifier only
    needs values at specific query indices. The polynomial evaluations at
    these points come from the proof (evals buffer).

    Args:
        stark_info: StarkInfo with evMap
        params: ProofContext with challenges
        query_indices: List of query point indices
        evals: Evaluation buffer from proof

    Returns:
        FRI polynomial values at query points as interleaved array
    """
    n_queries = len(query_indices)

    # Get vf1, vf2 challenges
    vf1_idx = next(
        i for i, cm in enumerate(stark_info.challengesMap)
        if cm.name == 'std_vf1'
    )
    vf2_idx = next(
        i for i, cm in enumerate(stark_info.challengesMap)
        if cm.name == 'std_vf2'
    )

    vf1 = ff3_from_numpy_coeffs(
        params.challenges[vf1_idx * FIELD_EXTENSION_DEGREE:(vf1_idx + 1) * FIELD_EXTENSION_DEGREE]
    )
    vf2 = ff3_from_numpy_coeffs(
        params.challenges[vf2_idx * FIELD_EXTENSION_DEGREE:(vf2_idx + 1) * FIELD_EXTENSION_DEGREE]
    )

    # Initialize result
    result = FF3(np.zeros(n_queries, dtype=np.uint64))

    # Precompute powers of vf2
    n_opening_points = len(stark_info.openingPoints)
    vf2_powers = [ff3([1, 0, 0])]
    for i in range(1, n_opening_points):
        vf2_powers.append(vf2_powers[-1] * vf2)

    # Process each evMap entry
    vf1_power = ff3([1, 0, 0])

    for ev_idx, ev_entry in enumerate(stark_info.evMap):
        opening_pos = ev_entry.openingPos

        # Get evaluations at query points from evals buffer
        # evals layout: [eval0_coeff0, eval0_coeff1, eval0_coeff2, eval1_coeff0, ...]
        eval_vals = np.zeros(n_queries * FIELD_EXTENSION_DEGREE, dtype=np.uint64)
        for q in range(n_queries):
            base_idx = ev_idx * FIELD_EXTENSION_DEGREE
            for k in range(FIELD_EXTENSION_DEGREE):
                eval_vals[q * FIELD_EXTENSION_DEGREE + k] = evals[base_idx + k]

        poly_vals = ff3_from_interleaved_numpy(eval_vals, n_queries)

        # Compute coefficient and add to result
        coeff = vf1_power * vf2_powers[opening_pos]
        result = result + coeff * poly_vals

        vf1_power = vf1_power * vf1

    return ff3_to_interleaved_numpy(result)
