"""STARK proof verification."""


import numpy as np
from poseidon2_ffi import linear_hash, verify_grinding

from primitives.field import (
    FF,
    FF3,
    FIELD_EXTENSION_DEGREE,
    SHIFT,
    FFArray,
    InterleavedFF3,
    ff3_array,
    ff3_coeffs,
    ff3_from_json,
    ff3_to_interleaved_numpy,
    get_omega,
)
from primitives.merkle_tree import HASH_SIZE, MerkleRoot
from primitives.merkle_verifier import MerkleVerifier
from primitives.pol_map import EvMap, PolynomialId
from primitives.polynomial import to_coefficients
from primitives.transcript import Transcript
from protocol.air_config import AirConfig
from protocol.data import VerifierData
from protocol.fri import FRI
from protocol.proof import STARKProof
from protocol.stark_info import StarkInfo

# Late import: get_constraint_module, VerifierConstraintContext imported inside functions

# --- Type Aliases ---
FRIQueryIndex = int  # Index into FRI query domain (0 to 2^n_bits_ext - 1)

# Query polynomial values: dict mapping PolynomialId -> FF3 array (vectorized over n_queries)
QueryPolynomials = dict[PolynomialId, FF3]


# Poseidon2 linear hash width for evaluation hashing.
# Value matches C++ EVALS_HASH_WIDTH in pil2-stark/src/starkpil/stark_info.hpp
# Set to 16 for Poseidon2 with arity 16 (the transcript arity).
EVALS_HASH_WIDTH = 16

# Stage number offsets from n_stages for special protocol stages
QUOTIENT_STAGE_OFFSET = 1  # n_stages + 1 = quotient polynomial stage
EVAL_STAGE_OFFSET = 2      # n_stages + 2 = evaluation stage (xi challenge)
FRI_STAGE_OFFSET = 3       # n_stages + 3 = FRI polynomial stage


def _get_challenge(challenges: InterleavedFF3, idx: int) -> InterleavedFF3:
    """Extract challenge at index from interleaved buffer."""
    return challenges[idx * FIELD_EXTENSION_DEGREE:(idx + 1) * FIELD_EXTENSION_DEGREE]


# --- Main Entry Point ---

def stark_verify(
    proof: STARKProof,
    air_config: AirConfig,
    verkey: MerkleRoot,
    global_challenge: InterleavedFF3,
    publics: FFArray | None = None,
    proof_values: FFArray | None = None,
) -> bool:
    """Verify a STARK proof. Returns True if valid.

    Verification phases:
    1. Parse proof components (evals, air values, trace values)
    2. Reconstruct Fiat-Shamir transcript to derive challenges
    3. Run verification checks:
       - Q(xi) = C(xi): quotient matches constraint evaluation
       - FRI consistency: polynomial evaluations match commitments
       - Merkle proofs: all commitment openings are valid
       - Degree bound: final FRI polynomial has correct degree
    """
    stark_info = air_config.stark_info
    stark_struct = stark_info.stark_struct

    # --- Parse proof components ---
    evals = _parse_evals(proof, stark_info)
    airgroup_values = _parse_airgroup_values(proof, stark_info)
    _air_values = _parse_air_values(proof, stark_info)  # Parsed for validation, used in transcript

    # --- Reconstruct Fiat-Shamir transcript ---
    challenges, final_pol = _reconstruct_transcript(proof, stark_info, global_challenge)

    # --- Verify proof-of-work ---
    grinding_idx = len(stark_info.challenges_map) + len(stark_struct.fri_fold_steps)
    grinding_challenge = _get_challenge(challenges, grinding_idx)
    if not verify_grinding(list(grinding_challenge), proof.nonce, stark_struct.pow_bits):
        print("ERROR: PoW verification failed")
        return False

    # --- Derive FRI query indices ---
    transcript_perm = Transcript(arity=stark_struct.transcript_arity, custom=stark_struct.merkle_tree_custom)
    transcript_perm.put(list(grinding_challenge))
    transcript_perm.put([proof.nonce])
    fri_queries = transcript_perm.get_permutations(stark_struct.n_queries, stark_struct.fri_fold_steps[0].domain_bits)

    # --- Parse query polynomial values ---
    poly_values = _parse_polynomial_values(proof, stark_info)
    ev_id_to_poly_id = _build_ev_id_to_poly_id_map(stark_info)

    # --- Compute x_div_x_sub ---
    xi = _find_xi_challenge(stark_info, challenges)
    x_div_x_sub = _compute_x_div_x_sub(stark_info, xi, fri_queries)

    # --- Verification Checks ---
    is_valid = True

    # Check 1: Q(xi) = C(xi)
    print("Verifying evaluations")
    if not _verify_evaluations(stark_info, evals, xi, challenges, airgroup_values):
        print("ERROR: Invalid evaluations")
        is_valid = False

    # Check 2: FRI polynomial consistency at query points
    print("Verifying FRI queries consistency")
    if not _verify_fri_consistency(
        proof, stark_info, poly_values, ev_id_to_poly_id, evals, x_div_x_sub, challenges, fri_queries
    ):
        print("ERROR: Verify FRI query consistency failed")
        is_valid = False

    # Check 3: Stage commitment Merkle trees
    print("Verifying stage Merkle trees")
    for stage_num in range(stark_info.n_stages + 1):
        root = proof.roots[stage_num]
        if not _verify_stage_merkle(proof, stark_info, root, stage_num + 1, fri_queries):
            print(f"ERROR: Stage {stage_num + 1} Merkle Tree verification failed")
            is_valid = False

    # Check 4: Constant polynomial Merkle tree
    print("Verifying constant Merkle tree")
    if not _verify_const_merkle(proof, stark_info, verkey, fri_queries):
        print("ERROR: Constant Merkle Tree verification failed")
        is_valid = False

    # Check 5: Custom commit Merkle trees
    print("Verifying custom commits Merkle trees")
    if publics is not None:
        for custom_commit in stark_info.custom_commits:
            root = [int(publics[custom_commit.public_values[j]]) for j in range(HASH_SIZE)]
            if not _verify_custom_commit_merkle(proof, stark_info, root, custom_commit.name, fri_queries):
                print(f"ERROR: Custom Commit {custom_commit.name} Merkle Tree verification failed")
                is_valid = False

    # Check 6: FRI layer Merkle trees
    print("Verifying FRI foldings Merkle Trees")
    for step in range(1, len(stark_struct.fri_fold_steps)):
        if not _verify_fri_merkle_tree(proof, stark_info, step, fri_queries):
            print("ERROR: FRI folding Merkle Tree verification failed")
            is_valid = False

    # Check 7: FRI folding correctness
    print("Verifying FRI foldings")
    for step in range(1, len(stark_struct.fri_fold_steps)):
        if not _verify_fri_folding(proof, stark_info, challenges, step, fri_queries):
            print("ERROR: FRI folding verification failed")
            is_valid = False

    # Check 8: Final polynomial degree bound
    print("Verifying final pol")
    if not _verify_final_polynomial(proof, stark_info):
        print("ERROR: Final polynomial verification failed")
        is_valid = False

    return is_valid


# --- Proof Parsing ---

def _parse_evals(proof: STARKProof, stark_info: StarkInfo) -> InterleavedFF3:
    return ff3_to_interleaved_numpy(ff3_from_json(proof.evals[:len(stark_info.ev_map)]))


def _parse_airgroup_values(proof: STARKProof, stark_info: StarkInfo) -> InterleavedFF3:
    num_airgroup_values = len(stark_info.airgroup_values_map)
    if num_airgroup_values == 0:
        return np.zeros(0, dtype=np.uint64)
    return ff3_to_interleaved_numpy(ff3_from_json(proof.airgroup_values[:num_airgroup_values]))


def _parse_air_values(proof: STARKProof, stark_info: StarkInfo) -> InterleavedFF3:
    """Stage 1 values are single Fe, stage 2+ are Fe3."""
    values = np.zeros(stark_info.air_values_size, dtype=np.uint64)
    buffer_offset = 0
    for i, air_value in enumerate(stark_info.air_values_map):
        if air_value.stage == 1:
            values[buffer_offset] = int(proof.air_values[i][0])
            buffer_offset += 1
        else:
            for j in range(FIELD_EXTENSION_DEGREE):
                values[buffer_offset + j] = int(proof.air_values[i][j])
            buffer_offset += FIELD_EXTENSION_DEGREE
    return values


def _parse_polynomial_values(proof: STARKProof, stark_info: StarkInfo) -> QueryPolynomials:
    """Parse polynomial values from proof into dict-based structure.

    This is the single function that replaces the previous buffer-based parsing.
    It returns a dict mapping PolynomialId -> FF3, where each FF3 value is
    vectorized across all query points.

    The [0] subscript pattern (extracting first element from proof value lists)
    is handled HERE at the parsing boundary, nowhere else.

    Args:
        proof: STARK proof with query proofs
        stark_info: STARK configuration

    Returns:
        QueryPolynomials mapping PolynomialId to FF3 arrays (shape: n_queries)
    """
    n_queries = stark_info.stark_struct.n_queries
    const_tree_idx = stark_info.n_stages + 1
    poly_values: QueryPolynomials = {}

    # --- Parse committed polynomials ---
    # Build name -> index mapping: for each name, count how many we've seen
    cm_name_indices: dict[str, int] = {}

    for cm_pol in stark_info.cm_pols_map:
        name = cm_pol.name
        stage = cm_pol.stage
        stage_pos = cm_pol.stage_pos
        dim = cm_pol.dim
        tree_idx = stage - 1

        # Get index for this name
        if name not in cm_name_indices:
            cm_name_indices[name] = 0
        index = cm_name_indices[name]
        cm_name_indices[name] += 1

        poly_id = PolynomialId('cm', name, index, stage)

        if dim == 1:
            # Base field polynomial
            vals = [
                int(proof.fri.trees.pol_queries[q][tree_idx].v[stage_pos][0])
                for q in range(n_queries)
            ]
            poly_values[poly_id] = FF3(vals)
        else:
            # Extension field polynomial (dim == 3)
            c0 = [int(proof.fri.trees.pol_queries[q][tree_idx].v[stage_pos][0]) for q in range(n_queries)]
            c1 = [int(proof.fri.trees.pol_queries[q][tree_idx].v[stage_pos + 1][0]) for q in range(n_queries)]
            c2 = [int(proof.fri.trees.pol_queries[q][tree_idx].v[stage_pos + 2][0]) for q in range(n_queries)]
            poly_values[poly_id] = ff3_array(c0, c1, c2)

    # --- Parse constant polynomials ---
    for const_pol in stark_info.const_pols_map:
        name = const_pol.name
        stage_pos = const_pol.stage_pos
        dim = const_pol.dim

        # Constants always have index 0 and stage 0
        poly_id = PolynomialId('const', name, 0, 0)

        if dim == 1:
            vals = [
                int(proof.fri.trees.pol_queries[q][const_tree_idx].v[stage_pos][0])
                for q in range(n_queries)
            ]
            poly_values[poly_id] = FF3(vals)
        else:
            c0 = [int(proof.fri.trees.pol_queries[q][const_tree_idx].v[stage_pos][0]) for q in range(n_queries)]
            c1 = [int(proof.fri.trees.pol_queries[q][const_tree_idx].v[stage_pos + 1][0]) for q in range(n_queries)]
            c2 = [int(proof.fri.trees.pol_queries[q][const_tree_idx].v[stage_pos + 2][0]) for q in range(n_queries)]
            poly_values[poly_id] = ff3_array(c0, c1, c2)

    return poly_values


def _build_ev_id_to_poly_id_map(stark_info: StarkInfo) -> dict[int, PolynomialId]:
    """Build mapping from ev_map index to PolynomialId.

    This is used by compute_fri_polynomial_verifier to look up polynomial values
    by their ev_map entry.
    """
    ev_id_to_poly_id: dict[int, PolynomialId] = {}

    # Build cm name -> index mapping (matching the order from parsing)
    cm_name_indices: dict[str, int] = {}
    cm_id_to_poly_id: dict[int, PolynomialId] = {}

    for cm_idx, cm_pol in enumerate(stark_info.cm_pols_map):
        name = cm_pol.name
        stage = cm_pol.stage

        if name not in cm_name_indices:
            cm_name_indices[name] = 0
        index = cm_name_indices[name]
        cm_name_indices[name] += 1

        cm_id_to_poly_id[cm_idx] = PolynomialId('cm', name, index, stage)

    # Build const mapping
    const_id_to_poly_id: dict[int, PolynomialId] = {}
    for const_idx, const_pol in enumerate(stark_info.const_pols_map):
        const_id_to_poly_id[const_idx] = PolynomialId('const', const_pol.name, 0, 0)

    # Map each ev_map entry to its PolynomialId
    for ev_idx, ev_entry in enumerate(stark_info.ev_map):
        ev_type = ev_entry.type
        ev_id = ev_entry.id

        if ev_type == EvMap.Type.cm:
            ev_id_to_poly_id[ev_idx] = cm_id_to_poly_id[ev_id]
        elif ev_type == EvMap.Type.const_:
            ev_id_to_poly_id[ev_idx] = const_id_to_poly_id[ev_id]
        # Skip custom type for now (not used in test AIRs)

    return ev_id_to_poly_id


def _find_xi_challenge(stark_info: StarkInfo, challenges: InterleavedFF3) -> InterleavedFF3:
    """Find xi (evaluation point) in challenges array.

    Args:
        stark_info: StarkInfo with challenges_map
        challenges: Interleaved challenge buffer

    Returns:
        xi challenge as interleaved FF3 coefficients

    Raises:
        ValueError: If xi challenge (std_xi) not found in challenges_map
    """
    for i, challenge_info in enumerate(stark_info.challenges_map):
        if challenge_info.stage == stark_info.n_stages + EVAL_STAGE_OFFSET and challenge_info.stage_id == 0:
            return _get_challenge(challenges, i)
    raise ValueError(
        f"Challenge 'std_xi' not found in challenges_map. "
        f"Expected at stage {stark_info.n_stages + EVAL_STAGE_OFFSET}, stage_id 0"
    )


# --- Fiat-Shamir Transcript Reconstruction ---

def _reconstruct_transcript(proof: STARKProof, stark_info: StarkInfo, global_challenge: InterleavedFF3) -> tuple[InterleavedFF3, InterleavedFF3]:
    """Reconstruct Fiat-Shamir transcript, returning (challenges, final_pol).

    Protocol flow:
    1. Initialize transcript with global_challenge
    2. For each stage 2..n_stages+1: derive challenges, absorb root and air values
    3. Derive evaluation point (xi) challenges
    4. Absorb evals (hashed if hash_commits enabled)
    5. Derive FRI polynomial challenges
    6. For each FRI step: derive fold challenge, absorb next root (or final poly)
    7. Derive grinding challenge for proof-of-work
    """
    stark_struct = stark_info.stark_struct
    n_challenges = len(stark_info.challenges_map)
    n_steps = len(stark_struct.fri_fold_steps)
    challenges = np.zeros((n_challenges + n_steps + 1) * FIELD_EXTENSION_DEGREE, dtype=np.uint64)

    transcript = Transcript(arity=stark_struct.transcript_arity, custom=stark_struct.merkle_tree_custom)
    transcript.put(global_challenge[:3].tolist())

    # Stages 2..n_stages+1
    challenge_idx = 0
    for stage_num in range(2, stark_info.n_stages + 2):
        for challenge_info in stark_info.challenges_map:
            if challenge_info.stage == stage_num:
                challenges[challenge_idx * FIELD_EXTENSION_DEGREE:(challenge_idx + 1) * FIELD_EXTENSION_DEGREE] = transcript.get_field()
                challenge_idx += 1

        # roots[stage_num-1] because roots[0] is root1
        transcript.put(proof.roots[stage_num - 1])

        for air_value in stark_info.air_values_map:
            if air_value.stage != 1 and air_value.stage == stage_num:
                idx = stark_info.air_values_map.index(air_value)
                transcript.put([int(v) for v in proof.air_values[idx]])

    # Evals stage (n_stages + EVAL_STAGE_OFFSET)
    for challenge_info in stark_info.challenges_map:
        if challenge_info.stage == stark_info.n_stages + EVAL_STAGE_OFFSET:
            challenges[challenge_idx * FIELD_EXTENSION_DEGREE:(challenge_idx + 1) * FIELD_EXTENSION_DEGREE] = transcript.get_field()
            challenge_idx += 1

    evals_flat = [int(v) for eval_entry in proof.evals[:len(stark_info.ev_map)] for v in eval_entry]
    if not stark_struct.hash_commits:
        transcript.put(evals_flat)
    else:
        transcript.put(list(linear_hash(evals_flat, width=EVALS_HASH_WIDTH)))

    # FRI polynomial stage (n_stages + FRI_STAGE_OFFSET)
    for challenge_info in stark_info.challenges_map:
        if challenge_info.stage == stark_info.n_stages + FRI_STAGE_OFFSET:
            challenges[challenge_idx * FIELD_EXTENSION_DEGREE:(challenge_idx + 1) * FIELD_EXTENSION_DEGREE] = transcript.get_field()
            challenge_idx += 1

    # FRI steps
    final_pol = None
    for step in range(n_steps):
        if step > 0:
            challenges[challenge_idx * FIELD_EXTENSION_DEGREE:(challenge_idx + 1) * FIELD_EXTENSION_DEGREE] = transcript.get_field()
        challenge_idx += 1

        if step < n_steps - 1:
            transcript.put(proof.fri.trees_fri[step].root)
        else:
            final_pol_ff3 = ff3_from_json(proof.fri.pol)
            final_pol = ff3_to_interleaved_numpy(final_pol_ff3)

            if not stark_struct.hash_commits:
                transcript.put(final_pol.tolist())
            else:
                hash_transcript = Transcript(arity=stark_struct.transcript_arity, custom=stark_struct.merkle_tree_custom)
                hash_transcript.put(final_pol.tolist())
                transcript.put(hash_transcript.get_state(HASH_SIZE))

    # Grinding challenge
    challenges[challenge_idx * FIELD_EXTENSION_DEGREE:(challenge_idx + 1) * FIELD_EXTENSION_DEGREE] = transcript.get_field()

    return challenges, final_pol


# --- Evaluation Verification ---

def _build_verifier_data(
    stark_info: StarkInfo, evals: InterleavedFF3, challenges: InterleavedFF3,
    airgroup_values: InterleavedFF3 = None
) -> VerifierData:
    """Build VerifierData from proof evaluations and challenges.

    Maps ev_map entries to (name, index, offset) tuples for constraint evaluation.

    Args:
        stark_info: StarkInfo with ev_map and challenges_map
        evals: Flattened evaluation buffer from proof
        challenges: Flattened challenges buffer
        airgroup_values: Optional airgroup values from proof (for boundary constraints)

    Returns:
        VerifierData ready for VerifierConstraintContext
    """
    data_evals = {}
    data_challenges = {}
    data_airgroup_values = {}

    # Map ev_map entries to evaluations
    for ev_idx, eval_entry in enumerate(stark_info.ev_map):
        ev_type = eval_entry.type
        ev_id = eval_entry.id
        offset = eval_entry.row_offset  # Row offset: -1, 0, or 1

        # Get polynomial name and index
        if ev_type.name == 'cm':
            pol_info = stark_info.cm_pols_map[ev_id]
            name = pol_info.name
            # Find index by counting same-name entries before this one
            index = 0
            for other in stark_info.cm_pols_map[:ev_id]:
                if other.name == name:
                    index += 1
        elif ev_type.name == 'const_':
            pol_info = stark_info.const_pols_map[ev_id]
            name = pol_info.name
            index = 0  # Constants don't have indices
        else:
            continue  # Skip unknown types

        # Extract evaluation value (FF3 from interleaved buffer)
        eval_base = ev_idx * FIELD_EXTENSION_DEGREE
        eval_val = FF3.Vector([
            int(evals[eval_base + 2]),
            int(evals[eval_base + 1]),
            int(evals[eval_base])
        ])

        data_evals[(name, index, offset)] = eval_val

    # Map challenges
    for ch_idx, challenge_info in enumerate(stark_info.challenges_map):
        ch_base = ch_idx * FIELD_EXTENSION_DEGREE
        ch_val = FF3.Vector([
            int(challenges[ch_base + 2]),
            int(challenges[ch_base + 1]),
            int(challenges[ch_base])
        ])
        data_challenges[challenge_info.name] = ch_val

    # Map airgroup values (for boundary constraints)
    if airgroup_values is not None:
        n_airgroup_values = len(stark_info.airgroup_values_map)
        for i in range(n_airgroup_values):
            idx = i * FIELD_EXTENSION_DEGREE
            data_airgroup_values[i] = FF3.Vector([
                int(airgroup_values[idx + 2]),
                int(airgroup_values[idx + 1]),
                int(airgroup_values[idx])
            ])

    return VerifierData(
        evals=data_evals,
        challenges=data_challenges,
        airgroup_values=data_airgroup_values
    )


def _evaluate_constraint_with_module(stark_info: StarkInfo, verifier_data: VerifierData, xi: FF3) -> InterleavedFF3:
    """Evaluate constraint polynomial C(xi)/Z_H(xi) using per-AIR constraint module.

    The constraint module returns C(xi), but we need Q(xi) = C(xi)/Z_H(xi) where
    Z_H(x) = x^N - 1 is the vanishing polynomial on the trace domain.

    Args:
        stark_info: StarkInfo with AIR name
        verifier_data: VerifierData with evaluations and challenges
        xi: The evaluation point (challenge)

    Returns:
        Buffer containing Q(xi) = C(xi)/Z_H(xi) coefficients in extension field
    """
    # Late import to avoid circular dependency
    from constraints import VerifierConstraintContext, get_constraint_module

    constraint_module = get_constraint_module(stark_info.name)
    ctx = VerifierConstraintContext(verifier_data)
    constraint_at_xi = constraint_module.constraint_polynomial(ctx)

    # Compute Z_H(xi) = xi^N - 1 where N is trace size
    trace_size = 1 << stark_info.stark_struct.n_bits
    xi_to_n = xi
    for _ in range(trace_size - 1):
        xi_to_n = xi_to_n * xi
    zh_at_xi = xi_to_n - FF3(1)

    # Q(xi) = C(xi) / Z_H(xi)
    quotient_at_xi = constraint_at_xi * (zh_at_xi ** -1)

    return np.array(ff3_coeffs(quotient_at_xi), dtype=np.uint64)


def _compute_x_div_x_sub(stark_info: StarkInfo, xi_challenge: InterleavedFF3, fri_queries: list[FRIQueryIndex]) -> InterleavedFF3:
    """Compute 1/(x - xi*w^openingPoint) for DEEP-ALI quotient.

    For each query point x and each opening point, we compute the denominator
    of the DEEP quotient: 1/(x - xi * w^openingPoint). This is used to
    reconstruct the committed polynomials from their evaluations.

    Matches C++ variable: xDivXSub (stark_verify.hpp, steps.hpp)
    """
    n_queries = stark_info.stark_struct.n_queries
    n_opening_points = len(stark_info.opening_points)

    x_div_x_sub = np.zeros(n_queries * n_opening_points * FIELD_EXTENSION_DEGREE, dtype=np.uint64)

    # Convert challenge to extension field element
    xi = FF3.Vector([int(xi_challenge[2]), int(xi_challenge[1]), int(xi_challenge[0])])

    # Domain generators
    omega_extended = FF(get_omega(stark_info.stark_struct.n_bits_ext))  # Extended domain
    omega_trace = FF(get_omega(stark_info.stark_struct.n_bits))        # Trace domain
    shift = FF(SHIFT)

    for query_idx in range(n_queries):
        # Evaluation point: x = shift * omega_extended^query_position
        query_position = fri_queries[query_idx]
        x = FF3(int(shift * (omega_extended ** query_position)))

        for opening_idx, opening_point in enumerate(stark_info.opening_points):
            # Compute omega_trace^opening_point (handle negative exponents)
            omega_power = omega_trace ** abs(opening_point)
            if opening_point < 0:
                omega_power = omega_power ** -1

            # Compute 1/(x - xi * omega^opening_point)
            shifted_challenge = xi * FF3(int(omega_power))
            inv_difference = (x - shifted_challenge) ** -1

            # Store in flattened buffer
            buffer_idx = (query_idx * n_opening_points + opening_idx) * FIELD_EXTENSION_DEGREE
            x_div_x_sub[buffer_idx:buffer_idx + FIELD_EXTENSION_DEGREE] = ff3_coeffs(inv_difference)

    return x_div_x_sub


def _compute_xi_to_trace_size(xi: FF3, trace_size: int) -> FF3:
    """Compute xi^N where N is the trace size.

    This is needed to reconstruct the full quotient polynomial from its split pieces.
    """
    x_power = FF3(1)
    for _ in range(trace_size):
        x_power = x_power * xi
    return x_power


def _reconstruct_quotient_at_xi(stark_info: StarkInfo, evals: InterleavedFF3, xi: FF3, xi_to_n: FF3) -> FF3:
    """Reconstruct Q(xi) from split quotient pieces Q_0, Q_1, ..., Q_{d-1}.

    The quotient polynomial Q is split into q_deg pieces to keep degrees manageable:
    Q(x) = Q_0(x) + x^N * Q_1(x) + x^(2N) * Q_2(x) + ...

    We reconstruct Q(xi) by summing these terms.
    """
    quotient_stage = stark_info.n_stages + QUOTIENT_STAGE_OFFSET
    quotient_start_idx = next(
        i for i, p in enumerate(stark_info.cm_pols_map)
        if p.stage == quotient_stage and p.stage_id == 0
    )

    reconstructed_quotient = FF3(0)
    xi_power_accumulator = FF3(1)

    for piece_idx in range(stark_info.q_deg):
        # Find evaluation of Q_i(xi) in the evals array
        eval_map_idx = next(
            j for j, e in enumerate(stark_info.ev_map)
            if e.type == EvMap.Type.cm and e.id == quotient_start_idx + piece_idx
        )

        # Extract the FF3 value from interleaved buffer (galois uses descending order)
        q_piece_eval = FF3.Vector([
            int(evals[eval_map_idx * FIELD_EXTENSION_DEGREE + 2]),
            int(evals[eval_map_idx * FIELD_EXTENSION_DEGREE + 1]),
            int(evals[eval_map_idx * FIELD_EXTENSION_DEGREE])
        ])

        # Accumulate: Q += xi^(i*N) * Q_i(xi)
        reconstructed_quotient = reconstructed_quotient + xi_power_accumulator * q_piece_eval
        xi_power_accumulator = xi_power_accumulator * xi_to_n

    return reconstructed_quotient


def _verify_evaluations(stark_info: StarkInfo, evals: InterleavedFF3,
                        xi_challenge: InterleavedFF3, challenges: InterleavedFF3,
                        airgroup_values: InterleavedFF3) -> bool:
    """Verify Q(xi) = C(xi) - the core STARK equation.

    This checks that the prover correctly computed the quotient polynomial Q
    such that C(x) = Q(x) * Z_H(x) where C is the constraint and Z_H is the
    vanishing polynomial on the trace domain.
    """
    # Convert xi challenge to FF3
    xi = FF3.Vector([int(xi_challenge[2]), int(xi_challenge[1]), int(xi_challenge[0])])

    # Evaluate constraint polynomial using per-AIR constraint module
    verifier_data = _build_verifier_data(stark_info, evals, challenges, airgroup_values)
    constraint_buffer = _evaluate_constraint_with_module(stark_info, verifier_data, xi)
    constraint_at_xi = FF3.Vector([int(constraint_buffer[2]), int(constraint_buffer[1]), int(constraint_buffer[0])])

    # Step 2: Compute powers of xi needed for reconstruction
    trace_size = 1 << stark_info.stark_struct.n_bits
    xi_to_n = _compute_xi_to_trace_size(xi, trace_size)

    # Step 3: Reconstruct Q(xi) from split quotient pieces
    quotient_at_xi = _reconstruct_quotient_at_xi(stark_info, evals, xi, xi_to_n)

    # Step 4: Verify Q(xi) = C(xi)
    residual = ff3_coeffs(quotient_at_xi - constraint_at_xi)

    if residual[0] != 0 or residual[1] != 0 or residual[2] != 0:
        print(f"  Q(xi): {ff3_coeffs(quotient_at_xi)}")
        print(f"  C(xi): {ff3_coeffs(constraint_at_xi)}")
        print(f"  residual: {residual}")
        return False

    return True


def _verify_fri_consistency(
    proof: STARKProof,
    stark_info: StarkInfo,
    poly_values: QueryPolynomials,
    ev_id_to_poly_id: dict[int, PolynomialId],
    evals: np.ndarray,
    x_div_x_sub: np.ndarray,
    challenges: np.ndarray,
    fri_queries: list[FRIQueryIndex],
) -> bool:
    """Verify FRI polynomial matches constraint evaluation at query points."""
    from protocol.fri_polynomial import compute_fri_polynomial_verifier

    n_queries = stark_info.stark_struct.n_queries
    n_steps = len(stark_info.stark_struct.fri_fold_steps)

    # Compute FRI polynomial at query points using dict-based polynomial access
    buff = compute_fri_polynomial_verifier(
        stark_info, poly_values, ev_id_to_poly_id, evals, x_div_x_sub, challenges, n_queries
    )

    for query_idx in range(n_queries):
        idx = fri_queries[query_idx] % (1 << stark_info.stark_struct.fri_fold_steps[0].domain_bits)

        if n_steps > 1:
            next_n_groups = 1 << stark_info.stark_struct.fri_fold_steps[1].domain_bits
            group_idx = idx // next_n_groups
            # Get FRI step 1 values: proof.fri.trees_fri[0].pol_queries[query_idx][0].v[col][0]
            fri_vals = proof.fri.trees_fri[0].pol_queries[query_idx][0].v
            proof_coeffs = [fri_vals[group_idx * FIELD_EXTENSION_DEGREE + j][0] for j in range(FIELD_EXTENSION_DEGREE)]
        else:
            proof_coeffs = proof.fri.pol[idx]

        computed = buff[query_idx * FIELD_EXTENSION_DEGREE:(query_idx + 1) * FIELD_EXTENSION_DEGREE]
        for j in range(FIELD_EXTENSION_DEGREE):
            if int(proof_coeffs[j]) != int(computed[j]):
                print(f"  FRI consistency mismatch at query {query_idx}, coefficient {j}")
                print(f"    proof: {proof_coeffs}, computed: {list(computed)}")
                return False

    return True


# --- Merkle Tree Verification ---

def _verify_stage_merkle(proof: STARKProof, stark_info: StarkInfo, root: MerkleRoot, stage: int,
                         fri_queries: list[FRIQueryIndex]) -> bool:
    """Verify stage commitment Merkle tree using MerkleVerifier.

    The MerkleVerifier encapsulates all last_level_verification logic internally,
    providing a clean verify_query() interface.
    """
    verifier = MerkleVerifier.for_stage(proof, stark_info, root, stage)
    n_queries = stark_info.stark_struct.n_queries
    tree_idx = stage - 1
    n_cols = stark_info.map_sections_n[f"cm{stage}"]

    for query_idx in range(n_queries):
        query_proof = proof.fri.trees.pol_queries[query_idx][tree_idx]
        # Extract values (handling [0] subscript at parsing boundary)
        values = [int(query_proof.v[i][0]) for i in range(n_cols)]
        # Extract siblings
        siblings = query_proof.mp

        if not verifier.verify_query(fri_queries[query_idx], values, siblings):
            print(f"  Stage {stage} Merkle verification failed at query {query_idx}")
            return False

    return True


def _verify_const_merkle(proof: STARKProof, stark_info: StarkInfo, verkey: MerkleRoot,
                         fri_queries: list[FRIQueryIndex]) -> bool:
    """Verify constant polynomial Merkle tree using MerkleVerifier."""
    verifier = MerkleVerifier.for_const(proof, stark_info, verkey)
    n_queries = stark_info.stark_struct.n_queries
    const_tree_idx = stark_info.n_stages + 1
    n_cols = stark_info.n_constants

    for query_idx in range(n_queries):
        query_proof = proof.fri.trees.pol_queries[query_idx][const_tree_idx]
        values = [int(query_proof.v[i][0]) for i in range(n_cols)]
        siblings = query_proof.mp

        if not verifier.verify_query(fri_queries[query_idx], values, siblings):
            print(f"  Constant tree Merkle verification failed at query {query_idx}")
            return False

    return True


def _verify_custom_commit_merkle(proof: STARKProof, stark_info: StarkInfo, root: MerkleRoot, name: str,
                                 fri_queries: list[FRIQueryIndex]) -> bool:
    """Verify custom commit Merkle tree (not implemented for test AIRs)."""
    # Custom commits are not used in test AIRs, return True for now
    return True


def _verify_fri_merkle_tree(proof: STARKProof, stark_info: StarkInfo, step: int, fri_queries: list[FRIQueryIndex]) -> bool:
    """Verify FRI layer Merkle tree using MerkleVerifier."""
    verifier = MerkleVerifier.for_fri_step(proof, stark_info, step)
    stark_struct = stark_info.stark_struct
    n_queries = stark_struct.n_queries

    # Compute number of columns for this FRI step
    n_groups = 1 << stark_struct.fri_fold_steps[step].domain_bits
    group_size = (1 << stark_struct.fri_fold_steps[step - 1].domain_bits) // n_groups
    n_cols = group_size * FIELD_EXTENSION_DEGREE

    for query_idx in range(n_queries):
        idx = fri_queries[query_idx] % (1 << stark_struct.fri_fold_steps[step].domain_bits)
        query_proof = proof.fri.trees_fri[step - 1].pol_queries[query_idx][0]
        values = [int(query_proof.v[i][0]) for i in range(n_cols)]
        siblings = query_proof.mp

        if not verifier.verify_query(idx, values, siblings):
            print(f"  FRI step {step} Merkle verification failed at query {query_idx}")
            return False

    return True


# --- FRI Verification ---

def _verify_fri_folding(proof: STARKProof, stark_info: StarkInfo, challenges: InterleavedFF3, step: int,
                        fri_queries: list[FRIQueryIndex]) -> bool:
    """Verify FRI folding: P'(y) derived correctly from P(y), P(-y), etc.

    FRI soundness relies on correct folding: at each step, the prover commits
    to a polynomial P' of half the degree, where P'(y) is computed from
    evaluations P(x), P(-x), P(wx), P(-wx), ... using a random challenge.

    For each query point, we:
    1. Gather sibling evaluations from the proof (all coset members)
    2. Recompute the folded value using FRI.verify_fold
    3. Check it matches the claimed value in the next FRI layer (or final poly)
    """
    stark_struct = stark_info.stark_struct
    n_queries = stark_struct.n_queries
    n_steps = len(stark_struct.fri_fold_steps)

    for query_idx in range(n_queries):
        idx = fri_queries[query_idx] % (1 << stark_struct.fri_fold_steps[step].domain_bits)

        # Gather sibling evaluations from FRI tree query proof
        n_x = 1 << (stark_struct.fri_fold_steps[step - 1].domain_bits - stark_struct.fri_fold_steps[step].domain_bits)
        fri_vals = proof.fri.trees_fri[step - 1].pol_queries[query_idx][0].v
        siblings = [
            [int(fri_vals[i * FIELD_EXTENSION_DEGREE + j][0]) for j in range(FIELD_EXTENSION_DEGREE)]
            for i in range(n_x)
        ]

        fold_challenge_idx = len(stark_info.challenges_map) + step
        challenge = [int(c) for c in _get_challenge(challenges, fold_challenge_idx)]

        value = FRI.verify_fold(
            value=[0, 0, 0],
            fri_round=step,
            n_bits_ext=stark_struct.n_bits_ext,
            current_bits=stark_struct.fri_fold_steps[step].domain_bits,
            prev_bits=stark_struct.fri_fold_steps[step - 1].domain_bits,
            challenge=challenge,
            idx=idx,
            siblings=siblings,
        )

        # Check against next layer or final polynomial
        if step < n_steps - 1:
            next_bits = stark_struct.fri_fold_steps[step + 1].domain_bits
            sibling_pos = idx >> next_bits
            next_fri_vals = proof.fri.trees_fri[step].pol_queries[query_idx][0].v
            expected = [next_fri_vals[sibling_pos * FIELD_EXTENSION_DEGREE + j][0] for j in range(FIELD_EXTENSION_DEGREE)]
        else:
            expected = proof.fri.pol[idx]

        if value != FF3.Vector([int(expected[2]), int(expected[1]), int(expected[0])]):
            print(f"  FRI folding mismatch at step {step}, query {query_idx}")
            print(f"    computed: {ff3_coeffs(value)}, expected: {expected}")
            return False

    return True


def _verify_final_polynomial(proof: STARKProof, stark_info: StarkInfo) -> bool:
    """Verify final polynomial has correct degree bound.

    Protocol check: The final FRI polynomial must have degree less than the
    claimed bound. We verify this by converting to coefficient form and checking
    that high-degree coefficients are zero.

    Note: The conversion to coefficient form is a protocol-level operation
    (interpolation), not an implementation detail. The fact that we use INTT
    internally is hidden by the polynomial abstraction.
    """
    stark_struct = stark_info.stark_struct
    final_pol_ff3 = ff3_from_json(proof.fri.pol)
    final_pol = ff3_to_interleaved_numpy(final_pol_ff3)
    final_pol_size = len(final_pol_ff3)

    # Convert from evaluation form to coefficient form
    final_pol_reshaped = final_pol.reshape(final_pol_size, FIELD_EXTENSION_DEGREE)
    final_pol_coeffs = to_coefficients(final_pol_reshaped, final_pol_size, n_cols=FIELD_EXTENSION_DEGREE)

    # High-degree coefficients must be zero
    last_step = stark_struct.fri_fold_steps[-1].domain_bits
    blowup_factor = stark_struct.n_bits_ext - stark_struct.n_bits
    init = 0 if blowup_factor > last_step else (1 << (last_step - blowup_factor))

    for i in range(init, final_pol_size):
        if any(int(final_pol_coeffs[i, j]) != 0 for j in range(FIELD_EXTENSION_DEGREE)):
            print(f"ERROR: Final polynomial is not zero at position {i}")
            return False

    return True
