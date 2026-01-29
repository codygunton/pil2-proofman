"""STARK proof verification."""

import math

import numpy as np
from poseidon2_ffi import hash_seq, linear_hash, verify_grinding

from primitives.field import (
    FF,
    FF3,
    FIELD_EXTENSION_DEGREE,
    SHIFT,
    FFArray,
    InterleavedFF3,
    ff3,
    ff3_coeffs,
    ff3_from_json,
    ff3_to_interleaved_numpy,
    get_omega,
)
from primitives.merkle_tree import HASH_SIZE, MerkleRoot, MerkleTree
from primitives.pol_map import EvMap
from primitives.polynomial import to_coefficients
from primitives.transcript import Transcript
from protocol.expression_evaluator import Dest, ExpressionsPack, Params
from protocol.fri import FRI
from protocol.proof_context import ProofContext
from protocol.setup_ctx import ProverHelpers, SetupCtx
from protocol.stark_info import StarkInfo

# --- Type Aliases ---
# These provide semantic clarity for the verifier's data structures.
# Challenge represents FF3 elements stored as interleaved numpy arrays for performance.

JProof = dict                   # JSON-decoded proof structure
Challenge = InterleavedFF3      # Extension field element [c0, c1, c2] - interleaved FF3 coefficients
QueryIdx = int                  # FRI query position in domain

# --- Module Constants ---
# Poseidon2 sponge width by Merkle tree arity (arity * HASH_SIZE)
SPONGE_WIDTH_BY_ARITY = {2: 8, 3: 12, 4: 16}

# Poseidon2 linear hash width for evaluation hashing
EVALS_HASH_WIDTH = 16


# --- Main Entry Point ---

def stark_verify(
    jproof: JProof,
    setup_ctx: SetupCtx,
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
    si = setup_ctx.stark_info
    si.verify = True
    ss = si.starkStruct

    # --- Parse proof components ---
    evals = _parse_evals(jproof, si)
    airgroup_values = _parse_airgroup_values(jproof, si)
    air_values = _parse_air_values(jproof, si)

    # --- Reconstruct Fiat-Shamir transcript ---
    challenges, final_pol = _reconstruct_transcript(jproof, si, global_challenge)

    # --- Verify proof-of-work ---
    grinding_idx = len(si.challengesMap) + len(ss.friFoldSteps)
    grinding_challenge = challenges[grinding_idx * FIELD_EXTENSION_DEGREE:(grinding_idx + 1) * FIELD_EXTENSION_DEGREE]
    if not verify_grinding(list(grinding_challenge), int(jproof["nonce"]), ss.powBits):
        print("ERROR: PoW verification failed")
        return False

    # --- Derive FRI query indices ---
    transcript_perm = Transcript(arity=ss.transcriptArity, custom=ss.merkleTreeCustom)
    transcript_perm.put(list(grinding_challenge))
    transcript_perm.put([int(jproof["nonce"])])
    fri_queries = transcript_perm.get_permutations(ss.nQueries, ss.friFoldSteps[0].domainBits)

    # --- Parse query values ---
    const_pols_vals = _parse_const_pols_vals(jproof, si)
    trace, aux_trace, custom_commits = _parse_trace_values(jproof, si)

    # --- Build verifier context ---
    xi = _find_xi_challenge(si, challenges)
    prover_helpers = ProverHelpers.from_challenge(si, xi)
    expressions_pack = ExpressionsPack(setup_ctx, prover_helpers, 1, ss.nQueries)
    x_div_x_sub = _compute_x_div_x_sub(si, xi, fri_queries)

    params = ProofContext(
        trace=trace,
        auxTrace=aux_trace,
        publicInputs=publics,
        proofValues=proof_values,
        challenges=challenges,
        airgroupValues=airgroup_values,
        airValues=air_values,
        evals=evals,
        xDivXSub=x_div_x_sub,
        constPols=const_pols_vals,
        constPolsExtended=None,
        customCommits=custom_commits,
    )

    # --- Verification Checks ---
    is_valid = True

    # Check 1: Q(xi) = C(xi)
    print("Verifying evaluations")
    if not _verify_evaluations(si, setup_ctx, expressions_pack, params, evals, xi):
        print("ERROR: Invalid evaluations")
        is_valid = False

    # Check 2: FRI polynomial consistency at query points
    print("Verifying FRI queries consistency")
    if not _verify_fri_consistency(jproof, si, setup_ctx, expressions_pack, params, fri_queries):
        print("ERROR: Verify FRI query consistency failed")
        is_valid = False

    # Check 3: Stage commitment Merkle trees
    print("Verifying stage Merkle trees")
    for s in range(si.nStages + 1):
        root = _parse_root(jproof, f"root{s + 1}")
        if not _verify_stage_merkle(jproof, si, root, s + 1, fri_queries):
            print(f"ERROR: Stage {s + 1} Merkle Tree verification failed")
            is_valid = False

    # Check 4: Constant polynomial Merkle tree
    print("Verifying constant Merkle tree")
    if not _verify_const_merkle(jproof, si, verkey, fri_queries):
        print("ERROR: Constant Merkle Tree verification failed")
        is_valid = False

    # Check 5: Custom commit Merkle trees
    print("Verifying custom commits Merkle trees")
    if publics is not None:
        for cc in si.customCommits:
            root = [int(publics[cc.publicValues[j]]) for j in range(HASH_SIZE)]
            if not _verify_custom_commit_merkle(jproof, si, root, cc.name, fri_queries):
                print(f"ERROR: Custom Commit {cc.name} Merkle Tree verification failed")
                is_valid = False

    # Check 6: FRI layer Merkle trees
    print("Verifying FRI foldings Merkle Trees")
    for step in range(1, len(ss.friFoldSteps)):
        if not _verify_fri_merkle_tree(jproof, si, step, fri_queries):
            print("ERROR: FRI folding Merkle Tree verification failed")
            is_valid = False

    # Check 7: FRI folding correctness
    print("Verifying FRI foldings")
    for step in range(1, len(ss.friFoldSteps)):
        if not _verify_fri_folding(jproof, si, challenges, step, fri_queries):
            print("ERROR: FRI folding verification failed")
            is_valid = False

    # Check 8: Final polynomial degree bound
    print("Verifying final pol")
    if not _verify_final_polynomial(jproof, si):
        print("ERROR: Final polynomial verification failed")
        is_valid = False

    return is_valid


# --- Proof Parsing ---

def _parse_root(jproof: JProof, key: str) -> MerkleRoot:
    val = jproof[key]
    return [int(val)] if isinstance(val, (int, str)) else [int(val[i]) for i in range(HASH_SIZE)]


def _parse_evals(jproof: JProof, si: StarkInfo) -> InterleavedFF3:
    return ff3_to_interleaved_numpy(ff3_from_json(jproof["evals"][:len(si.evMap)]))


def _parse_airgroup_values(jproof: JProof, si: StarkInfo) -> InterleavedFF3:
    n = len(si.airgroupValuesMap)
    if n == 0:
        return np.zeros(0, dtype=np.uint64)
    return ff3_to_interleaved_numpy(ff3_from_json(jproof["airgroupvalues"][:n]))


def _parse_air_values(jproof: JProof, si: StarkInfo) -> InterleavedFF3:
    """Stage 1 values are single Fe, stage 2+ are Fe3."""
    values = np.zeros(si.airValuesSize, dtype=np.uint64)
    a = 0
    for i, av in enumerate(si.airValuesMap):
        if av.stage == 1:
            values[a] = int(jproof["airvalues"][i][0])
            a += 1
        else:
            for j in range(FIELD_EXTENSION_DEGREE):
                values[a + j] = int(jproof["airvalues"][i][j])
            a += FIELD_EXTENSION_DEGREE
    return values


def _parse_const_pols_vals(jproof: JProof, si: StarkInfo) -> FFArray:
    n_queries, n_constants = si.starkStruct.nQueries, si.nConstants
    vals = np.zeros(n_constants * n_queries, dtype=np.uint64)
    for q in range(n_queries):
        for i in range(n_constants):
            vals[q * n_constants + i] = int(jproof["s0_valsC"][q][i])
    return vals


def _compute_stage_offsets(si: StarkInfo, n_queries: int) -> tuple[dict, int]:
    """Compute buffer offsets for each stage 2+ in aux_trace.

    Returns:
        (offsets, total_size) where offsets maps stage -> buffer offset
        and total_size is the total buffer size needed.
    """
    offsets = {}
    current_offset = 0
    for stage in range(2, si.nStages + 2):
        section = f"cm{stage}"
        if section in si.mapSectionsN:
            offsets[stage] = current_offset
            current_offset += n_queries * si.mapSectionsN[section]
    return offsets, current_offset


def _compute_custom_commit_offsets(si: StarkInfo, n_queries: int) -> tuple[dict, int]:
    """Compute buffer offsets for each custom commit.

    Returns:
        (offsets, total_size) where offsets maps commit_idx -> buffer offset
        and total_size is the total buffer size needed.
    """
    offsets = {}
    current_offset = 0
    for commit_idx, commit in enumerate(si.customCommits):
        section = commit.name + "0"
        if section in si.mapSectionsN:
            offsets[commit_idx] = current_offset
            current_offset += n_queries * si.mapSectionsN[section]
    return offsets, current_offset


def _allocate_trace_buffers(si: StarkInfo, stage_offsets: dict, stage_total: int,
                            custom_offsets: dict, custom_total: int, n_queries: int) -> tuple:
    """Allocate empty buffers for trace, aux_trace, and custom_commits."""
    cm1_n_pols = si.mapSectionsN["cm1"]
    trace = np.zeros(n_queries * cm1_n_pols, dtype=np.uint64)

    # aux_trace holds all stages 2+
    aux_trace_size = max(stage_total, si.mapTotalN)
    aux_trace = np.zeros(aux_trace_size, dtype=np.uint64)

    # custom_commits holds custom commitment values
    custom_size = max(custom_total, si.mapTotalNCustomCommitsFixed)
    custom_commits = np.zeros(custom_size, dtype=np.uint64)

    return trace, aux_trace, custom_commits


def _fill_trace_from_proof(jproof: JProof, si: StarkInfo, trace: FFArray, aux_trace: FFArray,
                           custom_commits: FFArray, stage_offsets: dict, custom_offsets: dict) -> None:
    """Fill trace buffers with values from proof."""
    n_queries = si.starkStruct.nQueries

    for query_idx in range(n_queries):
        # Fill committed polynomial values
        for cm_pol in si.cmPolsMap:
            stage = cm_pol.stage
            stage_pos = cm_pol.stagePos
            n_pols = si.mapSectionsN[f"cm{stage}"]

            if stage == 1:
                # Stage 1 goes into trace buffer
                for dim_offset in range(cm_pol.dim):
                    buffer_idx = query_idx * n_pols + stage_pos + dim_offset
                    trace[buffer_idx] = int(jproof[f"s0_vals{stage}"][query_idx][stage_pos + dim_offset])
            else:
                # Stage 2+ goes into aux_trace buffer
                base_idx = stage_offsets[stage] + query_idx * n_pols + stage_pos
                for dim_offset in range(cm_pol.dim):
                    aux_trace[base_idx + dim_offset] = int(jproof[f"s0_vals{stage}"][query_idx][stage_pos + dim_offset])

        # Fill custom commit values
        for commit_idx, commit in enumerate(si.customCommits):
            section = commit.name + "0"
            n_pols = si.mapSectionsN[section]
            base_idx = custom_offsets.get(commit_idx, 0) + query_idx * n_pols

            for cm in si.customCommitsMap[commit_idx]:
                proof_key = f"s0_vals_{commit.name}_0"
                custom_commits[base_idx + cm.stagePos] = int(jproof[proof_key][query_idx][cm.stagePos])


def _parse_trace_values(jproof: JProof, si: StarkInfo) -> tuple:
    """Parse trace query values into (trace, aux_trace, custom_commits) buffers.

    This function orchestrates three steps:
    1. Compute offsets - where each stage/commit starts in its buffer
    2. Allocate buffers - create appropriately-sized numpy arrays
    3. Fill from proof - copy values from JSON proof into buffers
    """
    n_queries = si.starkStruct.nQueries

    stage_offsets, stage_total = _compute_stage_offsets(si, n_queries)
    custom_offsets, custom_total = _compute_custom_commit_offsets(si, n_queries)

    trace, aux_trace, custom_commits = _allocate_trace_buffers(
        si, stage_offsets, stage_total, custom_offsets, custom_total, n_queries
    )

    _fill_trace_from_proof(jproof, si, trace, aux_trace, custom_commits, stage_offsets, custom_offsets)

    return trace, aux_trace, custom_commits


def _find_xi_challenge(si: StarkInfo, challenges: InterleavedFF3) -> Challenge:
    """Find xi (evaluation point) in challenges array."""
    for i, ch in enumerate(si.challengesMap):
        if ch.stage == si.nStages + 2 and ch.stageId == 0:
            return challenges[i * FIELD_EXTENSION_DEGREE:(i + 1) * FIELD_EXTENSION_DEGREE]
    return np.zeros(FIELD_EXTENSION_DEGREE, dtype=np.uint64)


# --- Fiat-Shamir Transcript Reconstruction ---

def _reconstruct_transcript(jproof: JProof, si: StarkInfo, global_challenge: InterleavedFF3) -> tuple:
    """Reconstruct Fiat-Shamir transcript, returning (challenges, final_pol).

    Protocol flow:
    1. Initialize transcript with global_challenge
    2. For each stage 2..nStages+1: derive challenges, absorb root and air values
    3. Derive evaluation point (xi) challenges
    4. Absorb evals (hashed if hashCommits enabled)
    5. Derive FRI polynomial challenges
    6. For each FRI step: derive fold challenge, absorb next root (or final poly)
    7. Derive grinding challenge for proof-of-work
    """
    ss = si.starkStruct
    n_challenges = len(si.challengesMap)
    n_steps = len(ss.friFoldSteps)
    challenges = np.zeros((n_challenges + n_steps + 1) * FIELD_EXTENSION_DEGREE, dtype=np.uint64)

    transcript = Transcript(arity=ss.transcriptArity, custom=ss.merkleTreeCustom)
    transcript.put(global_challenge[:3].tolist())

    # Stages 2..nStages+1
    c = 0
    for s in range(2, si.nStages + 2):
        for ch in si.challengesMap:
            if ch.stage == s:
                challenges[c * FIELD_EXTENSION_DEGREE:(c + 1) * FIELD_EXTENSION_DEGREE] = transcript.get_field()
                c += 1

        transcript.put(_parse_root(jproof, f"root{s}"))

        for av in si.airValuesMap:
            if av.stage != 1 and av.stage == s:
                idx = si.airValuesMap.index(av)
                transcript.put([int(v) for v in jproof["airvalues"][idx]])

    # Evals stage (nStages + 2)
    for ch in si.challengesMap:
        if ch.stage == si.nStages + 2:
            challenges[c * FIELD_EXTENSION_DEGREE:(c + 1) * FIELD_EXTENSION_DEGREE] = transcript.get_field()
            c += 1

    evals_flat = [int(v) for ev in jproof["evals"][:len(si.evMap)] for v in ev]
    if not ss.hashCommits:
        transcript.put(evals_flat)
    else:
        transcript.put(list(linear_hash(evals_flat, width=EVALS_HASH_WIDTH)))

    # FRI polynomial stage (nStages + 3)
    for ch in si.challengesMap:
        if ch.stage == si.nStages + 3:
            challenges[c * FIELD_EXTENSION_DEGREE:(c + 1) * FIELD_EXTENSION_DEGREE] = transcript.get_field()
            c += 1

    # FRI steps
    final_pol = None
    for step in range(n_steps):
        if step > 0:
            challenges[c * FIELD_EXTENSION_DEGREE:(c + 1) * FIELD_EXTENSION_DEGREE] = transcript.get_field()
        c += 1

        if step < n_steps - 1:
            transcript.put(_parse_root(jproof, f"s{step + 1}_root"))
        else:
            final_pol_ff3 = ff3_from_json(jproof["finalPol"])
            final_pol = ff3_to_interleaved_numpy(final_pol_ff3)

            if not ss.hashCommits:
                transcript.put(final_pol.tolist())
            else:
                th = Transcript(arity=ss.transcriptArity, custom=ss.merkleTreeCustom)
                th.put(final_pol.tolist())
                transcript.put(th.get_state(HASH_SIZE))

    # Grinding challenge
    challenges[c * FIELD_EXTENSION_DEGREE:(c + 1) * FIELD_EXTENSION_DEGREE] = transcript.get_field()

    return challenges, final_pol


# --- Evaluation Verification ---

def _compute_x_div_x_sub(si: StarkInfo, xi_challenge: Challenge, fri_queries: list[QueryIdx]) -> InterleavedFF3:
    """Compute 1/(x - xi*w^openingPoint) for DEEP-ALI quotient.

    For each query point x and each opening point, we compute the denominator
    of the DEEP quotient: 1/(x - xi * w^openingPoint). This is used to
    reconstruct the committed polynomials from their evaluations.
    """
    n_queries = si.starkStruct.nQueries
    n_opening_points = len(si.openingPoints)

    x_div_x_sub = np.zeros(n_queries * n_opening_points * FIELD_EXTENSION_DEGREE, dtype=np.uint64)

    # Convert challenge to extension field element
    xi = ff3([int(xi_challenge[0]), int(xi_challenge[1]), int(xi_challenge[2])])

    # Domain generators
    omega_extended = FF(get_omega(si.starkStruct.nBitsExt))  # Extended domain
    omega_trace = FF(get_omega(si.starkStruct.nBits))        # Trace domain
    shift = FF(SHIFT)

    for query_idx in range(n_queries):
        # Evaluation point: x = shift * omega_extended^query_position
        query_position = fri_queries[query_idx]
        x = ff3([int(shift * (omega_extended ** query_position)), 0, 0])

        for opening_idx, opening_point in enumerate(si.openingPoints):
            # Compute omega_trace^opening_point (handle negative exponents)
            omega_power = omega_trace ** abs(opening_point)
            if opening_point < 0:
                omega_power = omega_power ** -1

            # Compute 1/(x - xi * omega^opening_point)
            shifted_challenge = xi * ff3([int(omega_power), 0, 0])
            inv_difference = (x - shifted_challenge) ** -1

            # Store in flattened buffer
            buffer_idx = (query_idx * n_opening_points + opening_idx) * FIELD_EXTENSION_DEGREE
            x_div_x_sub[buffer_idx:buffer_idx + FIELD_EXTENSION_DEGREE] = ff3_coeffs(inv_difference)

    return x_div_x_sub


def _evaluate_constraint_at_xi(si: StarkInfo, setup_ctx: SetupCtx, expressions_pack: ExpressionsPack,
                               params: ProofContext) -> InterleavedFF3:
    """Evaluate the constraint polynomial C(xi) using the expression evaluator.

    Returns:
        Buffer containing C(xi) coefficients in extension field
    """
    buff = np.zeros(FIELD_EXTENSION_DEGREE, dtype=np.uint64)
    dest = Dest(dest=buff, domain_size=1, offset=0)
    dest.exp_id = si.cExpId
    dest.dim = setup_ctx.expressions_bin.expressions_info[si.cExpId].dest_dim
    dest.params.append(Params(exp_id=si.cExpId, dim=dest.dim, batch=True, op="tmp"))
    expressions_pack.calculate_expressions(params, dest, 1, False, False)
    return buff


def _compute_xi_to_trace_size(xi: FF3, trace_size: int) -> FF3:
    """Compute xi^N where N is the trace size.

    This is needed to reconstruct the full quotient polynomial from its split pieces.
    """
    x_power = ff3([1, 0, 0])
    for _ in range(trace_size):
        x_power = x_power * xi
    return x_power


def _reconstruct_quotient_at_xi(si: StarkInfo, evals: InterleavedFF3, xi: FF3, xi_to_n: FF3) -> FF3:
    """Reconstruct Q(xi) from split quotient pieces Q_0, Q_1, ..., Q_{d-1}.

    The quotient polynomial Q is split into qDeg pieces to keep degrees manageable:
    Q(x) = Q_0(x) + x^N * Q_1(x) + x^(2N) * Q_2(x) + ...

    We reconstruct Q(xi) by summing these terms.
    """
    quotient_stage = si.nStages + 1
    quotient_start_idx = next(
        i for i, p in enumerate(si.cmPolsMap)
        if p.stage == quotient_stage and p.stageId == 0
    )

    reconstructed_quotient = ff3([0, 0, 0])
    xi_power_accumulator = ff3([1, 0, 0])

    for piece_idx in range(si.qDeg):
        # Find evaluation of Q_i(xi) in the evals array
        eval_map_idx = next(
            j for j, e in enumerate(si.evMap)
            if e.type == EvMap.Type.cm and e.id == quotient_start_idx + piece_idx
        )

        # Extract the FF3 value from interleaved buffer
        q_piece_eval = ff3([
            int(evals[eval_map_idx * FIELD_EXTENSION_DEGREE + k])
            for k in range(FIELD_EXTENSION_DEGREE)
        ])

        # Accumulate: Q += xi^(i*N) * Q_i(xi)
        reconstructed_quotient = reconstructed_quotient + xi_power_accumulator * q_piece_eval
        xi_power_accumulator = xi_power_accumulator * xi_to_n

    return reconstructed_quotient


def _verify_evaluations(si: StarkInfo, setup_ctx: SetupCtx, expressions_pack: ExpressionsPack,
                        params: ProofContext, evals: InterleavedFF3, xi_challenge: Challenge) -> bool:
    """Verify Q(xi) = C(xi) - the core STARK equation.

    This checks that the prover correctly computed the quotient polynomial Q
    such that C(x) = Q(x) * Z_H(x) where C is the constraint and Z_H is the
    vanishing polynomial on the trace domain.
    """
    # Step 1: Evaluate constraint polynomial at xi
    constraint_buffer = _evaluate_constraint_at_xi(si, setup_ctx, expressions_pack, params)
    constraint_at_xi = ff3([int(constraint_buffer[k]) for k in range(FIELD_EXTENSION_DEGREE)])

    # Step 2: Compute powers of xi needed for reconstruction
    xi = ff3([int(xi_challenge[0]), int(xi_challenge[1]), int(xi_challenge[2])])
    trace_size = 1 << si.starkStruct.nBits
    xi_to_n = _compute_xi_to_trace_size(xi, trace_size)

    # Step 3: Reconstruct Q(xi) from split quotient pieces
    quotient_at_xi = _reconstruct_quotient_at_xi(si, evals, xi, xi_to_n)

    # Step 4: Verify Q(xi) = C(xi)
    residual = ff3_coeffs(quotient_at_xi - constraint_at_xi)

    if residual[0] != 0 or residual[1] != 0 or residual[2] != 0:
        print(f"  Q(xi): {ff3_coeffs(quotient_at_xi)}")
        print(f"  C(xi): {ff3_coeffs(constraint_at_xi)}")
        print(f"  residual: {residual}")
        return False

    return True


def _verify_fri_consistency(jproof: JProof, si: StarkInfo, setup_ctx: SetupCtx,
                            expressions_pack: ExpressionsPack, params: ProofContext,
                            fri_queries: list[QueryIdx]) -> bool:
    """Verify FRI polynomial matches constraint evaluation at query points."""
    n_queries = si.starkStruct.nQueries
    n_steps = len(si.starkStruct.friFoldSteps)

    # Evaluate FRI polynomial at query points
    buff = np.zeros(FIELD_EXTENSION_DEGREE * n_queries, dtype=np.uint64)
    dest = Dest(dest=buff, domain_size=n_queries, offset=0)
    dest.exp_id = si.friExpId
    dest.dim = setup_ctx.expressions_bin.expressions_info[si.friExpId].dest_dim
    dest.params.append(Params(exp_id=si.friExpId, dim=dest.dim, batch=True, op="tmp"))
    expressions_pack.calculate_expressions(params, dest, n_queries, False, False)

    for q in range(n_queries):
        idx = fri_queries[q] % (1 << si.starkStruct.friFoldSteps[0].domainBits)

        if n_steps > 1:
            next_n_groups = 1 << si.starkStruct.friFoldSteps[1].domainBits
            group_idx = idx // next_n_groups
            proof_coeffs = jproof["s1_vals"][q][group_idx * FIELD_EXTENSION_DEGREE:(group_idx + 1) * FIELD_EXTENSION_DEGREE]
        else:
            proof_coeffs = jproof["finalPol"][idx]

        computed = buff[q * FIELD_EXTENSION_DEGREE:(q + 1) * FIELD_EXTENSION_DEGREE]
        for j in range(FIELD_EXTENSION_DEGREE):
            if int(proof_coeffs[j]) != int(computed[j]):
                return False

    return True


# --- Merkle Tree Verification ---

def _build_parent_hash_input(child_hash: list[int], siblings: list[int],
                             child_position: int, arity: int, sponge_width: int) -> list[int]:
    """Build hash input for parent node from child hash and siblings.

    In a Merkle tree with arity N, each parent hashes N children together.
    This function constructs that hash input by placing the child hash at
    its position and filling other positions with sibling hashes.

    Args:
        child_hash: Hash of the child we're authenticating
        siblings: Hashes of the (arity-1) sibling children
        child_position: Which position (0..arity-1) the child occupies
        arity: Number of children per parent node
        sponge_width: Total width of hash input array

    Returns:
        Hash input array ready for hash_seq()
    """
    hash_input = [0] * sponge_width
    sibling_idx = 0

    for position in range(arity):
        for hash_element in range(HASH_SIZE):
            buffer_idx = position * HASH_SIZE + hash_element

            if buffer_idx < sponge_width:
                if position == child_position:
                    # This position holds our child's hash
                    hash_input[buffer_idx] = child_hash[hash_element]
                else:
                    # This position holds a sibling's hash
                    hash_input[buffer_idx] = siblings[sibling_idx * HASH_SIZE + hash_element]

        # Move to next sibling after processing non-child positions
        if position != child_position:
            sibling_idx += 1

    return hash_input


def _verify_merkle_query(root: MerkleRoot, level: list[int], siblings: list[list[int]],
                         idx: int, values: list[int], arity: int, sponge_width: int,
                         last_level_verification: int) -> bool:
    """Verify a single Merkle query proof.

    Walk up the tree from leaf to root, hashing at each level with siblings,
    until we reach either the root or the last-level-verification boundary.
    """
    current_hash = linear_hash(values, sponge_width)
    current_idx = idx

    for level_siblings in siblings:
        child_position = current_idx % arity
        current_idx = current_idx // arity

        hash_input = _build_parent_hash_input(current_hash, level_siblings, child_position, arity, sponge_width)
        current_hash = hash_seq(hash_input, sponge_width)

    # Check against root or last-level boundary
    if last_level_verification == 0:
        return current_hash[:HASH_SIZE] == root[:HASH_SIZE]
    else:
        expected = level[current_idx * HASH_SIZE:(current_idx + 1) * HASH_SIZE]
        return current_hash[:HASH_SIZE] == expected


def _verify_merkle_tree(jproof: JProof, si: StarkInfo, root: MerkleRoot, vals_key: str,
                        siblings_key: str, last_levels_key: str, n_cols: int,
                        fri_queries: list[QueryIdx], domain_bits: int) -> bool:
    """Verify Merkle tree for stage/constant/custom commits."""
    ss = si.starkStruct
    arity = ss.merkleTreeArity
    llv = ss.lastLevelVerification
    n_queries = ss.nQueries
    sponge_width = SPONGE_WIDTH_BY_ARITY[arity]

    # Parse last level nodes
    num_nodes = 0 if llv == 0 else arity ** llv
    level = []
    if num_nodes > 0:
        for i in range(num_nodes):
            for j in range(HASH_SIZE):
                level.append(int(jproof[last_levels_key][i][j]))

    if llv > 0:
        if not MerkleTree.verify_merkle_root(root, level, 1 << ss.nBitsExt, llv, arity, sponge_width):
            return False

    n_siblings = math.ceil(domain_bits / math.log2(arity)) - llv
    siblings_per_level = (arity - 1) * HASH_SIZE

    for q in range(n_queries):
        values = [int(jproof[vals_key][q][i]) for i in range(n_cols)]
        siblings = [
            [int(jproof[siblings_key][q][i][j]) for j in range(siblings_per_level)]
            for i in range(n_siblings)
        ]
        if not _verify_merkle_query(root, level, siblings, fri_queries[q], values,
                                    arity, sponge_width, llv):
            return False

    return True


def _verify_stage_merkle(jproof: JProof, si: StarkInfo, root: MerkleRoot, stage: int,
                         fri_queries: list[QueryIdx]) -> bool:
    """Verify stage commitment Merkle tree."""
    section = f"cm{stage}"
    return _verify_merkle_tree(
        jproof, si, root,
        f"s0_vals{stage}", f"s0_siblings{stage}", f"s0_last_levels{stage}",
        si.mapSectionsN[section], fri_queries, si.starkStruct.friFoldSteps[0].domainBits
    )


def _verify_const_merkle(jproof: JProof, si: StarkInfo, verkey: MerkleRoot,
                         fri_queries: list[QueryIdx]) -> bool:
    """Verify constant polynomial Merkle tree."""
    return _verify_merkle_tree(
        jproof, si, verkey,
        "s0_valsC", "s0_siblingsC", "s0_last_levelsC",
        si.nConstants, fri_queries, si.starkStruct.friFoldSteps[0].domainBits
    )


def _verify_custom_commit_merkle(jproof: JProof, si: StarkInfo, root: MerkleRoot, name: str,
                                 fri_queries: list[QueryIdx]) -> bool:
    """Verify custom commit Merkle tree."""
    section = f"{name}0"
    return _verify_merkle_tree(
        jproof, si, root,
        f"s0_vals_{name}_0", f"s0_siblings_{name}_0", f"s0_last_levels_{name}_0",
        si.mapSectionsN[section], fri_queries, si.starkStruct.friFoldSteps[0].domainBits
    )


def _verify_fri_merkle_tree(jproof: JProof, si: StarkInfo, step: int, fri_queries: list[QueryIdx]) -> bool:
    """Verify FRI layer Merkle tree."""
    ss = si.starkStruct
    arity = ss.merkleTreeArity
    llv = ss.lastLevelVerification
    n_queries = ss.nQueries
    sponge_width = SPONGE_WIDTH_BY_ARITY[arity]

    n_groups = 1 << ss.friFoldSteps[step].domainBits
    group_size = (1 << ss.friFoldSteps[step - 1].domainBits) // n_groups
    n_cols = group_size * FIELD_EXTENSION_DEGREE

    root = _parse_root(jproof, f"s{step}_root")

    # Parse last level nodes
    num_nodes = 0 if llv == 0 else arity ** llv
    level = []
    if num_nodes > 0:
        for i in range(num_nodes):
            for j in range(HASH_SIZE):
                level.append(int(jproof[f"s{step}_last_levels"][i][j]))

    if llv > 0:
        if not MerkleTree.verify_merkle_root(root, level, n_groups, llv, arity, sponge_width):
            return False

    n_siblings = math.ceil(ss.friFoldSteps[step].domainBits / math.log2(arity)) - llv
    siblings_per_level = (arity - 1) * HASH_SIZE

    for q in range(n_queries):
        idx = fri_queries[q] % (1 << ss.friFoldSteps[step].domainBits)
        values = [int(jproof[f"s{step}_vals"][q][i]) for i in range(n_cols)]
        siblings = [
            [int(jproof[f"s{step}_siblings"][q][i][j]) for j in range(siblings_per_level)]
            for i in range(n_siblings)
        ]
        if not _verify_merkle_query(root, level, siblings, idx, values, arity, sponge_width, llv):
            return False

    return True


# --- FRI Verification ---

def _verify_fri_folding(jproof: JProof, si: StarkInfo, challenges: InterleavedFF3, step: int,
                        fri_queries: list[QueryIdx]) -> bool:
    """Verify FRI folding: P'(y) derived correctly from P(y), P(-y), etc.

    FRI soundness relies on correct folding: at each step, the prover commits
    to a polynomial P' of half the degree, where P'(y) is computed from
    evaluations P(x), P(-x), P(wx), P(-wx), ... using a random challenge.

    For each query point, we:
    1. Gather sibling evaluations from the proof (all coset members)
    2. Recompute the folded value using FRI.verify_fold
    3. Check it matches the claimed value in the next FRI layer (or final poly)
    """
    ss = si.starkStruct
    n_queries = ss.nQueries
    n_steps = len(ss.friFoldSteps)

    for q in range(n_queries):
        idx = fri_queries[q] % (1 << ss.friFoldSteps[step].domainBits)

        # Gather sibling evaluations
        n_x = 1 << (ss.friFoldSteps[step - 1].domainBits - ss.friFoldSteps[step].domainBits)
        siblings = [
            [int(jproof[f"s{step}_vals"][q][i * FIELD_EXTENSION_DEGREE + j]) for j in range(FIELD_EXTENSION_DEGREE)]
            for i in range(n_x)
        ]

        challenge_idx = len(si.challengesMap) + step
        challenge = [int(challenges[challenge_idx * FIELD_EXTENSION_DEGREE + j]) for j in range(FIELD_EXTENSION_DEGREE)]

        value = FRI.verify_fold(
            value=[0, 0, 0],
            fri_round=step,
            n_bits_ext=ss.nBitsExt,
            current_bits=ss.friFoldSteps[step].domainBits,
            prev_bits=ss.friFoldSteps[step - 1].domainBits,
            challenge=challenge,
            idx=idx,
            siblings=siblings,
        )

        # Check against next layer or final polynomial
        if step < n_steps - 1:
            next_bits = ss.friFoldSteps[step + 1].domainBits
            sibling_pos = idx >> next_bits
            expected = jproof[f"s{step + 1}_vals"][q][sibling_pos * FIELD_EXTENSION_DEGREE:(sibling_pos + 1) * FIELD_EXTENSION_DEGREE]
        else:
            expected = jproof["finalPol"][idx]

        if value != ff3([int(v) for v in expected]):
            return False

    return True


def _verify_final_polynomial(jproof: JProof, si: StarkInfo) -> bool:
    """Verify final polynomial has correct degree bound.

    Protocol check: The final FRI polynomial must have degree less than the
    claimed bound. We verify this by converting to coefficient form and checking
    that high-degree coefficients are zero.

    Note: The conversion to coefficient form is a protocol-level operation
    (interpolation), not an implementation detail. The fact that we use INTT
    internally is hidden by the polynomial abstraction.
    """
    ss = si.starkStruct
    final_pol_ff3 = ff3_from_json(jproof["finalPol"])
    final_pol = ff3_to_interleaved_numpy(final_pol_ff3)
    final_pol_size = len(final_pol_ff3)

    # Convert from evaluation form to coefficient form
    final_pol_reshaped = final_pol.reshape(final_pol_size, FIELD_EXTENSION_DEGREE)
    final_pol_coeffs = to_coefficients(final_pol_reshaped, final_pol_size, n_cols=FIELD_EXTENSION_DEGREE)

    # High-degree coefficients must be zero
    last_step = ss.friFoldSteps[-1].domainBits
    blowup_factor = ss.nBitsExt - ss.nBits
    init = 0 if blowup_factor > last_step else (1 << (last_step - blowup_factor))

    for i in range(init, final_pol_size):
        if any(int(final_pol_coeffs[i, j]) != 0 for j in range(FIELD_EXTENSION_DEGREE)):
            print(f"ERROR: Final polynomial is not zero at position {i}")
            return False

    return True
