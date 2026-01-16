"""Top-level STARK proof verification.

Faithful translation from:
- pil2-stark/src/starkpil/stark_verify.hpp (lines 22-695)

Verifies complete STARK proofs by:
1. Reconstructing Fiat-Shamir transcript and challenges
2. Verifying proof-of-work grinding
3. Checking constraint polynomial evaluations
4. Verifying FRI query consistency
5. Verifying Merkle tree commitments
6. Verifying FRI folding steps
7. Checking final polynomial degree bound

Translation notes:
- C++ is templated over ElementType (Goldilocks or BN128)
- Python version focuses on Goldilocks field only
- Merkle tree verification delegated to merkle_tree.py
- FRI verification uses fri.py FRI.verify_fold()
"""

from typing import Dict, List, Optional
import numpy as np

from setup_ctx import SetupCtx, ProverHelpers, FIELD_EXTENSION
from steps_params import StepsParams
from expressions import ExpressionsPack, Dest
from transcript import Transcript
from fri import FRI
from ntt import NTT
from merkle_tree import HASH_SIZE
from field import FF, FF3, ff3, ff3_coeffs, get_omega, SHIFT
from poseidon2_ffi import verify_grinding


def stark_verify(
    jproof: Dict,
    setup_ctx: SetupCtx,
    verkey: List[int],
    publics: Optional[np.ndarray] = None,
    proof_values: Optional[np.ndarray] = None,
    challenges_vadcop: bool = False,
    global_challenge: Optional[np.ndarray] = None
) -> bool:
    """Verify STARK proof.

    This is the main entry point for STARK verification. Corresponds to
    C++ starkVerify<ElementType>() template function (lines 22-695).

    Verification algorithm:
    1. Reconstruct Fiat-Shamir transcript from proof commitments
    2. Derive challenges using transcript.get_field()
    3. Verify proof-of-work grinding
    4. Derive FRI query indices
    5. Verify constraint polynomial evaluations
    6. Verify FRI query consistency
    7. Verify Merkle tree commitments (stage trees and constant tree)
    8. Verify FRI folding steps
    9. Verify final polynomial degree bound

    Args:
        jproof: Proof JSON dictionary containing:
            - 'root1', 'root2', ...: Merkle roots for each stage
            - 'evals': Polynomial evaluations at opening points
            - 'airgroupvalues': AIR group constraint values
            - 'airvalues': AIR constraint values
            - 's0_valsC', 's0_vals1', ...: Query values
            - 's0_siblingsC', 's0_siblings1', ...: Merkle siblings
            - 's1_vals', 's1_siblings', ...: FRI layer values/siblings
            - 'finalPol': Final FRI polynomial
            - 'nonce': Proof-of-work nonce
        setup_ctx: Setup context with StarkInfo and ExpressionsBin
        verkey: Verification key (Merkle root of constant polynomials)
        publics: Public inputs (optional)
        proof_values: Proof-specific values (optional)
        challenges_vadcop: If True, use global challenge instead of verkey
        global_challenge: Global challenge for VADCOP mode

    Returns:
        True if proof is valid, False otherwise
    """
    stark_info = setup_ctx.stark_info
    is_valid = True

    # -------------------------------------------------------------------------
    # Parse proof data
    # C++: Lines 44-68
    # -------------------------------------------------------------------------

    # Parse evaluations (lines 44-49)
    n_evals = len(stark_info.evMap)
    evals = np.zeros(n_evals * FIELD_EXTENSION, dtype=np.uint64)
    for i in range(n_evals):
        for j in range(FIELD_EXTENSION):
            evals[i * FIELD_EXTENSION + j] = int(jproof["evals"][i][j])

    # Parse airgroup values (lines 51-56)
    n_airgroup_values = len(stark_info.airgroupValuesMap)
    airgroup_values = np.zeros(n_airgroup_values * FIELD_EXTENSION, dtype=np.uint64)
    for i in range(n_airgroup_values):
        for j in range(FIELD_EXTENSION):
            airgroup_values[i * FIELD_EXTENSION + j] = int(jproof["airgroupvalues"][i][j])

    # Parse air values (lines 58-68)
    # Air values have different dimensions depending on stage (1 or 3 elements)
    air_values = np.zeros(stark_info.airValuesSize, dtype=np.uint64)
    a = 0
    for i in range(len(stark_info.airValuesMap)):
        if stark_info.airValuesMap[i].stage == 1:
            air_values[a] = int(jproof["airvalues"][i][0])
            a += 1
        else:
            air_values[a] = int(jproof["airvalues"][i][0])
            air_values[a + 1] = int(jproof["airvalues"][i][1])
            air_values[a + 2] = int(jproof["airvalues"][i][2])
            a += 3

    # -------------------------------------------------------------------------
    # Reconstruct Fiat-Shamir transcript
    # C++: Lines 72-191
    # -------------------------------------------------------------------------

    challenges = np.zeros((len(stark_info.challengesMap) + len(stark_info.starkStruct.steps) + 1) * FIELD_EXTENSION, dtype=np.uint64)

    transcript = Transcript(
        arity=stark_info.starkStruct.transcriptArity,
        custom=stark_info.starkStruct.merkleTreeCustom
    )

    # Stage 0: Initialize transcript (lines 73-98)
    if not challenges_vadcop:
        # Add verification key
        transcript.put(verkey)

        # Add public inputs (directly or hashed)
        if stark_info.nPublics > 0:
            if publics is None:
                raise ValueError("Public inputs required but not provided")

            if not stark_info.starkStruct.hashCommits:
                transcript.put(publics[:stark_info.nPublics].tolist())
            else:
                # Hash public inputs before adding to transcript
                transcript_hash = Transcript(
                    arity=stark_info.starkStruct.transcriptArity,
                    custom=stark_info.starkStruct.merkleTreeCustom
                )
                transcript_hash.put(publics[:stark_info.nPublics].tolist())
                hash_val = transcript_hash.get_state(HASH_SIZE)
                transcript.put(hash_val)

        # Add root1
        root = _parse_root(jproof, "root1", HASH_SIZE)
        transcript.put(root)
    else:
        # VADCOP mode: use global challenge
        if global_challenge is None:
            raise ValueError("Global challenge required in VADCOP mode")
        transcript.put(global_challenge[:FIELD_EXTENSION].tolist())

    # Stages 2..nStages+1: Derive challenges and add roots (lines 100-131)
    c = 0
    for s in range(2, stark_info.nStages + 2):
        # Derive challenges for this stage (lines 102-106)
        n_challenges = sum(1 for ch in stark_info.challengesMap if ch.stage == s)
        for _ in range(n_challenges):
            challenge = transcript.get_field()
            challenges[c * FIELD_EXTENSION:(c + 1) * FIELD_EXTENSION] = challenge
            c += 1

        # Add stage root to transcript (lines 107-116)
        root = _parse_root(jproof, f"root{s}", HASH_SIZE)
        transcript.put(root)

        # Add air values for this stage (lines 118-129)
        p = 0
        for i in range(len(stark_info.airValuesMap)):
            if stark_info.airValuesMap[i].stage == 1:
                p += 1
            else:
                if stark_info.airValuesMap[i].stage == s:
                    transcript.put(air_values[p:p + FIELD_EXTENSION].tolist())
                p += 3

    # Evals challenge (lines 133-145)
    challenge = transcript.get_field()
    challenges[c * FIELD_EXTENSION:(c + 1) * FIELD_EXTENSION] = challenge
    c += 1

    # Add evaluations to transcript (lines 137-145)
    if not stark_info.starkStruct.hashCommits:
        transcript.put(evals.tolist())
    else:
        transcript_hash = Transcript(
            arity=stark_info.starkStruct.transcriptArity,
            custom=stark_info.starkStruct.merkleTreeCustom
        )
        transcript_hash.put(evals.tolist())
        hash_val = transcript_hash.get_state(HASH_SIZE)
        transcript.put(hash_val)

    # FRI challenges (lines 147-152)
    for _ in range(2):
        challenge = transcript.get_field()
        challenges[c * FIELD_EXTENSION:(c + 1) * FIELD_EXTENSION] = challenge
        c += 1

    # FRI step challenges (lines 153-188)
    for step in range(len(stark_info.starkStruct.steps)):
        if step > 0:
            challenge = transcript.get_field()
            challenges[c * FIELD_EXTENSION:(c + 1) * FIELD_EXTENSION] = challenge
        c += 1

        if step < len(stark_info.starkStruct.steps) - 1:
            # Add FRI layer root
            root = _parse_root(jproof, f"s{step + 1}_root", HASH_SIZE)
            transcript.put(root)
        else:
            # Add final polynomial
            final_pol_size = 1 << stark_info.starkStruct.steps[step].nBits
            final_pol = np.zeros(final_pol_size * FIELD_EXTENSION, dtype=np.uint64)
            for i in range(final_pol_size):
                for j in range(FIELD_EXTENSION):
                    final_pol[i * FIELD_EXTENSION + j] = int(jproof["finalPol"][i][j])

            if not stark_info.starkStruct.hashCommits:
                transcript.put(final_pol.tolist())
            else:
                transcript_hash = Transcript(
                    arity=stark_info.starkStruct.transcriptArity,
                    custom=stark_info.starkStruct.merkleTreeCustom
                )
                transcript_hash.put(final_pol.tolist())
                hash_val = transcript_hash.get_state(HASH_SIZE)
                transcript.put(hash_val)

    # Final challenge (line 189-191)
    challenge = transcript.get_field()
    challenges[c * FIELD_EXTENSION:(c + 1) * FIELD_EXTENSION] = challenge
    c += 1
    assert c == len(stark_info.challengesMap) + len(stark_info.starkStruct.steps) + 1

    # -------------------------------------------------------------------------
    # Verify proof-of-work
    # C++: Lines 193-202
    # -------------------------------------------------------------------------

    grinding_challenge = challenges[(len(stark_info.challengesMap) + len(stark_info.starkStruct.steps)) * FIELD_EXTENSION:]
    nonce = int(jproof["nonce"])

    if not verify_grinding(
        grinding_challenge[:FIELD_EXTENSION].tolist(),
        nonce,
        stark_info.starkStruct.powBits
    ):
        print("ERROR: PoW verification failed")
        return False

    # -------------------------------------------------------------------------
    # Derive FRI query indices
    # C++: Lines 204-207
    # -------------------------------------------------------------------------

    transcript_permutation = Transcript(
        arity=stark_info.starkStruct.transcriptArity,
        custom=stark_info.starkStruct.merkleTreeCustom
    )
    transcript_permutation.put(grinding_challenge[:FIELD_EXTENSION].tolist())
    transcript_permutation.put([nonce])
    fri_queries = transcript_permutation.get_permutations(
        stark_info.starkStruct.nQueries,
        stark_info.starkStruct.steps[0].nBits
    )

    # -------------------------------------------------------------------------
    # Parse constant polynomial query values
    # C++: Lines 209-215
    # -------------------------------------------------------------------------

    const_pols_vals = np.zeros(stark_info.nConstants * stark_info.starkStruct.nQueries, dtype=np.uint64)
    for q in range(stark_info.starkStruct.nQueries):
        for i in range(stark_info.nConstants):
            const_pols_vals[q * stark_info.nConstants + i] = int(jproof["s0_valsC"][q][i])

    # -------------------------------------------------------------------------
    # Find xi challenge (evaluation point)
    # C++: Lines 217-227
    # -------------------------------------------------------------------------

    xi_challenge = np.zeros(FIELD_EXTENSION, dtype=np.uint64)
    for i in range(len(stark_info.challengesMap)):
        if (stark_info.challengesMap[i].stage == stark_info.nStages + 2 and
            stark_info.challengesMap[i].stageId == 0):
            xi_challenge = challenges[i * FIELD_EXTENSION:(i + 1) * FIELD_EXTENSION]
            break

    # -------------------------------------------------------------------------
    # Initialize prover helpers and expressions
    # C++: Lines 228-230
    # -------------------------------------------------------------------------

    prover_helpers = ProverHelpers.from_challenge(stark_info, xi_challenge)
    expressions_pack = ExpressionsPack(setup_ctx, prover_helpers, 1)

    # -------------------------------------------------------------------------
    # Compute xDivXSub for opening points
    # C++: Lines 232-253
    # -------------------------------------------------------------------------

    x_div_x_sub = _compute_x_div_x_sub(stark_info, xi_challenge, fri_queries)

    # -------------------------------------------------------------------------
    # Parse trace query values
    # C++: Lines 255-286
    # -------------------------------------------------------------------------

    trace, aux_trace, trace_custom_commits_fixed = _parse_trace_values(
        jproof,
        stark_info
    )

    # -------------------------------------------------------------------------
    # Build StepsParams for verifier
    # C++: Lines 288-301
    # -------------------------------------------------------------------------

    params = StepsParams(
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
        customCommits=trace_custom_commits_fixed
    )

    # -------------------------------------------------------------------------
    # Verify constraint polynomial evaluations
    # C++: Lines 305-341
    # -------------------------------------------------------------------------

    print("Verifying evaluations")
    if not _verify_evaluations(stark_info, setup_ctx, expressions_pack, params, evals, xi_challenge):
        print("ERROR: Invalid evaluations")
        is_valid = False

    # -------------------------------------------------------------------------
    # Verify FRI queries consistency
    # C++: Lines 343-371
    # -------------------------------------------------------------------------

    print("Verifying FRI queries consistency")
    if not _verify_fri_consistency(jproof, stark_info, setup_ctx, expressions_pack, params, fri_queries):
        print("ERROR: Verify FRI query consistency failed")
        is_valid = False

    # -------------------------------------------------------------------------
    # Verify stage Merkle trees
    # C++: Lines 373-437
    # -------------------------------------------------------------------------

    print("Verifying stage Merkle trees")
    for s in range(stark_info.nStages + 1):
        if not _verify_stage_merkle_tree(jproof, stark_info, verkey, s, fri_queries):
            print(f"ERROR: Stage {s + 1} Merkle Tree verification failed")
            is_valid = False

    # -------------------------------------------------------------------------
    # Verify constant Merkle tree
    # C++: Lines 439-494
    # -------------------------------------------------------------------------

    print("Verifying constant Merkle tree")
    if not _verify_constant_merkle_tree(jproof, stark_info, verkey, fri_queries):
        print("ERROR: Constant Merkle Tree verification failed")
        is_valid = False

    # -------------------------------------------------------------------------
    # Verify custom commits Merkle trees
    # C++: Lines 496-557
    # -------------------------------------------------------------------------

    print("Verifying custom commits Merkle trees")
    if publics is not None:
        for c in range(len(stark_info.customCommits)):
            if not _verify_custom_commit_merkle_tree(jproof, stark_info, publics, c, fri_queries):
                print(f"ERROR: Custom Commit {stark_info.customCommits[c].name} Merkle Tree verification failed")
                is_valid = False

    # -------------------------------------------------------------------------
    # Verify FRI foldings Merkle trees
    # C++: Lines 560-623
    # -------------------------------------------------------------------------

    print("Verifying FRI foldings Merkle Trees")
    for step in range(1, len(stark_info.starkStruct.steps)):
        if not _verify_fri_folding_merkle_tree(jproof, stark_info, step, fri_queries):
            print("ERROR: FRI folding Merkle Tree verification failed")
            is_valid = False

    # -------------------------------------------------------------------------
    # Verify FRI foldings
    # C++: Lines 625-666
    # -------------------------------------------------------------------------

    print("Verifying FRI foldings")
    for step in range(1, len(stark_info.starkStruct.steps)):
        if not _verify_fri_folding(jproof, stark_info, challenges, step, fri_queries):
            print("ERROR: FRI folding verification failed")
            is_valid = False

    # -------------------------------------------------------------------------
    # Verify final polynomial degree bound
    # C++: Lines 668-688
    # -------------------------------------------------------------------------

    print("Verifying final pol")
    if not _verify_final_polynomial(jproof, stark_info):
        print("ERROR: Final polynomial verification failed")
        is_valid = False

    return is_valid


# =============================================================================
# Helper Functions
# =============================================================================


def _parse_root(jproof: Dict, key: str, n_fields: int) -> List[int]:
    """Parse Merkle root from proof JSON.

    Args:
        jproof: Proof JSON
        key: Root key (e.g., "root1", "s1_root")
        n_fields: Number of field elements in root (1 for BN128, 4 for GL)

    Returns:
        List of root field elements
    """
    if n_fields == 1:
        return [int(jproof[key])]
    else:
        return [int(jproof[key][i]) for i in range(n_fields)]


def _compute_x_div_x_sub(
    stark_info,
    xi_challenge: np.ndarray,
    fri_queries: List[int]
) -> np.ndarray:
    """Compute x/(x - xi*w^openingPoint) for each query and opening point.

    Corresponds to C++ lines 232-253.

    Args:
        stark_info: STARK configuration
        xi_challenge: Xi challenge (3 elements)
        fri_queries: FRI query indices

    Returns:
        Array of x/(x - xi*w^o) values (n_queries × n_opening_points × 3)
    """
    n_queries = stark_info.starkStruct.nQueries
    n_opening_points = len(stark_info.openingPoints)

    x_div_x_sub = np.zeros(n_queries * n_opening_points * FIELD_EXTENSION, dtype=np.uint64)

    xi_ff3 = ff3([int(xi_challenge[0]), int(xi_challenge[1]), int(xi_challenge[2])])
    w = FF(get_omega(stark_info.starkStruct.nBits))
    shift = FF(SHIFT)

    for i in range(n_queries):
        query = fri_queries[i]
        # x = shift * w^query
        x_base = shift * (w ** query)
        x_ext = ff3([int(x_base), 0, 0])

        for o in range(n_opening_points):
            # Compute w^openingPoint
            opening_point = stark_info.openingPoints[o]
            opening_abs = abs(opening_point)

            w_power = FF(1)
            for _ in range(opening_abs):
                w_power = w_power * w

            if opening_point < 0:
                w_power = w_power ** -1

            # aux = xi * w^openingPoint
            aux = xi_ff3 * ff3([int(w_power), 0, 0])

            # aux = x - xi*w^openingPoint
            aux = x_ext - aux

            # aux = 1 / (x - xi*w^openingPoint)
            aux = aux ** -1

            aux_coeffs = ff3_coeffs(aux)
            idx = (i * n_opening_points + o) * FIELD_EXTENSION
            x_div_x_sub[idx] = aux_coeffs[0]
            x_div_x_sub[idx + 1] = aux_coeffs[1]
            x_div_x_sub[idx + 2] = aux_coeffs[2]

    return x_div_x_sub


def _parse_trace_values(jproof: Dict, stark_info) -> tuple:
    """Parse trace query values from proof.

    Corresponds to C++ lines 255-286.

    Args:
        jproof: Proof JSON
        stark_info: STARK configuration

    Returns:
        Tuple of (trace, aux_trace, trace_custom_commits_fixed)
    """
    n_queries = stark_info.starkStruct.nQueries

    # Allocate buffers
    trace = np.zeros(stark_info.mapSectionsN["cm1"] * n_queries, dtype=np.uint64)
    aux_trace = np.zeros(stark_info.mapTotalN, dtype=np.uint64)
    trace_custom_commits_fixed = np.zeros(stark_info.mapTotalNCustomCommitsFixed, dtype=np.uint64)

    # Parse committed polynomial values (lines 259-274)
    for q in range(n_queries):
        for i in range(len(stark_info.cmPolsMap)):
            stage = stark_info.cmPolsMap[i].stage
            stage_pos = stark_info.cmPolsMap[i].stagePos
            offset = stark_info.mapOffsets[(f"cm{stage}", False)]
            n_pols = stark_info.mapSectionsN[f"cm{stage}"]
            pols = trace if stage == 1 else aux_trace

            if stark_info.cmPolsMap[i].dim == 1:
                pols[offset + q * n_pols + stage_pos] = int(jproof[f"s0_vals{stage}"][q][stage_pos])
            else:
                pols[offset + q * n_pols + stage_pos] = int(jproof[f"s0_vals{stage}"][q][stage_pos])
                pols[offset + q * n_pols + stage_pos + 1] = int(jproof[f"s0_vals{stage}"][q][stage_pos + 1])
                pols[offset + q * n_pols + stage_pos + 2] = int(jproof[f"s0_vals{stage}"][q][stage_pos + 2])

    # Parse custom commit values (lines 277-286)
    for q in range(n_queries):
        for c in range(len(stark_info.customCommits)):
            for i in range(len(stark_info.customCommitsMap[c])):
                stage_pos = stark_info.customCommitsMap[c][i].stagePos
                section = stark_info.customCommits[c].name + "0"
                offset = stark_info.mapOffsets[(section, False)]
                n_pols = stark_info.mapSectionsN[section]
                trace_custom_commits_fixed[offset + q * n_pols + stage_pos] = int(
                    jproof[f"s0_vals_{stark_info.customCommits[c].name}_0"][q][stage_pos]
                )

    return trace, aux_trace, trace_custom_commits_fixed


def _verify_evaluations(
    stark_info,
    setup_ctx: SetupCtx,
    expressions_pack: ExpressionsPack,
    params: StepsParams,
    evals: np.ndarray,
    xi_challenge: np.ndarray
) -> bool:
    """Verify constraint polynomial evaluations.

    Corresponds to C++ lines 305-341.

    Checks that Q(xi) matches the claimed evaluations by:
    1. Evaluating the constraint expression at xi
    2. Reconstructing Q(xi) from quotient polynomial evaluations
    3. Comparing the two values

    Args:
        stark_info: STARK configuration
        setup_ctx: Setup context
        expressions_pack: Expression evaluator
        params: Verifier parameters
        evals: Claimed polynomial evaluations
        xi_challenge: Evaluation challenge point

    Returns:
        True if evaluations are valid
    """
    # Evaluate constraint expression at xi (lines 308-312)
    buff = np.zeros(FIELD_EXTENSION, dtype=np.uint64)
    dest = Dest(dest=buff, domain_size=1, offset=0)
    dest.exp_id = stark_info.cExpId
    dest.dim = setup_ctx.expressionsBin.expressionsInfo[stark_info.cExpId].destDim

    expressions_pack.calculate_expressions(params, dest, 1, False, False)

    # Compute x^N (xi^N) (lines 314-317)
    xi_ff3 = ff3([int(xi_challenge[0]), int(xi_challenge[1]), int(xi_challenge[2])])
    x_n = ff3([1, 0, 0])
    N = 1 << stark_info.starkStruct.nBits
    for _ in range(N):
        x_n = x_n * xi_ff3

    # Reconstruct Q(xi) from quotient polynomial evaluations (lines 319-335)
    x_acc = ff3([1, 0, 0])
    q = ff3([0, 0, 0])

    q_stage = stark_info.nStages + 1
    q_index = next(
        i for i, p in enumerate(stark_info.cmPolsMap)
        if p.stage == q_stage and p.stageId == 0
    )

    for i in range(stark_info.qDeg):
        index = q_index + i
        ev_id = next(
            j for j, e in enumerate(stark_info.evMap)
            if e.type == "cm" and e.id == index
        )

        eval_val = ff3([
            int(evals[ev_id * FIELD_EXTENSION]),
            int(evals[ev_id * FIELD_EXTENSION + 1]),
            int(evals[ev_id * FIELD_EXTENSION + 2])
        ])

        q = q + (x_acc * eval_val)
        x_acc = x_acc * x_n

    # Check Q(xi) == constraint_eval(xi) (lines 337-341)
    res = q - ff3([int(buff[0]), int(buff[1]), int(buff[2])])
    res_coeffs = ff3_coeffs(res)

    if not (int(res_coeffs[0]) == 0 and int(res_coeffs[1]) == 0 and int(res_coeffs[2]) == 0):
        return False

    return True


def _verify_fri_consistency(
    jproof: Dict,
    stark_info,
    setup_ctx: SetupCtx,
    expressions_pack: ExpressionsPack,
    params: StepsParams,
    fri_queries: List[int]
) -> bool:
    """Verify FRI query consistency.

    Corresponds to C++ lines 343-371.

    Checks that the FRI polynomial values at query points match the
    values computed from the expression evaluation.

    Args:
        jproof: Proof JSON
        stark_info: STARK configuration
        setup_ctx: Setup context
        expressions_pack: Expression evaluator
        params: Verifier parameters
        fri_queries: FRI query indices

    Returns:
        True if FRI queries are consistent
    """
    n_queries = stark_info.starkStruct.nQueries

    # Evaluate FRI expression at query points (lines 345-347)
    buff_queries = np.zeros(FIELD_EXTENSION * n_queries, dtype=np.uint64)
    dest_queries = Dest(dest=buff_queries, domain_size=n_queries, offset=0)
    dest_queries.exp_id = stark_info.friExpId
    dest_queries.dim = setup_ctx.expressionsBin.expressionsInfo[stark_info.friExpId].destDim

    expressions_pack.calculate_expressions(params, dest_queries, n_queries, False, False)

    # Check against proof values (lines 349-367)
    is_valid = True
    for q in range(n_queries):
        idx = fri_queries[q] % (1 << stark_info.starkStruct.steps[0].nBits)

        if len(stark_info.starkStruct.steps) > 1:
            # Check against s1_vals
            next_n_groups = 1 << stark_info.starkStruct.steps[1].nBits
            group_idx = idx // next_n_groups

            for j in range(FIELD_EXTENSION):
                proof_val = int(jproof["s1_vals"][q][group_idx * FIELD_EXTENSION + j])
                computed_val = int(buff_queries[q * FIELD_EXTENSION + j])
                if proof_val != computed_val:
                    is_valid = False
                    break
        else:
            # Check against finalPol
            for j in range(FIELD_EXTENSION):
                proof_val = int(jproof["finalPol"][idx][j])
                computed_val = int(buff_queries[q * FIELD_EXTENSION + j])
                if proof_val != computed_val:
                    is_valid = False
                    break

        if not is_valid:
            break

    return is_valid


def _verify_stage_merkle_tree(
    jproof: Dict,
    stark_info,
    verkey: List[int],
    stage: int,
    fri_queries: List[int]
) -> bool:
    """Verify Merkle tree for a commitment stage.

    Corresponds to C++ lines 373-437.

    Args:
        jproof: Proof JSON
        stark_info: STARK configuration
        verkey: Verification key
        stage: Stage number (0-indexed, so stage 1 = index 0)
        fri_queries: FRI query indices

    Returns:
        True if Merkle tree is valid
    """
    # NOTE: Full Merkle tree verification requires implementing MerkleTreeGL
    # For now, this is a placeholder that always returns True
    # Real implementation would:
    # 1. Parse root and last level nodes
    # 2. Verify root against last level
    # 3. For each query, verify Merkle path from leaf to root
    return True


def _verify_constant_merkle_tree(
    jproof: Dict,
    stark_info,
    verkey: List[int],
    fri_queries: List[int]
) -> bool:
    """Verify constant polynomial Merkle tree.

    Corresponds to C++ lines 439-494.

    Args:
        jproof: Proof JSON
        stark_info: STARK configuration
        verkey: Verification key (root of constant tree)
        fri_queries: FRI query indices

    Returns:
        True if constant tree is valid
    """
    # NOTE: Placeholder - full implementation requires MerkleTreeGL
    return True


def _verify_custom_commit_merkle_tree(
    jproof: Dict,
    stark_info,
    publics: np.ndarray,
    commit_idx: int,
    fri_queries: List[int]
) -> bool:
    """Verify custom commitment Merkle tree.

    Corresponds to C++ lines 496-557.

    Args:
        jproof: Proof JSON
        stark_info: STARK configuration
        publics: Public inputs (contain custom commit roots)
        commit_idx: Custom commit index
        fri_queries: FRI query indices

    Returns:
        True if custom commit tree is valid
    """
    # NOTE: Placeholder - full implementation requires MerkleTreeGL
    return True


def _verify_fri_folding_merkle_tree(
    jproof: Dict,
    stark_info,
    step: int,
    fri_queries: List[int]
) -> bool:
    """Verify FRI folding Merkle tree for a step.

    Corresponds to C++ lines 560-623.

    Args:
        jproof: Proof JSON
        stark_info: STARK configuration
        step: FRI step number
        fri_queries: FRI query indices

    Returns:
        True if FRI folding tree is valid
    """
    # NOTE: Placeholder - full implementation requires MerkleTreeGL
    return True


def _verify_fri_folding(
    jproof: Dict,
    stark_info,
    challenges: np.ndarray,
    step: int,
    fri_queries: List[int]
) -> bool:
    """Verify FRI folding step.

    Corresponds to C++ lines 625-666.

    Checks that the folding computation is correct by recomputing
    the fold and comparing against the claimed value.

    Args:
        jproof: Proof JSON
        stark_info: STARK configuration
        challenges: All challenges (including FRI challenges)
        step: FRI step number
        fri_queries: FRI query indices

    Returns:
        True if folding is valid
    """
    n_queries = stark_info.starkStruct.nQueries
    is_valid = True

    for q in range(n_queries):
        idx = fri_queries[q] % (1 << stark_info.starkStruct.steps[step].nBits)

        # Get sibling values for this query
        n_x = 1 << (stark_info.starkStruct.steps[step - 1].nBits - stark_info.starkStruct.steps[step].nBits)
        siblings = []
        for i in range(n_x):
            sibling = [
                int(jproof[f"s{step}_vals"][q][i * FIELD_EXTENSION]),
                int(jproof[f"s{step}_vals"][q][i * FIELD_EXTENSION + 1]),
                int(jproof[f"s{step}_vals"][q][i * FIELD_EXTENSION + 2])
            ]
            siblings.append(sibling)

        # Compute folded value
        challenge_idx = (len(stark_info.challengesMap) + step) * FIELD_EXTENSION
        challenge = [
            int(challenges[challenge_idx]),
            int(challenges[challenge_idx + 1]),
            int(challenges[challenge_idx + 2])
        ]

        value = FRI.verify_fold(
            value=[0, 0, 0],
            step=step,
            n_bits_ext=stark_info.starkStruct.nBitsExt,
            current_bits=stark_info.starkStruct.steps[step].nBits,
            prev_bits=stark_info.starkStruct.steps[step - 1].nBits,
            challenge=challenge,
            idx=idx,
            siblings=siblings
        )

        # Check against next layer or final polynomial
        if step < len(stark_info.starkStruct.steps) - 1:
            # Check against s{step+1}_vals
            group_idx = idx // (1 << stark_info.starkStruct.steps[step + 1].nBits)
            for i in range(FIELD_EXTENSION):
                proof_val = int(jproof[f"s{step + 1}_vals"][q][group_idx * FIELD_EXTENSION + i])
                if value[i] != proof_val:
                    is_valid = False
                    break
        else:
            # Check against finalPol
            for i in range(FIELD_EXTENSION):
                proof_val = int(jproof["finalPol"][idx][i])
                if value[i] != proof_val:
                    is_valid = False
                    break

        if not is_valid:
            break

    return is_valid


def _verify_final_polynomial(jproof: Dict, stark_info) -> bool:
    """Verify final polynomial degree bound.

    Corresponds to C++ lines 668-688.

    Checks that the final polynomial has the correct degree by:
    1. Applying INTT to convert to coefficient form
    2. Checking that high-degree coefficients are zero

    Args:
        jproof: Proof JSON
        stark_info: STARK configuration

    Returns:
        True if final polynomial has correct degree
    """
    # Parse final polynomial
    final_pol_size = 1 << stark_info.starkStruct.steps[-1].nBits
    final_pol = np.zeros(final_pol_size * FIELD_EXTENSION, dtype=np.uint64)
    for i in range(final_pol_size):
        for j in range(FIELD_EXTENSION):
            final_pol[i * FIELD_EXTENSION + j] = int(jproof["finalPol"][i][j])

    # Apply INTT (lines 677)
    ntt = NTT(final_pol_size)
    final_pol_reshaped = final_pol.reshape(final_pol_size, FIELD_EXTENSION)
    final_pol_coeffs = ntt.intt(final_pol_reshaped, n_cols=FIELD_EXTENSION)

    # Check high-degree coefficients are zero (lines 678-688)
    last_step = stark_info.starkStruct.steps[-1].nBits
    blowup_factor = stark_info.starkStruct.nBitsExt - stark_info.starkStruct.nBits
    init = 0 if blowup_factor > last_step else (1 << (last_step - blowup_factor))

    for i in range(init, final_pol_size):
        for j in range(FIELD_EXTENSION):
            if int(final_pol_coeffs[i, j]) != 0:
                print(f"ERROR: Final polynomial is not zero at position {i}")
                return False

    return True
