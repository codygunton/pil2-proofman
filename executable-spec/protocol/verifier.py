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

from protocol.setup_ctx import SetupCtx, ProverHelpers, FIELD_EXTENSION
from protocol.steps_params import StepsParams
from protocol.expression_evaluator import ExpressionsPack, Dest, Params
from primitives.transcript import Transcript
from protocol.fri import FRI
from primitives.ntt import NTT
from primitives.merkle_tree import HASH_SIZE, MerkleTree
from primitives.pol_map import EvMap
from poseidon2_ffi import linear_hash, hash_seq
import math
from primitives.field import FF, FF3, ff3, ff3_coeffs, get_omega, SHIFT
from poseidon2_ffi import verify_grinding


# C++: pil2-stark/src/starkpil/stark_verify.hpp::starkVerify (lines 22-695)
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

    # Evals stage challenges (lines 133-145)
    # Derive ALL challenges for stage nStages + 2 (matches prover behavior)
    n_evals_challenges = sum(1 for ch in stark_info.challengesMap if ch.stage == stark_info.nStages + 2)
    for _ in range(n_evals_challenges):
        challenge = transcript.get_field()
        challenges[c * FIELD_EXTENSION:(c + 1) * FIELD_EXTENSION] = challenge
        c += 1

    # Add evaluations to transcript (lines 137-145)
    if not stark_info.starkStruct.hashCommits:
        transcript.put(evals.tolist())
    else:
        # Hash evaluations before adding (matches prover's linear_hash approach)
        evals_hash = list(linear_hash([int(v) for v in evals], width=16))
        transcript.put(evals_hash)

    # FRI polynomial challenges (lines 147-152)
    # Derive ALL challenges for stage nStages + 3 (matches prover behavior)
    n_fri_challenges = sum(1 for ch in stark_info.challengesMap if ch.stage == stark_info.nStages + 3)
    for _ in range(n_fri_challenges):
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
            print(f"DEBUG verifier xi_challenge (idx={i}): {list(xi_challenge)}")
            break

    # -------------------------------------------------------------------------
    # Initialize prover helpers and expressions
    # C++: Lines 228-230
    # -------------------------------------------------------------------------

    # Set verification mode for expression evaluator
    stark_info.verify = True

    n_queries = stark_info.starkStruct.nQueries
    prover_helpers = ProverHelpers.from_challenge(stark_info, xi_challenge)
    expressions_pack = ExpressionsPack(setup_ctx, prover_helpers, 1, n_queries)

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
    # Debug: print params before evaluation
    print(f"DEBUG BEFORE _verify_evaluations - params.trace (first 12): {list(params.trace[:12])}")
    if not _verify_evaluations(stark_info, setup_ctx, expressions_pack, params, evals, xi_challenge):
        print("ERROR: Invalid evaluations")
        is_valid = False
    # Debug: print params after evaluation
    print(f"DEBUG AFTER _verify_evaluations - params.trace (first 12): {list(params.trace[:12])}")

    # -------------------------------------------------------------------------
    # Verify FRI queries consistency
    # C++: Lines 343-371
    # -------------------------------------------------------------------------

    print("Verifying FRI queries consistency")
    # Debug: print params values being passed to FRI expression
    print(f"DEBUG params.challenges (first 18): {list(params.challenges[:18])}")
    print(f"DEBUG params.evals (first 9): {list(params.evals[:9])}")
    cm1_n_pols = stark_info.mapSectionsN["cm1"]
    print(f"DEBUG params.trace (query 0, {cm1_n_pols} pols): {list(params.trace[:cm1_n_pols])}")
    print(f"DEBUG params.xDivXSub (first 9): {list(params.xDivXSub[:9])}")
    print(f"DEBUG params.constPols (first 4): {list(params.constPols[:4])}")
    print(f"DEBUG fri_queries (first 10): {fri_queries[:10]}")
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


# Helper function for Merkle query verification
def _verify_merkle_query(
    root: List[int],
    level: List[int],
    siblings: List[List[int]],
    idx: int,
    values: List[int],
    arity: int,
    sponge_width: int,
    last_level_verification: int
) -> bool:
    """Verify a single Merkle query proof.

    Hashes up from the leaf values through the siblings and compares
    against either the root (if last_level_verification == 0) or the
    appropriate last level node.

    Args:
        root: Expected Merkle root (HASH_SIZE elements)
        level: Last level nodes (for last_level_verification > 0)
        siblings: Proof siblings per level
        idx: Query index (leaf index)
        values: Leaf values (polynomial evaluations)
        arity: Merkle tree arity (2, 3, or 4)
        sponge_width: Poseidon2 sponge width
        last_level_verification: Number of levels to skip from bottom

    Returns:
        True if the proof is valid
    """
    # Hash the leaf values
    computed = linear_hash(values, sponge_width)

    # Hash up through the proof siblings
    curr_idx = idx
    for level_siblings in siblings:
        # Determine position in parent
        pos_in_parent = curr_idx % arity
        curr_idx = curr_idx // arity

        # Build hash input: insert computed hash at correct position
        hash_input = [0] * sponge_width
        sibling_ptr = 0

        for i in range(arity):
            if i == pos_in_parent:
                # Insert our computed hash
                for j in range(HASH_SIZE):
                    if i * HASH_SIZE + j < sponge_width:
                        hash_input[i * HASH_SIZE + j] = computed[j]
            else:
                # Insert sibling hash
                for j in range(HASH_SIZE):
                    if i * HASH_SIZE + j < sponge_width:
                        hash_input[i * HASH_SIZE + j] = level_siblings[sibling_ptr * HASH_SIZE + j]
                sibling_ptr += 1

        computed = hash_seq(hash_input, sponge_width)

    # Compare against the expected value
    if last_level_verification == 0:
        # Compare against root
        return computed[:HASH_SIZE] == root[:HASH_SIZE]
    else:
        # Compare against the appropriate last level node
        # curr_idx is now the index into the last level
        expected = level[curr_idx * HASH_SIZE:(curr_idx + 1) * HASH_SIZE]
        return computed[:HASH_SIZE] == expected


# C++: stark_verify.hpp root parsing (inline)
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


# C++: stark_verify.hpp::computeXDivXSub
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
    # w_ext for x values on extended domain, w for opening point offsets
    w_ext = FF(get_omega(stark_info.starkStruct.nBitsExt))
    w = FF(get_omega(stark_info.starkStruct.nBits))
    shift = FF(SHIFT)

    for i in range(n_queries):
        query = fri_queries[i]
        # x = shift * w_ext^query (query points are on extended domain)
        x_base = shift * (w_ext ** query)
        x_ext = ff3([int(x_base), 0, 0])

        for o in range(n_opening_points):
            # Compute w^openingPoint (opening offsets use original domain omega)
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


# C++: stark_verify.hpp trace value parsing
def _parse_trace_values(jproof: Dict, stark_info) -> tuple:
    """Parse trace query values from proof.

    Corresponds to C++ lines 255-286.

    In verify mode, we use a contiguous layout for aux_trace where each stage
    (cm2, cm3, etc.) has its own non-overlapping region. This matches the
    verify-mode offsets computed in ExpressionsCtx.

    The verifier uses a query-based layout where each query's data is at:
    - For cm1: q * n_pols + stage_pos (in trace buffer)
    - For other stages: verify_offset + q * n_pols + stage_pos (in aux_trace)

    Args:
        jproof: Proof JSON
        stark_info: STARK configuration

    Returns:
        Tuple of (trace, aux_trace, trace_custom_commits_fixed)
    """
    n_queries = stark_info.starkStruct.nQueries

    # For cm1 (stage 1), data is accessed directly without offset in trace buffer
    cm1_n_pols = stark_info.mapSectionsN["cm1"]
    trace_size = n_queries * cm1_n_pols
    trace = np.zeros(trace_size, dtype=np.uint64)

    # Compute verify-mode offsets for stages 2+ (non-overlapping layout)
    # These must match the offsets computed in ExpressionsCtx for verify mode
    verify_offsets = {}
    verify_aux_offset = 0
    for stage in range(2, stark_info.nStages + 2):
        section = f"cm{stage}"
        if section in stark_info.mapSectionsN:
            verify_offsets[stage] = verify_aux_offset
            n_pols = stark_info.mapSectionsN[section]
            verify_aux_offset += n_queries * n_pols

    aux_trace_size = verify_aux_offset
    aux_trace = np.zeros(max(aux_trace_size, stark_info.mapTotalN), dtype=np.uint64)

    # Compute verify-mode offsets for custom commits (non-overlapping layout)
    custom_verify_offsets = {}
    custom_aux_offset = 0
    for c in range(len(stark_info.customCommits)):
        section = stark_info.customCommits[c].name + "0"
        if section in stark_info.mapSectionsN:
            custom_verify_offsets[c] = custom_aux_offset
            n_pols = stark_info.mapSectionsN[section]
            custom_aux_offset += n_queries * n_pols

    custom_commits_size = custom_aux_offset
    trace_custom_commits_fixed = np.zeros(max(custom_commits_size, stark_info.mapTotalNCustomCommitsFixed), dtype=np.uint64)

    # Parse committed polynomial values (lines 259-274)
    # Use verify-mode offsets matching expression_evaluator
    for q in range(n_queries):
        for i in range(len(stark_info.cmPolsMap)):
            stage = stark_info.cmPolsMap[i].stage
            stage_pos = stark_info.cmPolsMap[i].stagePos
            n_pols = stark_info.mapSectionsN[f"cm{stage}"]

            if stage == 1:
                # cm1 is accessed directly without offset in trace buffer
                trace[q * n_pols + stage_pos] = int(jproof[f"s0_vals{stage}"][q][stage_pos])
                if stark_info.cmPolsMap[i].dim > 1:
                    trace[q * n_pols + stage_pos + 1] = int(jproof[f"s0_vals{stage}"][q][stage_pos + 1])
                    trace[q * n_pols + stage_pos + 2] = int(jproof[f"s0_vals{stage}"][q][stage_pos + 2])
            else:
                # Other stages use verify-mode offset
                offset = verify_offsets[stage]
                aux_trace[offset + q * n_pols + stage_pos] = int(jproof[f"s0_vals{stage}"][q][stage_pos])
                if stark_info.cmPolsMap[i].dim > 1:
                    aux_trace[offset + q * n_pols + stage_pos + 1] = int(jproof[f"s0_vals{stage}"][q][stage_pos + 1])
                    aux_trace[offset + q * n_pols + stage_pos + 2] = int(jproof[f"s0_vals{stage}"][q][stage_pos + 2])

    # Parse custom commit values (lines 277-286)
    for q in range(n_queries):
        for c in range(len(stark_info.customCommits)):
            for i in range(len(stark_info.customCommitsMap[c])):
                stage_pos = stark_info.customCommitsMap[c][i].stagePos
                section = stark_info.customCommits[c].name + "0"
                offset = custom_verify_offsets.get(c, 0)
                n_pols = stark_info.mapSectionsN[section]
                trace_custom_commits_fixed[offset + q * n_pols + stage_pos] = int(
                    jproof[f"s0_vals_{stark_info.customCommits[c].name}_0"][q][stage_pos]
                )

    return trace, aux_trace, trace_custom_commits_fixed


# C++: stark_verify.hpp evaluation verification section
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
    dest.dim = setup_ctx.expressions_bin.expressions_info[stark_info.cExpId].dest_dim

    # Add expression parameter
    param = Params(exp_id=stark_info.cExpId, dim=dest.dim, batch=True, op="tmp")
    dest.params.append(param)

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
            if e.type == EvMap.Type.cm and e.id == index
        )

        eval_val = ff3([
            int(evals[ev_id * FIELD_EXTENSION]),
            int(evals[ev_id * FIELD_EXTENSION + 1]),
            int(evals[ev_id * FIELD_EXTENSION + 2])
        ])

        q = q + (x_acc * eval_val)
        x_acc = x_acc * x_n

    # Check Q(xi) == constraint_eval(xi) (lines 337-341)
    constraint_eval = ff3([int(buff[0]), int(buff[1]), int(buff[2])])
    res = q - constraint_eval
    res_coeffs = ff3_coeffs(res)

    if not (int(res_coeffs[0]) == 0 and int(res_coeffs[1]) == 0 and int(res_coeffs[2]) == 0):
        print(f"  Q(xi): {ff3_coeffs(q)}")
        print(f"  constraint_eval(xi): {ff3_coeffs(constraint_eval)}")
        print(f"  residual: {res_coeffs}")
        print(f"  xi_challenge: {list(xi_challenge)}")
        print(f"  challenges[0:3]: {list(params.challenges[:3])}")
        return False

    return True


# C++: stark_verify.hpp FRI consistency checks
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
    dest_queries.dim = setup_ctx.expressions_bin.expressions_info[stark_info.friExpId].dest_dim

    # Add expression parameter
    param = Params(exp_id=stark_info.friExpId, dim=dest_queries.dim, batch=True, op="tmp")
    dest_queries.params.append(param)

    expressions_pack.calculate_expressions(params, dest_queries, n_queries, False, False)

    # Check against proof values (lines 349-367)
    is_valid = True
    first_mismatch_printed = False
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
                    if not first_mismatch_printed:
                        print(f"DEBUG FRI mismatch: q={q}, idx={idx}, j={j}")
                        print(f"  proof_val: {proof_val}")
                        print(f"  computed_val: {computed_val}")
                        print(f"  fri_query: {fri_queries[q]}")
                        print(f"  finalPol[idx]: {jproof['finalPol'][idx]}")
                        print(f"  buff_queries[q*3:q*3+3]: {[int(buff_queries[q * FIELD_EXTENSION + k]) for k in range(3)]}")
                        first_mismatch_printed = True
                    is_valid = False
                    break

        if not is_valid:
            break

    return is_valid


# C++: stark_verify.hpp stage Merkle verification (lines 373-437)
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
    # Get tree parameters
    arity = stark_info.starkStruct.merkleTreeArity
    last_level_verification = stark_info.starkStruct.lastLevelVerification
    custom = stark_info.starkStruct.merkleTreeCustom
    n_bits_ext = stark_info.starkStruct.nBitsExt
    n_queries = stark_info.starkStruct.nQueries

    # Get section info
    section = f"cm{stage + 1}"
    n_cols = stark_info.mapSectionsN[section]

    # Sponge width based on arity
    sponge_width = {2: 8, 3: 12, 4: 16}[arity]

    # Parse root (4 elements for Goldilocks)
    root = _parse_root(jproof, f"root{stage + 1}", HASH_SIZE)

    # Parse last level nodes if applicable
    num_nodes_level = 0 if last_level_verification == 0 else arity ** last_level_verification
    level = []
    if num_nodes_level > 0:
        for i in range(num_nodes_level):
            for j in range(HASH_SIZE):
                level.append(int(jproof[f"s0_last_levels{stage + 1}"][i][j]))

    # Verify root from last level nodes
    if last_level_verification > 0:
        if not MerkleTree.verify_merkle_root(
            root, level, 1 << n_bits_ext, last_level_verification, arity, sponge_width
        ):
            return False

    # Calculate number of sibling levels
    # For Goldilocks: ceil(nBits / log2(arity)) - lastLevelVerification
    n_siblings = math.ceil(stark_info.starkStruct.steps[0].nBits / math.log2(arity)) - last_level_verification
    n_siblings_per_level = (arity - 1) * HASH_SIZE

    # Verify each query's Merkle proof
    for q in range(n_queries):
        # Parse leaf values
        values = [int(jproof[f"s0_vals{stage + 1}"][q][i]) for i in range(n_cols)]

        # Parse siblings (2D array: [level][sibling])
        siblings = []
        for i in range(n_siblings):
            level_siblings = [int(jproof[f"s0_siblings{stage + 1}"][q][i][j]) for j in range(n_siblings_per_level)]
            siblings.append(level_siblings)

        # Verify Merkle path
        if not _verify_merkle_query(
            root, level, siblings, fri_queries[q], values,
            arity, sponge_width, last_level_verification
        ):
            return False

    return True


# C++: stark_verify.hpp constant Merkle verification (lines 439-494)
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
    # Get tree parameters
    arity = stark_info.starkStruct.merkleTreeArity
    last_level_verification = stark_info.starkStruct.lastLevelVerification
    n_queries = stark_info.starkStruct.nQueries
    n_constants = stark_info.nConstants

    # Sponge width based on arity
    sponge_width = {2: 8, 3: 12, 4: 16}[arity]

    # Root is the verification key
    root = verkey

    # Parse last level nodes if applicable
    num_nodes_level = 0 if last_level_verification == 0 else arity ** last_level_verification
    level = []
    if num_nodes_level > 0:
        for i in range(num_nodes_level):
            for j in range(HASH_SIZE):
                level.append(int(jproof["s0_last_levelsC"][i][j]))

    # Verify root from last level nodes
    if last_level_verification > 0:
        if not MerkleTree.verify_merkle_root(
            root, level, 1 << stark_info.starkStruct.nBitsExt, last_level_verification, arity, sponge_width
        ):
            return False

    # Calculate number of sibling levels
    n_siblings = math.ceil(stark_info.starkStruct.steps[0].nBits / math.log2(arity)) - last_level_verification
    n_siblings_per_level = (arity - 1) * HASH_SIZE

    # Verify each query's Merkle proof
    for q in range(n_queries):
        # Parse leaf values (constant polynomial values)
        values = [int(jproof["s0_valsC"][q][i]) for i in range(n_constants)]

        # Parse siblings
        siblings = []
        for i in range(n_siblings):
            level_siblings = [int(jproof["s0_siblingsC"][q][i][j]) for j in range(n_siblings_per_level)]
            siblings.append(level_siblings)

        # Verify Merkle path
        if not _verify_merkle_query(
            root, level, siblings, fri_queries[q], values,
            arity, sponge_width, last_level_verification
        ):
            return False

    return True


# C++: stark_verify.hpp custom commit Merkle verification (lines 496-557)
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
    # Get tree parameters
    arity = stark_info.starkStruct.merkleTreeArity
    last_level_verification = stark_info.starkStruct.lastLevelVerification
    n_queries = stark_info.starkStruct.nQueries

    # Sponge width based on arity
    sponge_width = {2: 8, 3: 12, 4: 16}[arity]

    # Get custom commit info
    cc = stark_info.customCommits[commit_idx]
    name = cc.name
    section = f"{name}0"
    n_cols = stark_info.mapSectionsN[section]

    # Extract root from public inputs
    root = [int(publics[cc.publicValues[j]]) for j in range(HASH_SIZE)]

    # Parse last level nodes if applicable
    num_nodes_level = 0 if last_level_verification == 0 else arity ** last_level_verification
    level = []
    if num_nodes_level > 0:
        for i in range(num_nodes_level):
            for j in range(HASH_SIZE):
                level.append(int(jproof[f"s0_last_levels_{name}_0"][i][j]))

    # Verify root from last level nodes
    if last_level_verification > 0:
        if not MerkleTree.verify_merkle_root(
            root, level, 1 << stark_info.starkStruct.nBitsExt, last_level_verification, arity, sponge_width
        ):
            return False

    # Calculate number of sibling levels
    n_siblings = math.ceil(stark_info.starkStruct.steps[0].nBits / math.log2(arity)) - last_level_verification
    n_siblings_per_level = (arity - 1) * HASH_SIZE

    # Verify each query's Merkle proof
    for q in range(n_queries):
        # Parse leaf values
        values = [int(jproof[f"s0_vals_{name}_0"][q][i]) for i in range(n_cols)]

        # Parse siblings
        siblings = []
        for i in range(n_siblings):
            level_siblings = [int(jproof[f"s0_siblings_{name}_0"][q][i][j]) for j in range(n_siblings_per_level)]
            siblings.append(level_siblings)

        # Verify Merkle path
        if not _verify_merkle_query(
            root, level, siblings, fri_queries[q], values,
            arity, sponge_width, last_level_verification
        ):
            return False

    return True


# C++: stark_verify.hpp FRI folding Merkle verification (lines 560-623)
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
        step: FRI step number (1 to len(steps)-1)
        fri_queries: FRI query indices

    Returns:
        True if FRI folding tree is valid
    """
    # Get tree parameters
    arity = stark_info.starkStruct.merkleTreeArity
    last_level_verification = stark_info.starkStruct.lastLevelVerification
    n_queries = stark_info.starkStruct.nQueries

    # Sponge width based on arity
    sponge_width = {2: 8, 3: 12, 4: 16}[arity]

    # Calculate FRI dimensions for this step
    n_groups = 1 << stark_info.starkStruct.steps[step].nBits
    group_size = (1 << stark_info.starkStruct.steps[step - 1].nBits) // n_groups
    n_cols = group_size * FIELD_EXTENSION

    # Parse root
    root = _parse_root(jproof, f"s{step}_root", HASH_SIZE)

    # Parse last level nodes if applicable
    num_nodes_level = 0 if last_level_verification == 0 else arity ** last_level_verification
    level = []
    if num_nodes_level > 0:
        for i in range(num_nodes_level):
            for j in range(HASH_SIZE):
                level.append(int(jproof[f"s{step}_last_levels"][i][j]))

    # Verify root from last level nodes
    if last_level_verification > 0:
        if not MerkleTree.verify_merkle_root(
            root, level, n_groups, last_level_verification, arity, sponge_width
        ):
            return False

    # Calculate number of sibling levels for this step's tree
    # The tree at step has fewer leaves (n_groups), so fewer levels
    n_siblings = math.ceil(stark_info.starkStruct.steps[step].nBits / math.log2(arity)) - last_level_verification
    n_siblings_per_level = (arity - 1) * HASH_SIZE

    # Verify each query's Merkle proof
    for q in range(n_queries):
        # Query index for this step's tree
        idx = fri_queries[q] % (1 << stark_info.starkStruct.steps[step].nBits)

        # Parse leaf values (group_size * FIELD_EXTENSION elements)
        values = [int(jproof[f"s{step}_vals"][q][i]) for i in range(n_cols)]

        # Parse siblings
        siblings = []
        for i in range(n_siblings):
            level_siblings = [int(jproof[f"s{step}_siblings"][q][i][j]) for j in range(n_siblings_per_level)]
            siblings.append(level_siblings)

        # Verify Merkle path
        if not _verify_merkle_query(
            root, level, siblings, idx, values,
            arity, sponge_width, last_level_verification
        ):
            return False

    return True


# C++: stark_verify.hpp FRI folding verification
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
            # The FRI tree at step stores polynomial evaluations grouped for the next fold.
            # Tree layout: height = 2^next_bits leaves, each has n_groups evaluations.
            # Position idx in the fold output is stored in:
            #   - leaf = idx % (1 << next_bits)
            #   - group = idx >> next_bits
            next_bits = stark_info.starkStruct.steps[step + 1].nBits
            sibling_pos = idx >> next_bits
            for i in range(FIELD_EXTENSION):
                proof_val = int(jproof[f"s{step + 1}_vals"][q][sibling_pos * FIELD_EXTENSION + i])
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


# C++: stark_verify.hpp final polynomial degree check
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
