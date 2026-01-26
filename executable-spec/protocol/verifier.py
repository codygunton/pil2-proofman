"""STARK proof verification."""

import math
from typing import Dict, List, Optional

import numpy as np

from poseidon2_ffi import linear_hash, hash_seq, verify_grinding
from primitives.field import (FF, ff3, ff3_coeffs, ff3_from_json,
                               ff3_to_interleaved_numpy, get_omega, SHIFT,
                               FIELD_EXTENSION_DEGREE)
from primitives.merkle_tree import HASH_SIZE, MerkleTree
from primitives.ntt import NTT
from primitives.pol_map import EvMap
from primitives.transcript import Transcript
from protocol.expression_evaluator import ExpressionsPack, Dest, Params
from protocol.fri import FRI
from protocol.proof_context import ProofContext
from protocol.setup_ctx import SetupCtx, ProverHelpers

# --- Type Aliases ---

MerkleRoot = List[int]


# --- Main Entry Point ---

def stark_verify(
    jproof: Dict,
    setup_ctx: SetupCtx,
    verkey: List[int],
    publics: Optional[np.ndarray] = None,
    proof_values: Optional[np.ndarray] = None,
    challenges_vadcop: bool = False,
    global_challenge: Optional[np.ndarray] = None
) -> bool:
    """Verify a STARK proof."""
    stark_info = setup_ctx.stark_info
    stark_info.verify = True  # Enable verification mode for expression evaluator

    # --- Parse proof data ---
    evals = _parse_evals(jproof, stark_info)
    airgroup_values = _parse_airgroup_values(jproof, stark_info)
    air_values = _parse_air_values(jproof, stark_info)

    # --- Reconstruct Fiat-Shamir transcript ---
    challenges, final_pol = _reconstruct_transcript(
        jproof, stark_info, verkey, publics, challenges_vadcop, global_challenge
    )

    # --- Verify proof-of-work ---
    grinding_idx = len(stark_info.challengesMap) + len(stark_info.starkStruct.friFoldSteps)
    grinding_challenge = challenges[grinding_idx * FIELD_EXTENSION_DEGREE:(grinding_idx + 1) * FIELD_EXTENSION_DEGREE]
    nonce = int(jproof["nonce"])

    if not verify_grinding(list(grinding_challenge), nonce, stark_info.starkStruct.powBits):
        print("ERROR: PoW verification failed")
        return False

    # --- Derive FRI query indices ---
    transcript_permutation = Transcript(
        arity=stark_info.starkStruct.transcriptArity,
        custom=stark_info.starkStruct.merkleTreeCustom
    )
    transcript_permutation.put(list(grinding_challenge))
    transcript_permutation.put([nonce])
    fri_queries = transcript_permutation.get_permutations(
        stark_info.starkStruct.nQueries,
        stark_info.starkStruct.friFoldSteps[0].domainBits
    )

    # --- Parse query values ---
    const_pols_vals = _parse_const_pols_vals(jproof, stark_info)
    trace, aux_trace, custom_commits = _parse_trace_values(jproof, stark_info)

    # --- Find xi challenge ---
    xi_challenge = _find_xi_challenge(stark_info, challenges)

    # --- Build verifier parameters ---
    prover_helpers = ProverHelpers.from_challenge(stark_info, xi_challenge)
    expressions_pack = ExpressionsPack(setup_ctx, prover_helpers, 1, stark_info.starkStruct.nQueries)
    x_div_x_sub = _compute_x_div_x_sub(stark_info, xi_challenge, fri_queries)

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
        customCommits=custom_commits
    )

    # --- Run all verification checks ---
    is_valid = True

    print("Verifying evaluations")
    if not _verify_evaluations(stark_info, setup_ctx, expressions_pack, params, evals, xi_challenge):
        print("ERROR: Invalid evaluations")
        is_valid = False

    print("Verifying FRI queries consistency")
    if not _verify_fri_consistency(jproof, stark_info, setup_ctx, expressions_pack, params, fri_queries):
        print("ERROR: Verify FRI query consistency failed")
        is_valid = False

    print("Verifying stage Merkle trees")
    for s in range(stark_info.nStages + 1):
        root = _parse_root(jproof, f"root{s + 1}", HASH_SIZE)
        if not _verify_merkle_tree(jproof, stark_info, root, f"s0_vals{s + 1}", f"s0_siblings{s + 1}",
                                   f"s0_last_levels{s + 1}", f"cm{s + 1}", fri_queries):
            print(f"ERROR: Stage {s + 1} Merkle Tree verification failed")
            is_valid = False

    print("Verifying constant Merkle tree")
    if not _verify_merkle_tree(jproof, stark_info, verkey, "s0_valsC", "s0_siblingsC",
                               "s0_last_levelsC", None, fri_queries, n_cols=stark_info.nConstants):
        print("ERROR: Constant Merkle Tree verification failed")
        is_valid = False

    print("Verifying custom commits Merkle trees")
    if publics is not None:
        for c in range(len(stark_info.customCommits)):
            cc = stark_info.customCommits[c]
            root = [int(publics[cc.publicValues[j]]) for j in range(HASH_SIZE)]
            section = f"{cc.name}0"
            if not _verify_merkle_tree(jproof, stark_info, root,
                                       f"s0_vals_{cc.name}_0", f"s0_siblings_{cc.name}_0",
                                       f"s0_last_levels_{cc.name}_0", section, fri_queries):
                print(f"ERROR: Custom Commit {cc.name} Merkle Tree verification failed")
                is_valid = False

    print("Verifying FRI foldings Merkle Trees")
    for step in range(1, len(stark_info.starkStruct.friFoldSteps)):
        if not _verify_fri_merkle_tree(jproof, stark_info, step, fri_queries):
            print("ERROR: FRI folding Merkle Tree verification failed")
            is_valid = False

    print("Verifying FRI foldings")
    for step in range(1, len(stark_info.starkStruct.friFoldSteps)):
        if not _verify_fri_folding(jproof, stark_info, challenges, step, fri_queries):
            print("ERROR: FRI folding verification failed")
            is_valid = False

    print("Verifying final pol")
    if not _verify_final_polynomial(jproof, stark_info):
        print("ERROR: Final polynomial verification failed")
        is_valid = False

    return is_valid


# --- Proof Parsing ---

def _parse_root(jproof: Dict, key: str, n_fields: int) -> MerkleRoot:
    """Parse Merkle root from proof JSON."""
    if n_fields == 1:
        return [int(jproof[key])]
    return [int(jproof[key][i]) for i in range(n_fields)]


def _parse_evals(jproof: Dict, stark_info) -> np.ndarray:
    """Parse polynomial evaluations as flat numpy array."""
    evals_ff3 = ff3_from_json(jproof["evals"][:len(stark_info.evMap)])
    return ff3_to_interleaved_numpy(evals_ff3)


def _parse_airgroup_values(jproof: Dict, stark_info) -> np.ndarray:
    """Parse AIR group values as flat numpy array."""
    n = len(stark_info.airgroupValuesMap)
    if n == 0:
        return np.zeros(0, dtype=np.uint64)
    airgroup_ff3 = ff3_from_json(jproof["airgroupvalues"][:n])
    return ff3_to_interleaved_numpy(airgroup_ff3)


def _parse_air_values(jproof: Dict, stark_info) -> np.ndarray:
    """Parse AIR values (stage 1 = 1 elem, other stages = 3 elems)."""
    values = np.zeros(stark_info.airValuesSize, dtype=np.uint64)
    a = 0
    for i in range(len(stark_info.airValuesMap)):
        if stark_info.airValuesMap[i].stage == 1:
            values[a] = int(jproof["airvalues"][i][0])
            a += 1
        else:
            values[a] = int(jproof["airvalues"][i][0])
            values[a + 1] = int(jproof["airvalues"][i][1])
            values[a + 2] = int(jproof["airvalues"][i][2])
            a += 3
    return values


def _parse_const_pols_vals(jproof: Dict, stark_info) -> np.ndarray:
    """Parse constant polynomial values at query points."""
    n_queries = stark_info.starkStruct.nQueries
    n_constants = stark_info.nConstants
    vals = np.zeros(n_constants * n_queries, dtype=np.uint64)
    for q in range(n_queries):
        for i in range(n_constants):
            vals[q * n_constants + i] = int(jproof["s0_valsC"][q][i])
    return vals


def _parse_trace_values(jproof: Dict, stark_info) -> tuple:
    """Parse trace query values from proof.

    Returns (trace, aux_trace, custom_commits) arrays with verify-mode layout.
    """
    n_queries = stark_info.starkStruct.nQueries

    # cm1 goes in trace buffer
    cm1_n_pols = stark_info.mapSectionsN["cm1"]
    trace = np.zeros(n_queries * cm1_n_pols, dtype=np.uint64)

    # Compute verify-mode offsets for stages 2+
    verify_offsets = {}
    offset = 0
    for stage in range(2, stark_info.nStages + 2):
        section = f"cm{stage}"
        if section in stark_info.mapSectionsN:
            verify_offsets[stage] = offset
            offset += n_queries * stark_info.mapSectionsN[section]
    aux_trace = np.zeros(max(offset, stark_info.mapTotalN), dtype=np.uint64)

    # Compute verify-mode offsets for custom commits
    custom_offsets = {}
    offset = 0
    for c in range(len(stark_info.customCommits)):
        section = stark_info.customCommits[c].name + "0"
        if section in stark_info.mapSectionsN:
            custom_offsets[c] = offset
            offset += n_queries * stark_info.mapSectionsN[section]
    custom_commits = np.zeros(max(offset, stark_info.mapTotalNCustomCommitsFixed), dtype=np.uint64)

    # Parse committed polynomial values
    for q in range(n_queries):
        for i in range(len(stark_info.cmPolsMap)):
            stage = stark_info.cmPolsMap[i].stage
            stage_pos = stark_info.cmPolsMap[i].stagePos
            n_pols = stark_info.mapSectionsN[f"cm{stage}"]
            dim = stark_info.cmPolsMap[i].dim

            if stage == 1:
                for d in range(dim):
                    trace[q * n_pols + stage_pos + d] = int(jproof[f"s0_vals{stage}"][q][stage_pos + d])
            else:
                base = verify_offsets[stage] + q * n_pols + stage_pos
                for d in range(dim):
                    aux_trace[base + d] = int(jproof[f"s0_vals{stage}"][q][stage_pos + d])

    # Parse custom commit values
    for q in range(n_queries):
        for c in range(len(stark_info.customCommits)):
            cc = stark_info.customCommits[c]
            section = cc.name + "0"
            n_pols = stark_info.mapSectionsN[section]
            base = custom_offsets.get(c, 0) + q * n_pols
            for i in range(len(stark_info.customCommitsMap[c])):
                stage_pos = stark_info.customCommitsMap[c][i].stagePos
                custom_commits[base + stage_pos] = int(jproof[f"s0_vals_{cc.name}_0"][q][stage_pos])

    return trace, aux_trace, custom_commits


def _find_xi_challenge(stark_info, challenges: np.ndarray) -> np.ndarray:
    """Find xi challenge (evaluation point) from challenges array."""
    for i, ch in enumerate(stark_info.challengesMap):
        if ch.stage == stark_info.nStages + 2 and ch.stageId == 0:
            return challenges[i * FIELD_EXTENSION_DEGREE:(i + 1) * FIELD_EXTENSION_DEGREE]
    return np.zeros(FIELD_EXTENSION_DEGREE, dtype=np.uint64)


# --- Fiat-Shamir Transcript Reconstruction ---

def _reconstruct_transcript(
    jproof: Dict,
    stark_info,
    verkey: List[int],
    publics: Optional[np.ndarray],
    challenges_vadcop: bool,
    global_challenge: Optional[np.ndarray]
) -> tuple:
    """Reconstruct Fiat-Shamir transcript and derive all challenges.

    Returns (challenges, final_pol).
    """
    n_challenges = len(stark_info.challengesMap)
    n_steps = len(stark_info.starkStruct.friFoldSteps)
    challenges = np.zeros((n_challenges + n_steps + 1) * FIELD_EXTENSION_DEGREE, dtype=np.uint64)

    transcript = Transcript(
        arity=stark_info.starkStruct.transcriptArity,
        custom=stark_info.starkStruct.merkleTreeCustom
    )

    # Stage 0: Initialize transcript
    if not challenges_vadcop:
        transcript.put(verkey)
        if stark_info.nPublics > 0:
            if publics is None:
                raise ValueError("Public inputs required but not provided")
            if not stark_info.starkStruct.hashCommits:
                transcript.put(publics[:stark_info.nPublics].tolist())
            else:
                th = Transcript(arity=stark_info.starkStruct.transcriptArity,
                                custom=stark_info.starkStruct.merkleTreeCustom)
                th.put(publics[:stark_info.nPublics].tolist())
                transcript.put(th.get_state(HASH_SIZE))
        transcript.put(_parse_root(jproof, "root1", HASH_SIZE))
    else:
        if global_challenge is None:
            raise ValueError("Global challenge required in VADCOP mode")
        transcript.put(global_challenge[:3].tolist())

    # Stages 2..nStages+1: Derive challenges and add roots
    c = 0
    for s in range(2, stark_info.nStages + 2):
        # Derive challenges for this stage
        for ch in stark_info.challengesMap:
            if ch.stage == s:
                challenge = transcript.get_field()
                challenges[c * FIELD_EXTENSION_DEGREE:(c + 1) * FIELD_EXTENSION_DEGREE] = challenge
                c += 1

        # Add stage root
        transcript.put(_parse_root(jproof, f"root{s}", HASH_SIZE))

        # Add air values for this stage
        for av in stark_info.airValuesMap:
            if av.stage != 1 and av.stage == s:
                idx = stark_info.airValuesMap.index(av)
                transcript.put([int(v) for v in jproof["airvalues"][idx]])

    # Evals stage challenges (nStages + 2)
    for ch in stark_info.challengesMap:
        if ch.stage == stark_info.nStages + 2:
            challenge = transcript.get_field()
            challenges[c * FIELD_EXTENSION_DEGREE:(c + 1) * FIELD_EXTENSION_DEGREE] = challenge
            c += 1

    # Add evaluations to transcript - flatten [c0, c1, c2] triples
    evals_flat = [int(v) for ev in jproof["evals"][:len(stark_info.evMap)] for v in ev]
    if not stark_info.starkStruct.hashCommits:
        transcript.put(evals_flat)
    else:
        evals_hash = list(linear_hash(evals_flat, width=16))
        transcript.put(evals_hash)

    # FRI polynomial challenges (nStages + 3)
    for ch in stark_info.challengesMap:
        if ch.stage == stark_info.nStages + 3:
            challenge = transcript.get_field()
            challenges[c * FIELD_EXTENSION_DEGREE:(c + 1) * FIELD_EXTENSION_DEGREE] = challenge
            c += 1

    # FRI step challenges
    final_pol = None
    for step in range(n_steps):
        if step > 0:
            challenge = transcript.get_field()
            challenges[c * FIELD_EXTENSION_DEGREE:(c + 1) * FIELD_EXTENSION_DEGREE] = challenge
        c += 1

        if step < n_steps - 1:
            transcript.put(_parse_root(jproof, f"s{step + 1}_root", HASH_SIZE))
        else:
            # Parse and add final polynomial
            final_pol_ff3 = ff3_from_json(jproof["finalPol"])
            final_pol = ff3_to_interleaved_numpy(final_pol_ff3)

            if not stark_info.starkStruct.hashCommits:
                transcript.put(final_pol.tolist())
            else:
                th = Transcript(arity=stark_info.starkStruct.transcriptArity,
                                custom=stark_info.starkStruct.merkleTreeCustom)
                th.put(final_pol.tolist())
                transcript.put(th.get_state(HASH_SIZE))

    # Final challenge
    challenge = transcript.get_field()
    challenges[c * FIELD_EXTENSION_DEGREE:(c + 1) * FIELD_EXTENSION_DEGREE] = challenge

    return challenges, final_pol


# --- Verification Helpers ---

def _compute_x_div_x_sub(stark_info, xi_challenge: np.ndarray, fri_queries: List[int]) -> np.ndarray:
    """Compute x/(x - xi*w^openingPoint) for each query and opening point."""
    n_queries = stark_info.starkStruct.nQueries
    n_opening_points = len(stark_info.openingPoints)

    x_div_x_sub = np.zeros(n_queries * n_opening_points * FIELD_EXTENSION_DEGREE, dtype=np.uint64)

    xi = ff3([int(xi_challenge[0]), int(xi_challenge[1]), int(xi_challenge[2])])
    w_ext = FF(get_omega(stark_info.starkStruct.nBitsExt))
    w = FF(get_omega(stark_info.starkStruct.nBits))
    shift = FF(SHIFT)

    for i in range(n_queries):
        x_base = shift * (w_ext ** fri_queries[i])
        x = ff3([int(x_base), 0, 0])

        for o, opening_point in enumerate(stark_info.openingPoints):
            # w^|openingPoint|
            w_power = w ** abs(opening_point)
            if opening_point < 0:
                w_power = w_power ** -1

            # x / (x - xi * w^openingPoint)
            aux = x - xi * ff3([int(w_power), 0, 0])
            aux = aux ** -1

            idx = (i * n_opening_points + o) * FIELD_EXTENSION_DEGREE
            x_div_x_sub[idx:idx + FIELD_EXTENSION_DEGREE] = ff3_coeffs(aux)

    return x_div_x_sub


def _verify_evaluations(
    stark_info,
    setup_ctx: SetupCtx,
    expressions_pack: ExpressionsPack,
    params: ProofContext,
    evals: np.ndarray,
    xi_challenge: np.ndarray
) -> bool:
    """Verify Q(xi) == constraint_eval(xi)."""
    # Evaluate constraint expression at xi
    buff = np.zeros(FIELD_EXTENSION_DEGREE, dtype=np.uint64)
    dest = Dest(dest=buff, domain_size=1, offset=0)
    dest.exp_id = stark_info.cExpId
    dest.dim = setup_ctx.expressions_bin.expressions_info[stark_info.cExpId].dest_dim
    dest.params.append(Params(exp_id=stark_info.cExpId, dim=dest.dim, batch=True, op="tmp"))
    expressions_pack.calculate_expressions(params, dest, 1, False, False)

    # Compute xi^N
    xi = ff3([int(xi_challenge[0]), int(xi_challenge[1]), int(xi_challenge[2])])
    N = 1 << stark_info.starkStruct.nBits
    x_n = ff3([1, 0, 0])
    for _ in range(N):
        x_n = x_n * xi

    # Reconstruct Q(xi) from quotient polynomial evaluations
    q_stage = stark_info.nStages + 1
    q_index = next(i for i, p in enumerate(stark_info.cmPolsMap)
                   if p.stage == q_stage and p.stageId == 0)

    q = ff3([0, 0, 0])
    x_acc = ff3([1, 0, 0])

    for i in range(stark_info.qDeg):
        ev_id = next(j for j, e in enumerate(stark_info.evMap)
                     if e.type == EvMap.Type.cm and e.id == q_index + i)
        eval_val = ff3([int(evals[ev_id * FIELD_EXTENSION_DEGREE + k]) for k in range(FIELD_EXTENSION_DEGREE)])
        q = q + x_acc * eval_val
        x_acc = x_acc * x_n

    # Check Q(xi) == constraint_eval(xi)
    constraint_eval = ff3([int(buff[k]) for k in range(FIELD_EXTENSION_DEGREE)])
    res = ff3_coeffs(q - constraint_eval)

    if res[0] != 0 or res[1] != 0 or res[2] != 0:
        print(f"  Q(xi): {ff3_coeffs(q)}")
        print(f"  constraint_eval(xi): {ff3_coeffs(constraint_eval)}")
        print(f"  residual: {res}")
        return False

    return True


def _verify_fri_consistency(
    jproof: Dict,
    stark_info,
    setup_ctx: SetupCtx,
    expressions_pack: ExpressionsPack,
    params: ProofContext,
    fri_queries: List[int]
) -> bool:
    """Verify FRI polynomial values match expression evaluation at query points."""
    n_queries = stark_info.starkStruct.nQueries

    # Evaluate FRI expression at query points
    buff = np.zeros(FIELD_EXTENSION_DEGREE * n_queries, dtype=np.uint64)
    dest = Dest(dest=buff, domain_size=n_queries, offset=0)
    dest.exp_id = stark_info.friExpId
    dest.dim = setup_ctx.expressions_bin.expressions_info[stark_info.friExpId].dest_dim
    dest.params.append(Params(exp_id=stark_info.friExpId, dim=dest.dim, batch=True, op="tmp"))
    expressions_pack.calculate_expressions(params, dest, n_queries, False, False)

    # Check against proof values
    n_steps = len(stark_info.starkStruct.friFoldSteps)
    for q in range(n_queries):
        idx = fri_queries[q] % (1 << stark_info.starkStruct.friFoldSteps[0].domainBits)

        if n_steps > 1:
            next_n_groups = 1 << stark_info.starkStruct.friFoldSteps[1].domainBits
            group_idx = idx // next_n_groups
            # Compare FF3 value: proof vs computed
            proof_coeffs = jproof["s1_vals"][q][group_idx * FIELD_EXTENSION_DEGREE:(group_idx + 1) * FIELD_EXTENSION_DEGREE]
            computed_coeffs = buff[q * FIELD_EXTENSION_DEGREE:(q + 1) * FIELD_EXTENSION_DEGREE]
            for j in range(FIELD_EXTENSION_DEGREE):
                if int(proof_coeffs[j]) != int(computed_coeffs[j]):
                    return False
        else:
            # Compare FF3 value: finalPol vs computed
            proof_coeffs = jproof["finalPol"][idx]
            computed_coeffs = buff[q * FIELD_EXTENSION_DEGREE:(q + 1) * FIELD_EXTENSION_DEGREE]
            for j in range(FIELD_EXTENSION_DEGREE):
                if int(proof_coeffs[j]) != int(computed_coeffs[j]):
                    return False

    return True


# --- Merkle Tree Verification ---

def _verify_merkle_query(
    root: MerkleRoot,
    level: List[int],
    siblings: List[List[int]],
    idx: int,
    values: List[int],
    arity: int,
    sponge_width: int,
    last_level_verification: int
) -> bool:
    """Verify a single Merkle query proof."""
    computed = linear_hash(values, sponge_width)
    curr_idx = idx

    for level_siblings in siblings:
        pos = curr_idx % arity
        curr_idx = curr_idx // arity

        hash_input = [0] * sponge_width
        sib_ptr = 0
        for i in range(arity):
            for j in range(HASH_SIZE):
                if i * HASH_SIZE + j < sponge_width:
                    if i == pos:
                        hash_input[i * HASH_SIZE + j] = computed[j]
                    else:
                        hash_input[i * HASH_SIZE + j] = level_siblings[sib_ptr * HASH_SIZE + j]
            if i != pos:
                sib_ptr += 1

        computed = hash_seq(hash_input, sponge_width)

    if last_level_verification == 0:
        return computed[:HASH_SIZE] == root[:HASH_SIZE]
    else:
        expected = level[curr_idx * HASH_SIZE:(curr_idx + 1) * HASH_SIZE]
        return computed[:HASH_SIZE] == expected


def _verify_merkle_tree(
    jproof: Dict,
    stark_info,
    root: MerkleRoot,
    vals_key: str,
    siblings_key: str,
    last_levels_key: str,
    section: Optional[str],
    fri_queries: List[int],
    n_cols: Optional[int] = None
) -> bool:
    """Generic Merkle tree verification for stage/constant/custom commits."""
    arity = stark_info.starkStruct.merkleTreeArity
    llv = stark_info.starkStruct.lastLevelVerification
    n_queries = stark_info.starkStruct.nQueries
    sponge_width = {2: 8, 3: 12, 4: 16}[arity]

    if n_cols is None:
        n_cols = stark_info.mapSectionsN[section]

    # Parse last level nodes
    num_nodes = 0 if llv == 0 else arity ** llv
    level = []
    if num_nodes > 0:
        for i in range(num_nodes):
            for j in range(HASH_SIZE):
                level.append(int(jproof[last_levels_key][i][j]))

    # Verify root from last level nodes
    if llv > 0:
        if not MerkleTree.verify_merkle_root(
            root, level, 1 << stark_info.starkStruct.nBitsExt, llv, arity, sponge_width
        ):
            return False

    # Calculate sibling levels
    n_siblings = math.ceil(stark_info.starkStruct.friFoldSteps[0].domainBits / math.log2(arity)) - llv
    siblings_per_level = (arity - 1) * HASH_SIZE

    # Verify each query
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


def _verify_fri_merkle_tree(jproof: Dict, stark_info, step: int, fri_queries: List[int]) -> bool:
    """Verify FRI folding Merkle tree for a step."""
    arity = stark_info.starkStruct.merkleTreeArity
    llv = stark_info.starkStruct.lastLevelVerification
    n_queries = stark_info.starkStruct.nQueries
    sponge_width = {2: 8, 3: 12, 4: 16}[arity]

    n_groups = 1 << stark_info.starkStruct.friFoldSteps[step].domainBits
    group_size = (1 << stark_info.starkStruct.friFoldSteps[step - 1].domainBits) // n_groups
    n_cols = group_size * FIELD_EXTENSION_DEGREE  # FF3 values have FIELD_EXTENSION_DEGREE coefficients

    root = _parse_root(jproof, f"s{step}_root", HASH_SIZE)

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

    n_siblings = math.ceil(stark_info.starkStruct.friFoldSteps[step].domainBits / math.log2(arity)) - llv
    siblings_per_level = (arity - 1) * HASH_SIZE

    for q in range(n_queries):
        idx = fri_queries[q] % (1 << stark_info.starkStruct.friFoldSteps[step].domainBits)
        values = [int(jproof[f"s{step}_vals"][q][i]) for i in range(n_cols)]
        siblings = [
            [int(jproof[f"s{step}_siblings"][q][i][j]) for j in range(siblings_per_level)]
            for i in range(n_siblings)
        ]
        if not _verify_merkle_query(root, level, siblings, idx, values, arity, sponge_width, llv):
            return False

    return True


def _verify_fri_folding(
    jproof: Dict,
    stark_info,
    challenges: np.ndarray,
    step: int,
    fri_queries: List[int]
) -> bool:
    """Verify FRI folding step computation."""
    n_queries = stark_info.starkStruct.nQueries
    n_steps = len(stark_info.starkStruct.friFoldSteps)

    for q in range(n_queries):
        idx = fri_queries[q] % (1 << stark_info.starkStruct.friFoldSteps[step].domainBits)

        # Get sibling values (each is an FF3 triple [c0, c1, c2])
        n_x = 1 << (stark_info.starkStruct.friFoldSteps[step - 1].domainBits - stark_info.starkStruct.friFoldSteps[step].domainBits)
        siblings = [
            [int(jproof[f"s{step}_vals"][q][i * FIELD_EXTENSION_DEGREE + j]) for j in range(FIELD_EXTENSION_DEGREE)]
            for i in range(n_x)
        ]

        # Get challenge for this step
        challenge_idx = len(stark_info.challengesMap) + step
        challenge = [int(challenges[challenge_idx * FIELD_EXTENSION_DEGREE + j]) for j in range(FIELD_EXTENSION_DEGREE)]

        value = FRI.verify_fold(
            value=[0, 0, 0],
            fri_round=step,
            n_bits_ext=stark_info.starkStruct.nBitsExt,
            current_bits=stark_info.starkStruct.friFoldSteps[step].domainBits,
            prev_bits=stark_info.starkStruct.friFoldSteps[step - 1].domainBits,
            challenge=challenge,
            idx=idx,
            siblings=siblings
        )

        # Check against next layer or final polynomial
        if step < n_steps - 1:
            next_bits = stark_info.starkStruct.friFoldSteps[step + 1].domainBits
            sibling_pos = idx >> next_bits
            expected = jproof[f"s{step + 1}_vals"][q][sibling_pos * FIELD_EXTENSION_DEGREE:(sibling_pos + 1) * FIELD_EXTENSION_DEGREE]
            if value != ff3([int(v) for v in expected]):
                return False
        else:
            expected = jproof["finalPol"][idx]
            if value != ff3([int(v) for v in expected]):
                return False

    return True


def _verify_final_polynomial(jproof: Dict, stark_info) -> bool:
    """Verify final polynomial has correct degree bound."""
    # Parse final polynomial using FF3 helper
    final_pol_ff3 = ff3_from_json(jproof["finalPol"])
    final_pol = ff3_to_interleaved_numpy(final_pol_ff3)
    final_pol_size = len(final_pol_ff3)

    # INTT to coefficient form
    ntt = NTT(final_pol_size)
    final_pol_reshaped = final_pol.reshape(final_pol_size, FIELD_EXTENSION_DEGREE)
    final_pol_coeffs = ntt.intt(final_pol_reshaped, n_cols=FIELD_EXTENSION_DEGREE)

    # Check high-degree coefficients are zero
    last_step = stark_info.starkStruct.friFoldSteps[-1].domainBits
    blowup_factor = stark_info.starkStruct.nBitsExt - stark_info.starkStruct.nBits
    init = 0 if blowup_factor > last_step else (1 << (last_step - blowup_factor))

    for i in range(init, final_pol_size):
        if any(int(final_pol_coeffs[i, j]) != 0 for j in range(FIELD_EXTENSION_DEGREE)):
            print(f"ERROR: Final polynomial is not zero at position {i}")
            return False

    return True
