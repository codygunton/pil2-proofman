"""Top-level STARK proof generation."""

from typing import Optional

import numpy as np

from poseidon2_ffi import linear_hash
from primitives.merkle_tree import QueryProof
from primitives.ntt import NTT
from primitives.transcript import Transcript
from protocol.expression_evaluator import ExpressionsPack
from protocol.pcs import FriPcs, FriPcsConfig
from protocol.setup_ctx import ProverHelpers, SetupCtx
from protocol.stages import Starks
from protocol.steps_params import StepsParams
from protocol.witness_generation import calculate_witness_std

# --- Type Aliases ---

Fe3 = tuple[int, int, int]  # Cubic extension field element
MerkleRoot = list[int]
StageNum = int
FIELD_EXTENSION = 3


# --- Main Entry Point ---

def gen_proof(
    setup_ctx: SetupCtx,
    params: StepsParams,
    recursive: bool = False,
    transcript: Optional[Transcript] = None,
    skip_challenge_derivation: bool = False
) -> dict:
    """Generate complete STARK proof."""
    stark_info = setup_ctx.stark_info

    # --- Setup ---
    N = 1 << stark_info.starkStruct.nBits
    N_extended = 1 << stark_info.starkStruct.nBitsExt
    ntt = NTT(N)
    ntt_extended = NTT(N_extended)

    prover_helpers = ProverHelpers.from_stark_info(stark_info, pil1=False)
    starks = Starks(setup_ctx)
    expressions_ctx = ExpressionsPack(setup_ctx, prover_helpers)

    if transcript is None:
        transcript = Transcript(
            arity=stark_info.starkStruct.transcriptArity,
            custom=stark_info.starkStruct.merkleTreeCustom
        )

    # --- Stage 0: Initialize Transcript ---
    if recursive:
        if stark_info.nPublics > 0:
            transcript.put(params.publicInputs[:stark_info.nPublics])

    if params.constPolsExtended is not None and len(params.constPolsExtended) > 0:
        starks.build_const_tree(params.constPolsExtended)

    # --- Stage 1: Witness Commitment ---
    computed_roots: list[MerkleRoot] = []

    root1 = starks.commitStage(1, params, ntt)
    computed_roots.append(list(root1))

    if recursive:
        transcript.put(root1)

    # --- Stage 2: Intermediate Polynomials ---
    if not skip_challenge_derivation:
        _derive_stage_challenges(transcript, params, stark_info.challengesMap, stage=2)

    starks.calculateImPolsExpressions(2, params, expressions_ctx)

    # Compute grand product and sum polynomials for lookup/permutation arguments
    calculate_witness_std(stark_info, setup_ctx.expressions_bin, params, expressions_ctx, prod=True)
    calculate_witness_std(stark_info, setup_ctx.expressions_bin, params, expressions_ctx, prod=False)

    root2 = starks.commitStage(2, params, ntt)
    computed_roots.append(list(root2))
    transcript.put(root2)

    # --- Stage Q: Quotient Polynomial ---
    q_stage = stark_info.nStages + 1

    if not skip_challenge_derivation:
        _derive_stage_challenges(transcript, params, stark_info.challengesMap, stage=q_stage)

    starks.calculateQuotientPolynomial(params, expressions_ctx)

    rootQ = starks.commitStage(q_stage, params, ntt_extended)
    computed_roots.append(list(rootQ))
    transcript.put(rootQ)

    # --- Stage EVALS: Polynomial Evaluations ---
    xi_challenge_index = _derive_eval_challenges(
        transcript, params, stark_info, skip_challenge_derivation
    )
    xi = params.challenges[xi_challenge_index * FIELD_EXTENSION:(xi_challenge_index + 1) * FIELD_EXTENSION]

    _compute_all_evals(stark_info, starks, params, xi, ntt)

    n_evals = len(stark_info.evMap) * FIELD_EXTENSION
    if not stark_info.starkStruct.hashCommits:
        transcript.put(params.evals[:n_evals])
    else:
        evals_hash = list(linear_hash([int(v) for v in params.evals[:n_evals]], width=16))
        transcript.put(evals_hash)

    # FRI polynomial challenges
    if not skip_challenge_derivation:
        _derive_stage_challenges(transcript, params, stark_info.challengesMap,
                                 stage=stark_info.nStages + 3)

    # --- Stage FRI: Polynomial Commitment ---
    starks.calculateFRIPolynomial(params, expressions_ctx)

    fri_pol_offset = stark_info.mapOffsets[("f", True)]
    fri_pol_size = (1 << stark_info.starkStruct.steps[0].nBits) * FIELD_EXTENSION
    fri_pol = params.auxTrace[fri_pol_offset:fri_pol_offset + fri_pol_size]

    fri_config = FriPcsConfig(
        n_bits_ext=stark_info.starkStruct.steps[0].nBits,
        fri_steps=[step.nBits for step in stark_info.starkStruct.steps],
        n_queries=stark_info.starkStruct.nQueries,
        merkle_arity=stark_info.starkStruct.merkleTreeArity,
        pow_bits=stark_info.starkStruct.powBits,
        last_level_verification=stark_info.starkStruct.lastLevelVerification,
        hash_commits=stark_info.starkStruct.hashCommits,
        transcript_arity=stark_info.starkStruct.transcriptArity,
        merkle_tree_custom=stark_info.starkStruct.merkleTreeCustom,
    )

    fri_pcs = FriPcs(fri_config)
    fri_proof = fri_pcs.prove(fri_pol, transcript)

    # --- Collect Query Proofs ---
    query_indices = fri_proof.query_indices

    const_query_proofs = _collect_const_query_proofs(starks, query_indices)
    stage_query_proofs = _collect_stage_query_proofs(starks, stark_info, query_indices)
    last_level_nodes = _collect_last_level_nodes(starks, stark_info, fri_pcs)

    # --- Assemble Proof ---
    return {
        'evals': params.evals[:n_evals],
        'airgroup_values': params.airgroupValues,
        'air_values': params.airValues,
        'nonce': fri_proof.nonce,
        'fri_proof': fri_proof,
        'roots': computed_roots,
        'stage_query_proofs': stage_query_proofs,
        'const_query_proofs': const_query_proofs,
        'query_indices': query_indices,
        'last_level_nodes': last_level_nodes,
    }


# --- Challenge Derivation ---

def _derive_stage_challenges(transcript: Transcript, params: StepsParams,
                             challenges_map: list, stage: int) -> None:
    """Derive Fiat-Shamir challenges for a given stage."""
    for i, cm in enumerate(challenges_map):
        if cm.stage == stage:
            challenge = transcript.get_field()
            params.challenges[i * FIELD_EXTENSION:(i + 1) * FIELD_EXTENSION] = challenge


def _derive_eval_challenges(transcript: Transcript, params: StepsParams,
                            stark_info, skip: bool) -> int:
    """Derive evaluation-stage challenges, return xi challenge index."""
    eval_stage = stark_info.nStages + 2
    xi_index = 0

    for i, cm in enumerate(stark_info.challengesMap):
        if cm.stage == eval_stage:
            if cm.stageId == 0:
                xi_index = i
            if not skip:
                challenge = transcript.get_field()
                params.challenges[i * FIELD_EXTENSION:(i + 1) * FIELD_EXTENSION] = challenge

    return xi_index


# --- Polynomial Evaluations ---

def _compute_all_evals(stark_info, starks: Starks, params: StepsParams,
                       xi: np.ndarray, ntt: NTT) -> None:
    """Compute evaluations at all opening points in batches of 4."""
    for i in range(0, len(stark_info.openingPoints), 4):
        batch = stark_info.openingPoints[i:i + 4]
        LEv = starks.computeLEv(xi, batch, ntt)
        starks.computeEvals(params, LEv, batch)


# --- Query Proof Collection ---

def _collect_const_query_proofs(starks: Starks,
                                query_indices: list[int]) -> list[QueryProof]:
    """Collect constant polynomial query proofs."""
    if starks.const_tree is None:
        return []
    return [starks.get_const_query_proof(idx, elem_size=1) for idx in query_indices]


def _collect_stage_query_proofs(starks: Starks, stark_info,
                                query_indices: list[int]) -> dict[StageNum, list[QueryProof]]:
    """Collect query proofs for all stage trees."""
    result: dict[StageNum, list[QueryProof]] = {}
    for stage in range(1, stark_info.nStages + 2):
        if stage in starks.stage_trees:
            tree = starks.stage_trees[stage]
            result[stage] = [tree.get_query_proof(idx, elem_size=1) for idx in query_indices]
    return result


def _collect_last_level_nodes(starks: Starks, stark_info, fri_pcs: FriPcs) -> dict[str, list[int]]:
    """Collect last-level Merkle nodes for all trees (if lastLevelVerification > 0)."""
    result: dict[str, list[int]] = {}

    # Constant tree
    if starks.const_tree is not None:
        nodes = starks.const_tree.get_last_level_nodes()
        if nodes:
            result['const'] = nodes

    # Stage trees
    for stage in range(1, stark_info.nStages + 2):
        if stage in starks.stage_trees:
            nodes = starks.stage_trees[stage].get_last_level_nodes()
            if nodes:
                result[f'cm{stage}'] = nodes

    # FRI trees
    for step_idx in range(len(stark_info.starkStruct.steps) - 1):
        if step_idx < len(fri_pcs.fri_trees):
            nodes = fri_pcs.fri_trees[step_idx].get_last_level_nodes()
            if nodes:
                result[f'fri{step_idx}'] = nodes

    return result
