"""Top-level STARK proof generation."""

from typing import TYPE_CHECKING

import numpy as np
from poseidon2_ffi import linear_hash

from primitives.field import FF3, FIELD_EXTENSION_DEGREE, ff3_coeffs, ff3_from_interleaved_numpy
from primitives.merkle_tree import HASH_SIZE, QueryProof
from primitives.transcript import Transcript
from protocol.air_config import AirConfig, ProverHelpers
from protocol.pcs import FriPcs, FriPcsConfig
from protocol.stages import PolynomialCommitter, calculate_witness
from protocol.stark_info import StarkInfo
from protocol.utils.challenge_utils import derive_global_challenge

if TYPE_CHECKING:
    from primitives.pol_map import ChallengeMap

# --- Type Aliases ---
MerkleRoot = list[int]
StageNum = int
ChallengesDict = dict[str, FF3]

# --- Module Constants ---
# Default lattice expansion size for VADCOP protocol (CurveType::None)
# Reference: C++ proofman challenge_accumulation.rs
DEFAULT_LATTICE_SIZE = 368

# Poseidon2 linear hash width (internal state size)
POSEIDON2_LINEAR_HASH_WIDTH = 16


# --- Helper Functions ---


def _get_air_values_stage1(air_config: AirConfig, air_values: np.ndarray | None) -> list[int]:
    """Extract stage 1 air_values for global_challenge computation.

    C++ reference: proofman.rs:3472-3540 (get_contribution_air)
    Only stage 1 air_values go into global_challenge hash.
    For simple AIRs, this returns an empty list.
    """
    stark_info = air_config.stark_info
    result = []
    if (
        hasattr(stark_info, "air_values_map")
        and stark_info.air_values_map
        and air_values is not None
    ):
        for i, av in enumerate(stark_info.air_values_map):
            if av.stage == 1:
                # Stage 1 air_values are single field elements
                result.append(int(air_values[i]))
    return result


def _get_proof_values_stage1(_air_config: AirConfig) -> list[int]:
    """Extract stage 1 proof_values for global_challenge computation.

    C++ reference: challenge_accumulation.rs:96-99
    proofValuesMap is empty for all currently-supported AIRs, so this
    always returns []. When non-empty AIRs are added, implement extraction here.
    """
    return []


def derive_challenges_for_stage(
    transcript: Transcript, challenges_map: list["ChallengeMap"], stage: int
) -> ChallengesDict:
    """Derive all challenges for a stage from the transcript.

    Args:
        transcript: Fiat-Shamir transcript for challenge generation
        challenges_map: List of challenge specifications from AIR
        stage: Stage number to derive challenges for

    Returns:
        Dict mapping challenge name to FF3 value
    """
    result: ChallengesDict = {}
    for challenge_spec in challenges_map:
        if challenge_spec.stage == stage:
            challenge = transcript.get_field()  # Returns [c0, c1, c2]
            # Convert to FF3 (galois expects descending order)
            result[challenge_spec.name] = FF3.Vector([challenge[2], challenge[1], challenge[0]])
    return result


# --- Stage Helpers ---


def _commit_stage1(
    air_config: AirConfig,
    trace: np.ndarray,
    const_pols_extended: np.ndarray,
) -> tuple[list[int], list[int], np.ndarray, list[MerkleRoot], PolynomialCommitter]:
    """Commit stage-1 witness trace and build constant polynomial tree.

    Called by gen_proof() and prove_simple_pilout() to obtain root1 and verkey
    for global challenge derivation before running stages 2 through FRI.

    Args:
        air_config: AIR configuration with stark_info
        trace: Stage 1 witness trace buffer (N * cm1_cols)
        const_pols_extended: Constant polynomials on extended domain

    Returns:
        Tuple (verkey, root1, aux_trace, commitments, committer) where:
            verkey: Merkle root of constant polynomial tree (4 field elements)
            root1: Stage 1 Merkle commitment root (4 field elements)
            aux_trace: Zeroed auxiliary trace buffer for stages 2+
            commitments: List containing [root1] for proof assembly
            committer: PolynomialCommitter with const_tree and stage_trees[1] populated
    """
    stark_info = air_config.stark_info

    # PolynomialCommitter orchestrates polynomial commitment via Merkle trees
    # Manages: constant tree, stage trees (1, 2, Q), and FRI trees
    committer = PolynomialCommitter(air_config)

    # Build the verification key from constant polynomial commitments.
    # The verkey is the Merkle root (4 field elements) of the constant polynomial tree.
    # AIRs without constant polynomials (e.g., purely trace-based AIRs) use a zero verkey.
    # This matches C++ proofman: both prover and verifier must agree on this default,
    # because verkey enters the global challenge hash.
    if const_pols_extended is not None and len(const_pols_extended) > 0:
        verkey = committer.build_const_tree(const_pols_extended)
    else:
        verkey = [0] * HASH_SIZE

    # Auxiliary trace buffer: a single flat uint64 array that holds all stage polynomial
    # evaluations. The buffer is partitioned into non-overlapping slices by map_offsets:
    #   Stage 1 (raw trace columns)      base-domain  at map_offsets[("cm1", False)]
    #                                    extended      at map_offsets[("cm1", True)]
    #   Stage 2 (im_cluster, gsum, …)   base-domain  at map_offsets[("cm2", False)]
    #                                    extended      at map_offsets[("cm2", True)]
    #   Quotient polynomial Q(x)          extended-only at map_offsets[("q", True)]
    #   FRI polynomial f(x)               extended-only at map_offsets[("f", True)]
    # Total size: stark_info.map_total_n uint64 elements.
    aux_trace = np.zeros(stark_info.map_total_n, dtype=np.uint64)

    # <doc-anchor id="witness-commit">
    root1 = list(committer.commitStage(1, trace, aux_trace))
    commitments: list[MerkleRoot] = [root1]

    return verkey, root1, aux_trace, commitments, committer


def _gen_proof_stage2_plus(
    air_config: AirConfig,
    trace: np.ndarray,
    const_pols: np.ndarray,
    const_pols_extended: np.ndarray,
    aux_trace: np.ndarray,
    commitments: list[MerkleRoot],
    transcript_seed: list[int],
    committer: PolynomialCommitter,
    air_values: np.ndarray,
) -> dict:
    """Run proof stages 2 through FRI given committed stage-1 and global challenge.

    Called by gen_proof() (single-AIR) and prove_simple_pilout() (multi-AIR).
    Seeds the Fiat-Shamir transcript from transcript_seed (the global challenge)
    and runs all remaining protocol stages to produce the complete proof.

    Args:
        air_config: AIR configuration with stark_info
        trace: Stage 1 witness trace buffer
        const_pols: Constant polynomials on base domain
        const_pols_extended: Constant polynomials on extended domain
        aux_trace: Auxiliary trace buffer (stages 2+)
        commitments: Running list of Merkle roots (starts with [root1])
        transcript_seed: Global challenge for Fiat-Shamir initialization (3 field elements)
        committer: PolynomialCommitter with const_tree and stage_trees[1] populated
        air_values: Per-AIR instance values (typically zeros for simple AIRs)

    Returns:
        Dictionary containing the serialized proof.
    """
    stark_info = air_config.stark_info

    # ProverHelpers contains precomputed tables for constraint evaluation
    # Includes: L1(x) roots, zerofier roots, NTT twiddle factors
    prover_helpers = ProverHelpers.from_stark_info(stark_info, pil1=False)

    # Initialize Fiat-Shamir transcript seeded with the global challenge
    transcript = Transcript(
        arity=stark_info.stark_struct.transcript_arity,
        custom=stark_info.stark_struct.merkle_tree_custom,
    )
    # <doc-anchor id="transcript-seed-vadcop">
    transcript.put(transcript_seed)

    # === STAGE 2: Intermediate Polynomials ===
    # Generate witness polynomials that depend on stage-1 randomness
    # Examples: im_cluster (lookup multiplicity), gsum (bus accumulator)

    # <doc-anchor id="derive-stage2-challenges">
    # Derive stage 2 challenges from transcript (Fiat-Shamir).
    stage2_challenges = derive_challenges_for_stage(transcript, stark_info.challenges_map, stage=2)

    # Calculate stage-2 witness polynomials — the challenge-dependent part of the witness.
    # Stage-1 polynomials are the raw execution trace, fixed before any randomness.
    # Stage-2 polynomials can only be computed AFTER the stage-2 challenge is derived
    # from the stage-1 commitment, because they prove properties about stage-1 using
    # Fiat-Shamir randomness. Examples:
    #   im_cluster (lookup AIRs): multiplicity column — how many times each lookup table
    #     row is queried. Required to prove the lookup argument is balanced.
    #   gsum (bus AIRs): running bus accumulator — the sum of all bus messages sent and
    #     received, used to prove that senders and receivers agree.
    # Dispatches to the witness module registered for this AIR (SimpleLeft, Lookup2_12, …).
    # Writes computed columns into aux_trace; returns airgroup_values (cross-AIR VADCOP data).
    airgroup_values = calculate_witness(
        stark_info,
        trace,
        aux_trace,
        const_pols,
        stage2_challenges,
        expressions_bin=air_config.expressions_bin,
    )

    # <doc-anchor id="intermediate-commit">
    # Commit stage 2 witness polynomials via Merkle tree
    # commitments tracks roots for proof output; transcript absorbs them one-way
    stage2_commitment = committer.commitStage(2, trace, aux_trace)
    commitments.append(list(stage2_commitment))
    transcript.put(stage2_commitment)

    # === STAGE Q: Quotient Polynomial ===
    # Prove that all AIR constraints are satisfied by computing Q(x) = C(x) / Z_H(x)

    q_stage = stark_info.n_stages + 1

    # <doc-anchor id="derive-stageq-challenges">
    stageQ_challenges = derive_challenges_for_stage(
        transcript, stark_info.challenges_map, stage=q_stage
    )

    all_challenges = {**stage2_challenges, **stageQ_challenges}

    committer.calculateQuotientPolynomial(
        trace, aux_trace, const_pols_extended, all_challenges, prover_helpers, airgroup_values
    )

    # <doc-anchor id="quotient-commit">
    stageQ_commitment = committer.commitStage(q_stage, trace, aux_trace)
    commitments.append(list(stageQ_commitment))
    transcript.put(stageQ_commitment)

    # === STAGE EVALS: Polynomial Evaluations ===
    # Evaluate all polynomials at random challenge point xi and its shifted variants

    # <doc-anchor id="derive-eval-challenges">
    xi: FF3 | None = None
    eval_stage = stark_info.n_stages + 2
    eval_challenges = derive_challenges_for_stage(
        transcript, stark_info.challenges_map, stage=eval_stage
    )
    all_challenges.update(eval_challenges)
    for cm in stark_info.challenges_map:
        if cm.stage == eval_stage and cm.stage_id == 0:
            xi = eval_challenges[cm.name]
            break

    xi_coeffs = ff3_coeffs(xi)

    evals = _compute_all_evals(
        stark_info, committer, trace, aux_trace, const_pols_extended, xi_coeffs
    )

    # hash_commits controls how evaluations enter the Fiat-Shamir transcript.
    # False (default): absorb individual evaluation field elements directly.
    # True: first compress all evaluations with a Poseidon2 linear hash (16-element
    #   output), then absorb only the digest. This keeps transcript growth bounded
    #   when there are many openings (large ev_map), at the cost of one extra hash.
    # The setting is fixed per-AIR in stark_struct and must match between prover and verifier.
    if not stark_info.stark_struct.hash_commits:
        transcript.put(evals)
    else:
        evals_as_ints = [int(v) for v in evals]
        evals_hash = list(linear_hash(evals_as_ints, width=POSEIDON2_LINEAR_HASH_WIDTH))
        transcript.put(evals_hash)

    # === STAGE FRI ===
    # FRI proves low-degree of quotient polynomial via recursive folding

    fri_stage = stark_info.n_stages + 3
    fri_challenges = derive_challenges_for_stage(
        transcript, stark_info.challenges_map, stage=fri_stage
    )
    all_challenges.update(fri_challenges)

    vf1 = all_challenges["std_vf1"]
    vf2 = all_challenges["std_vf2"]

    committer.calculateFRIPolynomial(
        trace, aux_trace, const_pols_extended, evals, xi, vf1, vf2, prover_helpers
    )

    fri_pol_offset = stark_info.map_offsets[("f", True)]
    n_fri_elements = 1 << stark_info.stark_struct.fri_fold_steps[0].domain_bits
    fri_pol_size = n_fri_elements * FIELD_EXTENSION_DEGREE
    fri_pol_numpy = aux_trace[fri_pol_offset : fri_pol_offset + fri_pol_size]
    fri_pol = ff3_from_interleaved_numpy(fri_pol_numpy, n_fri_elements)

    fri_config = FriPcsConfig(
        n_bits_ext=stark_info.stark_struct.fri_fold_steps[0].domain_bits,
        fri_round_log_sizes=[step.domain_bits for step in stark_info.stark_struct.fri_fold_steps],
        n_queries=stark_info.stark_struct.n_queries,
        merkle_arity=stark_info.stark_struct.merkle_tree_arity,
        pow_bits=stark_info.stark_struct.pow_bits,
        last_level_verification=stark_info.stark_struct.last_level_verification,
        hash_commits=stark_info.stark_struct.hash_commits,
        transcript_arity=stark_info.stark_struct.transcript_arity,
        merkle_tree_custom=stark_info.stark_struct.merkle_tree_custom,
    )

    fri_pcs = FriPcs(fri_config)
    fri_proof = fri_pcs.prove(fri_pol, transcript)

    # === STAGE QUERY PROOFS ===
    # Collect Merkle authentication paths for all queried polynomial evaluations

    # <doc-anchor id="collect-query-proofs">
    query_indices = fri_proof.query_indices

    const_query_proofs = _collect_const_query_proofs(committer, query_indices)
    stage_query_proofs = _collect_stage_query_proofs(committer, stark_info, query_indices)
    last_level_nodes = _collect_last_level_nodes(committer, stark_info, fri_pcs)

    # === ASSEMBLE PROOF ===

    return {
        "evals": [int(v) for v in evals],
        "airgroup_values": airgroup_values,
        "air_values": air_values,
        "nonce": fri_proof.nonce,
        "fri_proof": fri_proof,
        "roots": commitments,
        "stage_query_proofs": stage_query_proofs,
        "const_query_proofs": const_query_proofs,
        "query_indices": query_indices,
        "last_level_nodes": last_level_nodes,
        # Global challenge seed used to initialize the Fiat-Shamir transcript.
        # Pass to stark_verify as global_challenge to reconstruct the transcript.
        "global_challenge": transcript_seed,
    }


# --- Main Entry Point ---


def gen_proof(
    air_config: AirConfig,
    trace: np.ndarray,
    const_pols: np.ndarray,
    const_pols_extended: np.ndarray,
    public_inputs: np.ndarray | None = None,
) -> dict:
    """Generate complete STARK proof via VADCOP protocol.

    Commits stage-1 witness, derives global challenge via lattice expansion,
    then runs stages 2 through FRI to produce the full proof.

    Args:
        air_config: AIR configuration with stark_info and global_info
        trace: Stage 1 witness trace buffer (N * cm1_cols)
        const_pols: Constant polynomials on base domain
        const_pols_extended: Constant polynomials on extended domain
        public_inputs: Public inputs array (optional)

    Returns:
        Dictionary containing serialized proof, including global_challenge.
    """
    # _commit_stage1 returns five objects:
    #   verkey:      Merkle root of the constant polynomial tree (4 ints).
    #                Passed to derive_global_challenge to bind the AIR's constants.
    #   root1:       Merkle root of the stage-1 witness commitment (4 ints).
    #                Passed to derive_global_challenge to bind the stage-1 trace.
    #   aux_trace:   Zeroed flat buffer for stage 2+ polynomial data (see _commit_stage1).
    #   commitments: Mutable list starting as [root1]. Stages 2 and Q append their roots
    #                here; the final list becomes proof["roots"] read by the verifier.
    #   committer:   Stateful PolynomialCommitter that already holds the const_tree and
    #                stage_trees[1]; needed to commit stages 2 and Q, evaluate polys, etc.
    # root1 and commitments[0] are the same value — root1 is kept separately because
    # derive_global_challenge needs it as a standalone argument, while commitments grows.
    verkey, root1, aux_trace, commitments, committer = _commit_stage1(
        air_config, trace, const_pols_extended
    )

    # Derive global challenge via lattice expansion (VADCOP protocol).
    # Binds all per-AIR stage-1 contributions to a shared global challenge.
    lattice_size = DEFAULT_LATTICE_SIZE
    if air_config.global_info is not None:
        lattice_size = air_config.global_info.lattice_size
    # air_values: per-AIR instance values — a buffer used by complex AIRs to pass
    # accumulator state between stages (e.g., bus totals in a VADCOP proof). For all
    # currently-supported AIRs, this buffer remains all zeros.
    air_values = np.zeros(air_config.stark_info.air_values_size, dtype=np.uint64)
    # air_values_stage1: the subset of air_values written during stage 1. These enter
    # the global challenge hash so verifiers can check cross-AIR state. Returns [] for
    # all currently-supported AIRs.
    air_values_stage1 = _get_air_values_stage1(air_config, air_values)
    # proof_values_stage1: cross-AIR boundary values (e.g., bus message totals) at stage 1.
    # These also enter the global challenge hash. Returns [] for all currently-supported AIRs.
    proof_values_stage1 = _get_proof_values_stage1(air_config)
    computed_challenge = derive_global_challenge(
        stark_info=air_config.stark_info,
        publics=public_inputs,
        root1=root1,
        verkey=verkey,
        air_values=air_values_stage1,
        proof_values_stage1=proof_values_stage1,
        lattice_size=lattice_size,
    )
    transcript_seed = list(computed_challenge[:3])

    return _gen_proof_stage2_plus(
        air_config,
        trace,
        const_pols,
        const_pols_extended,
        aux_trace,
        commitments,
        transcript_seed,
        committer,
        air_values,
    )


# --- Polynomial Evaluations ---


def _compute_all_evals(
    stark_info: StarkInfo,
    committer: PolynomialCommitter,
    trace: np.ndarray,
    aux_trace: np.ndarray,
    const_pols_extended: np.ndarray,
    xi: list[int],
) -> np.ndarray:
    """Compute polynomial evaluations at all opening points in batches of 4.

    For each EvMap entry, evaluates the specified polynomial at xi^row_offset.
    Opening points are processed in batches for efficiency - Lagrange basis
    evaluations (expensive) are computed once per batch and reused.

    Args:
        stark_info: AIR specification with opening points and ev_map configuration
        committer: Stage orchestrator with NTT-based evaluation methods
        trace: Stage 1 trace buffer (committed polynomials on base domain)
        aux_trace: Auxiliary trace buffer (stages 2+, quotient on extended domain)
        const_pols_extended: Constant polynomials on extended domain
        xi: FRI challenge point (extension field element as 3 ints)

    Returns:
        evals: Polynomial evaluations at opening points (n_evals * 3 field elements, interleaved)
            Each evaluation is an FF3 element corresponding to an EvMap entry

    Notes:
        Batch size of 4 matches C++ implementation for consistency.
        Each batch shares Lagrange evaluations L_j(xi^offset) to reduce computation.
    """
    from primitives.field import FIELD_EXTENSION_DEGREE

    # Allocate evaluations buffer
    # stark_info.ev_map: List[EvMap] defining which polynomials to evaluate and at what offsets
    n_evals = len(stark_info.ev_map)
    evals = np.zeros(n_evals * FIELD_EXTENSION_DEGREE, dtype=np.uint64)

    batch_size = 4
    for i in range(0, len(stark_info.opening_points), batch_size):
        batch = stark_info.opening_points[i : i + batch_size]
        # Compute Lagrange basis evaluations L_j(xi^offset) for this batch of offsets
        # These are shared across all polynomials evaluated at the same offset
        lagrange_evaluations = committer.computeLEv(xi, batch)
        # Evaluate all polynomials in ev_map that use offsets in this batch
        # Results written directly into evals array at appropriate indices
        committer.computeEvals(
            trace, aux_trace, const_pols_extended, evals, lagrange_evaluations, batch
        )

    return evals


# --- Query Proof Collection ---


def _collect_const_query_proofs(
    committer: PolynomialCommitter, query_indices: list[int]
) -> list[QueryProof]:
    """Collect Merkle query proofs for constant polynomials.

    Args:
        committer: Stage orchestrator with const_tree (if AIR has constants)
        query_indices: FRI-selected random indices to prove

    Returns:
        List of QueryProof objects (one per query index), empty if no constants.
        Each QueryProof contains: evaluation values and Merkle authentication path.
    """
    if committer.const_tree is None:
        return []
    return [committer.get_const_query_proof(idx, elem_size=1) for idx in query_indices]


def _collect_stage_query_proofs(
    committer: PolynomialCommitter, stark_info: StarkInfo, query_indices: list[int]
) -> dict[StageNum, list[QueryProof]]:
    """Collect Merkle query proofs for all polynomial commitment stages.

    Args:
        committer: Stage orchestrator with stage_trees dict
        stark_info: AIR specification (n_stages determines which stages exist)
        query_indices: FRI-selected random indices to prove

    Returns:
        Dict mapping stage number -> list of QueryProof objects.
        Stages: 1 (witness), 2 (intermediate), Q (quotient) = n_stages + 1.
        Each QueryProof contains: polynomial evaluations and Merkle authentication path.
    """
    result: dict[StageNum, list[QueryProof]] = {}
    for stage in range(1, stark_info.n_stages + 2):
        if stage in committer.stage_trees:
            tree = committer.stage_trees[stage]
            result[stage] = [tree.get_query_proof(idx, elem_size=1) for idx in query_indices]
    return result


def _collect_last_level_nodes(
    committer: PolynomialCommitter, stark_info: StarkInfo, fri_pcs: FriPcs
) -> dict[str, list[int]]:
    """Collect last-level Merkle nodes for all trees if verification is enabled.

    When last_level_verification > 0, this optimization sends the bottom k levels
    of each Merkle tree instead of individual authentication paths, reducing proof size.

    Args:
        committer: Stage orchestrator with const_tree and stage_trees
        stark_info: AIR specification with last_level_verification setting
        fri_pcs: FRI protocol instance with fri_trees from recursive folding

    Returns:
        Dict mapping tree name -> list of hash values for bottom k levels.
        Tree names: 'const', 'cm1', 'cm2', 'cmQ', 'fri0', 'fri1', ...
        Empty dict if last_level_verification == 0.
    """
    result: dict[str, list[int]] = {}

    # Collect constant polynomial tree nodes
    if committer.const_tree is not None:
        nodes = committer.const_tree.get_last_level_nodes()
        if nodes:
            result["const"] = nodes

    # Collect stage commitment tree nodes (stages 1, 2, Q)
    for stage in range(1, stark_info.n_stages + 2):
        if stage in committer.stage_trees:
            nodes = committer.stage_trees[stage].get_last_level_nodes()
            if nodes:
                result[f"cm{stage}"] = nodes

    # Collect FRI folding round tree nodes (all rounds except final)
    for step_idx in range(len(stark_info.stark_struct.fri_fold_steps) - 1):
        if step_idx < len(fri_pcs.fri_trees):
            nodes = fri_pcs.fri_trees[step_idx].get_last_level_nodes()
            if nodes:
                result[f"fri{step_idx}"] = nodes

    return result
