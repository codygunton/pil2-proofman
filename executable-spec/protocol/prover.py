"""Top-level STARK proof generation."""


from typing import TYPE_CHECKING

import numpy as np
from poseidon2_ffi import linear_hash

from primitives.field import FF3, FIELD_EXTENSION_DEGREE, ff3_from_interleaved_numpy
from primitives.merkle_tree import HASH_SIZE, QueryProof
from primitives.transcript import Transcript
from protocol.air_config import AirConfig, ProverHelpers
from protocol.pcs import FriPcs, FriPcsConfig
from protocol.stages import Starks, calculate_witness_with_module
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

def _get_air_values_stage1(stark_info: StarkInfo, air_values: np.ndarray | None) -> list[int]:
    """Extract stage 1 air_values for global_challenge computation.

    C++ reference: proofman.rs:3472-3540 (get_contribution_air)
    Only stage 1 air_values go into global_challenge hash.
    For simple AIRs, this returns an empty list.
    """
    result = []
    if hasattr(stark_info, 'air_values_map') and stark_info.air_values_map and air_values is not None:
        for i, av in enumerate(stark_info.air_values_map):
            if av.stage == 1:
                # Stage 1 air_values are single field elements
                result.append(int(air_values[i]))
    return result


def _get_proof_values_stage1(stark_info: StarkInfo) -> list[int]:
    """Extract stage 1 proof_values for global_challenge computation.

    C++ reference: challenge_accumulation.rs:96-99
    Stage 1 proof values are included if not empty.
    For simple AIRs, this returns an empty list.
    """
    result = []
    # proofValuesMap is typically empty for simple AIRs
    # When populated, extract stage 1 values
    if hasattr(stark_info, 'proofValuesMap') and stark_info.proofValuesMap:
        for pv in stark_info.proofValuesMap:
            if pv.get('stage') == 1:
                # Would extract from proof_values
                pass
    return result


def derive_challenges_for_stage(
    transcript: Transcript,
    challenges_map: list["ChallengeMap"],
    stage: int
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
    for cm in challenges_map:
        if cm.stage == stage:
            challenge = transcript.get_field()  # Returns [c0, c1, c2]
            # Convert to FF3 (galois expects descending order)
            result[cm.name] = FF3.Vector([challenge[2], challenge[1], challenge[0]])
    return result


def challenges_dict_to_array(
    challenges_dict: ChallengesDict,
    challenges_map: list["ChallengeMap"]
) -> np.ndarray:
    """Convert a challenges dict to interleaved numpy array.

    Args:
        challenges_dict: Dict mapping name -> FF3
        challenges_map: Challenge metadata for ordering

    Returns:
        Numpy array in interleaved format [c0, c1, c2, ...]
    """
    from primitives.field import ff3_coeffs
    n_challenges = len(challenges_map)
    result = np.zeros(n_challenges * FIELD_EXTENSION_DEGREE, dtype=np.uint64)
    for i, cm in enumerate(challenges_map):
        if cm.name in challenges_dict:
            coeffs = ff3_coeffs(challenges_dict[cm.name])
            result[i * 3:(i + 1) * 3] = coeffs
    return result


# --- Main Entry Point ---

def gen_proof(
    air_config: AirConfig,
    trace: np.ndarray,
    const_pols: np.ndarray,
    const_pols_extended: np.ndarray,
    public_inputs: np.ndarray | None = None,
    skip_challenge_derivation: bool = False,
    global_challenge: list[int] | None = None,
    compute_global_challenge: bool = True,
    injected_challenges: np.ndarray | None = None,
) -> dict:
    """Generate complete STARK proof.

    Args:
        air_config: AIR configuration with stark_info and global_info
        trace: Stage 1 witness trace buffer (N * cm1_cols)
        const_pols: Constant polynomials on base domain
        const_pols_extended: Constant polynomials on extended domain
        public_inputs: Public inputs array (optional)
        skip_challenge_derivation: Skip challenge derivation (testing)
        global_challenge: Pre-computed global challenge for VADCOP mode.
            If provided (3 field elements), uses directly (external VADCOP).
            If None, computed internally or uses non-VADCOP mode.
        compute_global_challenge: When global_challenge is None:
            If True: Compute via lattice expansion (VADCOP internal)
            If False: Use simpler verkey+publics+root1 seeding (non-VADCOP)
        injected_challenges: Pre-populated challenge array (testing only)

    Returns:
        Dictionary containing serialized proof.

    Notes:
        - External VADCOP: Uses externally-provided global_challenge
        - Internal VADCOP: Computes global_challenge via 368-element lattice expansion
        - Non-VADCOP: Seeds transcript with verkey + publics + root1 directly
        - For byte-identical proofs with C++ proofman, use internal or external VADCOP
    """
    stark_info = air_config.stark_info

    # === INITIALIZATION ===

    # Allocate auxiliary trace buffer (stages 2+, quotient, FRI polynomial)
    aux_trace = np.zeros(stark_info.map_total_n, dtype=np.uint64)

    # Allocate value arrays
    n_airgroup_values = len(stark_info.airgroup_values_map)
    airgroup_values = np.zeros(n_airgroup_values * FIELD_EXTENSION_DEGREE, dtype=np.uint64)
    air_values = np.zeros(stark_info.air_values_size, dtype=np.uint64)

    # Allocate evaluations array
    n_evals = len(stark_info.ev_map)
    evals = np.zeros(n_evals * FIELD_EXTENSION_DEGREE, dtype=np.uint64)

    # Master challenges array (populated as we go)
    n_challenges = len(stark_info.challenges_map)
    challenges = np.zeros(n_challenges * FIELD_EXTENSION_DEGREE, dtype=np.uint64)
    if injected_challenges is not None:
        challenges[:len(injected_challenges)] = injected_challenges

    # ProverHelpers contains precomputed tables
    prover_helpers = ProverHelpers.from_stark_info(stark_info, pil1=False)

    # Starks orchestrates polynomial commitment via Merkle trees
    starks = Starks(air_config)

    # Initialize Fiat-Shamir transcript
    transcript = Transcript(
        arity=stark_info.stark_struct.transcript_arity,
        custom=stark_info.stark_struct.merkle_tree_custom
    )

    # === STAGE 0: Initialize Constant Polynomials and Transcript ===

    verkey = None
    if const_pols_extended is not None and len(const_pols_extended) > 0:
        verkey = starks.build_const_tree(const_pols_extended)
    else:
        verkey = [0] * HASH_SIZE

    # === STAGE 1: Witness Commitment ===

    computed_roots: list[MerkleRoot] = []
    root1 = starks.commitStage(1, trace, aux_trace)
    computed_roots.append(list(root1))

    # === STAGE 0: Seed Fiat-Shamir Transcript ===

    if global_challenge is not None:
        transcript.put(global_challenge[:3])
    elif compute_global_challenge:
        lattice_size = DEFAULT_LATTICE_SIZE
        if air_config.global_info is not None:
            lattice_size = air_config.global_info.lattice_size

        air_values_stage1 = _get_air_values_stage1(stark_info, air_values)
        proof_values_stage1 = _get_proof_values_stage1(stark_info)

        computed_challenge = derive_global_challenge(
            stark_info=stark_info,
            publics=public_inputs,
            root1=list(root1),
            verkey=verkey,
            air_values=air_values_stage1,
            proof_values_stage1=proof_values_stage1,
            lattice_size=lattice_size
        )

        transcript.put(computed_challenge[:3])
    else:
        transcript.put(verkey)
        if stark_info.n_publics > 0 and public_inputs is not None:
            if stark_info.stark_struct.hash_commits:
                publics_transcript = Transcript(
                    arity=stark_info.stark_struct.transcript_arity,
                    custom=stark_info.stark_struct.merkle_tree_custom
                )
                publics_transcript.put(public_inputs[:stark_info.n_publics].tolist())
                transcript.put(publics_transcript.get_state(4))
            else:
                transcript.put(public_inputs[:stark_info.n_publics].tolist())
        transcript.put(list(root1))

    # === STAGE 2: Intermediate Polynomials ===

    # Derive stage 2 challenges
    stage2_challenges: ChallengesDict = {}
    if not skip_challenge_derivation:
        stage2_challenges = derive_challenges_for_stage(
            transcript, stark_info.challenges_map, stage=2
        )
        # Store in master array for downstream use
        for i, cm in enumerate(stark_info.challenges_map):
            if cm.name in stage2_challenges:
                from primitives.field import ff3_coeffs
                coeffs = ff3_coeffs(stage2_challenges[cm.name])
                challenges[i * 3:(i + 1) * 3] = coeffs
    else:
        # Extract from injected challenges
        for i, cm in enumerate(stark_info.challenges_map):
            if cm.stage == 2:
                c0 = int(challenges[i * 3])
                c1 = int(challenges[i * 3 + 1])
                c2 = int(challenges[i * 3 + 2])
                stage2_challenges[cm.name] = FF3.Vector([c2, c1, c0])

    # Calculate witness polynomials (im_cluster, gsum)
    calculate_witness_with_module(
        stark_info, trace, aux_trace, const_pols,
        stage2_challenges, airgroup_values
    )

    # Commit stage 2
    root2 = starks.commitStage(2, trace, aux_trace)
    computed_roots.append(list(root2))
    transcript.put(root2)

    # === STAGE Q: Quotient Polynomial ===

    q_stage = stark_info.n_stages + 1

    # Derive stage Q challenges
    stageQ_challenges: ChallengesDict = {}
    if not skip_challenge_derivation:
        stageQ_challenges = derive_challenges_for_stage(
            transcript, stark_info.challenges_map, stage=q_stage
        )
        for i, cm in enumerate(stark_info.challenges_map):
            if cm.name in stageQ_challenges:
                from primitives.field import ff3_coeffs
                coeffs = ff3_coeffs(stageQ_challenges[cm.name])
                challenges[i * 3:(i + 1) * 3] = coeffs
    else:
        for i, cm in enumerate(stark_info.challenges_map):
            if cm.stage == q_stage:
                c0 = int(challenges[i * 3])
                c1 = int(challenges[i * 3 + 1])
                c2 = int(challenges[i * 3 + 2])
                stageQ_challenges[cm.name] = FF3.Vector([c2, c1, c0])

    # Merge all challenges so far
    all_challenges = {**stage2_challenges, **stageQ_challenges}

    # Calculate quotient polynomial
    starks.calculateQuotientPolynomial(
        trace, aux_trace, const_pols_extended, all_challenges, prover_helpers, airgroup_values
    )

    # Commit quotient stage
    rootQ = starks.commitStage(q_stage, trace, aux_trace)
    computed_roots.append(list(rootQ))
    transcript.put(rootQ)

    # === STAGE EVALS: Polynomial Evaluations ===

    # Derive evaluation stage challenges (xi)
    xi: FF3 | None = None
    eval_stage = stark_info.n_stages + 2
    if not skip_challenge_derivation:
        eval_challenges = derive_challenges_for_stage(
            transcript, stark_info.challenges_map, stage=eval_stage
        )
        for i, cm in enumerate(stark_info.challenges_map):
            if cm.name in eval_challenges:
                from primitives.field import ff3_coeffs
                coeffs = ff3_coeffs(eval_challenges[cm.name])
                challenges[i * 3:(i + 1) * 3] = coeffs
                if cm.stage_id == 0:
                    xi = eval_challenges[cm.name]
        all_challenges.update(eval_challenges)
    else:
        for i, cm in enumerate(stark_info.challenges_map):
            if cm.stage == eval_stage:
                c0 = int(challenges[i * 3])
                c1 = int(challenges[i * 3 + 1])
                c2 = int(challenges[i * 3 + 2])
                ch = FF3.Vector([c2, c1, c0])
                all_challenges[cm.name] = ch
                if cm.stage_id == 0:
                    xi = ch

    # Get xi as list of coefficients for evaluation
    from primitives.field import ff3_coeffs
    xi_coeffs = ff3_coeffs(xi)

    # Compute all polynomial evaluations
    _compute_all_evals(stark_info, starks, trace, aux_trace, const_pols_extended, evals, xi_coeffs)

    # Feed evaluations into transcript
    if not stark_info.stark_struct.hash_commits:
        transcript.put(evals[:n_evals * FIELD_EXTENSION_DEGREE])
    else:
        evals_as_ints = [int(v) for v in evals[:n_evals * FIELD_EXTENSION_DEGREE]]
        evals_hash = list(linear_hash(evals_as_ints, width=POSEIDON2_LINEAR_HASH_WIDTH))
        transcript.put(evals_hash)

    # === STAGE FRI ===

    # Derive FRI challenges (vf1, vf2)
    fri_stage = stark_info.n_stages + 3
    if not skip_challenge_derivation:
        fri_challenges = derive_challenges_for_stage(
            transcript, stark_info.challenges_map, stage=fri_stage
        )
        for i, cm in enumerate(stark_info.challenges_map):
            if cm.name in fri_challenges:
                coeffs = ff3_coeffs(fri_challenges[cm.name])
                challenges[i * 3:(i + 1) * 3] = coeffs
        all_challenges.update(fri_challenges)
    else:
        for i, cm in enumerate(stark_info.challenges_map):
            if cm.stage == fri_stage:
                c0 = int(challenges[i * 3])
                c1 = int(challenges[i * 3 + 1])
                c2 = int(challenges[i * 3 + 2])
                all_challenges[cm.name] = FF3.Vector([c2, c1, c0])

    # Get vf1, vf2 from all_challenges
    vf1 = all_challenges['std_vf1']
    vf2 = all_challenges['std_vf2']

    # Calculate FRI polynomial
    starks.calculateFRIPolynomial(
        trace, aux_trace, const_pols_extended, evals, xi, vf1, vf2, prover_helpers
    )

    # Extract FRI polynomial from buffer
    fri_pol_offset = stark_info.map_offsets[("f", True)]
    n_fri_elements = 1 << stark_info.stark_struct.fri_fold_steps[0].domain_bits
    fri_pol_size = n_fri_elements * FIELD_EXTENSION_DEGREE
    fri_pol_numpy = aux_trace[fri_pol_offset:fri_pol_offset + fri_pol_size]
    fri_pol = ff3_from_interleaved_numpy(fri_pol_numpy, n_fri_elements)

    # Configure and run FRI
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

    query_indices = fri_proof.query_indices
    const_query_proofs = _collect_const_query_proofs(starks, query_indices)
    stage_query_proofs = _collect_stage_query_proofs(starks, stark_info, query_indices)
    last_level_nodes = _collect_last_level_nodes(starks, stark_info, fri_pcs)

    # === ASSEMBLE PROOF ===

    return {
        'evals': [int(v) for v in evals[:n_evals * FIELD_EXTENSION_DEGREE]],
        'airgroup_values': airgroup_values,
        'air_values': air_values,
        'nonce': fri_proof.nonce,
        'fri_proof': fri_proof,
        'roots': computed_roots,
        'stage_query_proofs': stage_query_proofs,
        'const_query_proofs': const_query_proofs,
        'query_indices': query_indices,
        'last_level_nodes': last_level_nodes,
    }


# --- Polynomial Evaluations ---

def _compute_all_evals(
    stark_info: StarkInfo,
    starks: Starks,
    trace: np.ndarray,
    aux_trace: np.ndarray,
    const_pols_extended: np.ndarray,
    evals: np.ndarray,
    xi: list[int]
) -> None:
    """Compute polynomial evaluations at all opening points in batches of 4.

    Args:
        stark_info: AIR specification with opening points configuration
        starks: Stage orchestrator with evaluation methods
        trace: Stage 1 trace buffer
        aux_trace: Auxiliary trace buffer
        const_pols_extended: Extended constant polynomials
        evals: Output array for evaluations
        xi: FRI challenge point (extension field element as 3 ints)
    """
    batch_size = 4
    for i in range(0, len(stark_info.opening_points), batch_size):
        batch = stark_info.opening_points[i:i + batch_size]
        lagrange_evaluations = starks.computeLEv(xi, batch)
        starks.computeEvals(trace, aux_trace, const_pols_extended, evals, lagrange_evaluations, batch)


# --- Query Proof Collection ---

def _collect_const_query_proofs(starks: Starks,
                                query_indices: list[int]) -> list[QueryProof]:
    """Collect Merkle query proofs for constant polynomials."""
    if starks.const_tree is None:
        return []
    return [starks.get_const_query_proof(idx, elem_size=1) for idx in query_indices]


def _collect_stage_query_proofs(starks: Starks, stark_info: StarkInfo,
                                query_indices: list[int]) -> dict[StageNum, list[QueryProof]]:
    """Collect Merkle query proofs for all polynomial commitment stages."""
    result: dict[StageNum, list[QueryProof]] = {}
    for stage in range(1, stark_info.n_stages + 2):
        if stage in starks.stage_trees:
            tree = starks.stage_trees[stage]
            result[stage] = [tree.get_query_proof(idx, elem_size=1) for idx in query_indices]
    return result


def _collect_last_level_nodes(starks: Starks, stark_info: StarkInfo,
                              fri_pcs: FriPcs) -> dict[str, list[int]]:
    """Collect last-level Merkle nodes for all trees if verification is enabled."""
    result: dict[str, list[int]] = {}

    if starks.const_tree is not None:
        nodes = starks.const_tree.get_last_level_nodes()
        if nodes:
            result['const'] = nodes

    for stage in range(1, stark_info.n_stages + 2):
        if stage in starks.stage_trees:
            nodes = starks.stage_trees[stage].get_last_level_nodes()
            if nodes:
                result[f'cm{stage}'] = nodes

    for step_idx in range(len(stark_info.stark_struct.fri_fold_steps) - 1):
        if step_idx < len(fri_pcs.fri_trees):
            nodes = fri_pcs.fri_trees[step_idx].get_last_level_nodes()
            if nodes:
                result[f'fri{step_idx}'] = nodes

    return result
