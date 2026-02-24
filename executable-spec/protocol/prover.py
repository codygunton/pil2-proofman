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


def _get_proof_values_stage1(stark_info: StarkInfo) -> list[int]:
    """Extract stage 1 proof_values for global_challenge computation.

    C++ reference: challenge_accumulation.rs:96-99
    Stage 1 proof values are included if not empty.
    For simple AIRs, this returns an empty list.
    """
    result = []
    # proofValuesMap is typically empty for simple AIRs
    # When populated, extract stage 1 values
    if hasattr(stark_info, "proofValuesMap") and stark_info.proofValuesMap:
        for pv in stark_info.proofValuesMap:
            if pv.get("stage") == 1:
                # Would extract from proof_values
                pass
    return result


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
    for cm in challenges_map:
        if cm.stage == stage:
            challenge = transcript.get_field()  # Returns [c0, c1, c2]
            # Convert to FF3 (galois expects descending order)
            result[cm.name] = FF3.Vector([challenge[2], challenge[1], challenge[0]])
    return result


def challenges_dict_to_array(
    challenges_dict: ChallengesDict, challenges_map: list["ChallengeMap"]
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
            result[i * 3 : (i + 1) * 3] = coeffs
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
    # DOCTASK: say what this does
    stark_info = air_config.stark_info

    # === INITIALIZATION ===

    # Allocate shared mutable buffers used across multiple stages

    # Master challenges array: Accumulated stage-by-stage via Fiat-Shamir
    # stark_info.challenges_map: List[ChallengeMap] defining challenge names and stages
    # Each challenge is an FF3 element (3 field elements)
    n_challenges = len(stark_info.challenges_map)
    challenges = np.zeros(n_challenges * FIELD_EXTENSION_DEGREE, dtype=np.uint64)
    # QUESTION: are these injected challenges needed or are they just diagnostic?
    if injected_challenges is not None:
        challenges[: len(injected_challenges)] = injected_challenges

    # ProverHelpers contains precomputed tables for constraint evaluation
    # Includes: L1(x) roots, zerofier roots, NTT twiddle factors
    prover_helpers = ProverHelpers.from_stark_info(stark_info, pil1=False)

    # Starks orchestrates polynomial commitment via Merkle trees
    # Manages: constant tree, stage trees (1, 2, Q), and FRI trees
    starks = Starks(air_config)

    # Initialize Fiat-Shamir transcript (Poseidon2-based)
    # Converts commitments into verifier challenges deterministically
    transcript = Transcript(
        arity=stark_info.stark_struct.transcript_arity,
        custom=stark_info.stark_struct.merkle_tree_custom,
    )

    # === STAGE 0: Initialize Constant Polynomials and Transcript ===

    # Build Merkle tree over constant polynomials (immutable AIR parameters)
    # verkey = Merkle root (4 field elements) serving as verification key
    # Used in non-VADCOP mode to seed transcript
    verkey = None
    # QUESTION: why do we need this task?
    if const_pols_extended is not None and len(const_pols_extended) > 0:
        verkey = starks.build_const_tree(const_pols_extended)
    else:
        verkey = [0] * HASH_SIZE

    # === STAGE 1: Witness Commitment ===

    # Commit stage 1 witness trace via Merkle tree
    # Input: trace buffer (N * n_cm1_cols, already populated by caller)
    # Output: root1 = Merkle root (4 field elements)

    # Auxiliary trace buffer: Written by stages 2, Q, and FRI at different offsets
    # stark_info.map_total_n = total size in field elements for all auxiliary polynomials
    # Computed from: stage offsets + quotient (q_dim * N_extended) + FRI poly (3 * N_extended)
    aux_trace = np.zeros(stark_info.map_total_n, dtype=np.uint64)

    # <doc-anchor id="witness-commit">
    computed_roots: list[MerkleRoot] = []
    root1 = starks.commitStage(1, trace, aux_trace)
    computed_roots.append(list(root1))

    # === STAGE 0: Seed Fiat-Shamir Transcript ===
    # Three modes for transcript initialization:
    # QUESTION: which of these modes do we actually use? Which do we actually need?
    # 1. External VADCOP: Use externally-provided global_challenge
    # 2. Internal VADCOP: Compute global_challenge via lattice expansion
    # 3. Standalone: Seed with verkey + publics + root1 directly

    # Mode 1: External VADCOP (global_challenge provided by coordinator)
    # <doc-anchor id="transcript-seed-vadcop">
    if global_challenge is not None:
        # Allocate air_values (may be populated externally or empty)
        air_values = np.zeros(stark_info.air_values_size, dtype=np.uint64)
        transcript.put(global_challenge[:3])

    # Mode 2: Internal VADCOP (compute global_challenge ourselves)
    elif compute_global_challenge:
        # Lattice expansion: Hash (verkey, publics, root1, air_values, proof_values)
        # into a 368-element challenge vector (default lattice_size)
        # This binds all per-AIR stage-1 contributions to a shared global challenge
        lattice_size = DEFAULT_LATTICE_SIZE
        if air_config.global_info is not None:
            lattice_size = air_config.global_info.lattice_size

        # Allocate per-AIR instance values for global challenge computation
        # stark_info.air_values_size: Total field elements (sum of air_values_map dimensions)
        # Most AIRs have empty air_values_map, resulting in zero-sized array
        air_values = np.zeros(stark_info.air_values_size, dtype=np.uint64)

        # Extract stage-1 values for lattice (most AIRs: empty lists)
        air_values_stage1 = _get_air_values_stage1(stark_info, air_values)
        proof_values_stage1 = _get_proof_values_stage1(stark_info)

        # Derive global challenge via repeated Poseidon2 hashing
        computed_challenge = derive_global_challenge(
            stark_info=stark_info,
            publics=public_inputs,
            root1=list(root1),
            verkey=verkey,
            air_values=air_values_stage1,
            proof_values_stage1=proof_values_stage1,
            lattice_size=lattice_size,
        )

        transcript.put(computed_challenge[:3])

    # Mode 3: Standalone (no VADCOP aggregation)
    else:
        # Allocate air_values (may be empty but needed for proof assembly)
        air_values = np.zeros(stark_info.air_values_size, dtype=np.uint64)

        # Seed transcript directly with verification key, public inputs, and stage-1 root
        # No lattice expansion - simpler but incompatible with C++ VADCOP proofs
        # <doc-anchor id="transcript-seed-standalone">
        transcript.put(verkey)
        if stark_info.n_publics > 0 and public_inputs is not None:
            if stark_info.stark_struct.hash_commits:
                # Hash public inputs first if AIR requires it
                publics_transcript = Transcript(
                    arity=stark_info.stark_struct.transcript_arity,
                    custom=stark_info.stark_struct.merkle_tree_custom,
                )
                publics_transcript.put(public_inputs[: stark_info.n_publics].tolist())
                transcript.put(publics_transcript.get_state(4))
            else:
                transcript.put(public_inputs[: stark_info.n_publics].tolist())
        transcript.put(list(root1))

    # === STAGE 2: Intermediate Polynomials ===
    # Generate witness polynomials that depend on stage-1 randomness
    # Examples: im_cluster (lookup multiplicity), gsum (bus accumulator)

    # <doc-anchor id="derive-stage2-challenges">
    # Derive stage 2 challenges from transcript (Fiat-Shamir)
    # Transcript state = hash of all prior commitments (verkey, root1)
    stage2_challenges: ChallengesDict = {}
    if not skip_challenge_derivation:
        stage2_challenges = derive_challenges_for_stage(
            transcript, stark_info.challenges_map, stage=2
        )
        # Store in master challenges array for downstream use
        for i, cm in enumerate(stark_info.challenges_map):
            if cm.name in stage2_challenges:
                from primitives.field import ff3_coeffs

                coeffs = ff3_coeffs(stage2_challenges[cm.name])
                challenges[i * 3 : (i + 1) * 3] = coeffs
    else:
        # Testing mode: extract from pre-injected challenges
        for i, cm in enumerate(stark_info.challenges_map):
            if cm.stage == 2:
                c0 = int(challenges[i * 3])
                c1 = int(challenges[i * 3 + 1])
                c2 = int(challenges[i * 3 + 2])
                stage2_challenges[cm.name] = FF3.Vector([c2, c1, c0])

    # Calculate AIR-specific witness polynomials using stage-2 challenges
    # Dispatches to witness module for AIR (SimpleLeft, Lookup2_12, etc.)
    # Writes: im_cluster, gsum columns into aux_trace buffer
    # Returns: airgroup_values (cross-AIR boundary values for VADCOP)
    airgroup_values = calculate_witness_with_module(
        stark_info, trace, aux_trace, const_pols, stage2_challenges
    )

    # <doc-anchor id="intermediate-commit">
    # Commit stage 2 witness polynomials via Merkle tree
    # Input: aux_trace buffer (stage-2 columns now populated)
    # Output: root2 = Merkle root (4 field elements)
    root2 = starks.commitStage(2, trace, aux_trace)
    computed_roots.append(list(root2))
    transcript.put(root2)

    # === STAGE Q: Quotient Polynomial ===
    # Prove that all AIR constraints are satisfied by computing Q(x) = C(x) / Z_H(x)
    # where C(x) = constraint polynomial, Z_H(x) = zerofier vanishing on trace domain

    # Stage number for quotient (always n_stages + 1)
    q_stage = stark_info.n_stages + 1

    # <doc-anchor id="derive-stageq-challenges">
    # Derive stage Q challenges (random linear combination coefficients)
    # Used to combine multiple constraint polynomials into single quotient
    # Transcript state = hash of (verkey, root1, root2)
    stageQ_challenges: ChallengesDict = {}
    if not skip_challenge_derivation:
        stageQ_challenges = derive_challenges_for_stage(
            transcript, stark_info.challenges_map, stage=q_stage
        )
        for i, cm in enumerate(stark_info.challenges_map):
            if cm.name in stageQ_challenges:
                from primitives.field import ff3_coeffs

                coeffs = ff3_coeffs(stageQ_challenges[cm.name])
                challenges[i * 3 : (i + 1) * 3] = coeffs
    else:
        # Testing mode: extract from pre-injected challenges
        for i, cm in enumerate(stark_info.challenges_map):
            if cm.stage == q_stage:
                c0 = int(challenges[i * 3])
                c1 = int(challenges[i * 3 + 1])
                c2 = int(challenges[i * 3 + 2])
                stageQ_challenges[cm.name] = FF3.Vector([c2, c1, c0])

    # Merge all challenges accumulated so far (stage 2 + stage Q)
    all_challenges = {**stage2_challenges, **stageQ_challenges}

    # Calculate quotient polynomial Q(x) over extended domain
    # Evaluates constraint polynomial C(x) via ConstraintModule
    # Divides by zerofier Z_H(x) to get Q(x) with degree < N_extended
    # Writes result into aux_trace buffer at quotient section offset
    starks.calculateQuotientPolynomial(
        trace, aux_trace, const_pols_extended, all_challenges, prover_helpers, airgroup_values
    )

    # <doc-anchor id="quotient-commit">
    # Commit quotient polynomial via Merkle tree
    # Input: aux_trace buffer (quotient section now populated)
    # Output: rootQ = Merkle root (4 field elements)
    rootQ = starks.commitStage(q_stage, trace, aux_trace)
    computed_roots.append(list(rootQ))
    transcript.put(rootQ)

    # === STAGE EVALS: Polynomial Evaluations ===
    # Evaluate all polynomials at random challenge point xi and its shifted variants
    # Used by verifier to check polynomial identities without downloading full polynomials

    # <doc-anchor id="derive-eval-challenges">
    # Derive evaluation point xi from transcript
    # Transcript state = hash of (verkey, root1, root2, rootQ)
    # xi is the primary evaluation challenge (stage_id == 0)
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
                challenges[i * 3 : (i + 1) * 3] = coeffs
                if cm.stage_id == 0:
                    xi = eval_challenges[cm.name]
        all_challenges.update(eval_challenges)
    else:
        # Testing mode: extract from pre-injected challenges
        for i, cm in enumerate(stark_info.challenges_map):
            if cm.stage == eval_stage:
                c0 = int(challenges[i * 3])
                c1 = int(challenges[i * 3 + 1])
                c2 = int(challenges[i * 3 + 2])
                ch = FF3.Vector([c2, c1, c0])
                all_challenges[cm.name] = ch
                if cm.stage_id == 0:
                    xi = ch

    # Convert xi to list of coefficients for polynomial evaluation functions
    from primitives.field import ff3_coeffs

    xi_coeffs = ff3_coeffs(xi)

    # Compute all polynomial evaluations at points defined by ev_map
    # For each EvMap entry: evaluates polynomial(type, id) at xi^row_offset
    # Examples: cm1[0](xi), cm2[3](xi*omega), const[1](xi*omega^2)
    # Returns: evals array (n_evals * 3 field elements, interleaved)
    evals = _compute_all_evals(stark_info, starks, trace, aux_trace, const_pols_extended, xi_coeffs)

    # Feed evaluations into transcript for next round
    if not stark_info.stark_struct.hash_commits:
        # Direct mode: put all evaluation elements
        transcript.put(evals)
    else:
        # Hashed mode: compress evaluations with Poseidon2 linear hash
        evals_as_ints = [int(v) for v in evals]
        evals_hash = list(linear_hash(evals_as_ints, width=POSEIDON2_LINEAR_HASH_WIDTH))
        transcript.put(evals_hash)

    # === STAGE FRI ===
    # FRI (Fast Reed-Solomon Interactive Oracle Proof) proves low-degree of quotient polynomial
    # Recursively commits to folded polynomials until reaching constant-size final polynomial

    # Derive FRI folding challenges (vf1, vf2) from transcript
    # Transcript state = hash of (verkey, root1, root2, rootQ, evals)
    # vf1, vf2 are used for random linear combination in FRI polynomial construction
    fri_stage = stark_info.n_stages + 3
    if not skip_challenge_derivation:
        fri_challenges = derive_challenges_for_stage(
            transcript, stark_info.challenges_map, stage=fri_stage
        )
        for i, cm in enumerate(stark_info.challenges_map):
            if cm.name in fri_challenges:
                coeffs = ff3_coeffs(fri_challenges[cm.name])
                challenges[i * 3 : (i + 1) * 3] = coeffs
        all_challenges.update(fri_challenges)
    else:
        # Testing mode: extract from pre-injected challenges
        for i, cm in enumerate(stark_info.challenges_map):
            if cm.stage == fri_stage:
                c0 = int(challenges[i * 3])
                c1 = int(challenges[i * 3 + 1])
                c2 = int(challenges[i * 3 + 2])
                all_challenges[cm.name] = FF3.Vector([c2, c1, c0])

    # Extract standard FRI challenges by name
    # vf1: First folding coefficient (combines polynomial with shifted evaluations)
    # vf2: Second folding coefficient (for boundary constraint)
    vf1 = all_challenges["std_vf1"]
    vf2 = all_challenges["std_vf2"]

    # Calculate FRI polynomial f(x) as random linear combination
    # f(x) = vf1 * Q(x) + vf2 * boundary_terms(x) + evaluation_terms(x)
    # This polynomial proves that Q has the claimed evaluations and low degree
    # Result written into aux_trace buffer at FRI section offset
    starks.calculateFRIPolynomial(
        trace, aux_trace, const_pols_extended, evals, xi, vf1, vf2, prover_helpers
    )

    # Extract FRI polynomial from auxiliary buffer for commitment
    # map_offsets[("f", True)] = byte offset of FRI polynomial in aux_trace
    # n_fri_elements = 2^n_bits_ext (size of extended domain)
    fri_pol_offset = stark_info.map_offsets[("f", True)]
    n_fri_elements = 1 << stark_info.stark_struct.fri_fold_steps[0].domain_bits
    fri_pol_size = n_fri_elements * FIELD_EXTENSION_DEGREE
    fri_pol_numpy = aux_trace[fri_pol_offset : fri_pol_offset + fri_pol_size]
    fri_pol = ff3_from_interleaved_numpy(fri_pol_numpy, n_fri_elements)

    # Configure FRI protocol parameters
    # fri_fold_steps: List of domain sizes for each folding round (decreasing by factor of 2-4)
    # n_queries: Number of random evaluation points to check (security parameter)
    # last_level_verification: Merkle tree optimization level
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

    # Run FRI protocol: recursive folding + query proof generation
    # Outputs: FRI commitments, query indices, final polynomial, nonce
    fri_pcs = FriPcs(fri_config)
    fri_proof = fri_pcs.prove(fri_pol, transcript)

    # === STAGE QUERY PROOFS ===
    # Collect Merkle authentication paths for all queried polynomial evaluations
    # Verifier will check these paths to ensure evaluations are consistent with committed polynomials

    # <doc-anchor id="collect-query-proofs">
    # FRI protocol selected random query indices (typically 27 for 100-bit security)
    # These indices determine which polynomial evaluations to reveal
    query_indices = fri_proof.query_indices

    # Collect Merkle proofs for constant polynomials at each query index
    # Empty if no constant polynomials exist
    const_query_proofs = _collect_const_query_proofs(starks, query_indices)

    # Collect Merkle proofs for all committed polynomial stages (1, 2, Q)
    # Each stage has its own Merkle tree; verifier checks root matches committed value
    stage_query_proofs = _collect_stage_query_proofs(starks, stark_info, query_indices)

    # Collect last-level Merkle nodes if last_level_verification > 0
    # Optimization: send bottom k levels of Merkle tree to reduce proof size
    last_level_nodes = _collect_last_level_nodes(starks, stark_info, fri_pcs)

    # === ASSEMBLE PROOF ===

    return {
        "evals": [int(v) for v in evals],
        "airgroup_values": airgroup_values,
        "air_values": air_values,
        "nonce": fri_proof.nonce,
        "fri_proof": fri_proof,
        "roots": computed_roots,
        "stage_query_proofs": stage_query_proofs,
        "const_query_proofs": const_query_proofs,
        "query_indices": query_indices,
        "last_level_nodes": last_level_nodes,
    }


# --- Polynomial Evaluations ---


def _compute_all_evals(
    stark_info: StarkInfo,
    starks: Starks,
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
        starks: Stage orchestrator with NTT-based evaluation methods
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
        lagrange_evaluations = starks.computeLEv(xi, batch)
        # Evaluate all polynomials in ev_map that use offsets in this batch
        # Results written directly into evals array at appropriate indices
        starks.computeEvals(
            trace, aux_trace, const_pols_extended, evals, lagrange_evaluations, batch
        )

    return evals


# --- Query Proof Collection ---


def _collect_const_query_proofs(starks: Starks, query_indices: list[int]) -> list[QueryProof]:
    """Collect Merkle query proofs for constant polynomials.

    Args:
        starks: Stage orchestrator with const_tree (if AIR has constants)
        query_indices: FRI-selected random indices to prove

    Returns:
        List of QueryProof objects (one per query index), empty if no constants.
        Each QueryProof contains: evaluation values and Merkle authentication path.
    """
    if starks.const_tree is None:
        return []
    return [starks.get_const_query_proof(idx, elem_size=1) for idx in query_indices]


def _collect_stage_query_proofs(
    starks: Starks, stark_info: StarkInfo, query_indices: list[int]
) -> dict[StageNum, list[QueryProof]]:
    """Collect Merkle query proofs for all polynomial commitment stages.

    Args:
        starks: Stage orchestrator with stage_trees dict
        stark_info: AIR specification (n_stages determines which stages exist)
        query_indices: FRI-selected random indices to prove

    Returns:
        Dict mapping stage number -> list of QueryProof objects.
        Stages: 1 (witness), 2 (intermediate), Q (quotient) = n_stages + 1.
        Each QueryProof contains: polynomial evaluations and Merkle authentication path.
    """
    result: dict[StageNum, list[QueryProof]] = {}
    for stage in range(1, stark_info.n_stages + 2):
        if stage in starks.stage_trees:
            tree = starks.stage_trees[stage]
            result[stage] = [tree.get_query_proof(idx, elem_size=1) for idx in query_indices]
    return result


def _collect_last_level_nodes(
    starks: Starks, stark_info: StarkInfo, fri_pcs: FriPcs
) -> dict[str, list[int]]:
    """Collect last-level Merkle nodes for all trees if verification is enabled.

    When last_level_verification > 0, this optimization sends the bottom k levels
    of each Merkle tree instead of individual authentication paths, reducing proof size.

    Args:
        starks: Stage orchestrator with const_tree and stage_trees
        stark_info: AIR specification with last_level_verification setting
        fri_pcs: FRI protocol instance with fri_trees from recursive folding

    Returns:
        Dict mapping tree name -> list of hash values for bottom k levels.
        Tree names: 'const', 'cm1', 'cm2', 'cmQ', 'fri0', 'fri1', ...
        Empty dict if last_level_verification == 0.
    """
    result: dict[str, list[int]] = {}

    # Collect constant polynomial tree nodes
    if starks.const_tree is not None:
        nodes = starks.const_tree.get_last_level_nodes()
        if nodes:
            result["const"] = nodes

    # Collect stage commitment tree nodes (stages 1, 2, Q)
    for stage in range(1, stark_info.n_stages + 2):
        if stage in starks.stage_trees:
            nodes = starks.stage_trees[stage].get_last_level_nodes()
            if nodes:
                result[f"cm{stage}"] = nodes

    # Collect FRI folding round tree nodes (all rounds except final)
    for step_idx in range(len(stark_info.stark_struct.fri_fold_steps) - 1):
        if step_idx < len(fri_pcs.fri_trees):
            nodes = fri_pcs.fri_trees[step_idx].get_last_level_nodes()
            if nodes:
                result[f"fri{step_idx}"] = nodes

    return result
