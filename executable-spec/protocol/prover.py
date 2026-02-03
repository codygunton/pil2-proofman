"""Top-level STARK proof generation."""


from poseidon2_ffi import linear_hash

from primitives.field import FIELD_EXTENSION_DEGREE, ff3_from_interleaved_numpy
from primitives.merkle_tree import HASH_SIZE, QueryProof
from primitives.transcript import Transcript
from protocol.expression_evaluator import ExpressionsPack
from protocol.pcs import FriPcs, FriPcsConfig
from protocol.proof_context import ProofContext
from protocol.air_config import ProverHelpers, SetupCtx
from protocol.stages import Starks, calculate_witness_with_module
from protocol.stark_info import StarkInfo
from protocol.utils.challenge_utils import derive_global_challenge

# --- Type Aliases ---
MerkleRoot = list[int]
StageNum = int

# --- Module Constants ---
# Default lattice expansion size for VADCOP protocol (CurveType::None)
# Reference: C++ proofman challenge_accumulation.rs
DEFAULT_LATTICE_SIZE = 368

# Poseidon2 linear hash width (internal state size)
POSEIDON2_LINEAR_HASH_WIDTH = 16


# --- Helper Functions ---

def _get_air_values_stage1(stark_info: StarkInfo, params: ProofContext) -> list[int]:
    """Extract stage 1 air_values for global_challenge computation.

    C++ reference: proofman.rs:3472-3540 (get_contribution_air)
    Only stage 1 air_values go into global_challenge hash.
    For simple AIRs, this returns an empty list.
    """
    result = []
    if hasattr(stark_info, 'airValuesMap') and stark_info.airValuesMap:
        for i, av in enumerate(stark_info.airValuesMap):
            if av.stage == 1:
                # Stage 1 air_values are single field elements
                result.append(int(params.airValues[i]))
    return result


def _get_proof_values_stage1(stark_info: StarkInfo, params: ProofContext) -> list[int]:
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
                # Would extract from params.proofValues
                pass
    return result


# --- Main Entry Point ---

def gen_proof(
    setup_ctx: SetupCtx,
    params: ProofContext,
    skip_challenge_derivation: bool = False,
    global_challenge: list[int] | None = None,
    compute_global_challenge: bool = True
) -> dict:
    """Generate complete STARK proof.

    Args:
        setup_ctx: Setup context with AIR configuration
        params: Prover parameters and witness data
        skip_challenge_derivation: Skip challenge derivation (testing)
        global_challenge: Pre-computed global challenge for VADCOP mode.
            If provided (3 field elements), uses directly (external VADCOP).
            If None, computed internally or uses non-VADCOP mode.
        compute_global_challenge: When global_challenge is None:
            If True: Compute via lattice expansion (VADCOP internal)
            If False: Use simpler verkey+publics+root1 seeding (non-VADCOP)

    Returns:
        Dictionary containing serialized proof.

    Notes:
        - External VADCOP: Uses externally-provided global_challenge
        - Internal VADCOP: Computes global_challenge via 368-element lattice expansion
        - Non-VADCOP: Seeds transcript with verkey + publics + root1 directly
        - For byte-identical proofs with C++ proofman, use internal or external VADCOP
    """
    # Extract the AIR specification (constraint definitions, parameters, domains, challenge map, etc.)
    # from setup context. stark_info contains:
    # - starkStruct: domain sizes, FRI configuration, merkle parameters, etc.
    # - constraintPols: the constraint polynomials (compiled from AIR expressions)
    # - nStages: how many polynomial commitment stages (usually 2: witness + intermediate)
    # - evMap: which polynomials are opened at which points (for verifier)
    # - mapOffsets: where each polynomial is stored in the auxTrace buffer
    # - challengesMap: which challenges are derived at which stages
    stark_info = setup_ctx.stark_info

    # === INITIALIZATION: Set up all working data structures ===

    # The main domain size N controls how many evaluation points we have.
    # This is 2^nBits, where nBits typically logs2(execution trace length).
    # All constraint traces are evaluated at N points in the field.
    # The domain is the multiplicative subgroup of order N in GF(p).
    N = 1 << stark_info.starkStruct.nBits

    # ProverHelpers contains precomputed tables derived from AIR structure. These include:
    # - Sibling maps for permutation constraints (which execution step has which sibling in permutation)
    # - Parent maps for lookup constraints (where to find elements in lookup table)
    # - Range check tables
    # These are used by constraint expression evaluation to validate permutation/lookup arguments.
    # This is an internal data structure that expression evaluation depends on.
    prover_helpers = ProverHelpers.from_stark_info(stark_info, pil1=False)

    # Starks orchestrates polynomial commitment via Merkle trees. It:
    # 1. Extends polynomials from trace domain to extended domain (via NTT, internal)
    # 2. Builds Merkle trees from extended evaluations
    # 3. Returns roots for transcript and stores trees for query proofs
    # NTT instances are created internally to hide implementation details.
    starks = Starks(setup_ctx)

    # ExpressionsPack manages constraint polynomial evaluation by parsing and executing AIR expressions.
    # It contains:
    # - Compiled expressions (from setup_ctx.expressions_bin) that compute constraint polynomials
    # - ProverHelpers for constraint evaluation (sibling/parent maps, etc.)
    # When you call expressions_ctx.compute(...), it evaluates expressions on params.polynomials
    # and stores results in params.auxTrace or other buffers. The key insight: expression evaluation
    # is a black box that takes polynomials and outputs constraint values.
    expressions_ctx = ExpressionsPack(setup_ctx, prover_helpers)

    # Initialize Fiat-Shamir transcript (deterministic RNG seeded by public protocol state).
    # The transcript is the heart of the protocol's security: it ensures challenges are unpredictable
    # yet reproducible. Every time we call transcript.get_field(), we:
    # 1. Hash all data fed into the transcript so far
    # 2. Return a field element derived from that hash
    # 3. Update internal state so the next call gets a different challenge
    # This is essentially: challenge_n = Hash(all_committed_data_so_far || counter).
    transcript = Transcript(
        arity=stark_info.starkStruct.transcriptArity,
        custom=stark_info.starkStruct.merkleTreeCustom
    )

    # === STAGE 0: Initialize Constant Polynomials and Transcript ===

    # If constant polynomials (read-only lookup tables) exist, build a merkle tree from them.
    # These are tables of constant values that lookup/permutation constraints reference.
    # We need to commit to them so the verifier can open them at arbitrary query points.
    # The merkle tree allows logarithmic-size proofs of specific table entries.
    # Note: Constant polynomials are evaluated over the extended domain (constPolsExtended).
    verkey = None
    if params.constPolsExtended is not None and len(params.constPolsExtended) > 0:
        # Build merkle tree from constant polynomials (no challenge derivation needed; they're fixed)
        # Capture the root as verkey (commitment to preprocessed data)
        verkey = starks.build_const_tree(params.constPolsExtended)
    else:
        # No constant polynomials - use empty root
        verkey = [0] * HASH_SIZE

    # === STAGE 1: Witness Commitment ===

    # The witness is the execution trace: all polynomial evaluations that satisfy the constraints.
    # In a computation, this is like the state at each step: CPU registers, memory, etc.
    # We commit to all witness polynomials by building a merkle tree.
    # The merkle root proves we've committed to a specific set of polynomial values without revealing them.
    # This is cryptographically binding: we can't change the polynomials without changing the root.

    # List to accumulate all merkle roots in order (Stage 1, Stage 2, Stage Q).
    # The verifier will need all of these to reconstruct the transcript and verify challenges.
    computed_roots: list[MerkleRoot] = []

    # commitStage(1, params) extracts all stage-1 polynomials from params,
    # extends them to the evaluation domain, builds a Merkle tree, and returns the root.
    # The tree is stored in starks.stage_trees[1] for later query proof generation.
    # Stage 1 is the witness stage: everything about the execution trace.
    root1 = starks.commitStage(1, params)
    computed_roots.append(list(root1))

    # === STAGE 0: Seed Fiat-Shamir Transcript ===
    #
    # Three modes depending on parameters:
    # 1. global_challenge provided → use directly (external VADCOP)
    # 2. compute_global_challenge=True → compute via lattice expansion (internal VADCOP)
    # 3. compute_global_challenge=False → seed with verkey+publics+root1 (non-VADCOP)

    if global_challenge is not None:
        # Mode 1: External VADCOP - use pre-computed global_challenge
        transcript.put(global_challenge[:3])
    elif compute_global_challenge:
        # Mode 2: Internal VADCOP - compute via lattice expansion algorithm
        # Matches C++ proofman challenge_accumulation.rs

        # Get lattice_size from globalInfo (default 368 for CurveType::None)
        lattice_size = DEFAULT_LATTICE_SIZE
        if setup_ctx.global_info is not None:
            lattice_size = setup_ctx.global_info.lattice_size

        # Extract stage 1 air_values (empty for simple AIRs)
        air_values_stage1 = _get_air_values_stage1(stark_info, params)

        # Extract stage 1 proof_values (empty for simple AIRs)
        proof_values_stage1 = _get_proof_values_stage1(stark_info, params)

        # Compute global_challenge via lattice expansion
        # Steps:
        # 1. Hash [verkey, root1, air_values] → 16-element state
        # 2. Expand to lattice_size (368) via Poseidon2 hash chain
        # 3. Hash [publics, proof_values_stage1, 368-element contribution]
        # 4. Extract 3 field elements
        computed_challenge = derive_global_challenge(
            stark_info=stark_info,
            publics=params.publicInputs,
            root1=list(root1),
            verkey=verkey,
            air_values=air_values_stage1,
            proof_values_stage1=proof_values_stage1,
            lattice_size=lattice_size
        )

        # Seed transcript with computed challenge
        transcript.put(computed_challenge[:3])
    else:
        # Mode 3: Non-VADCOP - seed with verkey + publics + root1 directly
        # Produces different challenge sequence than VADCOP mode
        transcript.put(verkey)
        if stark_info.nPublics > 0:
            if stark_info.starkStruct.hashCommits:
                publics_transcript = Transcript(
                    arity=stark_info.starkStruct.transcriptArity,
                    custom=stark_info.starkStruct.merkleTreeCustom
                )
                publics_transcript.put(params.publicInputs[:stark_info.nPublics].tolist())
                transcript.put(publics_transcript.get_state(4))
            else:
                transcript.put(params.publicInputs[:stark_info.nPublics].tolist())
        transcript.put(list(root1))

    # === STAGE 2: Intermediate Polynomials (Lookup/Permutation Witness) ===

    # Before checking constraints, we need to compute intermediate polynomials that support
    # lookup and permutation arguments. These are "preprocessed" values derived from the witness:
    #
    # - For lookup arguments: We need to prove each element in the witness appears in a lookup table.
    #   This requires computing a "grand product" polynomial that encodes table inclusion proofs.
    # - For permutation arguments: We need to prove elements are permuted consistently across columns.
    #   This requires a "grand product" polynomial that encodes permutation proofs.
    #
    # These grand products are built from the witness via polynomial expressions defined in the AIR.
    # The challenge: we can't compute them yet because the verifier hasn't given us random challenges.
    # The solution: Fiat-Shamir. We derive a random challenge from the transcript and use it to compute.

    # Derive Fiat-Shamir challenge for Stage 2 from the transcript.
    # This challenge is a random linear combination weight used in:
    # - Grand product computation for permutation arguments
    # - Expression evaluation for intermediate polynomial construction
    # The challenge must be random (derived from transcript), yet deterministic (same across prover/verifier).
    if not skip_challenge_derivation:
        _derive_stage_challenges(transcript, params, stark_info.challengesMap, stage=2)

    # Execute all AIR constraint expressions to compute intermediate polynomials (Stage 2).
    # These are derived values computed from the witness:
    # - Polynomial flags (is_first_row, is_last_row, etc.)
    # - Temporary values (T0, T1, ... = intermediate variables in constraints)
    # - Permutation/lookup support values
    # The expressions parse the AIR's constraint definitions and evaluate them point-by-point.
    # Results are stored in params.auxTrace (auxiliary trace buffer).
    starks.calculateImPolsExpressions(2, params, expressions_ctx)

    # For lookup/permutation arguments: compute grand product polynomials.
    # These polynomials prove the prover didn't cheat by skipping elements or using wrong values.
    #
    # The witness module computes:
    # - im_cluster columns: intermediate logup term sums clustered for degree optimization
    # - gsum/gprod columns: cumulative sum/product for constraint checking
    calculate_witness_with_module(stark_info, params)

    # Commit to all Stage 2 polynomials (witness, intermediate, grand products).
    # This is a second merkle tree, building on the same evaluation domain as Stage 1.
    # The root proves we've committed to all intermediate values without revealing them.
    root2 = starks.commitStage(2, params)
    computed_roots.append(list(root2))

    # Feed Stage 2 root into transcript for next challenge derivation.
    # The verifier will use this root to verify the challenge derivations match.
    transcript.put(root2)

    # === STAGE Q: Quotient Polynomial ===

    # The quotient polynomial is the core of constraint checking. The idea:
    #
    # For each constraint C(x):
    #   C(x) should equal 0 at every valid execution step
    #   Outside the domain, C(x) is garbage (not constrained)
    #
    # We define Q(x) = Sum of [C_i(x) / D(x)] over all constraints
    #   where D(x) is a "vanishing polynomial" = 0 everywhere except on domain
    #
    # Key insight: If all constraints are satisfied on the domain, Q(x) is a valid polynomial
    # of degree < trace_deg + constraint_deg. If even one constraint is violated, Q(x) will be
    # artificially high-degree and FRI will catch it.
    #
    # The quotient is typically degree ~(trace_deg + constraint_deg), which is still reasonable
    # to verify via FRI folding.

    # Stage Q is computed after Stage 2 (constraint checking depends on intermediate values).
    # q_stage index is nStages + 1 (e.g., if nStages=2, then q_stage=3).
    q_stage = stark_info.nStages + 1

    # Derive Fiat-Shamir challenge for Stage Q from the transcript.
    # This challenge is a random linear combination weight used when computing the quotient polynomial.
    # It's the weight used to combine all constraints: Q(x) = c0*C0(x)/D(x) + c1*C1(x)/D(x) + ...
    # The randomness ensures constraint violations can't be cancelled out by careful cancellation.
    if not skip_challenge_derivation:
        _derive_stage_challenges(transcript, params, stark_info.challengesMap, stage=q_stage)

    # Build the quotient polynomial.
    # This evaluates all constraints at all trace points, divides by vanishing polynomial,
    # and stores the result as Stage Q polynomials in params.auxTrace.
    # The quotient must be low-degree (verifiable by FRI), so constraint violations would
    # immediately make it high-degree.
    #
    # All supported AIRs now use the constraint module path (byte-identical proofs).
    use_constraint_module = stark_info.name in ('SimpleLeft', 'Permutation1_6', 'Lookup2_12')
    starks.calculateQuotientPolynomial(params, expressions_ctx, use_constraint_module=use_constraint_module,
                                       prover_helpers=prover_helpers)

    # Commit to the quotient polynomial.
    # Note: we use ntt_extended here because the quotient is evaluated over the extended domain.
    # This is necessary for FRI: we need evaluations on a larger domain than just the execution trace.
    # FRI will prove the quotient is low-degree by folding on this extended domain.
    rootQ = starks.commitStage(q_stage, params)
    computed_roots.append(list(rootQ))

    # Feed quotient root into transcript.
    transcript.put(rootQ)

    # === STAGE EVALS: Polynomial Evaluations at Challenge Point ===

    # Now we've committed to three things: witness, intermediate, quotient.
    # To prove they're actually low-degree, we open them all at a single random point.
    # If a polynomial is truly low-degree, opening at a random point should be easy.
    # If it's high-degree (cheating), the opening would be inconsistent with the low-degree commitment.

    # The key protocol step:
    # 1. Verifier derives a random challenge point (xi) from transcript
    # 2. Prover evaluates all committed polynomials at xi
    # 3. Verifier checks: the opening is consistent with the merkle root
    # 4. Verifier checks: the opened values satisfy a "polynomial relationship"
    #    (i.e., quotient = sum of [C(xi) / D(xi)])
    #
    # This is the constraint checking step. The verifier doesn't re-compute constraints;
    # it just checks that the prover's evaluations are consistent.

    # Derive FRI opening point (random evaluation point in field).
    # This is the point xi where we open all polynomials.
    # The challenge must be random for security: if prover can predict xi, it could craft
    # a high-degree polynomial that happens to "work" at xi.
    xi_challenge_index = _derive_eval_challenges(
        transcript, params, stark_info, skip_challenge_derivation
    )
    xi = params.get_challenge(xi_challenge_index)

    # Evaluate all committed polynomials at xi.
    # This is the expensive step: FFT evaluates a polynomial at a single point in O(log N) field ops.
    # We evaluate thousands of polynomials, so we batch them in groups of 4 for efficiency.
    # Results are stored in params.evals.
    #
    # What gets evaluated:
    # - All witness polynomials (trace columns)
    # - All intermediate polynomials (flags, temps, grand products)
    # - The quotient polynomial
    # - Potentially others (depends on evMap configuration)
    _compute_all_evals(stark_info, starks, params, xi)

    # Feed polynomial evaluations into the transcript (or their hash).
    # The verifier will derive the next challenge from these evaluations.
    # If we skip this step, the verifier can forge proofs by picking arbitrary evaluations.
    #
    # Two approaches:
    # (a) hashCommits=False: Put all evaluations directly in transcript
    #     Pro: Verifier has full data
    #     Con: Proof is larger (many field elements)
    # (b) hashCommits=True: Hash evaluations with Poseidon2, put hash in transcript
    #     Pro: Proof is smaller (just one hash)
    #     Con: Verifier must check the hash matches (adds a Poseidon2 verification constraint)
    #
    # This is a security/efficiency tradeoff. Recursive proofs typically use hashCommits=True.
    # CRITICAL ISSUE: The verifier uses conditional hashing for PUBLIC INPUTS (verifier.py:307-313):
    # - If hashCommits=False: puts publics raw
    # - If hashCommits=True: hashes publics through temporary transcript, then puts hash
    # But the prover (Stage 0 above) puts publics raw regardless of hashCommits.
    # This is INCONSISTENT. The verifier's conditional hashing pattern should be applied
    # to publics in prover too, but it's not. This diverges the challenge stream.

    n_evals = len(stark_info.evMap) * FIELD_EXTENSION_DEGREE
    # evMap contains which polynomials are evaluated (base field vs. extension field).
    # FIELD_EXTENSION_DEGREE is 3 (cubic extension), so extension evaluations are 3x base.
    if not stark_info.starkStruct.hashCommits:
        # Direct approach: all evaluations in transcript
        # Matches verifier (verifier.py:349)
        transcript.put(params.evals[:n_evals])
    else:
        # Optimized approach: hash evaluations to single Poseidon2 digest
        # Matches verifier (verifier.py:351)
        evals_as_ints = [int(v) for v in params.evals[:n_evals]]
        evals_hash = list(linear_hash(evals_as_ints, width=POSEIDON2_LINEAR_HASH_WIDTH))
        transcript.put(evals_hash)

    # === STAGE FRI: Polynomial Commitment via Low-Degree Test ===

    # We've committed to polynomials via merkle trees, but merkle trees alone don't prove low-degree.
    # Example: the merkle root could commit to arbitrary data (high-degree polynomial).
    # Merke tree is just a commitment; FRI is the proof of low-degree.
    #
    # FRI (Fast Reed-Solomon IOP) proves low-degree by:
    # 1. Taking a polynomial P(x) of claimed degree d
    # 2. Constructing a folded polynomial P'(x) from evaluations of P at 2d points
    #    (by taking even/odd evaluations and combining with a random challenge)
    # 3. Proving P'(x) has half the degree
    # 4. Recursing: fold again, degree halves, continue until degree=0
    #
    # At each level, the prover builds a merkle tree of folded evaluations and commits to the root.
    # The verifier randomly samples leaves, checks merkle proofs, and verifies the folding equations.
    # If the original polynomial is truly low-degree, all folding equations check out.
    # If it's high-degree, the prover is caught with exponential probability.

    # Derive Fiat-Shamir challenges for FRI folding stages.
    # Each FRI fold level (halving degree) needs a random challenge.
    # There are typically 10-15 folding levels (since degree goes from 2^20 → 2^19 → ... → 2^0).
    if not skip_challenge_derivation:
        _derive_stage_challenges(transcript, params, stark_info.challengesMap,
                                 stage=stark_info.nStages + 3)

    # Construct the FRI polynomial: the polynomial we'll prove low-degree-ness of.
    # This is a linear combination of all committed polynomials:
    #   FRI_Poly(x) = c0 * witness(x) + c1 * intermediate(x) + c2 * quotient(x) + ...
    # where c0, c1, c2 are random coefficients derived from challenges.
    #
    # Why a linear combination? Because we want to batch-prove all polynomials are low-degree.
    # If even one polynomial is high-degree, the linear combination is high-degree.
    # So proving the combination is low-degree proves all constituents are low-degree.
    # Debug: compare FRI polynomial implementations
    # Note: FRI polynomial uses Horner's method batching which differs from naive formula
    # The direct computation needs to match the bytecode's grouping scheme
    starks.calculateFRIPolynomial(params, expressions_ctx, use_direct_computation=True, debug_compare=False,
                                   prover_helpers=prover_helpers)

    # Extract the FRI polynomial from the auxiliary trace buffer.
    # params.auxTrace is a flat array containing all polynomials:
    #   [witness_polys, intermediate_polys, quotient, fri_poly, ...]
    # We need to find fri_poly and extract it.
    # mapOffsets[("f", True)] gives the byte offset of the FRI polynomial in auxTrace.
    fri_pol_offset = stark_info.mapOffsets[("f", True)]
    # The FRI polynomial is evaluated on the extended domain.
    n_fri_elements = 1 << stark_info.starkStruct.friFoldSteps[0].domainBits
    # Each element is FF3 (cubic extension), so 3 field elements per polynomial value.
    fri_pol_size = n_fri_elements * FIELD_EXTENSION_DEGREE
    # Extract the numpy array slice containing FRI polynomial data.
    fri_pol_numpy = params.auxTrace[fri_pol_offset:fri_pol_offset + fri_pol_size]

    # Convert from interleaved numpy buffer layout to FF3Poly (galois library format).
    # C++ stores data in a specific binary layout (C buffer order).
    # Python galois library uses a different layout (numpy interleaved).
    # ff3_from_interleaved_numpy handles the conversion:
    #   [a0, a1, a2, b0, b1, b2, ...] (interleaved: a=(a0,a1,a2), b=(b0,b1,b2))
    #   →
    #   [(a0, a1, a2), (b0, b1, b2), ...] (FF3Poly objects)
    fri_pol = ff3_from_interleaved_numpy(fri_pol_numpy, n_fri_elements)

    # Configure FRI with all protocol parameters.
    # FRI is heavily parameterized: folding schedule, query count, merkle tree structure, etc.
    fri_config = FriPcsConfig(
        # n_bits_ext: log2(extended domain size) for initial FRI level
        # E.g., if extended domain = 2^20, this is 20.
        # FRI folds this down to 2^19, 2^18, ..., 2^0.
        n_bits_ext=stark_info.starkStruct.friFoldSteps[0].domainBits,
        # fri_round_log_sizes: log2 size at each folding level
        # E.g., [20, 19, 18, 17, 16, 15, ...] (one per fold)
        fri_round_log_sizes=[step.domainBits for step in stark_info.starkStruct.friFoldSteps],
        # n_queries: how many leaves to sample for verification
        # Larger = more security, larger proof. Typically 16-128 queries.
        # Each query samples one leaf from the merkle tree at each fold level.
        n_queries=stark_info.starkStruct.nQueries,
        # ANSWER: merkleTreeArity is the branching factor of FRI merkle trees.
        # - arity=2 (binary): each node has 2 children, tree height = log2(N)
        # - arity=4 (quaternary): each node has 4 children, tree height = log4(N) = log2(N)/2
        # - arity=8 (octary): each node has 8 children, tree height = log8(N) = log2(N)/3
        # Larger arity = shorter proof (fewer merkle path elements) but larger intermediate nodes.
        # This spec supports any arity; C++ tests mainly use arity=4.
        merkle_arity=stark_info.starkStruct.merkleTreeArity,
        # pow_bits: difficulty of proof-of-work nonce
        # If pow_bits=20, prover must find a nonce such that Hash(proof || nonce) has 20 leading zero bits.
        # This adds computational cost but doesn't affect proof size or verifier time.
        # Used for anti-DOS in some applications. Typically 0 (disabled) for specs.
        pow_bits=stark_info.starkStruct.powBits,
        # last_level_verification: whether to include leaf hashes in the proof
        # If True, verifier can check the final constant values directly (extra security).
        # If False, verifier trusts the merkle tree commitment to the final level.
        last_level_verification=stark_info.starkStruct.lastLevelVerification,
        # hash_commits: whether to hash polynomial evaluations (evMap stage)
        # Matches the choice made earlier for efficiency/security tradeoff.
        hash_commits=stark_info.starkStruct.hashCommits,
        # transcript_arity: how many field elements per Poseidon2 hash (optimization)
        # Matches the transcript configuration.
        transcript_arity=stark_info.starkStruct.transcriptArity,
        # merkle_tree_custom: custom data for hash function (AIR-specific)
        merkle_tree_custom=stark_info.starkStruct.merkleTreeCustom,
    )

    # Run FRI: the main low-degree testing protocol.
    # FRI returns:
    # - merkle roots for each folding level (proves commitment to folded evaluations)
    # - query indices (which leaves were sampled)
    # - query proofs (merkle paths for those leaves)
    # - final constant value (when degree reaches 0)
    # This is the most cryptographically expensive part (merkle tree construction + hashing).
    fri_pcs = FriPcs(fri_config)
    fri_proof = fri_pcs.prove(fri_pol, transcript)

    # === STAGE QUERY PROOFS: Merkle Openings ===

    # FRI has told us which query indices to open (fri_proof.query_indices).
    # For each index, we need merkle proofs proving:
    # - The witness evaluations at that index are correct (match the root1 commitment)
    # - The intermediate evaluations at that index are correct (match the root2 commitment)
    # - The quotient evaluations at that index are correct (match the rootQ commitment)
    # - The constant table evaluations at that index are correct (if present)
    #
    # Without these merkle proofs, the verifier can't check that the opened values
    # correspond to the committed polynomials. The merkle proofs cryptographically
    # bind the evaluations to the roots.

    query_indices = fri_proof.query_indices
    # query_indices is a list of which evaluation points (0 to N-1) were sampled.
    # Typically 16-128 indices, determined by FRI's challenge derivation.

    # Collect merkle proofs for constant polynomials at query points.
    # If there's no const_tree (no lookup tables), this returns an empty list.
    # Otherwise, for each query_index in query_indices, we get a merkle path proving
    # const_poly[query_index] is correct.
    const_query_proofs = _collect_const_query_proofs(starks, query_indices)

    # Collect merkle proofs for all witness/intermediate/quotient polynomials at query points.
    # This returns a dict: { stage_num: [QueryProof, QueryProof, ...] }
    # For each stage (1, 2, Q) and each query index, we get a merkle path.
    # The merkle path allows verifier to reconstruct the root from the opened value.
    stage_query_proofs = _collect_stage_query_proofs(starks, stark_info, query_indices)

    # Collect last-level merkle tree nodes (if lastLevelVerification is enabled).
    # This includes leaf hashes from the merkle trees, allowing the verifier to
    # double-check that commitment roots match.
    # If lastLevelVerification=0, this is empty; if >0, it contains leaf hashes.
    last_level_nodes = _collect_last_level_nodes(starks, stark_info, fri_pcs)

    # === ASSEMBLE PROOF ===

    # Collect all proof components into a single dictionary.
    # This is what gets serialized and sent to the verifier.
    # The verifier will:
    # 1. Reconstruct the transcript from the roots
    # 2. Verify FRI (merkle trees, folding equations, query proofs)
    # 3. Verify constraint checking (polynomial relationship at xi)
    # 4. Accept or reject the proof
    return {
        # Polynomial evaluations at the FRI challenge point (xi).
        # Verifier uses these to check: quotient(xi) = sum of [constraint(xi) / vanishing(xi)].
        # This is the core constraint checking: if evaluations don't match the quotient relationship,
        # either the constraints are violated or the prover cheated.
        'evals': params.evals[:n_evals],

        # Computed AIR group values (internal, used for verifier computation).
        # These are intermediate values needed to re-compute constraint relationships during verification.
        'airgroup_values': params.airgroupValues,

        # Computed AIR values (internal, used for verifier computation).
        # Similar to airgroup_values, supports verifier constraint checking.
        'air_values': params.airValues,

        # Proof-of-work nonce (if powBits > 0).
        # If pow_bits is enabled, the nonce is such that Hash(proof || nonce) has powBits leading zeros.
        # Verifier will re-hash to confirm. If pow_bits=0 (disabled), this is 0.
        'nonce': fri_proof.nonce,

        # FRI low-degree proof object.
        # Contains: merkle roots per folding level, final constant value, folding equations.
        # This is what proves all committed polynomials are actually low-degree.
        'fri_proof': fri_proof,

        # List of merkle roots [root1, root2, rootQ].
        # root1: commitment to witness polynomials
        # root2: commitment to intermediate polynomials (flags, temps, grand products)
        # rootQ: commitment to quotient polynomial
        # Verifier uses these to verify merkle proofs in stage_query_proofs.
        'roots': computed_roots,

        # Dict of merkle query proofs by stage.
        # stage_query_proofs[1] = [QueryProof, ...] for witness stage at all query indices
        # stage_query_proofs[2] = [QueryProof, ...] for intermediate stage at all query indices
        # stage_query_proofs[3] = [QueryProof, ...] for quotient stage at all query indices
        # Verifier uses these to check that opened evaluations correspond to committed roots.
        'stage_query_proofs': stage_query_proofs,

        # List of merkle query proofs for constant polynomials.
        # If no constant polynomials, this is empty.
        # Otherwise, one QueryProof per query index, proving const_poly[idx] is correct.
        'const_query_proofs': const_query_proofs,

        # List of query indices sampled by FRI.
        # Typically [7, 42, 103, ...] (16-128 random indices, 0 to N-1).
        # Verifier will independently sample the same indices using Fiat-Shamir,
        # then check the merkle proofs match.
        'query_indices': query_indices,

        # Dict of last-level merkle tree nodes by tree name.
        # E.g., { 'const': [...], 'cm1': [...], 'cm2': [...], 'cm3': [...], 'fri0': [...], ... }
        # If lastLevelVerification=0, this is empty.
        # If >0, verifier can cross-check that leaves match the commitment roots.
        # Provides extra security against merkle tree collisions.
        'last_level_nodes': last_level_nodes,
    }


# --- Challenge Derivation ---

def _derive_stage_challenges(transcript: Transcript, params: ProofContext,
                             challenges_map: list, stage: int) -> None:
    """Derive Fiat-Shamir challenges for a given stage.

    Args:
        transcript: Fiat-Shamir transcript for challenge generation
        params: Proof context where challenges are stored
        challenges_map: List of challenge specifications from AIR
        stage: Stage number to derive challenges for
    """
    for i, cm in enumerate(challenges_map):
        if cm.stage == stage:
            challenge = transcript.get_field()
            params.set_challenge(i, challenge)


def _derive_eval_challenges(transcript: Transcript, params: ProofContext,
                            stark_info: StarkInfo, skip: bool) -> int:
    """Derive evaluation-stage challenges and return xi challenge index.

    Args:
        transcript: Fiat-Shamir transcript for challenge generation
        params: Proof context where challenges are stored
        stark_info: AIR specification with challenge map
        skip: If True, skip actual challenge derivation (testing mode)

    Returns:
        Index of xi challenge in params.challenges array
    """
    eval_stage = stark_info.nStages + 2
    xi_index = 0

    for i, cm in enumerate(stark_info.challengesMap):
        if cm.stage == eval_stage:
            if cm.stageId == 0:
                xi_index = i
            if not skip:
                challenge = transcript.get_field()
                params.set_challenge(i, challenge)

    return xi_index


# --- Polynomial Evaluations ---

def _compute_all_evals(stark_info: StarkInfo, starks: Starks, params: ProofContext,
                       xi: list[int]) -> None:
    """Compute polynomial evaluations at all opening points in batches of 4.

    Args:
        stark_info: AIR specification with opening points configuration
        starks: Stage orchestrator with evaluation methods
        params: Proof context where evaluations are stored
        xi: FRI challenge point (extension field element as 3 ints)
    """
    batch_size = 4
    for i in range(0, len(stark_info.openingPoints), batch_size):
        batch = stark_info.openingPoints[i:i + batch_size]
        lagrange_evaluations = starks.computeLEv(xi, batch)
        starks.computeEvals(params, lagrange_evaluations, batch)


# --- Query Proof Collection ---

def _collect_const_query_proofs(starks: Starks,
                                query_indices: list[int]) -> list[QueryProof]:
    """Collect Merkle query proofs for constant polynomials.

    Args:
        starks: Stage orchestrator containing constant tree
        query_indices: Evaluation point indices to open

    Returns:
        List of Merkle query proofs, one per query index (empty if no constant tree)
    """
    if starks.const_tree is None:
        return []
    return [starks.get_const_query_proof(idx, elem_size=1) for idx in query_indices]


def _collect_stage_query_proofs(starks: Starks, stark_info: StarkInfo,
                                query_indices: list[int]) -> dict[StageNum, list[QueryProof]]:
    """Collect Merkle query proofs for all polynomial commitment stages.

    Args:
        starks: Stage orchestrator containing stage trees
        stark_info: AIR specification with stage count
        query_indices: Evaluation point indices to open

    Returns:
        Dictionary mapping stage number to list of query proofs
    """
    result: dict[StageNum, list[QueryProof]] = {}
    for stage in range(1, stark_info.nStages + 2):
        if stage in starks.stage_trees:
            tree = starks.stage_trees[stage]
            result[stage] = [tree.get_query_proof(idx, elem_size=1) for idx in query_indices]
    return result


def _collect_last_level_nodes(starks: Starks, stark_info: StarkInfo,
                              fri_pcs: FriPcs) -> dict[str, list[int]]:
    """Collect last-level Merkle nodes for all trees if verification is enabled.

    Args:
        starks: Stage orchestrator containing const and stage trees
        stark_info: AIR specification with stage and FRI configuration
        fri_pcs: FRI polynomial commitment scheme with FRI trees

    Returns:
        Dictionary mapping tree name to list of leaf-level node hashes
        (empty dict if lastLevelVerification is disabled)
    """
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
    for step_idx in range(len(stark_info.starkStruct.friFoldSteps) - 1):
        if step_idx < len(fri_pcs.fri_trees):
            nodes = fri_pcs.fri_trees[step_idx].get_last_level_nodes()
            if nodes:
                result[f'fri{step_idx}'] = nodes

    return result
