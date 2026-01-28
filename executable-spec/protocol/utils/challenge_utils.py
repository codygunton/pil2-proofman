"""Utilities for computing global_challenge following C++ pattern.

The global_challenge is derived from publics and proof values using Fiat-Shamir,
matching the C++ implementation in proofman/src/challenge_accumulation.rs

The computation has three steps:
1. Hash [verkey, root1, air_values] through transcript to get 16-element state
2. Expand to latticeSize elements via Poseidon2 hash chain
3. Hash [publics, proof_values_stage1, expanded_contribution] to get challenge
"""

import numpy as np
from typing import Optional, List

from poseidon2_ffi import poseidon2_hash
from primitives.transcript import Transcript


def calculate_internal_contribution(
    stark_info,
    verkey: List[int],
    root1: List[int],
    air_values: Optional[List[int]] = None,
    lattice_size: int = 368
) -> List[int]:
    """Compute internal contribution by hashing verkey + root1 + air_values.

    This matches C++ calculate_internal_contributions() in challenge_accumulation.rs.

    The C++ algorithm:
    1. Hash [verkey, root1, air_values] through transcript
    2. Get 16-element state
    3. Expand to lattice_size via Poseidon2 hash chain

    Args:
        stark_info: STARK configuration with transcript parameters
        verkey: 4-element verification key (constant polynomial tree root)
        root1: 4-element Stage 1 Merkle root (witness commitment)
        air_values: Optional air-specific values (empty for simple AIR)
        lattice_size: Size of contribution (from globalInfo.latticeSize)

    Returns:
        List of lattice_size field elements representing the expanded contribution.

    C++ reference (challenge_accumulation.rs lines 46-72):
        values_to_hash = [verkey[0..4], root1[0..4], air_values...]
        hash = Transcript::new()
        hash.put(values_to_hash)
        contribution = hash.get_state()

        // Expand to lattice_size via hash chain
        values_row[0..16] = contribution[0..16]
        n_hashes = lattice_size / 16 - 1
        for j in 0..n_hashes:
            values_row[(j+1)*16..(j+2)*16] = poseidon2_hash(values_row[j*16..(j+1)*16])
    """
    # Build the values to hash: [verkey, root1, air_values]
    values_to_hash = list(verkey) + list(root1)
    if air_values:
        values_to_hash.extend(air_values)

    # Hash through a fresh Poseidon2 transcript
    hash_transcript = Transcript(
        arity=stark_info.starkStruct.transcriptArity,
        custom=stark_info.starkStruct.merkleTreeCustom
    )
    hash_transcript.put(values_to_hash)

    # Get transcript state (16 elements)
    initial_state = hash_transcript.get_state(16)

    # Expand to lattice_size via Poseidon2 hash chain
    # This matches C++ CurveType::None case in calculate_internal_contributions()
    values_row = [0] * lattice_size

    # Copy initial 16 elements
    for i in range(16):
        values_row[i] = initial_state[i]

    # Chain hash to expand
    n_hashes = lattice_size // 16 - 1
    for j in range(n_hashes):
        # Take input from current block
        input_block = values_row[j * 16:(j + 1) * 16]
        # Hash and put into next block
        output_block = poseidon2_hash(input_block, 16)
        values_row[(j + 1) * 16:(j + 2) * 16] = output_block[:16]

    return values_row


def derive_global_challenge(
    stark_info,
    publics: np.ndarray,
    root1: List[int],
    verkey: List[int],
    air_values: Optional[List[int]] = None,
    proof_values_stage1: Optional[List[int]] = None,
    lattice_size: int = 368
) -> List[int]:
    """Derive global_challenge from publics and proof values.

    Implements C++ pattern from challenge_accumulation.rs (lines 84-111).

    Three-step process:
    1. Compute internal contribution = hash([verkey, root1, air_values])
    2. Expand contribution to lattice_size via Poseidon2 chain
    3. Hash [publics, proof_values_stage1, expanded_contribution] and extract challenge

    Args:
        stark_info: STARK configuration with transcript parameters
        publics: Public input array (from params.publicInputs)
        root1: Stage 1 Merkle root (from witness commitment)
        verkey: Verification key from constant polynomial tree
        air_values: Optional air-specific values (default: empty)
        proof_values_stage1: Optional Stage 1 proof values (default: empty)
        lattice_size: Size of contribution (from globalInfo.latticeSize)

    Returns:
        List of 3 field elements [c0, c1, c2] representing cubic extension challenge

    C++ reference (challenge_accumulation.rs):
        transcript = Transcript::new()
        transcript.put(publics)
        transcript.put(proof_values_stage1)  // if not empty
        contribution = calculate_internal_contributions(verkey, root1, air_values)
        transcript.put(contribution)  // all lattice_size elements!
        global_challenge = transcript.get_field()  // 3 elements
    """
    # Step 1: Compute expanded internal contribution
    contribution = calculate_internal_contribution(
        stark_info, verkey, root1, air_values, lattice_size
    )

    # Step 2: Create global_challenge transcript
    transcript = Transcript(
        arity=stark_info.starkStruct.transcriptArity,
        custom=stark_info.starkStruct.merkleTreeCustom
    )

    # Phase 1: Hash public inputs
    if stark_info.nPublics > 0:
        transcript.put(publics[:stark_info.nPublics].tolist())

    # Phase 2: Hash Stage 1 proof values (if any)
    # For simple AIRs this is typically empty
    if proof_values_stage1:
        transcript.put(proof_values_stage1)

    # Phase 3: Hash the full expanded contribution (all lattice_size elements!)
    transcript.put(contribution)

    # Phase 4: Extract 3 field elements
    global_challenge = transcript.get_field()

    return global_challenge
