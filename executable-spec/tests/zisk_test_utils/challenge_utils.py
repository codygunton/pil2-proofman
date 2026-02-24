"""Global VADCOP challenge derivation from per-AIR proofs.

Implements the multi-AIR challenge accumulation algorithm matching C++
challenge_accumulation.rs. Derives a single global challenge from all
per-AIR proof commitments for VADCOP verification.
"""

import json
from pathlib import Path

import numpy as np

from protocol.air_config import AirConfig
from protocol.utils.challenge_utils import (
    calculate_internal_contribution,
    derive_global_challenge_multi_air,
)
from .fixture_loader import (
    load_air_config,
    load_verkey,
    load_publics,
    load_proof_values,
    load_binary_proof,
    get_proving_key_dir,
)


def derive_global_challenge_from_proofs(
    air_names: list[str],
    proof_stems: list[str],
) -> list[int]:
    """Derive global VADCOP challenge from all per-AIR proofs.

    Computes the VADCOP global challenge by:
    1. For each AIR: hash [verkey, root1, stage1_air_values] → 368-element contribution
    2. Accumulate all contributions via element-wise addition (mod Goldilocks)
    3. Hash [publics, proof_values_stage1, accumulated] → 3-element challenge

    This matches C++ challenge_accumulation.rs exactly.

    Args:
        air_names: List of AIR names (e.g., ["Main", "Rom", "Mem", ...])
        proof_stems: List of proof filenames without extension (e.g., ["Main_0", "Rom_1", ...])

    Returns:
        Global challenge as [c0, c1, c2] (3 Goldilocks field elements)

    Raises:
        FileNotFoundError: If any required file is missing
        ValueError: If air_names and proof_stems have different lengths
    """
    if len(air_names) != len(proof_stems):
        raise ValueError(
            f"Mismatched lengths: {len(air_names)} AIR names vs {len(proof_stems)} proof stems"
        )

    # Load global parameters from pilout.globalInfo.json
    pk_dir = get_proving_key_dir()
    global_info_path = pk_dir / "pilout.globalInfo.json"

    if not global_info_path.exists():
        raise FileNotFoundError(f"Global info not found: {global_info_path}")

    with open(global_info_path) as f:
        global_info = json.load(f)

    lattice_size = global_info["latticeSize"]
    transcript_arity = global_info["transcriptArity"]
    n_publics = global_info["nPublics"]
    proof_values_map = global_info.get("proofValuesMap", [])

    # Compute per-AIR contributions
    contributions = []
    for air_name, proof_stem in zip(air_names, proof_stems):
        # Load AIR configuration
        air_config = load_air_config(air_name)
        starkinfo = air_config.stark_info
        verkey = load_verkey(air_name)
        proof = load_binary_proof(proof_stem, starkinfo)

        # Extract stage 1 Merkle root
        root1 = proof.roots[0]

        # Extract stage 1 air_values (first component of each FF3 triple)
        # Most AIRs have empty air_values_map, resulting in empty list
        stage1_air_values = [
            proof.air_values[i][0]
            for i, av in enumerate(starkinfo.air_values_map)
            if av.stage == 1
        ]

        # Calculate this AIR's contribution to the global challenge
        contribution = calculate_internal_contribution(
            starkinfo,
            verkey,
            root1,
            air_values=stage1_air_values or None,
            lattice_size=lattice_size,
        )
        contributions.append(contribution)

    # Load shared public inputs
    publics = load_publics()

    # Load and extract stage 1 proof values
    proof_values_raw = load_proof_values()
    proof_values_stage1 = [
        int(pv[0])
        for pv, pvm in zip(proof_values_raw, proof_values_map)
        if pvm["stage"] == 1
    ]

    # Derive final global challenge from accumulated contributions
    global_challenge = derive_global_challenge_multi_air(
        publics=publics.tolist(),
        n_publics=n_publics,
        proof_values_stage1=proof_values_stage1,
        contributions=contributions,
        transcript_arity=transcript_arity,
        lattice_size=lattice_size,
    )

    # Return as numpy array for verifier compatibility
    return np.array(global_challenge, dtype=np.uint64)
