"""Multi-AIR Stage-1 coordination for the Simple pilout.

The Simple pilout contains five AIRs: SimpleLeft, SimpleRight, U8Air, U16Air,
SpecifiedRanges. C++ proofman proves all five simultaneously and derives the
global_challenge by element-wise accumulating each AIR's Poseidon2 lattice
contribution before any AIR advances to Stage 2.

prove_simple_pilout_stage1() replicates this protocol step, enabling
byte-identical proof comparison between Python and C++.

Usage::

    from protocol.simple_pilout import AIRStage1Data, prove_simple_pilout_stage1

    result = prove_simple_pilout_stage1({
        'SimpleLeft': AIRStage1Data(air_config=..., trace=..., ...),
        ...
    })
    global_challenge = result.global_challenge
    # Then call gen_proof(..., global_challenge=global_challenge) for each AIR
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from protocol.air_config import AirConfig
from protocol.stages import PolynomialCommitter
from protocol.utils.challenge_utils import (
    calculate_internal_contribution,
    derive_global_challenge_multi_air,
)

LATTICE_SIZE = 368      # from pilout.globalInfo.json
TRANSCRIPT_ARITY = 4   # from pilout.globalInfo.json


@dataclass
class AIRStage1Data:
    """All data needed to commit Stage 1 for one AIR in the Simple pilout."""

    air_config: AirConfig
    trace: np.ndarray            # Stage-1 cm1 buffer (N * cm1_cols elements)
    const_pols: np.ndarray       # Constant polynomials on base domain
    const_pols_extended: np.ndarray  # Constant polynomials on extended domain


@dataclass
class SimplePiloutStage1Result:
    """Stage-1 results for all five Simple AIRs."""

    verkeys: dict[str, list[int]]             # air_name → 4-element verkey
    stage1_commitments: dict[str, list[int]]  # air_name → 4-element root1
    global_challenge: list[int]               # 3-element cubic extension challenge


def prove_simple_pilout_stage1(
    air_data: dict[str, AIRStage1Data],
) -> SimplePiloutStage1Result:
    """Commit Stage 1 for all Simple pilout AIRs and derive the multi-AIR global challenge.

    Implements the C++ proofman pattern from challenge_accumulation.rs:
      1. For each AIR: build const tree (verkey) and commit Stage-1 witness (root1).
      2. For each AIR: compute Poseidon2 lattice contribution from (verkey, root1).
      3. Accumulate all contributions element-wise (mod Goldilocks prime).
      4. Hash accumulated contribution with publics → global_challenge.

    The Simple pilout has n_publics=0 and no proof_values_stage1, so only the
    five AIR contributions enter the challenge hash.

    Args:
        air_data: Dict mapping AIR name → AIRStage1Data for all five Simple AIRs.
            Keys must include: 'SimpleLeft', 'SimpleRight', 'U8Air', 'U16Air',
            'SpecifiedRanges' (order determines accumulation order).

    Returns:
        SimplePiloutStage1Result with verkeys, stage1_commitments, and global_challenge.
    """
    verkeys: dict[str, list[int]] = {}
    stage1_commitments: dict[str, list[int]] = {}
    contributions: list[list[int]] = []

    for air_name, data in air_data.items():
        committer = PolynomialCommitter(data.air_config)
        stark_info = data.air_config.stark_info

        # Build verkey from constant polynomials
        verkey = committer.build_const_tree(data.const_pols_extended)
        verkeys[air_name] = list(verkey)

        # Commit Stage-1 witness into a fresh auxiliary trace buffer
        aux_trace = np.zeros(stark_info.map_total_n, dtype=np.uint64)
        root1 = committer.commitStage(1, data.trace, aux_trace)
        stage1_commitments[air_name] = list(root1)

        # Compute this AIR's lattice contribution from (verkey, root1)
        contribution = calculate_internal_contribution(
            stark_info=stark_info,
            verkey=list(verkey),
            root1=list(root1),
            air_values=[],   # All Simple AIRs have no air_values
            lattice_size=LATTICE_SIZE,
        )
        contributions.append(contribution)

    # Derive global challenge from all contributions accumulated element-wise.
    # n_publics=0: Simple pilout has no public inputs.
    # proof_values_stage1=[]: Simple pilout has no proof_values at Stage 1.
    global_challenge = derive_global_challenge_multi_air(
        publics=[],
        n_publics=0,
        proof_values_stage1=[],
        contributions=contributions,
        transcript_arity=TRANSCRIPT_ARITY,
        merkle_tree_custom=False,
        lattice_size=LATTICE_SIZE,
    )

    return SimplePiloutStage1Result(
        verkeys=verkeys,
        stage1_commitments=stage1_commitments,
        global_challenge=global_challenge,
    )
