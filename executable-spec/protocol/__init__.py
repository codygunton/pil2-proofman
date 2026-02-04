"""Protocol - Core STARK protocol algorithms."""

from protocol.air_config import AirConfig, ProverHelpers, SetupCtx
from protocol.fri import FRI
from protocol.pcs import (
    FIELD_EXTENSION_DEGREE,
    EvalPoly,
    FriPcs,
    FriPcsConfig,
    FriProof,
    Nonce,
    QueryIndex,
)
from protocol.proof import STARKProof
from protocol.proof_context import ProofContext
from protocol.prover import gen_proof
from protocol.stages import Starks
from protocol.stark_info import StarkInfo
from protocol.verifier import stark_verify

__all__ = [
    # FRI
    "FRI",
    "EvalPoly",
    "FIELD_EXTENSION_DEGREE",
    # FRI PCS
    "FriPcs",
    "FriPcsConfig",
    "FriProof",
    "Nonce",
    "QueryIndex",
    # STARK
    "Starks",
    "stark_verify",
    "gen_proof",
    # Configuration and data structures
    "StarkInfo",
    "AirConfig",
    "SetupCtx",  # Deprecated alias for AirConfig
    "ProverHelpers",
    "ProofContext",
    "STARKProof",
]
