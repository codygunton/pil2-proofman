"""Protocol - Core STARK protocol algorithms."""

from protocol.fri import FRI
from protocol.pcs import (
    EvalPoly,
    FIELD_EXTENSION_DEGREE,
    FriPcs,
    FriPcsConfig,
    FriProof,
    Nonce,
    QueryIndex,
)

from protocol.stages import Starks

from protocol.expression_evaluator import ExpressionsPack

from protocol.verifier import stark_verify

from protocol.witness_generation import calculate_witness_std

from protocol.prover import gen_proof

from protocol.stark_info import StarkInfo
from protocol.air_config import SetupCtx, AirConfig, ProverHelpers
from protocol.proof_context import ProofContext
from protocol.expressions_bin import ExpressionsBin
from protocol.proof import STARKProof

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
    "ExpressionsPack",
    "stark_verify",
    "calculate_witness_std",
    "gen_proof",
    # Configuration and data structures
    "StarkInfo",
    "AirConfig",
    "SetupCtx",  # Deprecated alias for AirConfig
    "ProverHelpers",
    "ProofContext",
    "ExpressionsBin",
    "STARKProof",
]
