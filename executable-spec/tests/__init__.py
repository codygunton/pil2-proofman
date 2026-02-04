"""Tests - Test suite for the STARK executable specification."""

# Re-export protocol types for convenience in tests
from protocol import (
    AirConfig,
    ProofContext,
    ProverHelpers,
    StarkInfo,
    STARKProof,
    gen_proof,
)

__all__ = [
    "AirConfig",
    "ProofContext",
    "ProverHelpers",
    "StarkInfo",
    "STARKProof",
    "gen_proof",
]
