"""ZisK test utilities for per-AIR verifier testing.

This package provides shared infrastructure for loading test fixtures
and deriving VADCOP challenges from multi-AIR proofs.
"""

from .fixture_loader import (
    load_starkinfo,
    load_air_config,
    load_verkey,
    load_publics,
    load_proof_values,
    load_binary_proof,
    get_proving_key_dir,
)
from .challenge_utils import derive_global_challenge_from_proofs

__all__ = [
    "load_starkinfo",
    "load_air_config",
    "load_verkey",
    "load_publics",
    "load_proof_values",
    "load_binary_proof",
    "get_proving_key_dir",
    "derive_global_challenge_from_proofs",
]
