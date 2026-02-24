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

# List of all 12 ZisK AIRs with their proof stems
# Instance IDs may vary between proof generation runs
ZISK_AIR_PARAMS = [
    ("Main", "Main_0"),
    ("Rom", "Rom_1"),
    ("Mem", "Mem_2"),
    ("RomData", "RomData_3"),
    ("InputData", "InputData_4"),
    ("MemAlign", "MemAlign_5"),
    ("BinaryExtension", "BinaryExtension_6"),
    ("BinaryAdd", "BinaryAdd_7"),
    ("Binary", "Binary_8"),
    ("SpecifiedRanges", "SpecifiedRanges_9"),
    ("VirtualTable0", "VirtualTable0_10"),
    ("VirtualTable1", "VirtualTable1_11"),
]

# Compute global VADCOP challenge once at import time (shared across all tests)
# This avoids loading all 12 proofs in each test file
_air_names = [name for name, _ in ZISK_AIR_PARAMS]
_proof_stems = [stem for _, stem in ZISK_AIR_PARAMS]
GLOBAL_CHALLENGE = derive_global_challenge_from_proofs(_air_names, _proof_stems)

__all__ = [
    "load_starkinfo",
    "load_air_config",
    "load_verkey",
    "load_publics",
    "load_proof_values",
    "load_binary_proof",
    "get_proving_key_dir",
    "derive_global_challenge_from_proofs",
    "ZISK_AIR_PARAMS",
    "GLOBAL_CHALLENGE",
]
