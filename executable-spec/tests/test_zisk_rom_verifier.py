"""Verifier E2E test for Rom AIR using GPU-generated proof from Fibonacci(10)."""

import pytest

from tests.zisk_test_utils import (
    load_air_config,
    load_verkey,
    load_publics,
    load_binary_proof,
    derive_global_challenge_from_proofs,
)
from protocol.verifier import stark_verify


# List of all 12 AIRs with their proof stems (instance IDs may vary)
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


def test_rom_verifier():
    """Verify Rom AIR proof from Fibonacci(10) guest program.

    Rom AIR handles read-only memory access.
    """
    air_name = "Rom"
    proof_stem = "Rom_1"

    # Derive global VADCOP challenge from all 12 per-AIR proofs
    air_names = [name for name, _ in ZISK_AIR_PARAMS]
    proof_stems = [stem for _, stem in ZISK_AIR_PARAMS]
    global_challenge = derive_global_challenge_from_proofs(air_names, proof_stems)

    # Load AIR-specific fixtures
    air_config = load_air_config(air_name)
    verkey = load_verkey(air_name)
    publics = load_publics()
    proof = load_binary_proof(proof_stem, air_config.stark_info)

    # Verify proof
    result = stark_verify(
        proof=proof,
        air_config=air_config,
        verkey=verkey,
        global_challenge=global_challenge,
        publics=publics,
    )

    assert result is True, f"{air_name} AIR proof verification failed"
