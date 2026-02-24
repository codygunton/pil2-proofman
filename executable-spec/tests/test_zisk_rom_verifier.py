"""Verifier E2E test for Rom AIR using GPU-generated proof from Fibonacci(10)."""

from tests.zisk_test_utils import (
    load_air_config,
    load_verkey,
    load_publics,
    load_binary_proof,
    GLOBAL_CHALLENGE,
)
from protocol.verifier import stark_verify


def test_rom_verifier():
    """Rom AIR handles read-only memory access."""
    air_name = "Rom"
    proof_stem = "Rom_1"

    # Load AIR-specific fixtures
    air_config = load_air_config(air_name)
    verkey = load_verkey(air_name)
    publics = load_publics()
    proof = load_binary_proof(proof_stem, air_config.stark_info)

    # Verify proof (using shared global challenge computed once at import time)
    result = stark_verify(
        proof=proof,
        air_config=air_config,
        verkey=verkey,
        global_challenge=GLOBAL_CHALLENGE,
        publics=publics,
    )

    assert result is True, f"{air_name} AIR proof verification failed"
