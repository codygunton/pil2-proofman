"""Fixture loading utilities for ZisK AIR tests.

Provides functions to load starkinfo, verkey, proofs, and public inputs
from the proving key directory and test fixtures.
"""

import json
import os
from pathlib import Path

import numpy as np

from protocol.stark_info import StarkInfo
from protocol.air_config import AirConfig
from protocol.proof import from_bytes_full


def get_proving_key_dir() -> Path:
    """Get ZisK proving key directory.

    Checks ZISK_PROVING_KEY environment variable first, falls back to default.

    Returns:
        Path to proving key directory

    Raises:
        FileNotFoundError: If proving key directory doesn't exist
    """
    env_path = os.environ.get("ZISK_PROVING_KEY")
    if env_path:
        pk_dir = Path(env_path)
    else:
        pk_dir = Path("/home/cody/zisk-for-spec/provingKey")

    if not pk_dir.exists():
        raise FileNotFoundError(
            f"Proving key directory not found: {pk_dir}\n"
            f"Set ZISK_PROVING_KEY environment variable or ensure default path exists."
        )

    return pk_dir


def load_starkinfo(air_name: str) -> StarkInfo:
    """Load starkinfo.json for given AIR from proving key.

    Args:
        air_name: Name of the AIR (e.g., "Main", "Rom", "Mem")

    Returns:
        StarkInfo object parsed from JSON

    Raises:
        FileNotFoundError: If starkinfo file doesn't exist
    """
    pk_dir = get_proving_key_dir()
    starkinfo_path = (
        pk_dir / "zisk" / "Zisk" / "airs" / air_name / "air" / f"{air_name}.starkinfo.json"
    )

    if not starkinfo_path.exists():
        raise FileNotFoundError(
            f"StarkInfo not found for AIR '{air_name}': {starkinfo_path}"
        )

    return StarkInfo.from_json(str(starkinfo_path))


def load_air_config(air_name: str) -> AirConfig:
    """Load AirConfig for given AIR from proving key.

    Args:
        air_name: Name of the AIR (e.g., "Main", "Rom", "Mem")

    Returns:
        AirConfig object with stark_info and global_info

    Raises:
        FileNotFoundError: If starkinfo file doesn't exist
    """
    pk_dir = get_proving_key_dir()
    starkinfo_path = (
        pk_dir / "zisk" / "Zisk" / "airs" / air_name / "air" / f"{air_name}.starkinfo.json"
    )

    if not starkinfo_path.exists():
        raise FileNotFoundError(
            f"StarkInfo not found for AIR '{air_name}': {starkinfo_path}"
        )

    return AirConfig.from_starkinfo(str(starkinfo_path))


def load_verkey(air_name: str) -> list[int]:
    """Load verification key (Merkle root) for given AIR.

    Args:
        air_name: Name of the AIR (e.g., "Main", "Rom", "Mem")

    Returns:
        List of 4 field elements (Poseidon2 hash)

    Raises:
        FileNotFoundError: If verkey file doesn't exist
    """
    pk_dir = get_proving_key_dir()
    verkey_path = (
        pk_dir / "zisk" / "Zisk" / "airs" / air_name / "air" / f"{air_name}.verkey.json"
    )

    if not verkey_path.exists():
        raise FileNotFoundError(
            f"Verification key not found for AIR '{air_name}': {verkey_path}"
        )

    with open(verkey_path) as f:
        return json.load(f)


def load_publics() -> np.ndarray:
    """Load publics.json (shared across all AIRs).

    Returns:
        Numpy array of public inputs

    Raises:
        FileNotFoundError: If publics.json doesn't exist
    """
    test_data_dir = Path(__file__).parent.parent / "test-data" / "zisk"
    publics_path = test_data_dir / "publics.json"

    if not publics_path.exists():
        raise FileNotFoundError(f"Public inputs not found: {publics_path}")

    with open(publics_path) as f:
        publics_data = json.load(f)

    return np.array(publics_data, dtype=np.uint64)


def load_proof_values() -> dict:
    """Load proof_values.json (shared across all AIRs).

    Returns:
        Dict with stage1 proof values

    Raises:
        FileNotFoundError: If proof_values.json doesn't exist
    """
    test_data_dir = Path(__file__).parent.parent / "test-data" / "zisk"
    proof_values_path = test_data_dir / "proof_values.json"

    if not proof_values_path.exists():
        raise FileNotFoundError(f"Proof values not found: {proof_values_path}")

    with open(proof_values_path) as f:
        return json.load(f)


def load_binary_proof(proof_stem: str, starkinfo=None):
    """Load binary proof from test fixtures.

    Args:
        proof_stem: Proof filename without extension (e.g., "Main_0", "Rom_1")
        starkinfo: Optional StarkInfo for proof deserialization (if needed)

    Returns:
        Proof dict deserialized from binary format

    Raises:
        FileNotFoundError: If proof file doesn't exist
    """
    test_data_dir = Path(__file__).parent.parent / "test-data" / "zisk" / "proofs"
    proof_path = test_data_dir / f"{proof_stem}.proof.bin"

    if not proof_path.exists():
        raise FileNotFoundError(f"Binary proof not found: {proof_path}")

    with open(proof_path, "rb") as f:
        proof_bytes = f.read()

    # from_bytes_full can optionally take starkinfo for additional validation
    if starkinfo is not None:
        return from_bytes_full(proof_bytes, starkinfo)
    else:
        return from_bytes_full(proof_bytes)
