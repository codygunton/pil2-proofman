"""FRI Polynomial Commitment Scheme - Python Executable Specification.

Package structure:
    primitives/ - Low-level cryptographic and mathematical building blocks
    protocol/   - Core STARK protocol algorithms
    tests/      - Test suite and test infrastructure
"""

# Re-export from subpackages for convenience
from primitives import (
    # Field
    FF,
    FF3,
    ff3,
    ff3_coeffs,
    GOLDILOCKS_PRIME,
    W,
    SHIFT,
    SHIFT_INV,
    ntt,
    intt,
    get_omega,
    get_omega_inv,
    # NTT
    NTT,
    # Merkle Tree
    MerkleTree,
    MerkleRoot,
    QueryProof,
    LeafData,
    HASH_SIZE,
    transpose_for_merkle,
    # Transcript
    Transcript,
    SpongeState,
    Hash,
    Challenge,
    # Polynomial mappings
    PolMap,
    EvMap,
    ChallengeMap,
    CustomCommits,
    Boundary,
)

from protocol import (
    # FRI
    FRI,
    EvalPoly,
    FIELD_EXTENSION_DEGREE,
    # FRI PCS
    FriPcs,
    FriPcsConfig,
    FriProof,
    Nonce,
    QueryIndex,
    # STARK
    Starks,
    ExpressionsPack,
    stark_verify,
    calculate_witness_std,
)

# Poseidon2 is in a separate FFI package
from poseidon2_ffi import (
    poseidon2_hash,
    linear_hash,
    hash_seq,
    grinding,
    verify_grinding,
    CAPACITY,
)

__version__ = "0.1.0"

__all__ = [
    # Field
    "FF",
    "FF3",
    "ff3",
    "ff3_coeffs",
    "GOLDILOCKS_PRIME",
    "W",
    "SHIFT",
    "SHIFT_INV",
    "ntt",
    "intt",
    "get_omega",
    "get_omega_inv",
    # NTT
    "NTT",
    # Poseidon2
    "poseidon2_hash",
    "linear_hash",
    "hash_seq",
    "grinding",
    "verify_grinding",
    "CAPACITY",
    # Merkle Tree
    "MerkleTree",
    "MerkleRoot",
    "QueryProof",
    "LeafData",
    "HASH_SIZE",
    "transpose_for_merkle",
    # Transcript
    "Transcript",
    "SpongeState",
    "Hash",
    "Challenge",
    # Polynomial mappings
    "PolMap",
    "EvMap",
    "ChallengeMap",
    "CustomCommits",
    "Boundary",
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
]
