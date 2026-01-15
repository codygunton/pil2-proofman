"""FRI Polynomial Commitment Scheme - Python Executable Specification."""

# --- Field Arithmetic ---

from field import (
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
)

# --- Poseidon2 Hashing ---

from poseidon2_ffi import (
    poseidon2_hash,
    linear_hash,
    hash_seq,
    grinding,
    verify_grinding,
    CAPACITY,
)

# --- Merkle Tree ---

from merkle_tree import (
    MerkleTree,
    MerkleRoot,
    MerkleProof,
    LeafData,
    HASH_SIZE,
    transpose_for_merkle,
)

# --- Fiat-Shamir Transcript ---

from transcript import (
    Transcript,
    SpongeState,
    Hash,
    Challenge,
)

# --- FRI Core ---

from fri import (
    FRI,
    EvalPoly,
    FriLayer,
    FIELD_EXTENSION,
)

# --- FRI PCS ---

from fri_pcs import (
    FriPcs,
    FriPcsConfig,
    FriProof,
    Nonce,
    QueryIndex,
)

# --- Verifier ---

from verifier import (
    FriVerifier,
    VerificationResult,
)

# --- Test Vectors ---

from test_vectors import (
    get_config,
    get_expected_final_pol,
    get_expected_nonce,
    get_expected_hash,
    get_fri_input_polynomial,
    get_fri_input_hash,
    get_fri_challenges,
    get_grinding_challenge,
    get_fri_steps,
    get_n_bits_ext,
)

# --- Proof Loading ---

from proof_loader import (
    FriProofData,
    load_proof,
    find_proof_file,
    detect_air_type,
)

# --- Package Metadata ---

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
    "MerkleProof",
    "LeafData",
    "HASH_SIZE",
    "transpose_for_merkle",
    # Transcript
    "Transcript",
    "SpongeState",
    "Hash",
    "Challenge",
    # FRI
    "FRI",
    "EvalPoly",
    "FriLayer",
    "FIELD_EXTENSION",
    # FRI PCS
    "FriPcs",
    "FriPcsConfig",
    "FriProof",
    "Nonce",
    "QueryIndex",
    # Verifier
    "FriVerifier",
    "VerificationResult",
    # Test Vectors
    "get_config",
    "get_expected_final_pol",
    "get_expected_nonce",
    "get_expected_hash",
    "get_fri_input_polynomial",
    "get_fri_input_hash",
    "get_fri_challenges",
    "get_grinding_challenge",
    "get_fri_steps",
    "get_n_bits_ext",
    # Proof Loading
    "FriProofData",
    "load_proof",
    "find_proof_file",
    "detect_air_type",
]
