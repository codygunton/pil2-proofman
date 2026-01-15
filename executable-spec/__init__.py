"""FRI Polynomial Commitment Scheme - Python Executable Specification."""

# --- Field Arithmetic ---

from field import (
    Fe,
    Fe3,
    GF,
    GF3,
    GOLDILOCKS_PRIME,
    W,
    SHIFT,
    ntt,
    intt,
    pow_mod,
    inv_mod,
    get_shift,
    get_omega,
    get_root_of_unity,
    fe3_mul,
    fe3_add,
    fe3_sub,
    fe3_scalar_mul,
    fe3_from_base,
    fe3_zero,
    fe3_one,
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
    "Fe",
    "GF",
    "GOLDILOCKS_PRIME",
    "W",
    "SHIFT",
    "ntt",
    "intt",
    "pow_mod",
    "inv_mod",
    "get_shift",
    "get_omega",
    "get_root_of_unity",
    "Fe3",
    "GF3",
    "fe3_mul",
    "fe3_add",
    "fe3_sub",
    "fe3_scalar_mul",
    "fe3_from_base",
    "fe3_zero",
    "fe3_one",
    "poseidon2_hash",
    "linear_hash",
    "hash_seq",
    "grinding",
    "verify_grinding",
    "CAPACITY",
    "MerkleTree",
    "MerkleRoot",
    "MerkleProof",
    "LeafData",
    "HASH_SIZE",
    "Transcript",
    "SpongeState",
    "Hash",
    "Challenge",
    "FRI",
    "EvalPoly",
    "FriLayer",
    "FIELD_EXTENSION",
    "FriPcs",
    "FriPcsConfig",
    "FriProof",
    "Nonce",
    "QueryIndex",
    "FriVerifier",
    "VerificationResult",
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
    "FriProofData",
    "load_proof",
    "find_proof_file",
    "detect_air_type",
]
