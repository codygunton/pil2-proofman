"""
FRI PCS Python Specification

A faithful Python implementation of the FRI (Fast Reed-Solomon Interactive
Oracle Proof of Proximity) Polynomial Commitment Scheme from pil2-proofman.

This package provides:
- Goldilocks field arithmetic (via galois)
- Poseidon2 cryptographic hash
- Merkle tree construction
- Fiat-Shamir transcript
- FRI folding and query algorithms
- FRI PCS wrapper

Usage (from within the package):
    from fri_pcs import FriPcs, FriPcsConfig
    from transcript import Transcript

    config = FriPcsConfig(
        n_bits_ext=13,
        fri_steps=[12, 8, 4],
        n_queries=228,
    )
    fri = FriPcs(config)
    transcript = Transcript(arity=4)
    proof = fri.prove(polynomial, transcript)
"""

# Field arithmetic (via galois)
from field import (
    GF,
    GF3,
    ntt,
    intt,
    GOLDILOCKS_PRIME,
    get_root_of_unity,
    W,
    pow_mod,
    inv_mod,
    get_shift,
    get_omega,
)

# Cryptographic hashing
from poseidon2_ffi import (
    poseidon2_hash,
    linear_hash,
    hash_seq,
    grinding,
    verify_grinding,
    CAPACITY,
)

# Merkle tree
from merkle_tree import (
    MerkleTree,
    HASH_SIZE,
)

# Fiat-Shamir transcript
from transcript import Transcript

# FRI core algorithms
from fri import FRI

# FRI PCS wrapper
from fri_pcs import (
    FriPcs,
    FriPcsConfig,
    FriProof,
)

# Test vectors
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

# Proof loading (Phase 2)
from proof_loader import (
    FriProofData,
    load_proof,
    find_proof_file,
    detect_air_type,
)

__version__ = "0.1.0"
__all__ = [
    # Field
    "GF",
    "GF3",
    "ntt",
    "intt",
    "GOLDILOCKS_PRIME",
    "get_root_of_unity",
    "W",
    "pow_mod",
    "inv_mod",
    "get_shift",
    "get_omega",
    # Hash
    "poseidon2_hash",
    "linear_hash",
    "hash_seq",
    "grinding",
    "verify_grinding",
    "CAPACITY",
    # Merkle
    "MerkleTree",
    "HASH_SIZE",
    # Transcript
    "Transcript",
    # FRI
    "FRI",
    "FriPcs",
    "FriPcsConfig",
    "FriProof",
    # Test vectors
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
    # Proof loading
    "FriProofData",
    "load_proof",
    "find_proof_file",
    "detect_air_type",
]
