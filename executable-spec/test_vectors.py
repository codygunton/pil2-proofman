"""
FRI pinning test vectors.

Test vectors are stored in JSON files in executable-spec/test-data/.
DO NOT MODIFY the JSON files - values must match the C++ implementation exactly.

JSON Schema:
    {
        "metadata": {
            "air_name": str,           # AIR identifier (e.g., "SimpleLeft", "Lookup2_12")
            "n_bits": int,             # Original polynomial size (log2)
            "n_bits_ext": int,         # Extended domain size (log2)
            "fri_steps": List[int],    # Domain bits at each FRI step
            "n_queries": int,          # Number of FRI queries
            "pow_bits": int,           # Proof-of-work difficulty
            "merkle_arity": int,       # Merkle tree branching factor
            "transcript_arity": int,   # Fiat-Shamir sponge arity
        },
        "inputs": {
            "fri_input_polynomial": List[int],  # Input to FRI (evaluations)
            "fri_challenges": List[List[int]],  # Folding challenges (cubic ext)
            "grinding_challenge": List[int],    # PoW challenge (4 elements)
            "fri_queries": List[int],           # Query indices
            "transcript_state": List[int],      # Transcript state at FRI start
        },
        "expected": {
            "final_pol": List[int],       # Final polynomial after all folds
            "nonce": int,                 # Grinding nonce
            "final_pol_hash": List[int],  # Hash of final polynomial
        },
        "intermediates": {                # Optional step-by-step values
            "merkle_roots": List[List[int]],
            "poly_hashes_after_fold": List[List[int]],
        }
    }

Source: pil2-stark/src/goldilocks/tests/fri_pinning_vectors.hpp
"""

import json
from pathlib import Path

# Cache for loaded JSON vectors
_vectors_cache = {}


def _load_vectors(air_name: str) -> dict:
    """
    Load vectors for given AIR from JSON file.

    C++ Reference: NO CORRESPONDING FUNCTION
                   (Python test data loader)
    """
    # Normalize air name to file name
    if air_name.lower() in ['simple', 'simpleleft', 'simple_left']:
        file_name = 'simple-left.json'
    elif air_name.lower() in ['lookup', 'lookup2_12', 'lookup2', 'lookup2_12_2']:
        file_name = 'lookup2-12.json'
    else:
        raise ValueError(f"Unknown AIR: {air_name}")

    if file_name not in _vectors_cache:
        vectors_path = Path(__file__).parent / 'test-data' / file_name
        if not vectors_path.exists():
            raise FileNotFoundError(
                f"Vectors not found at {vectors_path}. "
                f"Run generate-fri-vectors.sh to generate them."
            )
        with open(vectors_path, 'r') as f:
            _vectors_cache[file_name] = json.load(f)
    return _vectors_cache[file_name]


# ============================================================================
# Helper functions
# ============================================================================

def get_config(air_name: str) -> dict:
    """
    Get configuration for given AIR.

    C++ Reference: NO CORRESPONDING FUNCTION
                   (Python test utility)
    """
    vectors = _load_vectors(air_name)
    metadata = vectors['metadata']
    return {
        'n_bits': metadata.get('n_bits'),
        'n_bits_ext': metadata.get('n_bits_ext'),
        'n_queries': metadata.get('n_queries'),
        'pow_bits': metadata.get('pow_bits'),
        'merkle_arity': metadata.get('merkle_arity'),
        'transcript_arity': metadata.get('transcript_arity'),
        'last_level_verification': metadata.get('last_level_verification'),
        'hash_commits': metadata.get('hash_commits'),
        'merkle_tree_custom': metadata.get('merkle_tree_custom'),
        'num_fri_steps': metadata.get('num_fri_steps'),
        'fri_steps': metadata.get('fri_steps'),
    }


def get_expected_final_pol(air_name: str) -> list:
    """
    Get expected final polynomial for given AIR.

    C++ Reference: NO CORRESPONDING FUNCTION
                   (Python test utility)
    """
    # DOTHIS: isn't this pattern of repeatedly loading the vectors at runtime kind of crazy?  Fix it so that vectors load once ever (per top-level test)
    vectors = _load_vectors(air_name)
    return vectors['expected']['final_pol']


def get_expected_nonce(air_name: str) -> int:
    """
    Get expected nonce for given AIR.

    C++ Reference: NO CORRESPONDING FUNCTION
                   (Python test utility)
    """
    vectors = _load_vectors(air_name)
    return vectors['expected']['nonce']


def get_expected_hash(air_name: str) -> list:
    """
    Get expected Poseidon2 hash of final polynomial for given AIR.

    C++ Reference: NO CORRESPONDING FUNCTION
                   (Python test utility)
    """
    vectors = _load_vectors(air_name)
    return vectors['expected']['final_pol_hash']


def get_fri_input_polynomial(air_name: str) -> list:
    """
    Get FRI input polynomial for given AIR.

    C++ Reference: NO CORRESPONDING FUNCTION
                   (Python test utility)
    """
    vectors = _load_vectors(air_name)
    return vectors['inputs']['fri_input_polynomial']


def get_fri_input_hash(air_name: str) -> list:
    """
    Get FRI input polynomial hash for given AIR.

    C++ Reference: NO CORRESPONDING FUNCTION
                   (Python test utility)
    """
    vectors = _load_vectors(air_name)
    return vectors['inputs'].get('fri_input_pol_hash', [])


def get_fri_challenges(air_name: str) -> list:
    """
    Get FRI folding challenges for given AIR.

    C++ Reference: NO CORRESPONDING FUNCTION
                   (Python test utility)
    """
    vectors = _load_vectors(air_name)
    return vectors['inputs']['fri_challenges']


def get_grinding_challenge(air_name: str) -> list:
    """
    Get grinding challenge for given AIR.

    C++ Reference: NO CORRESPONDING FUNCTION
                   (Python test utility)
    """
    vectors = _load_vectors(air_name)
    return vectors['inputs']['grinding_challenge']


def get_fri_queries(air_name: str) -> list:
    """
    Get FRI query indices for given AIR.

    These are the indices derived from grinding_challenge + nonce
    via transcript.getPermutations(n_queries, domain_bits).

    C++ Reference: NO CORRESPONDING FUNCTION
                   (Python test utility)
    """
    vectors = _load_vectors(air_name)
    fri_queries = vectors['inputs'].get('fri_queries', [])
    if not fri_queries:
        raise ValueError(
            f"FRI queries not available for AIR: {air_name}. "
            "Regenerate vectors with ./generate-fri-vectors.sh"
        )
    return fri_queries


def get_fri_steps(air_name: str) -> list:
    """
    Get FRI steps configuration for given AIR.

    C++ Reference: NO CORRESPONDING FUNCTION
                   (Python test utility)
    """
    vectors = _load_vectors(air_name)
    return vectors['metadata']['fri_steps']


def get_n_bits_ext(air_name: str) -> int:
    """
    Get extended domain bits for given AIR.

    C++ Reference: NO CORRESPONDING FUNCTION
                   (Python test utility)
    """
    vectors = _load_vectors(air_name)
    return vectors['metadata']['n_bits_ext']


def get_merkle_roots(air_name: str) -> list:
    """
    Get expected Merkle roots at each FRI step.

    C++ Reference: NO CORRESPONDING FUNCTION
                   (Python test utility)
    """
    vectors = _load_vectors(air_name)
    return vectors.get('intermediates', {}).get('merkle_roots', [])


def get_poly_hashes_after_fold(air_name: str) -> list:
    """
    Get expected polynomial hashes after each FRI fold step.

    C++ Reference: NO CORRESPONDING FUNCTION
                   (Python test utility)
    """
    vectors = _load_vectors(air_name)
    return vectors.get('intermediates', {}).get('poly_hashes_after_fold', [])


def get_transcript_state(air_name: str) -> dict:
    """
    Get transcript state at FRI start for given AIR.

    C++ Reference: NO CORRESPONDING FUNCTION
                   (Python test utility)

    Returns dict with:
        - state: 16-element array (sponge state)
        - out: 16-element array (output buffer)
        - out_cursor: current output cursor position
        - pending_cursor: current pending cursor position
    """
    vectors = _load_vectors(air_name)
    inputs = vectors.get('inputs', {})
    return {
        'state': inputs.get('transcript_state', []),
        'out': inputs.get('transcript_out', []),
        'out_cursor': inputs.get('transcript_out_cursor', 0),
        'pending_cursor': inputs.get('transcript_pending_cursor', 0),
    }


def get_query_proof_siblings(air_name: str) -> list:
    """
    Get expected Merkle proof siblings for the first FRI query.

    This is used to validate that Python's MerkleTree.get_group_proof()
    produces byte-identical output to C++'s MerkleTreeGL::getGroupProof().

    C++ Reference: NO CORRESPONDING FUNCTION
                   (Python test utility)

    Returns:
        List of sibling hash elements for the first query at step 0.
        Empty list if not captured in test vectors.
    """
    vectors = _load_vectors(air_name)
    return vectors.get('intermediates', {}).get('query_proof_siblings', [])


# ============================================================================
# Backwards compatibility - expose constants for existing test imports
# ============================================================================

# Load SimpleLeft vectors for backwards compatibility with existing tests
def _get_simple_left():
    try:
        return _load_vectors('simple')
    except FileNotFoundError:
        return None

_sl = _get_simple_left()
if _sl:
    SIMPLE_LEFT_CONFIG = get_config('simple')
    SIMPLE_LEFT_EXPECTED_FINAL_POL = _sl['expected']['final_pol']
    SIMPLE_LEFT_EXPECTED_NONCE = _sl['expected']['nonce']
    SIMPLE_LEFT_EXPECTED_FINAL_POL_HASH = _sl['expected']['final_pol_hash']
    SIMPLE_LEFT_FRI_INPUT_POLYNOMIAL = _sl['inputs']['fri_input_polynomial']
    SIMPLE_LEFT_FRI_INPUT_POL_HASH = _sl['inputs'].get('fri_input_pol_hash', [])
    SIMPLE_LEFT_FRI_CHALLENGES = _sl['inputs']['fri_challenges']
    SIMPLE_LEFT_GRINDING_CHALLENGE = _sl['inputs']['grinding_challenge']
    SIMPLE_LEFT_FRI_QUERIES = _sl['inputs'].get('fri_queries', [])
else:
    SIMPLE_LEFT_CONFIG = {}
    SIMPLE_LEFT_EXPECTED_FINAL_POL = []
    SIMPLE_LEFT_EXPECTED_NONCE = 0
    SIMPLE_LEFT_EXPECTED_FINAL_POL_HASH = []
    SIMPLE_LEFT_FRI_INPUT_POLYNOMIAL = []
    SIMPLE_LEFT_FRI_INPUT_POL_HASH = []
    SIMPLE_LEFT_FRI_CHALLENGES = []
    SIMPLE_LEFT_GRINDING_CHALLENGE = []
    SIMPLE_LEFT_FRI_QUERIES = []

# Load Lookup2_12 vectors for backwards compatibility
def _get_lookup2_12():
    try:
        return _load_vectors('lookup')
    except FileNotFoundError:
        return None

_lk = _get_lookup2_12()
if _lk:
    LOOKUP2_12_CONFIG = get_config('lookup')
    LOOKUP2_12_EXPECTED_FINAL_POL = _lk['expected']['final_pol']
    LOOKUP2_12_EXPECTED_NONCE = _lk['expected']['nonce']
    LOOKUP2_12_EXPECTED_FINAL_POL_HASH = _lk['expected']['final_pol_hash']
else:
    LOOKUP2_12_CONFIG = {}
    LOOKUP2_12_EXPECTED_FINAL_POL = []
    LOOKUP2_12_EXPECTED_NONCE = 0
    LOOKUP2_12_EXPECTED_FINAL_POL_HASH = []
