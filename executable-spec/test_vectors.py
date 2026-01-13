# QUESTION: Can the data in here be moved to a central location with the external JSON data? What would be a robust pattern for when we expand tests, separating logic from data? ANS: Yes, all vectors could live in vectors/*.json. Current split is: small vectors (SimpleLeft ~50 values) inline here, large vectors (Lookup2_12 ~25K values) in JSON. Robust pattern: move ALL test data to vectors/<air_name>.json with consistent schema {config, input_polynomial, challenges, expected_output, etc}. Test code would just load JSON and run assertions. This mirrors how C++ separates fri_pinning_vectors.hpp (data) from fri_pinning_test.cpp (logic). We kept small vectors inline to match C++ header structure, but JSON-only would be cleaner. Can simplify at cost of C++ divergence? Y - JSON-only would be cleaner Python, but diverges from C++ header file pattern.
# TODO: duplicate of other issue; fix
"""
FRI pinning test vectors.

These are the expected golden values from the C++ implementation.
DO NOT MODIFY - these values must match the C++ headers exactly.

Source: pil2-stark/src/goldilocks/tests/fri_pinning_vectors.hpp

Large vectors (Lookup2_12) are stored in JSON files in executable-spec/vectors/
to keep this file manageable.
"""

import json
from pathlib import Path

# Cache for loaded JSON vectors
_lookup2_12_vectors = None


def _load_lookup2_12_vectors():
    """Load Lookup2_12 input vectors from JSON file."""
    global _lookup2_12_vectors
    if _lookup2_12_vectors is None:
        vectors_path = Path(__file__).parent / 'vectors' / 'lookup2_12_2.json'
        if not vectors_path.exists():
            raise FileNotFoundError(
                f"Lookup2_12 vectors not found at {vectors_path}. "
                "Run generate-fri-vectors.sh lookup to generate them."
            )
        with open(vectors_path, 'r') as f:
            _lookup2_12_vectors = json.load(f)
    return _lookup2_12_vectors


# ============================================================================
# SimpleLeft Configuration
# ============================================================================

SIMPLE_LEFT_CONFIG = {
    'n_bits': 3,                      # Base domain: 2^3 = 8 rows
    'n_bits_ext': 4,                  # Extended domain: 2^4 = 16
    'n_queries': 228,                 # FRI queries for soundness
    'pow_bits': 16,                   # Proof-of-work grinding bits
    'merkle_arity': 4,                # Merkle tree branching factor
    'transcript_arity': 4,            # Fiat-Shamir arity
    'last_level_verification': 2,     # Merkle tree last level depth
    'hash_commits': True,             # Hash polynomial commitments
    'merkle_tree_custom': True,       # Using custom Merkle tree
    'num_fri_steps': 1,               # Single folding step
    'fri_steps': [4],                 # Reduce to 2^4 = 16 elements
}

# Expected final polynomial (16 cubic extension elements = 48 Goldilocks values)
SIMPLE_LEFT_EXPECTED_FINAL_POL = [
    3055503030217023883, 14674508583309298785, 5885849117767276278,    # Element 0
    13701831255698438944, 1283723217496151905, 6787061737207648806,    # Element 1
    1490285254039880334, 12206638945089264610, 4028039824881281066,    # Element 2
    6173674811141161353, 12727931143765845850, 11772504568132636170,   # Element 3
    2124711334127787032, 2422792798526012876, 595475889981943084,      # Element 4
    12895309280498340374, 10209758780222158475, 11026945906801590302,  # Element 5
    7932333378049291554, 11698649812757253058, 65233997353509573,      # Element 6
    8522747463959870547, 12526681977083944153, 8187629827557060993,    # Element 7
    15943641703712512390, 13900674231866633987, 9119815241417913437,   # Element 8
    13214328069786755482, 1290362087763361579, 15374365308707279671,   # Element 9
    14555069521905791416, 12285886796485120627, 14952573041881450266,  # Element 10
    7489272786740350018, 184279497294762181, 6702168602610022660,      # Element 11
    2872310693891620498, 18442687036345179693, 12600134693347240975,   # Element 12
    15762660494228645950, 1089223122280328124, 12538857081211527031,   # Element 13
    3260775988529739921, 3467800841604774028, 5041750969204501126,     # Element 14
    10368294881249253002, 12894191081247816755, 16792827882436518814,  # Element 15
]

# Expected nonce
SIMPLE_LEFT_EXPECTED_NONCE = 56

# Expected Poseidon2 hash of final polynomial (4 Goldilocks elements)
SIMPLE_LEFT_EXPECTED_FINAL_POL_HASH = [
    16201618454940366509,
    9223689653289312170,
    6707438330426141909,
    10762121192969877648,
]

# SHA256 checksum
SIMPLE_LEFT_EXPECTED_FINAL_POL_CHECKSUM = "45f67c58cbbac0383eb7d29cef8e93a12a18aa5520dc3a346369b6dacaedf921"


# ============================================================================
# SimpleLeft FRI Input Vectors (captured from C++ with CAPTURE_FRI_VECTORS)
# ============================================================================
# NOTE: For SimpleLeft, input equals output (no FRI folding needed for small AIRs).
# This is expected behavior and validates deterministic proof generation.

# Input polynomial to FRI (before folding) - identical to EXPECTED_FINAL_POL for SimpleLeft
SIMPLE_LEFT_FRI_INPUT_POLYNOMIAL = SIMPLE_LEFT_EXPECTED_FINAL_POL.copy()

# Hash of input polynomial - identical to EXPECTED_FINAL_POL_HASH for SimpleLeft
SIMPLE_LEFT_FRI_INPUT_POL_HASH = SIMPLE_LEFT_EXPECTED_FINAL_POL_HASH.copy()

# FRI folding challenges (one per FRI step, each is a cubic extension element)
SIMPLE_LEFT_FRI_CHALLENGES = [
    [5360955783996970004, 3623636231864186898, 10531370013360693355],  # Challenge 0
]

# Grinding challenge (used for proof-of-work)
# For SimpleLeft with single FRI step, equals the last FRI challenge
SIMPLE_LEFT_GRINDING_CHALLENGE = [
    5360955783996970004,
    3623636231864186898,
    10531370013360693355,
]

# FRI query indices (derived from grinding_challenge + nonce via transcript.getPermutations)
# These are the indices into the extended polynomial domain for FRI queries.
# Computed using Python transcript (verified to match C++ exactly).
SIMPLE_LEFT_FRI_QUERIES = [
    15, 3, 0, 11, 3, 6, 8, 1, 8, 9,
    11, 1, 6, 9, 14, 12, 14, 12, 0, 15,
    13, 4, 2, 3, 6, 12, 11, 10, 5, 15,
    2, 11, 9, 11, 11, 15, 13, 7, 14, 3,
    3, 14, 6, 11, 4, 7, 10, 2, 12, 9,
    11, 14, 5, 12, 2, 10, 4, 0, 7, 15,
    2, 3, 10, 5, 4, 1, 12, 3, 6, 2,
    11, 5, 7, 13, 1, 4, 5, 15, 10, 9,
    10, 13, 3, 10, 3, 10, 5, 9, 3, 3,
    5, 6, 14, 9, 2, 5, 5, 5, 3, 4,
    10, 1, 12, 12, 13, 13, 12, 6, 9, 2,
    5, 13, 11, 8, 0, 7, 7, 4, 4, 1,
    8, 12, 13, 1, 3, 3, 5, 7, 10, 8,
    8, 11, 4, 4, 14, 8, 1, 4, 13, 2,
    9, 1, 12, 3, 7, 15, 6, 11, 14, 4,
    9, 15, 13, 15, 9, 6, 14, 13, 5, 4,
    1, 11, 0, 11, 13, 6, 11, 5, 14, 6,
    10, 12, 12, 6, 3, 13, 6, 7, 13, 7,
    2, 0, 14, 11, 14, 13, 14, 0, 3, 2,
    2, 13, 1, 7, 12, 5, 4, 13, 11, 4,
    15, 1, 5, 0, 14, 15, 4, 14, 9, 2,
    13, 1, 12, 14, 9, 6, 11, 13, 3, 1,
    1, 9, 10, 8, 6, 2, 11, 1,
]


# ============================================================================
# Lookup2_12 Configuration
# ============================================================================

LOOKUP2_12_CONFIG = {
    'n_bits': 12,                     # Base domain: 2^12 = 4096 rows
    'n_bits_ext': 13,                 # Extended domain: 2^13
    'n_queries': 228,                 # FRI queries for soundness
    'pow_bits': 16,                   # Proof-of-work grinding bits
    'merkle_arity': 4,                # Merkle tree branching factor
    'transcript_arity': 4,            # Fiat-Shamir arity
}

# Expected final polynomial (32 cubic extension elements = 96 Goldilocks values)
LOOKUP2_12_EXPECTED_FINAL_POL = [
    14434583126679987313, 5482150761621168896, 3249328641526182044,      # Element 0
    15342740250347407991, 3376553363229461591, 4257268957549436242,      # Element 1
    7204487384040872062, 1419173031459822675, 2061249537966676017,       # Element 2
    2360586269179456038, 15376369807336137918, 9353401887418425164,      # Element 3
    10412156313889373274, 3591314333206605595, 4803765269341221341,      # Element 4
    5033644672118612008, 7219991869283703241, 5001325043480604972,       # Element 5
    15948725184182871707, 15522723472618604735, 9907990838610836609,     # Element 6
    9470319161037913018, 17268345614200704752, 3654202055025360269,      # Element 7
    13100866642308064996, 17341759162511200959, 7319519320015423486,     # Element 8
    12084612760618137204, 7454792536055106792, 2659215907969302634,      # Element 9
    197416323470751095, 4767691990383163790, 6429445215664945539,        # Element 10
    15599679625630644600, 10704837000018217994, 14619111704412444750,    # Element 11
    15879145559683750116, 10806891138089601907, 6398240568623563867,     # Element 12
    14868897281419723370, 924837540248075600, 13479315813292439965,      # Element 13
    11860535291544263725, 9525832088029768261, 1056937185540367752,      # Element 14
    9242712766516462579, 3678973432283065878, 6246989568381022564,       # Element 15
    3986523664812881640, 15175234450602730740, 12905501262580237230,     # Element 16
    10705369138838456284, 10702382605332658692, 7629631655928945403,     # Element 17
    9262724744720817643, 15887564237035175821, 9968888681798946160,      # Element 18
    5157862280797414087, 15846645308041041927, 14044103179964922718,     # Element 19
    7541286177638753403, 9959371914069074779, 4742210589618127119,       # Element 20
    8945694359776425999, 5857016951276199961, 15956542795161863896,      # Element 21
    5097832630748515311, 2805433767902235137, 14156619039058681370,      # Element 22
    5359383358562328040, 10696011412389368858, 14259441144882985156,     # Element 23
    10562871434525600334, 2950782197354151668, 5287728438265398672,      # Element 24
    4179399445730488462, 699779008451773962, 6724499112382485659,        # Element 25
    17736390686191080988, 6782110977108258102, 9204523493687027062,      # Element 26
    6821914454530953253, 14820845627046358896, 12893257468286467420,     # Element 27
    4125657212508052294, 11795123797861066031, 2646944690559974986,      # Element 28
    8386604238912971683, 12635389879257946431, 788283794214107156,       # Element 29
    9665347948841523245, 10612365642456120293, 15820909052152390155,     # Element 30
    5010386192355180209, 7162751007858926896, 2839955806073769762,       # Element 31
]

# Expected nonce
LOOKUP2_12_EXPECTED_NONCE = 33180

# Expected Poseidon2 hash of final polynomial (4 Goldilocks elements)
LOOKUP2_12_EXPECTED_FINAL_POL_HASH = [
    16724271852290172135,
    167123672743506872,
    85739372367436007,
    15077976899410783742,
]


# ============================================================================
# Helper functions
# ============================================================================

def get_config(air_name: str) -> dict:
    """Get configuration for given AIR."""
    if air_name.lower() in ['simple', 'simpleleft', 'simple_left']:
        return SIMPLE_LEFT_CONFIG
    elif air_name.lower() in ['lookup', 'lookup2_12', 'lookup2']:
        return LOOKUP2_12_CONFIG
    else:
        raise ValueError(f"Unknown AIR: {air_name}")


def get_expected_final_pol(air_name: str) -> list:
    """Get expected final polynomial for given AIR."""
    if air_name.lower() in ['simple', 'simpleleft', 'simple_left']:
        return SIMPLE_LEFT_EXPECTED_FINAL_POL
    elif air_name.lower() in ['lookup', 'lookup2_12', 'lookup2']:
        return LOOKUP2_12_EXPECTED_FINAL_POL
    else:
        raise ValueError(f"Unknown AIR: {air_name}")


def get_expected_nonce(air_name: str) -> int:
    """Get expected nonce for given AIR."""
    if air_name.lower() in ['simple', 'simpleleft', 'simple_left']:
        return SIMPLE_LEFT_EXPECTED_NONCE
    elif air_name.lower() in ['lookup', 'lookup2_12', 'lookup2']:
        return LOOKUP2_12_EXPECTED_NONCE
    else:
        raise ValueError(f"Unknown AIR: {air_name}")


def get_expected_hash(air_name: str) -> list:
    """Get expected Poseidon2 hash of final polynomial for given AIR."""
    if air_name.lower() in ['simple', 'simpleleft', 'simple_left']:
        return SIMPLE_LEFT_EXPECTED_FINAL_POL_HASH
    elif air_name.lower() in ['lookup', 'lookup2_12', 'lookup2']:
        return LOOKUP2_12_EXPECTED_FINAL_POL_HASH
    else:
        raise ValueError(f"Unknown AIR: {air_name}")


def get_fri_input_polynomial(air_name: str) -> list:
    """Get FRI input polynomial for given AIR."""
    if air_name.lower() in ['simple', 'simpleleft', 'simple_left']:
        return SIMPLE_LEFT_FRI_INPUT_POLYNOMIAL
    elif air_name.lower() in ['lookup', 'lookup2_12', 'lookup2']:
        vectors = _load_lookup2_12_vectors()
        return vectors['inputs']['fri_input_polynomial']
    else:
        raise ValueError(f"FRI input polynomial not available for AIR: {air_name}")


def get_fri_input_hash(air_name: str) -> list:
    """Get FRI input polynomial hash for given AIR."""
    if air_name.lower() in ['simple', 'simpleleft', 'simple_left']:
        return SIMPLE_LEFT_FRI_INPUT_POL_HASH
    elif air_name.lower() in ['lookup', 'lookup2_12', 'lookup2']:
        vectors = _load_lookup2_12_vectors()
        return vectors['inputs']['fri_input_pol_hash']
    else:
        raise ValueError(f"FRI input hash not available for AIR: {air_name}")


def get_fri_challenges(air_name: str) -> list:
    """Get FRI folding challenges for given AIR."""
    if air_name.lower() in ['simple', 'simpleleft', 'simple_left']:
        return SIMPLE_LEFT_FRI_CHALLENGES
    elif air_name.lower() in ['lookup', 'lookup2_12', 'lookup2']:
        vectors = _load_lookup2_12_vectors()
        return vectors['inputs']['fri_challenges']
    else:
        raise ValueError(f"FRI challenges not available for AIR: {air_name}")


def get_grinding_challenge(air_name: str) -> list:
    """Get grinding challenge for given AIR."""
    if air_name.lower() in ['simple', 'simpleleft', 'simple_left']:
        return SIMPLE_LEFT_GRINDING_CHALLENGE
    elif air_name.lower() in ['lookup', 'lookup2_12', 'lookup2']:
        vectors = _load_lookup2_12_vectors()
        return vectors['inputs']['grinding_challenge']
    else:
        raise ValueError(f"Grinding challenge not available for AIR: {air_name}")


def get_fri_queries(air_name: str) -> list:
    """
    Get FRI query indices for given AIR.

    These are the indices derived from grinding_challenge + nonce
    via transcript.getPermutations(n_queries, domain_bits).
    """
    if air_name.lower() in ['simple', 'simpleleft', 'simple_left']:
        if SIMPLE_LEFT_FRI_QUERIES is None:
            raise ValueError(
                "SimpleLeft FRI queries not available. "
                "Regenerate vectors with ./generate-fri-vectors.sh simple"
            )
        return SIMPLE_LEFT_FRI_QUERIES
    elif air_name.lower() in ['lookup', 'lookup2_12', 'lookup2']:
        vectors = _load_lookup2_12_vectors()
        fri_queries = vectors['inputs'].get('fri_queries', [])
        if not fri_queries:
            raise ValueError(
                "Lookup2_12 FRI queries not available. "
                "Regenerate vectors with ./generate-fri-vectors.sh lookup"
            )
        return fri_queries
    else:
        raise ValueError(f"FRI queries not available for AIR: {air_name}")


def get_fri_steps(air_name: str) -> list:
    """Get FRI steps configuration for given AIR."""
    if air_name.lower() in ['simple', 'simpleleft', 'simple_left']:
        return SIMPLE_LEFT_CONFIG['fri_steps']
    elif air_name.lower() in ['lookup', 'lookup2_12', 'lookup2']:
        vectors = _load_lookup2_12_vectors()
        return vectors['metadata']['fri_steps']
    else:
        raise ValueError(f"FRI steps not available for AIR: {air_name}")


def get_n_bits_ext(air_name: str) -> int:
    """Get extended domain bits for given AIR."""
    if air_name.lower() in ['simple', 'simpleleft', 'simple_left']:
        return SIMPLE_LEFT_CONFIG['n_bits_ext']
    elif air_name.lower() in ['lookup', 'lookup2_12', 'lookup2']:
        vectors = _load_lookup2_12_vectors()
        return vectors['metadata']['n_bits_ext']
    else:
        raise ValueError(f"n_bits_ext not available for AIR: {air_name}")


def get_merkle_roots(air_name: str) -> list:
    """Get expected Merkle roots at each FRI step."""
    if air_name.lower() in ['lookup', 'lookup2_12', 'lookup2']:
        vectors = _load_lookup2_12_vectors()
        return vectors.get('intermediates', {}).get('merkle_roots', [])
    else:
        raise ValueError(f"Merkle roots not available for AIR: {air_name}")


def get_poly_hashes_after_fold(air_name: str) -> list:
    """Get expected polynomial hashes after each FRI fold step."""
    if air_name.lower() in ['lookup', 'lookup2_12', 'lookup2']:
        vectors = _load_lookup2_12_vectors()
        return vectors.get('intermediates', {}).get('poly_hashes_after_fold', [])
    else:
        raise ValueError(f"Polynomial hashes not available for AIR: {air_name}")


def get_transcript_state(air_name: str) -> dict:
    """
    Get transcript state at FRI start for given AIR.

    Returns dict with:
        - state: 16-element array (sponge state)
        - out: 16-element array (output buffer)
        - out_cursor: current output cursor position
        - pending_cursor: current pending cursor position
    """
    if air_name.lower() in ['lookup', 'lookup2_12', 'lookup2']:
        vectors = _load_lookup2_12_vectors()
        inputs = vectors.get('inputs', {})
        return {
            'state': inputs.get('transcript_state', []),
            'out': inputs.get('transcript_out', []),
            'out_cursor': inputs.get('transcript_out_cursor', 0),
            'pending_cursor': inputs.get('transcript_pending_cursor', 0),
        }
    else:
        raise ValueError(f"Transcript state not available for AIR: {air_name}")
