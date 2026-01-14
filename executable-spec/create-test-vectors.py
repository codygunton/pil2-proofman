#!/usr/bin/env python3
"""
Create JSON test vectors from C++ capture output.

This script parses the JSON blocks output by CAPTURE_FRI_VECTORS and combines
them with data from the proof JSON and starkinfo files to produce complete
test vector JSON files for the Python executable specification.

Usage:
    python create-test-vectors.py \
        --capture-file <stderr_output.txt> \
        --proof-file <proof.json> \
        --starkinfo-file <.starkinfo.json> \
        --air-name <SimpleLeft|Lookup2_12> \
        --output <test-data/simple-left.json>
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


def parse_json_block(text: str, start_marker: str, end_marker: str) -> dict | None:
    """Extract and parse a JSON block between markers."""
    pattern = re.escape(start_marker) + r'\s*(.*?)\s*' + re.escape(end_marker)
    match = re.search(pattern, text, re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group(1))
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON block between {start_marker} and {end_marker}: {e}", file=sys.stderr)
        return None


def parse_capture_output(capture_text: str) -> dict:
    """
    Parse JSON blocks from C++ CAPTURE_FRI_VECTORS stderr output.

    Returns dict with all captured data merged together.
    """
    result = {}

    # Parse gen_proof.hpp output (FRI input polynomial)
    gen_proof_data = parse_json_block(
        capture_text,
        '=== FRI_GEN_PROOF_JSON_START ===',
        '=== FRI_GEN_PROOF_JSON_END ==='
    )
    if gen_proof_data:
        result.update(gen_proof_data)

    # Parse fri_pcs.hpp output (challenges, transcript state, etc.)
    fri_pcs_data = parse_json_block(
        capture_text,
        '=== FRI_PCS_JSON_START ===',
        '=== FRI_PCS_JSON_END ==='
    )
    if fri_pcs_data:
        result.update(fri_pcs_data)

    # Parse FRI queries output
    queries_data = parse_json_block(
        capture_text,
        '=== FRI_QUERIES_JSON_START ===',
        '=== FRI_QUERIES_JSON_END ==='
    )
    if queries_data:
        result.update(queries_data)

    return result


def extract_from_proof(proof_path: Path) -> dict:
    """
    Extract finalPol and nonce from proof JSON file.

    Returns dict with:
        - final_pol: flattened list of uint64 values (as integers)
        - nonce: int
    """
    with open(proof_path) as f:
        proof = json.load(f)

    # finalPol is an array of cubic extension elements [[a,b,c], [d,e,f], ...]
    # Flatten to [a,b,c,d,e,f,...] and ensure all values are integers
    final_pol_nested = proof.get('finalPol', [])
    final_pol = []
    for elem in final_pol_nested:
        if isinstance(elem, list):
            final_pol.extend(int(v) for v in elem)
        else:
            final_pol.append(int(elem))

    return {
        'final_pol': final_pol,
        'nonce': int(proof.get('nonce', 0)),
    }


def compute_final_pol_hash(final_pol: list) -> list:
    """
    Compute Poseidon2 hash of final polynomial using the Rust FFI.

    Returns list of 4 uint64 values.
    """
    try:
        from poseidon2_ffi import linear_hash
        return list(linear_hash(final_pol))
    except ImportError:
        print("Warning: poseidon2 FFI not available, skipping hash computation", file=sys.stderr)
        return []


def compute_checksum(final_pol: list) -> str:
    """Compute SHA256 checksum of final polynomial values."""
    data = ','.join(str(v) for v in final_pol)
    return hashlib.sha256(data.encode()).hexdigest()


def load_starkinfo(starkinfo_path: Path) -> dict:
    """
    Load AIR configuration from .starkinfo.json file.

    Returns dict with FRI configuration parameters.
    """
    with open(starkinfo_path) as f:
        starkinfo = json.load(f)

    stark_struct = starkinfo.get('starkStruct', {})
    steps = stark_struct.get('steps', [])

    return {
        'name': starkinfo.get('name', ''),
        'n_bits': stark_struct.get('nBits'),
        'n_bits_ext': stark_struct.get('nBitsExt'),
        'n_queries': stark_struct.get('nQueries'),
        'pow_bits': stark_struct.get('powBits'),
        'merkle_arity': stark_struct.get('merkleTreeArity'),
        'transcript_arity': stark_struct.get('transcriptArity'),
        'last_level_verification': stark_struct.get('lastLevelVerification'),
        'hash_commits': stark_struct.get('hashCommits'),
        'merkle_tree_custom': stark_struct.get('merkleTreeCustom'),
        'num_fri_steps': len(steps),
        'fri_steps': [step.get('nBits') for step in steps],
    }


def build_test_vectors(
    capture_data: dict,
    proof_data: dict,
    starkinfo: dict,
    air_name: str,
) -> dict:
    """
    Assemble final JSON structure matching test_vectors.py schema.
    """
    # For final_pol_hash, if final_pol == fri_input_polynomial, use the captured hash
    # This avoids hash function mismatch between Python FFI and C++ implementation
    fri_input_pol = capture_data.get('fri_input_polynomial', [])
    final_pol = proof_data['final_pol']
    fri_input_pol_hash = capture_data.get('fri_input_pol_hash', [])

    if final_pol == fri_input_pol and fri_input_pol_hash:
        # No folding happened, use captured hash
        final_pol_hash = fri_input_pol_hash
    else:
        # Compute hash using Python FFI (may differ from C++ for some cases)
        final_pol_hash = compute_final_pol_hash(final_pol)

    final_pol_checksum = compute_checksum(final_pol)

    result = {
        'metadata': {
            'air_name': air_name,
            'n_bits': starkinfo['n_bits'],
            'n_bits_ext': starkinfo['n_bits_ext'],
            'n_queries': starkinfo['n_queries'],
            'pow_bits': starkinfo['pow_bits'],
            'merkle_arity': starkinfo['merkle_arity'],
            'transcript_arity': starkinfo['transcript_arity'],
            'last_level_verification': starkinfo['last_level_verification'],
            'hash_commits': starkinfo['hash_commits'],
            'merkle_tree_custom': starkinfo['merkle_tree_custom'],
            'num_fri_steps': starkinfo['num_fri_steps'],
            'fri_steps': starkinfo['fri_steps'],
        },
        'expected': {
            'final_pol': proof_data['final_pol'],
            'nonce': proof_data['nonce'],
            'final_pol_hash': final_pol_hash,
            'final_pol_checksum': final_pol_checksum,
        },
        'inputs': {
            'fri_input_polynomial': capture_data.get('fri_input_polynomial', []),
            'fri_input_pol_hash': capture_data.get('fri_input_pol_hash', []),
            'fri_challenges': capture_data.get('fri_challenges', []),
            'grinding_challenge': capture_data.get('grinding_challenge', []),
            'fri_queries': capture_data.get('fri_queries', []),
        },
    }

    # Add optional fields if present
    if capture_data.get('transcript_state'):
        result['inputs']['transcript_state'] = capture_data['transcript_state']
    if capture_data.get('transcript_out'):
        result['inputs']['transcript_out'] = capture_data['transcript_out']
    if 'transcript_out_cursor' in capture_data:
        result['inputs']['transcript_out_cursor'] = capture_data['transcript_out_cursor']
    if 'transcript_pending_cursor' in capture_data:
        result['inputs']['transcript_pending_cursor'] = capture_data['transcript_pending_cursor']

    # Add intermediates if present
    intermediates = {}
    if capture_data.get('merkle_roots'):
        intermediates['merkle_roots'] = capture_data['merkle_roots']
    if capture_data.get('poly_hashes_after_fold'):
        intermediates['poly_hashes_after_fold'] = capture_data['poly_hashes_after_fold']
    if capture_data.get('query_proof_siblings'):
        intermediates['query_proof_siblings'] = capture_data['query_proof_siblings']

    if intermediates:
        result['intermediates'] = intermediates

    # Add extra metadata from capture if available
    if capture_data.get('airgroup') is not None:
        result['metadata']['airgroup'] = capture_data['airgroup']
    if capture_data.get('air') is not None:
        result['metadata']['air'] = capture_data['air']
    if capture_data.get('instance') is not None:
        result['metadata']['instance'] = capture_data['instance']
    if capture_data.get('fri_pol_size') is not None:
        result['metadata']['fri_pol_size'] = capture_data['fri_pol_size']

    return result


def main():
    parser = argparse.ArgumentParser(
        description='Create JSON test vectors from C++ capture output'
    )
    parser.add_argument(
        '--capture-file',
        type=Path,
        required=True,
        help='Path to file containing C++ CAPTURE_FRI_VECTORS stderr output'
    )
    parser.add_argument(
        '--proof-file',
        type=Path,
        required=True,
        help='Path to proof JSON file'
    )
    parser.add_argument(
        '--starkinfo-file',
        type=Path,
        required=True,
        help='Path to .starkinfo.json file'
    )
    parser.add_argument(
        '--air-name',
        type=str,
        required=True,
        help='AIR name (e.g., SimpleLeft, Lookup2_12)'
    )
    parser.add_argument(
        '--output',
        type=Path,
        required=True,
        help='Output path for JSON test vectors'
    )

    args = parser.parse_args()

    # Validate input files exist
    if not args.capture_file.exists():
        print(f"Error: Capture file not found: {args.capture_file}", file=sys.stderr)
        sys.exit(1)
    if not args.proof_file.exists():
        print(f"Error: Proof file not found: {args.proof_file}", file=sys.stderr)
        sys.exit(1)
    if not args.starkinfo_file.exists():
        print(f"Error: Starkinfo file not found: {args.starkinfo_file}", file=sys.stderr)
        sys.exit(1)

    # Parse capture output
    print(f"Parsing capture output from {args.capture_file}...")
    with open(args.capture_file) as f:
        capture_text = f.read()
    capture_data = parse_capture_output(capture_text)

    if not capture_data:
        print("Warning: No capture data found in stderr output", file=sys.stderr)

    # Extract from proof
    print(f"Extracting data from proof {args.proof_file}...")
    proof_data = extract_from_proof(args.proof_file)

    # Load starkinfo
    print(f"Loading starkinfo from {args.starkinfo_file}...")
    starkinfo = load_starkinfo(args.starkinfo_file)

    # Build test vectors
    print("Building test vectors...")
    test_vectors = build_test_vectors(
        capture_data,
        proof_data,
        starkinfo,
        args.air_name,
    )

    # Write output
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, 'w') as f:
        json.dump(test_vectors, f, indent=2)

    print(f"Written test vectors to {args.output}")

    # Summary
    print(f"\nSummary:")
    print(f"  AIR: {args.air_name}")
    print(f"  FRI input polynomial size: {len(test_vectors['inputs']['fri_input_polynomial'])}")
    print(f"  Final polynomial size: {len(test_vectors['expected']['final_pol'])}")
    print(f"  Nonce: {test_vectors['expected']['nonce']}")
    print(f"  FRI challenges: {len(test_vectors['inputs']['fri_challenges'])}")
    print(f"  FRI queries: {len(test_vectors['inputs']['fri_queries'])}")
    if test_vectors['expected']['final_pol_hash']:
        print(f"  Final pol hash: [{', '.join(str(h) for h in test_vectors['expected']['final_pol_hash'])}]")


if __name__ == '__main__':
    main()
