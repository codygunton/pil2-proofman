#!/usr/bin/env python3
"""
Create JSON test vectors from C++ capture output.

This script parses the JSON blocks output by CAPTURE_TEST_VECTORS and combines
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


def parse_all_json_blocks(text: str, start_marker: str, end_marker: str) -> list[dict]:
    """Extract and parse ALL JSON blocks between markers."""
    pattern = re.escape(start_marker) + r'\s*(.*?)\s*' + re.escape(end_marker)
    results = []
    for match in re.finditer(pattern, text, re.DOTALL):
        try:
            results.append(json.loads(match.group(1)))
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON block: {e}", file=sys.stderr)
    return results


def parse_capture_output(capture_text: str, instance: int | None = None) -> dict:
    """
    Parse JSON blocks from C++ CAPTURE_TEST_VECTORS stderr output.

    Args:
        capture_text: Raw stderr output from C++ with CAPTURE_TEST_VECTORS
        instance: If specified, filter to only this instance number

    Returns dict with all captured data merged together.
    """
    # Parse all gen_proof blocks and find matching instance
    gen_proof_blocks = parse_all_json_blocks(
        capture_text,
        '=== FRI_GEN_PROOF_JSON_START ===',
        '=== FRI_GEN_PROOF_JSON_END ==='
    )

    # Find the block matching requested instance (or first if not specified)
    gen_proof_data = None
    block_index = 0
    for i, block in enumerate(gen_proof_blocks):
        if instance is None or block.get('instance') == instance:
            gen_proof_data = block
            block_index = i
            break

    if gen_proof_data is None and gen_proof_blocks:
        gen_proof_data = gen_proof_blocks[0]
        block_index = 0

    result = {}
    if gen_proof_data:
        result.update(gen_proof_data)

    # Parse prover inputs blocks (witness trace, public inputs, etc.)
    prover_inputs_blocks = parse_all_json_blocks(
        capture_text,
        '=== STARK_PROVER_INPUTS_JSON_START ===',
        '=== STARK_PROVER_INPUTS_JSON_END ==='
    )
    if block_index < len(prover_inputs_blocks):
        result.update(prover_inputs_blocks[block_index])

    # Parse fri_pcs blocks - use same index as gen_proof
    fri_pcs_blocks = parse_all_json_blocks(
        capture_text,
        '=== FRI_PCS_JSON_START ===',
        '=== FRI_PCS_JSON_END ==='
    )
    if block_index < len(fri_pcs_blocks):
        result.update(fri_pcs_blocks[block_index])

    # Parse FRI queries blocks - use same index
    queries_blocks = parse_all_json_blocks(
        capture_text,
        '=== FRI_QUERIES_JSON_START ===',
        '=== FRI_QUERIES_JSON_END ==='
    )
    if block_index < len(queries_blocks):
        result.update(queries_blocks[block_index])

    # Parse STARK stage blocks - use same index
    stage1_blocks = parse_all_json_blocks(
        capture_text,
        '=== STARK_STAGE1_JSON_START ===',
        '=== STARK_STAGE1_JSON_END ==='
    )
    if block_index < len(stage1_blocks):
        result.update(stage1_blocks[block_index])

    stage2_blocks = parse_all_json_blocks(
        capture_text,
        '=== STARK_STAGE2_JSON_START ===',
        '=== STARK_STAGE2_JSON_END ==='
    )
    if block_index < len(stage2_blocks):
        result.update(stage2_blocks[block_index])

    stageq_blocks = parse_all_json_blocks(
        capture_text,
        '=== STARK_STAGEQ_JSON_START ===',
        '=== STARK_STAGEQ_JSON_END ==='
    )
    if block_index < len(stageq_blocks):
        result.update(stageq_blocks[block_index])

    evals_blocks = parse_all_json_blocks(
        capture_text,
        '=== STARK_EVALS_JSON_START ===',
        '=== STARK_EVALS_JSON_END ==='
    )
    if block_index < len(evals_blocks):
        result.update(evals_blocks[block_index])

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

    Uses width=16 to match the C++ implementation's sponge width.

    Returns list of 4 uint64 values.
    """
    try:
        from poseidon2_ffi import linear_hash
        return list(linear_hash(final_pol, width=16))
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
        'num_fri_round_log_sizes': len(steps),
        'fri_round_log_sizes': [step.get('nBits') for step in steps],
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
            'num_fri_round_log_sizes': starkinfo['num_fri_round_log_sizes'],
            'fri_round_log_sizes': starkinfo['fri_round_log_sizes'],
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

    # Add prover inputs (for full e2e testing)
    if capture_data.get('witness_trace'):
        result['inputs']['witness_trace'] = capture_data['witness_trace']
    if capture_data.get('public_inputs'):
        result['inputs']['public_inputs'] = capture_data['public_inputs']
    if capture_data.get('global_challenge'):
        result['inputs']['global_challenge'] = capture_data['global_challenge']
    if capture_data.get('const_pols'):
        result['inputs']['const_pols'] = capture_data['const_pols']
    if capture_data.get('transcript_state_step0'):
        result['inputs']['transcript_state_step0'] = capture_data['transcript_state_step0']
    if capture_data.get('n_cols_stage1'):
        result['inputs']['n_cols_stage1'] = capture_data['n_cols_stage1']
    if capture_data.get('n_constants'):
        result['inputs']['n_constants'] = capture_data['n_constants']

    # Add intermediates if present
    intermediates = {}
    if capture_data.get('merkle_roots'):
        intermediates['merkle_roots'] = capture_data['merkle_roots']
    if capture_data.get('poly_hashes_after_fold'):
        intermediates['poly_hashes_after_fold'] = capture_data['poly_hashes_after_fold']
    if capture_data.get('query_proof_siblings'):
        intermediates['query_proof_siblings'] = capture_data['query_proof_siblings']

    # Add STARK stage intermediates
    if capture_data.get('root1'):
        intermediates['root1'] = capture_data['root1']
    if capture_data.get('trace_extended_hash'):
        intermediates['trace_extended_hash'] = capture_data['trace_extended_hash']
    if capture_data.get('root2'):
        intermediates['root2'] = capture_data['root2']
    if capture_data.get('challenges_stage2'):
        intermediates['challenges_stage2'] = capture_data['challenges_stage2']
    if capture_data.get('air_values_stage2'):
        intermediates['air_values_stage2'] = capture_data['air_values_stage2']
    if capture_data.get('rootQ'):
        intermediates['rootQ'] = capture_data['rootQ']
    if capture_data.get('quotient_poly_hash'):
        intermediates['quotient_poly_hash'] = capture_data['quotient_poly_hash']
    if capture_data.get('challenges_stageQ'):
        intermediates['challenges_stageQ'] = capture_data['challenges_stageQ']
    if capture_data.get('evals'):
        intermediates['evals'] = capture_data['evals']
    if capture_data.get('LEv_hash'):
        intermediates['LEv_hash'] = capture_data['LEv_hash']
    if capture_data.get('xi_challenge'):
        intermediates['xi_challenge'] = capture_data['xi_challenge']
    if capture_data.get('challenges_fri'):
        intermediates['challenges_fri'] = capture_data['challenges_fri']

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
        help='Path to file containing C++ CAPTURE_TEST_VECTORS stderr output'
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
    parser.add_argument(
        '--instance',
        type=int,
        default=None,
        help='Instance number to extract (for multi-AIR proofs)'
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
    capture_data = parse_capture_output(capture_text, instance=args.instance)

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
    print("\nSummary:")
    print(f"  AIR: {args.air_name}")
    print(f"  FRI input polynomial size: {len(test_vectors['inputs']['fri_input_polynomial'])}")
    print(f"  Final polynomial size: {len(test_vectors['expected']['final_pol'])}")
    print(f"  Nonce: {test_vectors['expected']['nonce']}")
    print(f"  FRI challenges: {len(test_vectors['inputs']['fri_challenges'])}")
    print(f"  FRI queries: {len(test_vectors['inputs']['fri_queries'])}")
    if test_vectors['expected']['final_pol_hash']:
        print(f"  Final pol hash: [{', '.join(str(h) for h in test_vectors['expected']['final_pol_hash'])}]")

    # Prover inputs summary
    if test_vectors['inputs'].get('witness_trace'):
        print(f"  Witness trace size: {len(test_vectors['inputs']['witness_trace'])}")
    if test_vectors['inputs'].get('const_pols'):
        print(f"  Constant polynomials size: {len(test_vectors['inputs']['const_pols'])}")
    if test_vectors['inputs'].get('public_inputs'):
        print(f"  Public inputs: {len(test_vectors['inputs']['public_inputs'])}")
    if test_vectors['inputs'].get('transcript_state_step0'):
        print(f"  Transcript state captured: Yes")


if __name__ == '__main__':
    main()
