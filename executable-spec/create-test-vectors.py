#!/usr/bin/env python3
"""
Extract FRI test vectors from C++ capture output.

This script parses the stderr output from proof generation when
CAPTURE_FRI_VECTORS is enabled, and saves it as JSON files for
Python test consumption.

Usage:
    python extract_vectors.py <captured_file> <output_json>

Example:
    python extract_vectors.py fri_input_vectors.txt simple_left_vectors.json
"""

import json
import re
import sys
from pathlib import Path
from typing import Optional


def parse_array_values(lines: list[str], start_idx: int) -> tuple[list[int], int]:
    """
    Parse array values from lines starting at start_idx.
    Returns (values, end_idx).

    C++ Reference: NO CORRESPONDING FUNCTION
                   (Python extraction utility)
    """
    values = []
    idx = start_idx

    while idx < len(lines):
        line = lines[idx].strip()

        # End of array
        if line.startswith('};'):
            return values, idx + 1

        # Skip comments and empty lines
        if not line or line.startswith('//'):
            idx += 1
            continue

        # Extract numeric values (handles both "123ULL," and "123ULL")
        matches = re.findall(r'(\d+)ULL', line)
        for m in matches:
            values.append(int(m))

        idx += 1

    return values, idx


def parse_nested_array(lines: list[str], start_idx: int) -> tuple[list[list[int]], int]:
    """
    Parse nested array values like FRI_CHALLENGES.
    Returns (values, end_idx).

    C++ Reference: NO CORRESPONDING FUNCTION
                   (Python parsing utility)
    """
    values = []
    idx = start_idx

    while idx < len(lines):
        line = lines[idx].strip()

        # End of array
        if line.startswith('}};'):
            return values, idx + 1

        # Skip comments and empty lines
        if not line or line.startswith('//'):
            idx += 1
            continue

        # Extract inner array: {val1, val2, val3}
        match = re.search(r'\{(\d+)ULL,\s*(\d+)ULL,\s*(\d+)ULL\}', line)
        if match:
            values.append([int(match.group(1)), int(match.group(2)), int(match.group(3))])

        idx += 1

    return values, idx


def parse_air_block(lines: list[str], start_idx: int) -> tuple[Optional[dict], int]:
    """
    Parse a single AIR block from the capture output.
    Returns (air_data, end_idx) or (None, end_idx) if parsing fails.

    C++ Reference: NO CORRESPONDING FUNCTION
                   (Python parsing utility)
    """
    air_data = {}
    idx = start_idx

    # Find AIR header
    while idx < len(lines):
        line = lines[idx].strip()
        if line.startswith('// AIR:'):
            # Parse: "// AIR: airgroup=0 air=2 instance=2"
            match = re.search(r'airgroup=(\d+)\s+air=(\d+)\s+instance=(\d+)', line)
            if match:
                air_data['airgroup'] = int(match.group(1))
                air_data['air'] = int(match.group(2))
                air_data['instance'] = int(match.group(3))
            idx += 1
            break
        idx += 1

    if 'air' not in air_data:
        return None, idx

    # Parse friPolSize
    while idx < len(lines):
        line = lines[idx].strip()
        if line.startswith('// friPolSize:'):
            match = re.search(r'friPolSize:\s*(\d+)', line)
            if match:
                air_data['fri_pol_size'] = int(match.group(1))
            idx += 1
            break
        if line.startswith('// === END'):
            return air_data, idx
        idx += 1

    # Parse arrays
    while idx < len(lines):
        line = lines[idx].strip()

        if line.startswith('// === END FRI INPUT VECTORS'):
            return air_data, idx + 1

        # FRI_INPUT_POLYNOMIAL
        if 'FRI_INPUT_POLYNOMIAL' in line and '=' in line:
            values, idx = parse_array_values(lines, idx + 1)
            air_data['fri_input_polynomial'] = values
            continue

        # FRI_INPUT_POL_HASH
        if 'FRI_INPUT_POL_HASH' in line and '=' in line:
            values, idx = parse_array_values(lines, idx + 1)
            air_data['fri_input_pol_hash'] = values
            continue

        # FRI_CHALLENGES (nested array)
        if 'FRI_CHALLENGES' in line and '=' in line:
            values, idx = parse_nested_array(lines, idx + 1)
            air_data['fri_challenges'] = values
            continue

        # GRINDING_CHALLENGE
        if 'GRINDING_CHALLENGE' in line and '=' in line:
            values, idx = parse_array_values(lines, idx + 1)
            air_data['grinding_challenge'] = values
            continue

        # FRI_QUERIES (query indices derived from grinding)
        if 'FRI_QUERIES' in line and '=' in line:
            values, idx = parse_array_values(lines, idx + 1)
            air_data['fri_queries'] = values
            continue

        idx += 1

    return air_data, idx


def parse_capture_file(filepath: str) -> list[dict]:
    """
    Parse a complete capture file containing multiple AIR blocks.

    C++ Reference: NO CORRESPONDING FUNCTION
                   (Python extraction utility)
    """
    with open(filepath, 'r') as f:
        content = f.read()

    lines = content.split('\n')
    airs = []
    idx = 0

    while idx < len(lines):
        line = lines[idx].strip()

        # Find start of AIR block
        if '=== FRI INPUT VECTORS (CAPTURE_FRI_VECTORS) ===' in line:
            air_data, idx = parse_air_block(lines, idx + 1)
            if air_data and 'fri_input_polynomial' in air_data:
                airs.append(air_data)
        else:
            idx += 1

    return airs


def load_proof_json(proof_path: str) -> dict:
    """
    Load the proof JSON file to extract output values.

    C++ Reference: NO CORRESPONDING FUNCTION
                   (Python test utility)
    """
    with open(proof_path, 'r') as f:
        proof = json.load(f)

    # Extract finalPol as flat list
    final_pol = []
    for elem in proof['finalPol']:
        for val in elem:
            final_pol.append(int(val))

    return {
        'final_pol': final_pol,
        'nonce': int(proof['nonce']),
    }


def create_test_vectors(capture_path: str, proof_path: str, air_id: int) -> dict:
    """
    Create complete test vectors for a specific AIR.

    C++ Reference: NO CORRESPONDING FUNCTION
                   (Python test utility)

    Args:
        capture_path: Path to fri_input_vectors.txt
        proof_path: Path to proof JSON file
        air_id: AIR ID to extract (e.g., 0 for SimpleLeft, 2 for Lookup2_12_2)
    """
    # Parse captured inputs
    airs = parse_capture_file(capture_path)

    # Find the specific AIR
    air_data = None
    for air in airs:
        if air['air'] == air_id:
            air_data = air
            break

    if air_data is None:
        raise ValueError(f"AIR {air_id} not found in capture file")

    # Load proof output
    proof_data = load_proof_json(proof_path)

    # Combine into test vectors
    return {
        'metadata': {
            'airgroup': air_data['airgroup'],
            'air': air_data['air'],
            'instance': air_data['instance'],
            'fri_pol_size': air_data.get('fri_pol_size', len(air_data['fri_input_polynomial'])),
        },
        'inputs': {
            'fri_input_polynomial': air_data['fri_input_polynomial'],
            'fri_input_pol_hash': air_data.get('fri_input_pol_hash', []),
            'fri_challenges': air_data.get('fri_challenges', []),
            'grinding_challenge': air_data.get('grinding_challenge', []),
            'fri_queries': air_data.get('fri_queries', []),
        },
        'outputs': {
            'final_pol': proof_data['final_pol'],
            'nonce': proof_data['nonce'],
        }
    }


def main():
    if len(sys.argv) < 4:
        print("Usage: python extract_vectors.py <capture_file> <proof_json> <output_json> [air_id]")
        print("Example: python extract_vectors.py fri_input_vectors.txt SimpleLeft_0.json simple_left_vectors.json 0")
        sys.exit(1)

    capture_file = sys.argv[1]
    proof_file = sys.argv[2]
    output_file = sys.argv[3]
    air_id = int(sys.argv[4]) if len(sys.argv) > 4 else 0

    print(f"Extracting vectors for AIR {air_id}...")
    print(f"  Capture file: {capture_file}")
    print(f"  Proof file: {proof_file}")
    print(f"  Output file: {output_file}")

    vectors = create_test_vectors(capture_file, proof_file, air_id)

    with open(output_file, 'w') as f:
        json.dump(vectors, f, indent=2)

    print(f"\nExtracted vectors:")
    print(f"  Input polynomial size: {len(vectors['inputs']['fri_input_polynomial'])} values")
    print(f"  Challenges: {len(vectors['inputs']['fri_challenges'])} steps")
    print(f"  Query indices: {len(vectors['inputs']['fri_queries'])} queries")
    print(f"  Output polynomial size: {len(vectors['outputs']['final_pol'])} values")
    print(f"  Nonce: {vectors['outputs']['nonce']}")
    print(f"\nSaved to {output_file}")


if __name__ == '__main__':
    main()
