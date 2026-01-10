#!/usr/bin/env python3
"""
Extract FRI test vectors from proof JSON and generate C++ header.

Usage:
    python extract_fri_vectors.py <proof.json> [output.hpp]

Example:
    python extract_fri_vectors.py SimpleLeft_0.json fri_pinning_vectors.hpp
"""

import json
import hashlib
import sys
import os


def extract_vectors(proof_path: str) -> dict:
    """Extract FRI-related vectors from proof JSON."""
    with open(proof_path) as f:
        proof = json.load(f)

    # Extract finalPol as flat array
    final_pol = []
    for elem in proof['finalPol']:
        final_pol.extend([int(v) for v in elem])

    # Compute checksum
    checksum_data = ','.join(str(v) for v in final_pol)
    checksum = hashlib.sha256(checksum_data.encode()).hexdigest()

    return {
        'final_pol': final_pol,
        'nonce': int(proof['nonce']),
        'checksum': checksum,
        'num_cubic_elements': len(proof['finalPol']),
        'proof_name': os.path.splitext(os.path.basename(proof_path))[0]
    }


def generate_cpp_header(vectors: dict, output_path: str = None):
    """Generate C++ header with test vectors."""
    lines = [
        '#ifndef FRI_PINNING_VECTORS_HPP',
        '#define FRI_PINNING_VECTORS_HPP',
        '',
        '#include <array>',
        '#include <cstdint>',
        '',
        '/**',
        ' * FRI Pinning Test Vectors',
        ' *',
        f' * Auto-generated from {vectors["proof_name"]}.json',
        ' * Run extract_fri_vectors.py to regenerate if FRI output changes.',
        ' */',
        'namespace FriPinningVectors {',
        '',
        f'namespace {vectors["proof_name"].replace("_", "")} {{',
        '',
    ]

    # finalPol array
    n_elements = len(vectors['final_pol'])
    lines.append(f'    constexpr std::array<uint64_t, {n_elements}> EXPECTED_FINAL_POL = {{')

    for i in range(0, n_elements, 3):
        elem_idx = i // 3
        lines.append(f'        // Element {elem_idx}')
        for j in range(3):
            idx = i + j
            suffix = ',' if idx < n_elements - 1 else ''
            lines.append(f'        {vectors["final_pol"][idx]}ULL{suffix}')

    lines.append('    };')
    lines.append('')

    # nonce
    lines.append(f'    constexpr uint64_t EXPECTED_NONCE = {vectors["nonce"]};')
    lines.append('')

    # checksum
    lines.append(f'    constexpr const char* EXPECTED_FINAL_POL_CHECKSUM =')
    lines.append(f'        "{vectors["checksum"]}";')
    lines.append('')

    lines.extend([
        f'}} // namespace {vectors["proof_name"].replace("_", "")}',
        '',
        '} // namespace FriPinningVectors',
        '',
        '#endif // FRI_PINNING_VECTORS_HPP',
    ])

    output = '\n'.join(lines)

    if output_path:
        with open(output_path, 'w') as f:
            f.write(output)
        print(f'Generated: {output_path}')
    else:
        print(output)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    proof_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None

    if not os.path.exists(proof_path):
        print(f'Error: File not found: {proof_path}')
        sys.exit(1)

    vectors = extract_vectors(proof_path)

    print(f'Extracted vectors from: {proof_path}')
    print(f'  finalPol: {vectors["num_cubic_elements"]} cubic elements ({len(vectors["final_pol"])} Goldilocks)')
    print(f'  nonce: {vectors["nonce"]}')
    print(f'  checksum: {vectors["checksum"][:16]}...')
    print()

    generate_cpp_header(vectors, output_path)


if __name__ == '__main__':
    main()
