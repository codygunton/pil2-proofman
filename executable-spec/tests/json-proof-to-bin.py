#!/usr/bin/env python3
"""Convert C++ JSON proof files to binary format expected by from_bytes_full().

Usage:
    python json-proof-to-bin.py \
        --proof-json /tmp/zisk-proof-out/proofs/Main_0.json \
        --starkinfo /path/to/Main.starkinfo.json \
        --output /tmp/Main_0.proof.bin

The C++ prover produces JSON proofs with string-encoded uint64 values.
The Python executable-spec expects binary proofs (flat little-endian uint64 arrays).
This script bridges the two formats.

Binary layout (matches from_bytes_full() in protocol/proof.py):
  Section 1:  airgroupValues  (each FF3 = 3 uint64)
  Section 2:  airValues       (stage 1 = 1 uint64, stage 2+ = 3 uint64)
  Section 3:  roots           (each hash = 4 uint64)
  Section 4:  evals           (each FF3 = 3 uint64)
  Section 5:  const tree query values
  Section 6:  const tree query merkle paths
  Section 7:  const tree last-level nodes
  Section 8:  custom commit trees (values, paths, last-levels per commit)
  Section 9:  stage trees cm1..cmQ (values, paths, last-levels per stage)
  Section 10: FRI step roots
  Section 11: FRI step query proofs (values, paths, last-levels per step)
  Section 12: finalPol        (each FF3 = 3 uint64)
  Section 13: nonce           (1 uint64)
"""

import argparse
import json
import math
import struct
import sys
from pathlib import Path

# Add parent directory to path so we can import protocol modules
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from protocol.stark_info import HASH_SIZE, StarkInfo

FIELD_EXTENSION_DEGREE = 3


def parse_int(s: str) -> int:
    """Parse a string value to uint64 int."""
    return int(s)


def convert_json_proof_to_binary(proof_json: dict, stark_info: StarkInfo) -> bytes:
    """Convert a C++ JSON proof dict to binary format matching from_bytes_full().

    Args:
        proof_json: Parsed JSON proof from C++ prover.
        stark_info: Parsed StarkInfo for this AIR.

    Returns:
        Binary proof as bytes (little-endian packed uint64 values).
    """
    values: list[int] = []

    # --- Configuration ---
    n_queries = stark_info.stark_struct.n_queries
    n_stages = stark_info.n_stages
    n_constants = len(stark_info.const_pols_map)
    merkle_arity = stark_info.stark_struct.merkle_tree_arity
    last_level_verification = stark_info.stark_struct.last_level_verification
    n_bits_ext = stark_info.stark_struct.n_bits_ext

    n_siblings = int(math.ceil(n_bits_ext / math.log2(merkle_arity))) - last_level_verification
    n_siblings_per_level = (merkle_arity - 1) * HASH_SIZE

    # --- Section 1: airgroupValues ---
    for av in proof_json.get("airgroupvalues", []):
        # Each entry is [c0, c1, c2] as strings -> 3 uint64
        for c in av[:FIELD_EXTENSION_DEGREE]:
            values.append(parse_int(c))

    # --- Section 2: airValues ---
    # C++ always writes FIELD_EXTENSION (3) uint64s per entry, regardless of stage
    air_values_json = proof_json.get("airvalues", [])
    for av in air_values_json:
        for c in av[:FIELD_EXTENSION_DEGREE]:
            values.append(parse_int(c))

    # --- Section 3: roots ---
    # n_stages + 1 roots (root1, root2, ..., rootN+1)
    for root_idx in range(1, n_stages + 2):
        root_key = f"root{root_idx}"
        root_data = proof_json[root_key]
        for h in root_data[:HASH_SIZE]:
            values.append(parse_int(h))

    # --- Section 4: evals ---
    for ev in proof_json["evals"]:
        for c in ev[:FIELD_EXTENSION_DEGREE]:
            values.append(parse_int(c))

    # --- Sections 5-7: const tree query proofs ---
    # s0_valsC, s0_siblingsC, s0_last_levelsC
    if n_constants > 0:
        # Section 5: const tree values
        s0_valsC = proof_json.get("s0_valsC", [])
        for q in range(n_queries):
            for col in range(n_constants):
                values.append(parse_int(s0_valsC[q][col]))

        # Section 6: const tree merkle paths
        s0_siblingsC = proof_json.get("s0_siblingsC", [])
        for q in range(n_queries):
            for lvl in range(n_siblings):
                # Each level is a list of n_siblings_per_level values
                for s in s0_siblingsC[q][lvl][:n_siblings_per_level]:
                    values.append(parse_int(s))

        # Section 7: const tree last-level nodes
        if last_level_verification != 0:
            s0_last_levelsC = proof_json.get("s0_last_levelsC", [])
            num_nodes = int(merkle_arity ** last_level_verification)
            for node_idx in range(num_nodes):
                # Each node is a hash [h0, h1, h2, h3]
                for h in s0_last_levelsC[node_idx][:HASH_SIZE]:
                    values.append(parse_int(h))

    # --- Section 8: custom commit trees ---
    for c, custom_commit in enumerate(stark_info.custom_commits):
        section_name = custom_commit.name + "0"
        n_custom_cols = stark_info.map_sections_n.get(section_name, 0)
        # JSON keys: s0_vals_{name}_{index}, e.g. s0_vals_rom_0
        name = custom_commit.name
        vals_key = f"s0_vals_{name}_{c}"
        sibs_key = f"s0_siblings_{name}_{c}"
        ll_key = f"s0_last_levels_{name}_{c}"

        s0_vals_cc = proof_json.get(vals_key, [])
        s0_siblings_cc = proof_json.get(sibs_key, [])
        s0_last_levels_cc = proof_json.get(ll_key, [])

        # Values
        for q in range(n_queries):
            for col in range(n_custom_cols):
                values.append(parse_int(s0_vals_cc[q][col]))

        # Merkle paths
        for q in range(n_queries):
            for lvl in range(n_siblings):
                for s in s0_siblings_cc[q][lvl][:n_siblings_per_level]:
                    values.append(parse_int(s))

        # Last levels
        if last_level_verification != 0:
            num_nodes = int(merkle_arity ** last_level_verification)
            for node_idx in range(num_nodes):
                for h in s0_last_levels_cc[node_idx][:HASH_SIZE]:
                    values.append(parse_int(h))

    # --- Section 9: stage trees (cm1, cm2, ..., cmQ) ---
    # Binary order: cm1 (stage 1), cm2 (stage 2), ..., cm{n_stages+1} (quotient)
    # JSON keys: s0_vals1, s0_vals2, s0_vals3 for cm1, cm2, cm3
    for stage_num in range(1, n_stages + 2):
        n_stage_cols = stark_info.map_sections_n.get(f"cm{stage_num}", 0)

        s0_vals = proof_json.get(f"s0_vals{stage_num}", [])
        s0_siblings = proof_json.get(f"s0_siblings{stage_num}", [])
        s0_last_levels = proof_json.get(f"s0_last_levels{stage_num}", [])

        # Values
        for q in range(n_queries):
            for col in range(n_stage_cols):
                values.append(parse_int(s0_vals[q][col]))

        # Merkle paths
        for q in range(n_queries):
            for lvl in range(n_siblings):
                for s in s0_siblings[q][lvl][:n_siblings_per_level]:
                    values.append(parse_int(s))

        # Last levels
        if last_level_verification != 0:
            num_nodes = int(merkle_arity ** last_level_verification)
            for node_idx in range(num_nodes):
                for h in s0_last_levels[node_idx][:HASH_SIZE]:
                    values.append(parse_int(h))

    # --- Section 10: FRI step roots ---
    n_fri_steps = len(stark_info.stark_struct.fri_fold_steps) - 1
    for step_idx in range(1, n_fri_steps + 1):
        fri_root = proof_json[f"s{step_idx}_root"]
        for h in fri_root[:HASH_SIZE]:
            values.append(parse_int(h))

    # --- Section 11: FRI step query proofs ---
    for step_idx in range(1, n_fri_steps + 1):
        prev_bits = stark_info.stark_struct.fri_fold_steps[step_idx - 1].domain_bits
        curr_bits = stark_info.stark_struct.fri_fold_steps[step_idx].domain_bits
        n_fri_cols = (1 << (prev_bits - curr_bits)) * FIELD_EXTENSION_DEGREE

        fri_vals = proof_json[f"s{step_idx}_vals"]
        fri_siblings = proof_json[f"s{step_idx}_siblings"]
        fri_last_levels = proof_json.get(f"s{step_idx}_last_levels", [])

        # Values
        for q in range(n_queries):
            for col in range(n_fri_cols):
                values.append(parse_int(fri_vals[q][col]))

        # Merkle paths
        n_siblings_fri = int(math.ceil(curr_bits / math.log2(merkle_arity))) - last_level_verification
        for q in range(n_queries):
            for lvl in range(n_siblings_fri):
                for s in fri_siblings[q][lvl][:n_siblings_per_level]:
                    values.append(parse_int(s))

        # Last levels
        if last_level_verification != 0:
            num_nodes = int(merkle_arity ** last_level_verification)
            for node_idx in range(num_nodes):
                for h in fri_last_levels[node_idx][:HASH_SIZE]:
                    values.append(parse_int(h))

    # --- Section 12: finalPol ---
    for pol_coef in proof_json["finalPol"]:
        for c in pol_coef[:FIELD_EXTENSION_DEGREE]:
            values.append(parse_int(c))

    # --- Section 13: nonce ---
    values.append(parse_int(proof_json["nonce"]))

    return struct.pack(f"<{len(values)}Q", *values)


def verify_round_trip(binary_data: bytes, stark_info: StarkInfo, proof_json: dict) -> bool:
    """Verify that the binary data round-trips through from_bytes_full().

    Loads the binary back with from_bytes_full() and checks key fields match
    the original JSON proof.

    Args:
        binary_data: The binary proof we just produced.
        stark_info: Parsed StarkInfo for this AIR.
        proof_json: The original JSON proof dict to compare against.

    Returns:
        True if verification passes, False otherwise.
    """
    from protocol.proof import from_bytes_full

    proof = from_bytes_full(binary_data, stark_info)
    errors: list[str] = []

    # C++ always writes FIELD_EXTENSION uint64s per air value entry
    expected_size = stark_info.proof_size * 8
    if len(binary_data) != expected_size:
        errors.append(
            f"Binary size mismatch: got {len(binary_data)} bytes "
            f"({len(binary_data) // 8} uint64s), "
            f"expected {expected_size} bytes ({stark_info.proof_size} uint64s)"
        )

    # Verify airgroupValues
    json_agv = proof_json.get("airgroupvalues", [])
    for i, av in enumerate(json_agv):
        expected = [parse_int(c) for c in av[:FIELD_EXTENSION_DEGREE]]
        if i < len(proof.airgroup_values) and proof.airgroup_values[i] != expected:
            errors.append(f"airgroup_values[{i}]: got {proof.airgroup_values[i]}, expected {expected}")

    # Verify airValues (all entries are FF3 in binary format)
    json_av = proof_json.get("airvalues", [])
    for i, av in enumerate(json_av):
        if i >= len(proof.air_values):
            errors.append(f"air_values[{i}]: missing from parsed proof")
            continue
        expected = [parse_int(c) for c in av[:FIELD_EXTENSION_DEGREE]]
        if proof.air_values[i] != expected:
            errors.append(f"air_values[{i}]: got {proof.air_values[i]}, expected {expected}")

    # Verify roots
    n_stages = stark_info.n_stages
    for root_idx in range(1, n_stages + 2):
        root_key = f"root{root_idx}"
        expected = [parse_int(h) for h in proof_json[root_key][:HASH_SIZE]]
        proof_root = proof.roots[root_idx - 1] if (root_idx - 1) < len(proof.roots) else []
        if proof_root != expected:
            errors.append(f"root{root_idx}: got {proof_root}, expected {expected}")

    # Verify evals
    json_evals = proof_json["evals"]
    for i, ev in enumerate(json_evals):
        expected = [parse_int(c) for c in ev[:FIELD_EXTENSION_DEGREE]]
        if i < len(proof.evals) and proof.evals[i] != expected:
            errors.append(f"evals[{i}]: got {proof.evals[i]}, expected {expected}")

    # Verify nonce
    expected_nonce = parse_int(proof_json["nonce"])
    if proof.nonce != expected_nonce:
        errors.append(f"nonce: got {proof.nonce}, expected {expected_nonce}")

    # Verify finalPol
    json_final_pol = proof_json["finalPol"]
    for i, pol_coef in enumerate(json_final_pol):
        expected = [parse_int(c) for c in pol_coef[:FIELD_EXTENSION_DEGREE]]
        if i < len(proof.fri.pol) and proof.fri.pol[i] != expected:
            errors.append(f"finalPol[{i}]: got {proof.fri.pol[i]}, expected {expected}")

    # Verify FRI roots
    n_fri_steps = len(stark_info.stark_struct.fri_fold_steps) - 1
    for step_idx in range(1, n_fri_steps + 1):
        expected = [parse_int(h) for h in proof_json[f"s{step_idx}_root"][:HASH_SIZE]]
        if (step_idx - 1) < len(proof.fri.trees_fri):
            actual = proof.fri.trees_fri[step_idx - 1].root
            if actual != expected:
                errors.append(f"FRI root s{step_idx}: got {actual}, expected {expected}")

    # Verify a sample of query values (first query, const tree)
    n_constants = len(stark_info.const_pols_map)
    if n_constants > 0:
        s0_valsC = proof_json.get("s0_valsC", [])
        if s0_valsC:
            const_tree_idx = n_stages + 1
            for col in range(n_constants):
                expected_val = parse_int(s0_valsC[0][col])
                actual = proof.fri.trees.pol_queries[0][const_tree_idx].v[col][0]
                if actual != expected_val:
                    errors.append(
                        f"const query[0] col[{col}]: got {actual}, expected {expected_val}"
                    )

    # Verify a sample of stage tree query values (first query, cm1)
    s0_vals1 = proof_json.get("s0_vals1", [])
    n_cm1_cols = stark_info.map_sections_n.get("cm1", 0)
    if s0_vals1 and n_cm1_cols > 0:
        for col in range(min(3, n_cm1_cols)):
            expected_val = parse_int(s0_vals1[0][col])
            actual = proof.fri.trees.pol_queries[0][0].v[col][0]
            if actual != expected_val:
                errors.append(
                    f"cm1 query[0] col[{col}]: got {actual}, expected {expected_val}"
                )

    if errors:
        print("Round-trip verification FAILED:")
        for err in errors:
            print(f"  - {err}")
        return False

    print("Round-trip verification PASSED")
    print(f"  Binary size: {len(binary_data)} bytes ({len(binary_data) // 8} uint64 values)")
    print(f"  Expected: {stark_info.proof_size} uint64 values")
    print(f"  Airgroup values: {len(proof.airgroup_values)}")
    print(f"  Air values: {len(proof.air_values)}")
    print(f"  Roots: {len(proof.roots)}")
    print(f"  Evals: {len(proof.evals)}")
    print(f"  FRI trees: {len(proof.fri.trees_fri)}")
    print(f"  Final pol coeffs: {len(proof.fri.pol)}")
    print(f"  Nonce: {proof.nonce}")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert C++ JSON proof to binary format for from_bytes_full()."
    )
    parser.add_argument(
        "--proof-json",
        required=True,
        help="Path to the C++ JSON proof file (e.g., Main_0.json)",
    )
    parser.add_argument(
        "--starkinfo",
        required=True,
        help="Path to the starkinfo JSON file (e.g., Main.starkinfo.json)",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path for the output binary proof file",
    )
    parser.add_argument(
        "--skip-verify",
        action="store_true",
        help="Skip round-trip verification after conversion",
    )
    args = parser.parse_args()

    # Load inputs
    print(f"Loading starkinfo: {args.starkinfo}")
    stark_info = StarkInfo.from_json(args.starkinfo)

    print(f"Loading JSON proof: {args.proof_json}")
    with open(args.proof_json) as f:
        proof_json = json.load(f)

    # Print configuration summary
    ss = stark_info.stark_struct
    print("Configuration:")
    print(f"  AIR name: {stark_info.name}")
    print(f"  n_stages: {stark_info.n_stages}")
    print(f"  n_constants: {len(stark_info.const_pols_map)}")
    print(f"  n_queries: {ss.n_queries}")
    print(f"  merkle_arity: {ss.merkle_tree_arity}")
    print(f"  last_level_verification: {ss.last_level_verification}")
    print(f"  FRI fold steps: {[s.domain_bits for s in ss.fri_fold_steps]}")
    print(f"  airgroup_values: {len(stark_info.airgroup_values_map)}")
    print(f"  air_values: {len(stark_info.air_values_map)}")
    print(f"  evals: {len(stark_info.ev_map)}")
    print(f"  custom_commits: {len(stark_info.custom_commits)}")
    print(f"  expected proof_size: {stark_info.proof_size} uint64 values")

    # Convert
    print("\nConverting JSON proof to binary...")
    binary_data = convert_json_proof_to_binary(proof_json, stark_info)

    # Write output
    print(f"Writing binary proof: {args.output} ({len(binary_data)} bytes)")
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(binary_data)

    # Verify round-trip
    if not args.skip_verify:
        print("\nVerifying round-trip through from_bytes_full()...")
        success = verify_round_trip(binary_data, stark_info, proof_json)
        if not success:
            sys.exit(1)

    print("\nDone.")


if __name__ == "__main__":
    main()
