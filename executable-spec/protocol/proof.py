"""STARK proof data structures and serialization."""

import json
import math
import struct
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from primitives.field import ff3_coeffs, ff3_to_flat_list
from protocol.stark_info import FIELD_EXTENSION_DEGREE, HASH_SIZE

# --- Type Aliases ---
Hash = list[int]  # Poseidon hash output [h0, h1, h2, h3]


# --- Proof Data Structures ---

@dataclass
class MerkleProof:
    """Merkle authentication path: leaf values and sibling hashes."""
    v: list[list[int]] = field(default_factory=list)   # Leaf values
    mp: list[list[int]] = field(default_factory=list)  # Sibling hashes per level


@dataclass
class ProofTree:
    """Merkle tree commitment with query proofs."""
    root: Hash = field(default_factory=list)
    last_levels: list[int] = field(default_factory=list)
    pol_queries: list[list[MerkleProof]] = field(default_factory=list)


@dataclass
class FriProof:
    """FRI opening proof: folding trees and final polynomial."""
    trees: ProofTree = field(default_factory=ProofTree)
    trees_fri: list[ProofTree] = field(default_factory=list)
    pol: list[list[int]] = field(default_factory=list)  # [[c0,c1,c2], ...]


@dataclass
class STARKProof:
    """Complete STARK proof for a single AIR.

    Contains all components needed to verify that a prover knows a valid
    execution trace satisfying the AIR constraints.

    Attributes:
        roots: Merkle roots for each stage commitment (stages 1 to n_stages+1).
               roots[0] is stage 1 (witness), roots[-1] is quotient polynomial.
        last_levels: Pre-verified Merkle nodes for last_level_verification optimization.
                     Indexed by tree: [stage_0, ..., stage_n, const_tree].
        evals: Polynomial evaluations at challenge point xi. Each entry is
               [c0, c1, c2] coefficients of an FF3 extension field element.
        airgroup_values: Values shared across all AIRs in an airgroup (e.g., gsum_result).
                         Used for cross-AIR boundary constraints. Each is [c0, c1, c2].
        air_values: Values specific to this individual AIR instance.
                    Stage 1 values are single FF, stage 2+ are FF3 [c0, c1, c2].
        custom_commits: Names of custom commitment schemes used (if any).
        fri: FRI protocol data - folding trees, query proofs, and final polynomial.
        nonce: Proof-of-work nonce satisfying the grinding constraint.
    """
    roots: list[Hash] = field(default_factory=list)
    last_levels: list[list[int]] = field(default_factory=list)
    evals: list[list[int]] = field(default_factory=list)
    airgroup_values: list[list[int]] = field(default_factory=list)
    air_values: list[list[int]] = field(default_factory=list)
    custom_commits: list[str] = field(default_factory=list)
    fri: FriProof = field(default_factory=FriProof)
    nonce: int = 0


# --- JSON Serialization ---

def proof_to_json(proof: STARKProof, n_stages: int, n_field_elements: int = HASH_SIZE) -> dict[str, Any]:
    """Convert STARK proof to JSON-serializable dictionary."""
    j: dict[str, Any] = {}

    # Stage roots
    for i in range(n_stages):
        if n_field_elements == 1:
            j[f"root{i + 1}"] = str(proof.roots[i][0])
        else:
            j[f"root{i + 1}"] = [str(r) for r in proof.roots[i]]

    # Evaluations
    j["evals"] = [[str(e) for e in ev] for ev in proof.evals]

    # AIR group values
    if proof.airgroup_values:
        j["airgroupvalues"] = [[str(a) for a in av] for av in proof.airgroup_values]

    # AIR values
    if proof.air_values:
        j["airvalues"] = [[str(a) for a in av] for av in proof.air_values]

    # Final polynomial
    j["finalPol"] = [[str(c) for c in pol_coef] for pol_coef in proof.fri.pol]

    j["nonce"] = str(proof.nonce)
    return j


def load_proof_from_json(path: str) -> tuple[STARKProof, dict[str, Any]]:
    """Load STARK proof from JSON file."""
    with open(path) as f:
        data = json.load(f)

    proof = STARKProof()
    metadata = data.get("metadata", {})

    # Load roots (root1, root2, ...)
    i = 1
    while f"root{i}" in data:
        root_data = data[f"root{i}"]
        if isinstance(root_data, list):
            proof.roots.append([int(r) for r in root_data])
        else:
            proof.roots.append([int(root_data)])
        i += 1

    # Load evaluations
    if "evals" in data:
        proof.evals = [[int(e) for e in ev] for ev in data["evals"]]

    # Load AIR group values
    if "airgroupvalues" in data:
        proof.airgroup_values = [[int(a) for a in av] for av in data["airgroupvalues"]]

    # Load AIR values
    if "airvalues" in data:
        proof.air_values = [[int(a) for a in av] for av in data["airvalues"]]

    # Load final polynomial
    if "finalPol" in data:
        proof.fri.pol = [[int(c) for c in pol] for pol in data["finalPol"]]

    # Load nonce
    if "nonce" in data:
        proof.nonce = int(data["nonce"])

    # Load FRI roots (s1_root, s2_root, ...)
    step = 1
    while f"s{step}_root" in data:
        root_data = data[f"s{step}_root"]
        fri_tree = ProofTree()
        if isinstance(root_data, list):
            fri_tree.root = [int(r) for r in root_data]
        else:
            fri_tree.root = [int(root_data)]
        proof.fri.trees_fri.append(fri_tree)
        step += 1

    return proof, metadata


# --- Binary Deserialization ---

def from_vadcop_final_bytes(data: bytes, stark_info: Any) -> tuple[STARKProof, np.ndarray]:
    """Parse a VadcopFinal proof binary with embedded publics header.

    VadcopFinal proofs prepend [n_publics: u64] [publics: n_publics * u64]
    before the standard proof body (ref: recursion.rs lines 622-627).

    Returns:
        Tuple of (STARKProof, publics_array) where publics_array is numpy uint64.
    """
    n_publics = struct.unpack('<Q', data[:8])[0]
    header_size = 8 + n_publics * 8
    publics = np.array(
        struct.unpack(f'<{n_publics}Q', data[8:header_size]),
        dtype=np.uint64,
    )
    proof = from_bytes_full(data[header_size:], stark_info)
    return proof, publics


def from_bytes_full(data: bytes, stark_info: Any) -> STARKProof:
    """Deserialize binary proof to STARKProof structure.

    Parses the binary format produced by C++ proof2pointer() into a structured
    STARKProof dataclass with typed fields for all proof components.
    """
    n_vals = len(data) // 8
    values = list(struct.unpack(f'<{n_vals}Q', data))
    idx = 0

    proof = STARKProof()

    # Configuration
    n_queries = stark_info.stark_struct.n_queries
    n_stages = stark_info.n_stages
    n_constants = len(stark_info.const_pols_map)
    merkle_arity = stark_info.stark_struct.merkle_tree_arity
    last_level_verification = stark_info.stark_struct.last_level_verification
    n_bits_ext = stark_info.stark_struct.n_bits_ext
    n_siblings = int(math.ceil(n_bits_ext / math.log2(merkle_arity))) - last_level_verification
    n_siblings_per_level = (merkle_arity - 1) * HASH_SIZE

    # Section 1: airgroupValues
    n_airgroup_values = len(stark_info.airgroup_values_map)
    for _ in range(n_airgroup_values):
        proof.airgroup_values.append(list(values[idx:idx + FIELD_EXTENSION_DEGREE]))
        idx += FIELD_EXTENSION_DEGREE

    # Section 2: airValues (C++ always writes FIELD_EXTENSION uint64s per entry)
    for _ in range(len(stark_info.air_values_map)):
        proof.air_values.append(list(values[idx:idx + FIELD_EXTENSION_DEGREE]))
        idx += FIELD_EXTENSION_DEGREE

    # Section 3: roots
    for _ in range(n_stages + 1):
        proof.roots.append(list(values[idx:idx + HASH_SIZE]))
        idx += HASH_SIZE

    # Section 4: evals
    n_evals = len(stark_info.ev_map)
    for _ in range(n_evals):
        proof.evals.append(list(values[idx:idx + FIELD_EXTENSION_DEGREE]))
        idx += FIELD_EXTENSION_DEGREE

    # Initialize FRI trees structure for pol_queries
    # pol_queries[query_idx][tree_idx] = MerkleProof
    # tree_idx: 0..(n_stages) for stages, n_stages+1 for const, n_stages+2+c for custom commit c
    n_custom = len(stark_info.custom_commits)
    n_trees = n_stages + 2 + n_custom
    proof.fri.trees.pol_queries = [[MerkleProof() for _ in range(n_trees)] for _ in range(n_queries)]

    # Pre-allocate last_levels (n_trees slots)
    proof.last_levels = [[] for _ in range(n_trees)]
    const_tree_idx = n_stages + 1

    # Sections 5-7: const tree query proofs (stored at tree index n_stages + 1)
    if n_constants > 0:
        # Values
        for q in range(n_queries):
            proof.fri.trees.pol_queries[q][const_tree_idx].v = [
                [values[idx + i]] for i in range(n_constants)
            ]
            idx += n_constants

        # Merkle paths
        for q in range(n_queries):
            for _ in range(n_siblings):
                proof.fri.trees.pol_queries[q][const_tree_idx].mp.append(
                    list(values[idx:idx + n_siblings_per_level])
                )
                idx += n_siblings_per_level

        # Last levels (stored at const_tree_idx)
        if last_level_verification != 0:
            num_nodes = int(merkle_arity ** last_level_verification)
            const_last_levels = []
            for _ in range(num_nodes):
                const_last_levels.append(list(values[idx:idx + HASH_SIZE]))
                idx += HASH_SIZE
            proof.last_levels[const_tree_idx] = const_last_levels

    # Section 8: custom commits (mirrors const/stage tree parsing above)
    for c, custom_commit in enumerate(stark_info.custom_commits):
        n_custom_cols = stark_info.map_sections_n.get(custom_commit.name + "0", 0)
        tree_idx = n_stages + 2 + c

        # Values
        for q in range(n_queries):
            proof.fri.trees.pol_queries[q][tree_idx].v = [
                [values[idx + i]] for i in range(n_custom_cols)
            ]
            idx += n_custom_cols

        # Merkle paths
        for q in range(n_queries):
            for _ in range(n_siblings):
                proof.fri.trees.pol_queries[q][tree_idx].mp.append(
                    list(values[idx:idx + n_siblings_per_level])
                )
                idx += n_siblings_per_level

        # Last levels
        if last_level_verification != 0:
            num_nodes = int(merkle_arity ** last_level_verification)
            custom_last_levels = []
            for _ in range(num_nodes):
                custom_last_levels.append(list(values[idx:idx + HASH_SIZE]))
                idx += HASH_SIZE
            proof.last_levels[tree_idx] = custom_last_levels

    # Section 9: stage tree proofs (cm1, cm2, ..., cmQ)
    # Stored at tree indices 0..(n_stages)
    for stage_num in range(1, n_stages + 2):
        tree_idx = stage_num - 1
        n_stage_cols = stark_info.map_sections_n.get(f"cm{stage_num}", 0)

        # Values
        for q in range(n_queries):
            proof.fri.trees.pol_queries[q][tree_idx].v = [
                [values[idx + i]] for i in range(n_stage_cols)
            ]
            idx += n_stage_cols

        # Merkle paths
        for q in range(n_queries):
            for _ in range(n_siblings):
                proof.fri.trees.pol_queries[q][tree_idx].mp.append(
                    list(values[idx:idx + n_siblings_per_level])
                )
                idx += n_siblings_per_level

        # Last levels (stored at tree_idx)
        if last_level_verification != 0:
            num_nodes = int(merkle_arity ** last_level_verification)
            stage_last_levels = []
            for _ in range(num_nodes):
                stage_last_levels.append(list(values[idx:idx + HASH_SIZE]))
                idx += HASH_SIZE
            proof.last_levels[tree_idx] = stage_last_levels

    # Section 10: FRI step roots
    n_fri_round_log_sizes = len(stark_info.stark_struct.fri_fold_steps) - 1
    for _ in range(n_fri_round_log_sizes):
        fri_tree = ProofTree()
        fri_tree.root = list(values[idx:idx + HASH_SIZE])
        fri_tree.pol_queries = [[MerkleProof()] for _ in range(n_queries)]
        proof.fri.trees_fri.append(fri_tree)
        idx += HASH_SIZE

    # Section 11: FRI step query proofs
    for step_idx in range(n_fri_round_log_sizes):
        prev_bits = stark_info.stark_struct.fri_fold_steps[step_idx].domain_bits
        curr_bits = stark_info.stark_struct.fri_fold_steps[step_idx + 1].domain_bits
        n_fri_cols = (1 << (prev_bits - curr_bits)) * FIELD_EXTENSION_DEGREE

        # Values
        for q in range(n_queries):
            proof.fri.trees_fri[step_idx].pol_queries[q][0].v = [
                [values[idx + i]] for i in range(n_fri_cols)
            ]
            idx += n_fri_cols

        # Merkle paths
        n_siblings_fri = int(math.ceil(curr_bits / math.log2(merkle_arity))) - last_level_verification
        for q in range(n_queries):
            for _ in range(n_siblings_fri):
                proof.fri.trees_fri[step_idx].pol_queries[q][0].mp.append(
                    list(values[idx:idx + n_siblings_per_level])
                )
                idx += n_siblings_per_level

        # Last levels
        if last_level_verification != 0:
            num_nodes = int(merkle_arity ** last_level_verification)
            fri_last_levels = []
            for _ in range(num_nodes):
                fri_last_levels.append(list(values[idx:idx + HASH_SIZE]))
                idx += HASH_SIZE
            proof.fri.trees_fri[step_idx].last_levels = fri_last_levels

    # Section 12: finalPol
    final_pol_size = 1 << stark_info.stark_struct.fri_fold_steps[-1].domain_bits
    for _ in range(final_pol_size):
        proof.fri.pol.append(list(values[idx:idx + FIELD_EXTENSION_DEGREE]))
        idx += FIELD_EXTENSION_DEGREE

    # Section 13: nonce
    proof.nonce = values[idx]
    idx += 1

    if idx != n_vals:
        raise ValueError(f"Binary proof parsing error: consumed {idx} values, expected {n_vals}")

    return proof


# --- Binary Serialization ---

def _is_galois_array(arr: Any) -> bool:
    """Check if arr is a galois FieldArray type."""
    # galois arrays have vector() method and degree on the class
    return hasattr(arr, 'vector') and hasattr(type(arr), 'degree')


def _is_extension_field(arr: Any) -> bool:
    """Check if arr is an extension field (degree > 1)."""
    return hasattr(type(arr), 'degree') and type(arr).degree > 1


def _to_list(arr: Any) -> list:
    """Convert array to flat int list for serialization."""
    if arr is None:
        return []

    # Handle galois FieldArray types
    if _is_galois_array(arr):
        if _is_extension_field(arr):
            # FF3: use field.py helpers for ascending coefficient order
            if arr.ndim == 0:
                return ff3_coeffs(arr)
            return ff3_to_flat_list(arr)
        else:
            # FF (base field): just convert to ints
            if arr.ndim == 0:
                return [int(arr)]
            return [int(v) for v in arr]

    # Handle numpy arrays
    if hasattr(arr, 'tolist'):
        return arr.tolist()

    return list(arr)


def to_bytes_partial(proof_dict: dict[str, Any], stark_info: Any) -> tuple[bytes, bytes]:
    """Serialize proof header and footer (without query proofs) for partial comparison."""
    header_values: list[int] = []

    # 1. airgroupValues
    airgroup_values = _to_list(proof_dict.get('airgroup_values', []))
    n_airgroup_values = len(stark_info.airgroup_values_map)
    for i in range(n_airgroup_values):
        start = i * FIELD_EXTENSION_DEGREE
        header_values.extend(int(v) for v in airgroup_values[start:start + FIELD_EXTENSION_DEGREE])

    # 2. airValues
    air_values = _to_list(proof_dict.get('air_values', []))
    n_air_values = len(stark_info.air_values_map)
    for i in range(n_air_values):
        start = i * FIELD_EXTENSION_DEGREE
        header_values.extend(int(v) for v in air_values[start:start + FIELD_EXTENSION_DEGREE])

    # 3. roots
    for root in proof_dict.get('roots', []):
        header_values.extend(int(v) for v in root[:HASH_SIZE])

    # 4. evals
    evals = _to_list(proof_dict.get('evals', []))
    n_evals = len(stark_info.ev_map)
    for i in range(n_evals):
        start = i * FIELD_EXTENSION_DEGREE
        header_values.extend(int(v) for v in evals[start:start + FIELD_EXTENSION_DEGREE])

    header_bytes = struct.pack(f'<{len(header_values)}Q', *header_values)

    # Footer: finalPol and nonce
    footer_values: list[int] = []
    fri_proof = proof_dict.get('fri_proof')
    if fri_proof is not None:
        final_pol = _to_list(fri_proof.final_pol) if hasattr(fri_proof, 'final_pol') else []
        for i in range(0, len(final_pol), FIELD_EXTENSION_DEGREE):
            footer_values.extend(int(v) for v in final_pol[i:i + FIELD_EXTENSION_DEGREE])

    footer_values.append(int(proof_dict.get('nonce', 0)))
    footer_bytes = struct.pack(f'<{len(footer_values)}Q', *footer_values)

    return header_bytes, footer_bytes


def to_bytes_full(proof: STARKProof, stark_info: Any) -> bytes:
    """Serialize complete STARK proof to binary format (requires query proofs)."""
    if not hasattr(proof.fri, 'trees') or not proof.fri.trees.pol_queries:
        raise ValueError("Cannot serialize full proof: query proofs not populated.")

    values: list[int] = []

    # 1-4: Header (airgroup_values, air_values, roots, evals)
    for av in proof.airgroup_values:
        values.extend(av[:FIELD_EXTENSION_DEGREE])
    for av in proof.air_values:
        values.extend(av[:FIELD_EXTENSION_DEGREE])
    for root in proof.roots:
        values.extend(root[:HASH_SIZE])
    for ev in proof.evals:
        values.extend(ev[:FIELD_EXTENSION_DEGREE])

    # Configuration
    n_queries = stark_info.stark_struct.n_queries
    n_constants = stark_info.n_constants
    n_stages = stark_info.n_stages
    n_field_elements = HASH_SIZE
    merkle_arity = stark_info.stark_struct.merkle_tree_arity
    last_level_verification = stark_info.stark_struct.last_level_verification

    n_siblings = int(math.ceil(stark_info.stark_struct.fri_fold_steps[0].domain_bits / math.log2(merkle_arity))) - last_level_verification
    n_siblings_per_level = (merkle_arity - 1) * n_field_elements

    # 5-7: Constant tree queries
    for i in range(n_queries):
        for col in range(n_constants):
            values.append(proof.fri.trees.pol_queries[i][n_stages + 1].v[col][0])

    for i in range(n_queries):
        for lvl in range(n_siblings):
            values.extend(proof.fri.trees.pol_queries[i][n_stages + 1].mp[lvl][:n_siblings_per_level])

    if last_level_verification != 0:
        num_nodes = int(merkle_arity ** last_level_verification) * n_field_elements
        values.extend(proof.last_levels[n_stages + 1][:num_nodes])

    # 8: Custom commits
    for c, custom_commit in enumerate(stark_info.custom_commits):
        n_custom_cols = stark_info.map_sections_n.get(custom_commit.name + "0", 0)
        tree_idx = n_stages + 2 + c

        for i in range(n_queries):
            for col in range(n_custom_cols):
                values.append(proof.fri.trees.pol_queries[i][tree_idx].v[col][0])

        for i in range(n_queries):
            for lvl in range(n_siblings):
                values.extend(proof.fri.trees.pol_queries[i][tree_idx].mp[lvl][:n_siblings_per_level])

        if last_level_verification != 0:
            values.extend(proof.last_levels[tree_idx][:num_nodes])

    # 9: Stage trees (cm1, cm2, ..., cmQ)
    for s in range(n_stages + 1):
        n_stage_cols = stark_info.map_sections_n.get(f"cm{s + 1}", 0)

        for i in range(n_queries):
            for col in range(n_stage_cols):
                values.append(proof.fri.trees.pol_queries[i][s].v[col][0])

        for i in range(n_queries):
            for lvl in range(n_siblings):
                values.extend(proof.fri.trees.pol_queries[i][s].mp[lvl][:n_siblings_per_level])

        if last_level_verification != 0:
            values.extend(proof.last_levels[s][:num_nodes])

    # 10: FRI step roots
    for step in range(1, len(stark_info.stark_struct.fri_fold_steps)):
        values.extend(proof.fri.trees_fri[step - 1].root[:n_field_elements])

    # 11: FRI step query proofs
    for step in range(1, len(stark_info.stark_struct.fri_fold_steps)):
        prev_bits = stark_info.stark_struct.fri_fold_steps[step - 1].domain_bits
        curr_bits = stark_info.stark_struct.fri_fold_steps[step].domain_bits
        n_fri_vals = (1 << (prev_bits - curr_bits)) * FIELD_EXTENSION_DEGREE

        for i in range(n_queries):
            for col in range(n_fri_vals):
                values.append(proof.fri.trees_fri[step - 1].pol_queries[i][0].v[col][0])

        n_siblings_fri = int(math.ceil(curr_bits / math.log2(merkle_arity))) - last_level_verification
        for i in range(n_queries):
            for lvl in range(n_siblings_fri):
                values.extend(proof.fri.trees_fri[step - 1].pol_queries[i][0].mp[lvl][:n_siblings_per_level])

        if last_level_verification != 0:
            values.extend(proof.fri.trees_fri[step - 1].last_levels[:num_nodes])

    # 12: finalPol
    for pol_coef in proof.fri.pol:
        values.extend(pol_coef[:FIELD_EXTENSION_DEGREE])

    # 13: nonce
    values.append(proof.nonce)

    return struct.pack(f'<{len(values)}Q', *values)


def to_bytes_full_from_dict(proof_dict: dict[str, Any], stark_info: Any) -> bytes:
    """Serialize proof dictionary to binary format matching C++ proof2pointer()."""
    values: list[int] = []

    # Extract components
    airgroup_values = _to_list(proof_dict.get('airgroup_values', []))
    air_values = _to_list(proof_dict.get('air_values', []))
    roots = proof_dict.get('roots', [])
    evals = _to_list(proof_dict.get('evals', []))
    fri_proof = proof_dict.get('fri_proof')
    stage_query_proofs = proof_dict.get('stage_query_proofs', {})
    nonce = proof_dict.get('nonce', 0)
    last_level_nodes = proof_dict.get('last_level_nodes', {})

    # Configuration
    n_stages = stark_info.n_stages
    merkle_arity = stark_info.stark_struct.merkle_tree_arity
    last_level_verification = stark_info.stark_struct.last_level_verification

    # Section 1: airgroupValues
    n_airgroup_values = len(stark_info.airgroup_values_map)
    for i in range(n_airgroup_values):
        start = i * FIELD_EXTENSION_DEGREE
        values.extend(int(v) for v in airgroup_values[start:start + FIELD_EXTENSION_DEGREE])

    # Section 2: airValues
    n_air_values = len(stark_info.air_values_map)
    for i in range(n_air_values):
        start = i * FIELD_EXTENSION_DEGREE
        values.extend(int(v) for v in air_values[start:start + FIELD_EXTENSION_DEGREE])

    # Section 3: roots
    for root in roots:
        values.extend(int(v) for v in root[:HASH_SIZE])

    # Section 4: evals
    n_evals = len(stark_info.ev_map)
    for i in range(n_evals):
        start = i * FIELD_EXTENSION_DEGREE
        values.extend(int(v) for v in evals[start:start + FIELD_EXTENSION_DEGREE])

    # Sections 5-7: const tree query proofs
    const_query_proofs = proof_dict.get('const_query_proofs', [])
    n_constants = len(stark_info.const_pols_map)

    n_bits_ext = stark_info.stark_struct.n_bits_ext
    n_siblings = int(math.ceil(n_bits_ext / math.log2(merkle_arity))) - last_level_verification
    n_siblings_per_level = (merkle_arity - 1) * HASH_SIZE

    if const_query_proofs and n_constants > 0:
        # Values
        for query_proof in const_query_proofs:
            for col in range(n_constants):
                values.append(int(query_proof.v[col][0]) if col < len(query_proof.v) else 0)

        # Merkle paths
        for query_proof in const_query_proofs:
            for level_idx in range(n_siblings):
                if level_idx < len(query_proof.mp):
                    values.extend(int(v) for v in query_proof.mp[level_idx][:n_siblings_per_level])
                else:
                    values.extend([0] * n_siblings_per_level)

        # Last levels
        if last_level_verification != 0:
            num_nodes = int(merkle_arity ** last_level_verification) * HASH_SIZE
            const_last_lvl = last_level_nodes.get('const', [])
            if const_last_lvl:
                values.extend(int(v) for v in const_last_lvl[:num_nodes])
            else:
                values.extend([0] * num_nodes)

    # Section 8: custom commits
    custom_commit_query_proofs = proof_dict.get('custom_commit_query_proofs', {})
    for c, custom_commit in enumerate(stark_info.custom_commits):
        n_custom_cols = stark_info.map_sections_n.get(custom_commit.name + "0", 0)
        cc_proofs = custom_commit_query_proofs.get(c, [])

        if cc_proofs:
            for query_proof in cc_proofs:
                for col in range(n_custom_cols):
                    values.append(int(query_proof.v[col][0]) if col < len(query_proof.v) else 0)

            for query_proof in cc_proofs:
                for level_idx in range(n_siblings):
                    if level_idx < len(query_proof.mp):
                        values.extend(int(v) for v in query_proof.mp[level_idx][:n_siblings_per_level])
                    else:
                        values.extend([0] * n_siblings_per_level)

            if last_level_verification != 0:
                num_nodes = int(merkle_arity ** last_level_verification) * HASH_SIZE
                cc_last_lvl = last_level_nodes.get(custom_commit.name, [])
                if cc_last_lvl:
                    values.extend(int(v) for v in cc_last_lvl[:num_nodes])
                else:
                    values.extend([0] * num_nodes)

    # Section 9: stage tree proofs (cm1, cm2, ..., cmQ)
    for stage_num in range(1, n_stages + 2):
        n_stage_cols = stark_info.map_sections_n.get(f"cm{stage_num}", 0)

        if stage_num not in stage_query_proofs:
            raise ValueError(f"Missing stage {stage_num} query proofs for full serialization")

        proofs = stage_query_proofs[stage_num]

        # Values
        for query_proof in proofs:
            for col in range(n_stage_cols):
                values.append(int(query_proof.v[col][0]) if col < len(query_proof.v) else 0)

        # Merkle paths
        for query_proof in proofs:
            for level_idx in range(n_siblings):
                if level_idx < len(query_proof.mp):
                    values.extend(int(v) for v in query_proof.mp[level_idx][:n_siblings_per_level])
                else:
                    values.extend([0] * n_siblings_per_level)

        # Last levels
        if last_level_verification != 0:
            num_nodes = int(merkle_arity ** last_level_verification) * HASH_SIZE
            stage_last_lvl = last_level_nodes.get(f"cm{stage_num}", [])
            if stage_last_lvl:
                values.extend(int(v) for v in stage_last_lvl[:num_nodes])
            else:
                values.extend([0] * num_nodes)

    # Section 10: FRI step roots
    if fri_proof is not None:
        for fri_root in fri_proof.fri_roots:
            values.extend(int(v) for v in fri_root[:HASH_SIZE])

    # Section 11: FRI step query proofs
    if fri_proof is not None:
        for step_idx in range(len(stark_info.stark_struct.fri_fold_steps) - 1):
            prev_bits = stark_info.stark_struct.fri_fold_steps[step_idx].domain_bits
            curr_bits = stark_info.stark_struct.fri_fold_steps[step_idx + 1].domain_bits
            n_fri_groups = 1 << (prev_bits - curr_bits)

            # Values
            if step_idx < len(fri_proof.query_proofs):
                for qp in fri_proof.query_proofs[step_idx]:
                    for group_idx in range(n_fri_groups):
                        if group_idx < len(qp.v):
                            values.extend(int(v) for v in qp.v[group_idx][:FIELD_EXTENSION_DEGREE])
                        else:
                            values.extend([0] * FIELD_EXTENSION_DEGREE)

            # Merkle paths
            n_siblings_fri = int(math.ceil(curr_bits / math.log2(merkle_arity))) - last_level_verification
            if step_idx < len(fri_proof.query_proofs):
                for qp in fri_proof.query_proofs[step_idx]:
                    for level_idx in range(n_siblings_fri):
                        if level_idx < len(qp.mp):
                            values.extend(int(v) for v in qp.mp[level_idx][:n_siblings_per_level])
                        else:
                            values.extend([0] * n_siblings_per_level)

            # Last levels
            if last_level_verification != 0:
                num_nodes = int(merkle_arity ** last_level_verification) * HASH_SIZE
                fri_last_lvl = last_level_nodes.get(f'fri{step_idx}', [])
                if fri_last_lvl:
                    values.extend(int(v) for v in fri_last_lvl[:num_nodes])
                else:
                    values.extend([0] * num_nodes)

    # Section 12: finalPol
    if fri_proof is not None:
        final_pol = _to_list(fri_proof.final_pol)
        for i in range(0, len(final_pol), FIELD_EXTENSION_DEGREE):
            values.extend(int(v) for v in final_pol[i:i + FIELD_EXTENSION_DEGREE])

    # Section 13: nonce
    values.append(int(nonce))

    return struct.pack(f'<{len(values)}Q', *values)


# --- Validation ---

def validate_proof_structure(proof: STARKProof, stark_info: Any) -> list[str]:
    """Validate that proof structure matches STARK configuration."""
    errors = []

    expected_stages = stark_info.n_stages + 1
    if len(proof.roots) != expected_stages:
        errors.append(f"Expected {expected_stages} stage roots, got {len(proof.roots)}")

    if len(proof.evals) != len(stark_info.ev_map):
        errors.append(f"Expected {len(stark_info.ev_map)} evaluations, got {len(proof.evals)}")

    for i, ev in enumerate(proof.evals):
        if len(ev) != FIELD_EXTENSION_DEGREE:
            errors.append(f"Evaluation {i} has dimension {len(ev)}, expected {FIELD_EXTENSION_DEGREE}")

    if len(proof.airgroup_values) != len(stark_info.airgroup_values_map):
        errors.append(
            f"Expected {len(stark_info.airgroup_values_map)} airgroup values, "
            f"got {len(proof.airgroup_values)}"
        )

    if len(proof.air_values) != len(stark_info.air_values_map):
        errors.append(
            f"Expected {len(stark_info.air_values_map)} air values, "
            f"got {len(proof.air_values)}"
        )

    expected_fri_round_log_sizes = len(stark_info.stark_struct.fri_fold_steps) - 1
    if len(proof.fri.trees_fri) != expected_fri_round_log_sizes:
        errors.append(f"Expected {expected_fri_round_log_sizes} FRI trees, got {len(proof.fri.trees_fri)}")

    if proof.fri.pol:
        expected_degree = 1 << stark_info.stark_struct.fri_fold_steps[-1].domain_bits
        if len(proof.fri.pol) != expected_degree:
            errors.append(f"Final polynomial degree {len(proof.fri.pol)}, expected {expected_degree}")

    return errors
