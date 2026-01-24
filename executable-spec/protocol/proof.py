"""STARK proof data structures and serialization."""

import json
import math
import struct
from dataclasses import dataclass, field
from typing import Any, List

from primitives.field import ff3_coeffs, ff3_to_flat_list
from protocol.stark_info import FIELD_EXTENSION_DEGREE, HASH_SIZE


# --- Type Aliases ---
Hash = List[int]  # Poseidon hash output [h0, h1, h2, h3]


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
    trees_fri: List[ProofTree] = field(default_factory=list)
    pol: List[List[int]] = field(default_factory=list)  # [[c0,c1,c2], ...]


@dataclass
class STARKProof:
    """Complete STARK proof."""
    roots: List[Hash] = field(default_factory=list)
    last_levels: List[List[int]] = field(default_factory=list)
    evals: List[List[int]] = field(default_factory=list)  # [[c0,c1,c2], ...]
    airgroup_values: List[List[int]] = field(default_factory=list)  # [[c0,c1,c2], ...]
    air_values: List[List[int]] = field(default_factory=list)  # [[c0,c1,c2], ...]
    custom_commits: List[str] = field(default_factory=list)
    fri: FriProof = field(default_factory=FriProof)
    nonce: int = 0


@dataclass
class FRIProofFull:
    """Full FRI proof with metadata."""
    proof: STARKProof = field(default_factory=STARKProof)
    publics: List[int] = field(default_factory=list)
    airgroup_id: int = 0
    air_id: int = 0
    instance_id: int = 0


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
    with open(path, 'r') as f:
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


def load_proof_from_binary(path: str) -> STARKProof:
    """Load STARK proof from binary file (not implemented)."""
    raise NotImplementedError("Use from_bytes_full_to_jproof() instead.")


# --- Binary Deserialization ---

def from_bytes_full_to_jproof(data: bytes, stark_info: Any) -> dict[str, Any]:
    """Deserialize binary proof to jproof format expected by stark_verify."""
    n_vals = len(data) // 8
    values = list(struct.unpack(f'<{n_vals}Q', data))
    idx = 0

    jproof: dict[str, Any] = {}

    # Configuration
    n_queries = stark_info.starkStruct.nQueries
    n_stages = stark_info.nStages
    n_constants = len(stark_info.constPolsMap)
    merkle_arity = stark_info.starkStruct.merkleTreeArity
    last_level_verification = stark_info.starkStruct.lastLevelVerification
    n_bits_ext = stark_info.starkStruct.nBitsExt
    n_siblings = int(math.ceil(n_bits_ext / math.log2(merkle_arity))) - last_level_verification
    n_siblings_per_level = (merkle_arity - 1) * HASH_SIZE

    # Section 1: airgroupValues
    n_airgroup_values = len(stark_info.airgroupValuesMap)
    jproof['airgroupvalues'] = []
    for _ in range(n_airgroup_values):
        jproof['airgroupvalues'].append(values[idx:idx + FIELD_EXTENSION_DEGREE])
        idx += FIELD_EXTENSION_DEGREE

    # Section 2: airValues
    jproof['airvalues'] = []
    for i in range(len(stark_info.airValuesMap)):
        if stark_info.airValuesMap[i].stage == 1:
            jproof['airvalues'].append([values[idx]])
            idx += 1
        else:
            jproof['airvalues'].append(values[idx:idx + FIELD_EXTENSION_DEGREE])
            idx += FIELD_EXTENSION_DEGREE

    # Section 3: roots
    for stage in range(1, n_stages + 2):
        jproof[f'root{stage}'] = values[idx:idx + HASH_SIZE]
        idx += HASH_SIZE

    # Section 4: evals
    n_evals = len(stark_info.evMap)
    jproof['evals'] = []
    for _ in range(n_evals):
        jproof['evals'].append(values[idx:idx + FIELD_EXTENSION_DEGREE])
        idx += FIELD_EXTENSION_DEGREE

    # Sections 5-7: const tree query proofs
    if n_constants > 0:
        # Values
        jproof['s0_valsC'] = []
        for _ in range(n_queries):
            jproof['s0_valsC'].append(values[idx:idx + n_constants])
            idx += n_constants

        # Merkle paths
        jproof['s0_siblingsC'] = []
        for _ in range(n_queries):
            siblings = []
            for _ in range(n_siblings):
                siblings.append(values[idx:idx + n_siblings_per_level])
                idx += n_siblings_per_level
            jproof['s0_siblingsC'].append(siblings)

        # Last levels
        if last_level_verification != 0:
            num_nodes = int(merkle_arity ** last_level_verification)
            jproof['s0_last_levelsC'] = []
            for _ in range(num_nodes):
                jproof['s0_last_levelsC'].append(values[idx:idx + HASH_SIZE])
                idx += HASH_SIZE

    # Section 8: custom commits (not used in test AIRs)

    # Section 9: stage tree proofs (cm1, cm2, ..., cmQ)
    for stage_num in range(1, n_stages + 2):
        n_stage_cols = stark_info.mapSectionsN.get(f"cm{stage_num}", 0)

        # Values
        jproof[f's0_vals{stage_num}'] = []
        for _ in range(n_queries):
            jproof[f's0_vals{stage_num}'].append(values[idx:idx + n_stage_cols])
            idx += n_stage_cols

        # Merkle paths
        jproof[f's0_siblings{stage_num}'] = []
        for _ in range(n_queries):
            siblings = []
            for _ in range(n_siblings):
                siblings.append(values[idx:idx + n_siblings_per_level])
                idx += n_siblings_per_level
            jproof[f's0_siblings{stage_num}'].append(siblings)

        # Last levels
        if last_level_verification != 0:
            num_nodes = int(merkle_arity ** last_level_verification)
            jproof[f's0_last_levels{stage_num}'] = []
            for _ in range(num_nodes):
                jproof[f's0_last_levels{stage_num}'].append(values[idx:idx + HASH_SIZE])
                idx += HASH_SIZE

    # Section 10: FRI step roots
    n_fri_steps = len(stark_info.starkStruct.steps) - 1
    for step in range(1, n_fri_steps + 1):
        jproof[f's{step}_root'] = values[idx:idx + HASH_SIZE]
        idx += HASH_SIZE

    # Section 11: FRI step query proofs
    for step_idx in range(n_fri_steps):
        step = step_idx + 1
        prev_bits = stark_info.starkStruct.steps[step_idx].nBits
        curr_bits = stark_info.starkStruct.steps[step_idx + 1].nBits
        n_fri_cols = (1 << (prev_bits - curr_bits)) * FIELD_EXTENSION_DEGREE

        # Values
        jproof[f's{step}_vals'] = []
        for _ in range(n_queries):
            jproof[f's{step}_vals'].append(values[idx:idx + n_fri_cols])
            idx += n_fri_cols

        # Merkle paths
        n_siblings_fri = int(math.ceil(curr_bits / math.log2(merkle_arity))) - last_level_verification
        jproof[f's{step}_siblings'] = []
        for _ in range(n_queries):
            siblings = []
            for _ in range(n_siblings_fri):
                siblings.append(values[idx:idx + n_siblings_per_level])
                idx += n_siblings_per_level
            jproof[f's{step}_siblings'].append(siblings)

        # Last levels
        if last_level_verification != 0:
            num_nodes = int(merkle_arity ** last_level_verification)
            jproof[f's{step}_last_levels'] = []
            for _ in range(num_nodes):
                jproof[f's{step}_last_levels'].append(values[idx:idx + HASH_SIZE])
                idx += HASH_SIZE

    # Section 12: finalPol
    final_pol_size = 1 << stark_info.starkStruct.steps[-1].nBits
    jproof['finalPol'] = []
    for _ in range(final_pol_size):
        jproof['finalPol'].append(values[idx:idx + FIELD_EXTENSION_DEGREE])
        idx += FIELD_EXTENSION_DEGREE

    # Section 13: nonce
    jproof['nonce'] = values[idx]
    idx += 1

    if idx != n_vals:
        raise ValueError(f"Binary proof parsing error: consumed {idx} values, expected {n_vals}")

    return jproof


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
    n_airgroup_values = len(stark_info.airgroupValuesMap)
    for i in range(n_airgroup_values):
        start = i * FIELD_EXTENSION_DEGREE
        header_values.extend(int(v) for v in airgroup_values[start:start + FIELD_EXTENSION_DEGREE])

    # 2. airValues
    air_values = _to_list(proof_dict.get('air_values', []))
    n_air_values = len(stark_info.airValuesMap)
    for i in range(n_air_values):
        start = i * FIELD_EXTENSION_DEGREE
        header_values.extend(int(v) for v in air_values[start:start + FIELD_EXTENSION_DEGREE])

    # 3. roots
    for root in proof_dict.get('roots', []):
        header_values.extend(int(v) for v in root[:HASH_SIZE])

    # 4. evals
    evals = _to_list(proof_dict.get('evals', []))
    n_evals = len(stark_info.evMap)
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
    n_queries = stark_info.starkStruct.nQueries
    n_constants = stark_info.nConstants
    n_stages = stark_info.nStages
    n_field_elements = HASH_SIZE
    merkle_arity = stark_info.starkStruct.merkleTreeArity
    last_level_verification = stark_info.starkStruct.lastLevelVerification

    n_siblings = int(math.ceil(stark_info.starkStruct.steps[0].nBits / math.log2(merkle_arity))) - last_level_verification
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
    for c, custom_commit in enumerate(stark_info.customCommits):
        n_custom_cols = stark_info.mapSectionsN.get(custom_commit.name + "0", 0)
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
        n_stage_cols = stark_info.mapSectionsN.get(f"cm{s + 1}", 0)

        for i in range(n_queries):
            for col in range(n_stage_cols):
                values.append(proof.fri.trees.pol_queries[i][s].v[col][0])

        for i in range(n_queries):
            for lvl in range(n_siblings):
                values.extend(proof.fri.trees.pol_queries[i][s].mp[lvl][:n_siblings_per_level])

        if last_level_verification != 0:
            values.extend(proof.last_levels[s][:num_nodes])

    # 10: FRI step roots
    for step in range(1, len(stark_info.starkStruct.steps)):
        values.extend(proof.fri.trees_fri[step - 1].root[:n_field_elements])

    # 11: FRI step query proofs
    for step in range(1, len(stark_info.starkStruct.steps)):
        prev_bits = stark_info.starkStruct.steps[step - 1].nBits
        curr_bits = stark_info.starkStruct.steps[step].nBits
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
    n_stages = stark_info.nStages
    merkle_arity = stark_info.starkStruct.merkleTreeArity
    last_level_verification = stark_info.starkStruct.lastLevelVerification

    # Section 1: airgroupValues
    n_airgroup_values = len(stark_info.airgroupValuesMap)
    for i in range(n_airgroup_values):
        start = i * FIELD_EXTENSION_DEGREE
        values.extend(int(v) for v in airgroup_values[start:start + FIELD_EXTENSION_DEGREE])

    # Section 2: airValues
    n_air_values = len(stark_info.airValuesMap)
    for i in range(n_air_values):
        start = i * FIELD_EXTENSION_DEGREE
        values.extend(int(v) for v in air_values[start:start + FIELD_EXTENSION_DEGREE])

    # Section 3: roots
    for root in roots:
        values.extend(int(v) for v in root[:HASH_SIZE])

    # Section 4: evals
    n_evals = len(stark_info.evMap)
    for i in range(n_evals):
        start = i * FIELD_EXTENSION_DEGREE
        values.extend(int(v) for v in evals[start:start + FIELD_EXTENSION_DEGREE])

    # Sections 5-7: const tree query proofs
    const_query_proofs = proof_dict.get('const_query_proofs', [])
    n_constants = len(stark_info.constPolsMap)

    n_bits_ext = stark_info.starkStruct.nBitsExt
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

    # Section 8: custom commits (not implemented)

    # Section 9: stage tree proofs (cm1, cm2, ..., cmQ)
    for stage_num in range(1, n_stages + 2):
        n_stage_cols = stark_info.mapSectionsN.get(f"cm{stage_num}", 0)

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
        for step_idx in range(len(stark_info.starkStruct.steps) - 1):
            prev_bits = stark_info.starkStruct.steps[step_idx].nBits
            curr_bits = stark_info.starkStruct.steps[step_idx + 1].nBits
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

    expected_stages = stark_info.nStages + 1
    if len(proof.roots) != expected_stages:
        errors.append(f"Expected {expected_stages} stage roots, got {len(proof.roots)}")

    if len(proof.evals) != len(stark_info.evMap):
        errors.append(f"Expected {len(stark_info.evMap)} evaluations, got {len(proof.evals)}")

    for i, ev in enumerate(proof.evals):
        if len(ev) != FIELD_EXTENSION_DEGREE:
            errors.append(f"Evaluation {i} has dimension {len(ev)}, expected {FIELD_EXTENSION_DEGREE}")

    if len(proof.airgroup_values) != len(stark_info.airgroupValuesMap):
        errors.append(
            f"Expected {len(stark_info.airgroupValuesMap)} airgroup values, "
            f"got {len(proof.airgroup_values)}"
        )

    if len(proof.air_values) != len(stark_info.airValuesMap):
        errors.append(
            f"Expected {len(stark_info.airValuesMap)} air values, "
            f"got {len(proof.air_values)}"
        )

    expected_fri_steps = len(stark_info.starkStruct.steps) - 1
    if len(proof.fri.trees_fri) != expected_fri_steps:
        errors.append(f"Expected {expected_fri_steps} FRI trees, got {len(proof.fri.trees_fri)}")

    if proof.fri.pol:
        expected_degree = 1 << stark_info.starkStruct.steps[-1].nBits
        if len(proof.fri.pol) != expected_degree:
            errors.append(f"Final polynomial degree {len(proof.fri.pol)}, expected {expected_degree}")

    return errors


# --- Legacy Function (reference implementation, incomplete) ---

def proof_to_pointer_layout(proof: STARKProof, stark_info: Any) -> list[int]:
    """Convert STARK proof to pointer layout (reference implementation)."""
    pointer: list[int] = []

    for av in proof.airgroup_values:
        pointer.extend(av)
    for av in proof.air_values:
        pointer.extend(av)
    for root in proof.roots:
        pointer.extend(root)
    for ev in proof.evals:
        pointer.extend(ev)

    # Note: Query proofs omitted (incomplete reference implementation)

    for pol_coef in proof.fri.pol:
        pointer.extend(pol_coef)
    pointer.append(proof.nonce)

    return pointer
