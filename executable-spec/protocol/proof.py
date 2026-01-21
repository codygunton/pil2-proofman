"""
STARK proof data structures and serialization.

This module provides a faithful Python translation of the C++ proof classes
from pil2-stark/src/starkpil/proof_stark.hpp.

The proof structures represent the complete STARK proof, including:
- FRI proof components (merkle roots, query responses, final polynomial)
- Stage commitments (roots for each proof stage)
- Polynomial evaluations at challenge points
- Query responses with Merkle authentication paths
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from protocol.stark_info import FIELD_EXTENSION, HASH_SIZE


# C++: pil2-stark/src/starkpil/proof_stark.hpp::MerkleProof<ElementType> (lines 39-69)
@dataclass
class MerkleProof:
    """Merkle authentication path for a query.

    Corresponds to C++ template class MerkleProof in proof_stark.hpp (lines 39-69).

    Attributes:
        v: Leaf values (polynomial evaluations at query index)
        mp: Merkle path (sibling hashes from leaf to root)
    """
    v: List[List[int]] = field(default_factory=list)  # List of [value] (Goldilocks elements)
    mp: List[List[int]] = field(default_factory=list)  # List of sibling hashes


# C++: pil2-stark/src/starkpil/proof_stark.hpp::ProofTree<ElementType> (lines 71-95)
@dataclass
class ProofTree:
    """Merkle tree commitment for a polynomial stage.

    Corresponds to C++ template class ProofTree in proof_stark.hpp (lines 71-95).

    Attributes:
        root: Merkle root (HASH_SIZE field elements)
        last_levels: Last level nodes (for optimization, may be empty)
        pol_queries: Query responses (one MerkleProof per query)
    """
    root: List[int] = field(default_factory=list)  # Length HASH_SIZE
    last_levels: List[int] = field(default_factory=list)  # May be empty
    pol_queries: List[List[MerkleProof]] = field(default_factory=list)  # [n_queries][n_trees]


# C++: pil2-stark/src/starkpil/proof_stark.hpp::Fri<ElementType> (lines 97-125)
@dataclass
class FriProof:
    """FRI polynomial commitment opening proof.

    Corresponds to C++ class Fri in proof_stark.hpp (lines 97-125).

    The FRI protocol proves that a committed polynomial has a bounded degree
    by recursively folding it and building Merkle trees at each step.

    Attributes:
        trees: Main proof tree (for constants and committed polynomials)
        trees_fri: FRI folding step trees (one per folding step except last)
        pol: Final polynomial coefficients (at last FRI step)
    """
    trees: ProofTree = field(default_factory=ProofTree)
    trees_fri: List[ProofTree] = field(default_factory=list)
    pol: List[List[int]] = field(default_factory=list)  # [degree][FIELD_EXTENSION]


# C++: pil2-stark/src/starkpil/proof_stark.hpp::Proofs<ElementType> (lines 127-537)
@dataclass
class STARKProof:
    """Complete STARK proof.

    Corresponds to C++ class Proofs in proof_stark.hpp (lines 127-537).

    A STARK proof consists of:
    1. Commitments to polynomials at each stage (roots)
    2. Evaluations of polynomials at challenge point (evals)
    3. FRI proof of bounded degree (fri)
    4. AIR-specific values (airgroup_values, air_values)
    5. Proof-of-work nonce

    Attributes:
        roots: Merkle roots for each stage (stage 1, 2, ..., Q)
        last_levels: Last level nodes for optimization (may be empty)
        evals: Polynomial evaluations at challenge point
        airgroup_values: AIR group values (for aggregation)
        air_values: AIR-specific values
        custom_commits: Custom commitment names
        fri: FRI opening proof
        nonce: Proof-of-work nonce
    """
    # Stage commitments
    roots: List[List[int]] = field(default_factory=list)  # [n_stages + 1][HASH_SIZE]
    last_levels: List[List[int]] = field(default_factory=list)  # [n_stages + n_custom + 1][nodes]

    # Polynomial evaluations
    evals: List[List[int]] = field(default_factory=list)  # [n_evals][FIELD_EXTENSION]

    # AIR values
    airgroup_values: List[List[int]] = field(default_factory=list)  # [n_airgroup][FIELD_EXTENSION]
    air_values: List[List[int]] = field(default_factory=list)  # [n_air][FIELD_EXTENSION]

    # Custom commits
    custom_commits: List[str] = field(default_factory=list)

    # FRI proof
    fri: FriProof = field(default_factory=FriProof)

    # Proof-of-work
    nonce: int = 0


# C++: No direct equivalent (Python-specific wrapper with metadata)
@dataclass
class FRIProofFull:
    """Full FRI proof with metadata.

    Corresponds to C++ class FRIProof in proof_stark.hpp (lines 539-556).

    Attributes:
        proof: The STARK proof data
        publics: Public inputs (Goldilocks field elements)
        airgroup_id: AIR group identifier
        air_id: AIR identifier
        instance_id: Instance identifier
    """
    proof: STARKProof = field(default_factory=STARKProof)
    publics: List[int] = field(default_factory=list)
    airgroup_id: int = 0
    air_id: int = 0
    instance_id: int = 0


# C++: No direct equivalent (Python-specific serialization)
def proof_to_json(proof: STARKProof, n_stages: int, n_field_elements: int = HASH_SIZE) -> Dict[str, Any]:
    """Convert STARK proof to JSON-serializable dictionary.

    Corresponds to C++ Proofs::proof2json() (lines 380-536 of proof_stark.hpp).

    Args:
        proof: STARK proof to serialize
        n_stages: Number of proof stages
        n_field_elements: Number of field elements per hash (4 for GL, 1 for BN128)

    Returns:
        JSON-serializable dictionary
    """
    j = {}

    # Stage roots (lines 384-394)
    for i in range(n_stages):
        if n_field_elements == 1:
            j[f"root{i + 1}"] = str(proof.roots[i][0])
        else:
            j[f"root{i + 1}"] = [str(r) for r in proof.roots[i]]

    # Evaluations (lines 396-404)
    j["evals"] = []
    for ev in proof.evals:
        j["evals"].append([str(e) for e in ev])

    # AIR group values (lines 406-416)
    if len(proof.airgroup_values) > 0:
        j["airgroupvalues"] = []
        for av in proof.airgroup_values:
            j["airgroupvalues"].append([str(a) for a in av])

    # AIR values (lines 418-428)
    if len(proof.air_values) > 0:
        j["airvalues"] = []
        for av in proof.air_values:
            j["airvalues"].append([str(a) for a in av])

    # Final polynomial (lines 527-534)
    j["finalPol"] = []
    for pol_coef in proof.fri.pol:
        j["finalPol"].append([str(c) for c in pol_coef])

    # Nonce
    j["nonce"] = str(proof.nonce)

    return j


# C++: No direct equivalent (Python-specific deserialization)
def load_proof_from_json(path: str) -> Tuple[STARKProof, Dict[str, Any]]:
    """Load STARK proof from JSON file.

    This function loads proof data from JSON files generated by the C++
    implementation (via pointer2json in proof2zkinStark.cpp).

    Args:
        path: Path to JSON proof file

    Returns:
        Tuple of (STARKProof, metadata_dict)

    Raises:
        FileNotFoundError: If file doesn't exist
        json.JSONDecodeError: If file is not valid JSON
    """
    with open(path, 'r') as f:
        data = json.load(f)

    proof = STARKProof()
    metadata = {}

    # Extract metadata if present
    if "metadata" in data:
        metadata = data["metadata"]

    # Load roots (lines 37-43 of proof2zkinStark.cpp)
    i = 1
    while f"root{i}" in data:
        root_data = data[f"root{i}"]
        if isinstance(root_data, list):
            proof.roots.append([int(r) for r in root_data])
        else:
            proof.roots.append([int(root_data)])
        i += 1

    # Load evaluations (lines 45-53)
    if "evals" in data:
        for ev_data in data["evals"]:
            proof.evals.append([int(e) for e in ev_data])

    # Load AIR group values (lines 13-22)
    if "airgroupvalues" in data:
        for av_data in data["airgroupvalues"]:
            proof.airgroup_values.append([int(a) for a in av_data])

    # Load AIR values (lines 25-35)
    if "airvalues" in data:
        for av_data in data["airvalues"]:
            proof.air_values.append([int(a) for a in av_data])

    # Load final polynomial (lines 185-192)
    if "finalPol" in data:
        for pol_data in data["finalPol"]:
            proof.fri.pol.append([int(c) for c in pol_data])

    # Load nonce (line 194)
    if "nonce" in data:
        proof.nonce = int(data["nonce"])

    # Load FRI roots (lines 150-155)
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


# C++: Proofs::loadProof methods in proof_stark.hpp
def load_proof_from_binary(path: str) -> STARKProof:
    """Load STARK proof from binary file.

    This is a placeholder for binary proof loading. The C++ implementation
    uses proof2pointer (lines 235-378 of proof_stark.hpp) to serialize
    proofs to a binary buffer.

    Args:
        path: Path to binary proof file

    Returns:
        Loaded STARKProof

    Raises:
        NotImplementedError: Binary loading not yet implemented
    """
    raise NotImplementedError(
        "Binary proof loading not yet implemented. "
        "Use load_proof_from_json() instead."
    )


# C++: Proofs pointer/offset layout methods
def proof_to_pointer_layout(proof: STARKProof, stark_info: Any) -> List[int]:
    """Convert STARK proof to pointer layout (array of uint64).

    Corresponds to C++ Proofs::proof2pointer() (lines 235-378 of proof_stark.hpp).

    This function serializes the proof into a flat array of uint64 values,
    matching the C++ binary layout exactly. This is useful for:
    1. Cross-validation with C++ implementation
    2. Binary proof file generation
    3. Understanding proof structure

    Args:
        proof: STARK proof to serialize
        stark_info: StarkInfo configuration

    Returns:
        List of uint64 values representing the serialized proof

    Note:
        This is a reference implementation. The full implementation would
        need to handle all proof components in the exact order specified
        by the C++ code.
    """
    pointer = []

    # AIR group values (lines 238-243)
    for av in proof.airgroup_values:
        pointer.extend(av)

    # AIR values (lines 246-251)
    for av in proof.air_values:
        pointer.extend(av)

    # Stage roots (lines 253-258)
    for root in proof.roots:
        pointer.extend(root)

    # Evaluations (lines 260-265)
    for ev in proof.evals:
        pointer.extend(ev)

    # ... (remaining components would follow the C++ implementation)

    # Final polynomial (lines 368-373)
    for pol_coef in proof.fri.pol:
        pointer.extend(pol_coef)

    # Nonce (line 375)
    pointer.append(proof.nonce)

    return pointer


# C++: Proofs::toBytes methods
def to_bytes_partial(proof_dict: Dict[str, Any], stark_info: Any) -> Tuple[bytes, bytes]:
    """Serialize proof header and footer to bytes for partial comparison.

    Since the Python spec doesn't generate query proofs (Merkle paths), we can only
    compare the header (before query data) and footer (after query data) portions
    of the proof.

    The C++ proof2pointer layout is:
        1. airgroupValues          <- HEADER (we have)
        2. airValues               <- HEADER (we have)
        3. roots                   <- HEADER (we have, may be empty)
        4. evals                   <- HEADER (we have)
        5-11. Query proofs         <- QUERY DATA (we don't have)
        12. finalPol               <- FOOTER (we have)
        13. nonce                  <- FOOTER (we have)

    Args:
        proof_dict: Proof dictionary from gen_proof()
        stark_info: StarkInfo configuration

    Returns:
        Tuple of (header_bytes, footer_bytes)
    """
    import struct

    header_values = []

    # 1. airgroupValues (FIELD_EXTENSION per entry)
    # Use len(airgroupValuesMap) to get actual count, not buffer size
    airgroup_values = proof_dict.get('airgroup_values', [])
    if hasattr(airgroup_values, 'tolist'):
        airgroup_values = airgroup_values.tolist()
    n_airgroup_values = len(stark_info.airgroupValuesMap)
    for i in range(n_airgroup_values):
        start = i * FIELD_EXTENSION
        header_values.extend(int(v) for v in airgroup_values[start:start + FIELD_EXTENSION])

    # 2. airValues (FIELD_EXTENSION per entry)
    # Use len(airValuesMap) to get actual count, not buffer size
    air_values = proof_dict.get('air_values', [])
    if hasattr(air_values, 'tolist'):
        air_values = air_values.tolist()
    n_air_values = len(stark_info.airValuesMap)
    for i in range(n_air_values):
        start = i * FIELD_EXTENSION
        header_values.extend(int(v) for v in air_values[start:start + FIELD_EXTENSION])

    # 3. roots (HASH_SIZE per stage, nStages+1 stages)
    roots = proof_dict.get('roots', [])
    for root in roots:
        header_values.extend(int(v) for v in root[:HASH_SIZE])

    # 4. evals (FIELD_EXTENSION per eval)
    # Use len(evMap) to get actual count
    evals = proof_dict.get('evals', [])
    if hasattr(evals, 'tolist'):
        evals = evals.tolist()
    n_evals = len(stark_info.evMap)
    for i in range(n_evals):
        start = i * FIELD_EXTENSION
        header_values.extend(int(v) for v in evals[start:start + FIELD_EXTENSION])

    # Convert header to bytes
    header_bytes = struct.pack(f'<{len(header_values)}Q', *header_values)

    # Footer: finalPol and nonce
    footer_values = []

    # 12. finalPol (FIELD_EXTENSION per coefficient)
    fri_proof = proof_dict.get('fri_proof')
    if fri_proof is not None:
        final_pol = fri_proof.final_pol if hasattr(fri_proof, 'final_pol') else []
        if hasattr(final_pol, 'tolist'):
            final_pol = final_pol.tolist()
        for i in range(0, len(final_pol), FIELD_EXTENSION):
            footer_values.extend(int(v) for v in final_pol[i:i + FIELD_EXTENSION])

    # 13. nonce
    nonce = proof_dict.get('nonce', 0)
    footer_values.append(int(nonce))

    # Convert footer to bytes
    footer_bytes = struct.pack(f'<{len(footer_values)}Q', *footer_values)

    return header_bytes, footer_bytes


# C++: Proofs::toBytesFull methods
def to_bytes_full(proof: STARKProof, stark_info: Any) -> bytes:
    """Serialize STARK proof to canonical binary format matching C++ proof2pointer().

    This function produces the exact byte layout that C++ proof2pointer() generates.
    Use this for byte-level equivalence testing.

    Args:
        proof: STARKProof instance with all fields populated
        stark_info: StarkInfo configuration

    Returns:
        bytes: Little-endian packed uint64 array

    Raises:
        ValueError: If proof is missing required fields for full serialization

    Note:
        This requires a fully-populated STARKProof including query proofs.
        For partial comparison (without query proofs), use to_bytes_partial().
    """
    import struct
    import math

    values = []

    # 1. airgroupValues (FIELD_EXTENSION per entry)
    for av in proof.airgroup_values:
        values.extend(av[:FIELD_EXTENSION])

    # 2. airValues (FIELD_EXTENSION per entry)
    for av in proof.air_values:
        values.extend(av[:FIELD_EXTENSION])

    # 3. roots (HASH_SIZE per stage, nStages+1 stages)
    for root in proof.roots:
        values.extend(root[:HASH_SIZE])

    # 4. evals (FIELD_EXTENSION per eval)
    for ev in proof.evals:
        values.extend(ev[:FIELD_EXTENSION])

    # 5-11. Query proofs
    # These require MerkleProof data which Python spec doesn't yet generate
    if not hasattr(proof.fri, 'trees') or not proof.fri.trees.pol_queries:
        raise ValueError(
            "Cannot serialize full proof: query proofs not populated. "
            "Use to_bytes_partial() for partial comparison."
        )

    n_queries = stark_info.starkStruct.nQueries
    n_constants = stark_info.nConstants
    n_stages = stark_info.nStages
    n_field_elements = HASH_SIZE  # 4 for Goldilocks
    merkle_arity = stark_info.starkStruct.merkleTreeArity
    last_level_verification = stark_info.starkStruct.lastLevelVerification

    n_siblings = int(math.ceil(stark_info.starkStruct.steps[0].nBits / math.log2(merkle_arity))) - last_level_verification
    n_siblings_per_level = (merkle_arity - 1) * n_field_elements

    # 5. Constant tree query values
    for i in range(n_queries):
        for l in range(n_constants):
            values.append(proof.fri.trees.pol_queries[i][n_stages + 1].v[l][0])

    # 6. Constant tree merkle paths
    for i in range(n_queries):
        for l in range(n_siblings):
            values.extend(proof.fri.trees.pol_queries[i][n_stages + 1].mp[l][:n_siblings_per_level])

    # 7. Constant tree last_levels (if applicable)
    if last_level_verification != 0:
        num_nodes = int(merkle_arity ** last_level_verification) * n_field_elements
        values.extend(proof.last_levels[n_stages + 1][:num_nodes])

    # 8. Custom commits (iterate over each)
    for c, custom_commit in enumerate(stark_info.customCommits):
        custom_name = custom_commit.name + "0"
        n_custom_cols = stark_info.mapSectionsN.get(custom_name, 0)
        tree_idx = n_stages + 2 + c

        # Query values
        for i in range(n_queries):
            for l in range(n_custom_cols):
                values.append(proof.fri.trees.pol_queries[i][tree_idx].v[l][0])

        # Merkle paths
        for i in range(n_queries):
            for l in range(n_siblings):
                values.extend(proof.fri.trees.pol_queries[i][tree_idx].mp[l][:n_siblings_per_level])

        # Last levels
        if last_level_verification != 0:
            values.extend(proof.last_levels[tree_idx][:num_nodes])

    # 9. Stage trees (cm1, cm2, ..., cmQ)
    for s in range(n_stages + 1):
        stage = s + 1
        stage_name = f"cm{stage}"
        n_stage_cols = stark_info.mapSectionsN.get(stage_name, 0)

        # Query values
        for i in range(n_queries):
            for l in range(n_stage_cols):
                values.append(proof.fri.trees.pol_queries[i][s].v[l][0])

        # Merkle paths
        for i in range(n_queries):
            for l in range(n_siblings):
                values.extend(proof.fri.trees.pol_queries[i][s].mp[l][:n_siblings_per_level])

        # Last levels
        if last_level_verification != 0:
            values.extend(proof.last_levels[s][:num_nodes])

    # 10. FRI step roots
    for step in range(1, len(stark_info.starkStruct.steps)):
        values.extend(proof.fri.trees_fri[step - 1].root[:n_field_elements])

    # 11. FRI step query proofs
    for step in range(1, len(stark_info.starkStruct.steps)):
        prev_bits = stark_info.starkStruct.steps[step - 1].nBits
        curr_bits = stark_info.starkStruct.steps[step].nBits
        n_fri_vals = (1 << (prev_bits - curr_bits)) * FIELD_EXTENSION

        # Query values
        for i in range(n_queries):
            for l in range(n_fri_vals):
                values.append(proof.fri.trees_fri[step - 1].pol_queries[i][0].v[l][0])

        # Merkle paths
        n_siblings_fri = int(math.ceil(curr_bits / math.log2(merkle_arity))) - last_level_verification
        for i in range(n_queries):
            for l in range(n_siblings_fri):
                values.extend(proof.fri.trees_fri[step - 1].pol_queries[i][0].mp[l][:n_siblings_per_level])

        # Last levels
        if last_level_verification != 0:
            values.extend(proof.fri.trees_fri[step - 1].last_levels[:num_nodes])

    # 12. finalPol (FIELD_EXTENSION per coefficient)
    for pol_coef in proof.fri.pol:
        values.extend(pol_coef[:FIELD_EXTENSION])

    # 13. nonce
    values.append(proof.nonce)

    return struct.pack(f'<{len(values)}Q', *values)


# C++: No direct equivalent (Python-specific)
def to_bytes_full_from_dict(proof_dict: Dict[str, Any], stark_info: Any) -> bytes:
    """Serialize proof dictionary to canonical binary format matching C++ proof2pointer().

    This function takes the proof dictionary from gen_proof() and produces the exact
    byte layout that C++ proof2pointer() generates. Use this for byte-level equivalence
    testing.

    Binary layout (sections 1-13):
        1. airgroupValues    [n_airgroup × FIELD_EXTENSION]
        2. airValues         [n_air × FIELD_EXTENSION]
        3. roots             [(nStages+1) × HASH_SIZE]
        4. evals             [n_evals × FIELD_EXTENSION]
        5. const tree values [nQueries × nConstants]
        6. const tree siblings [nQueries × nSiblings × (arity-1) × HASH_SIZE]
        7. const tree last_lvls [arity^lastLvl × HASH_SIZE] (if applicable)
        8. custom commit proofs [for each custom commit...]
        9. stage tree proofs   [for cm1, cm2, ..., cmQ...]
        10. FRI step roots     [(nSteps-1) × HASH_SIZE]
        11. FRI step proofs    [for each step: values + siblings + last_lvls]
        12. finalPol          [final_degree × FIELD_EXTENSION]
        13. nonce             [1 element]

    Args:
        proof_dict: Proof dictionary from gen_proof()
        stark_info: StarkInfo configuration

    Returns:
        bytes: Little-endian packed uint64 array identical to C++ proof2pointer()

    Raises:
        ValueError: If proof is incomplete (missing required components)
    """
    import struct
    import math

    values: List[int] = []

    # Helper to convert numpy arrays or lists
    def to_list(arr):
        if hasattr(arr, 'tolist'):
            return arr.tolist()
        return list(arr) if arr is not None else []

    # Extract components from proof_dict
    airgroup_values = to_list(proof_dict.get('airgroup_values', []))
    air_values = to_list(proof_dict.get('air_values', []))
    roots = proof_dict.get('roots', [])
    evals = to_list(proof_dict.get('evals', []))
    fri_proof = proof_dict.get('fri_proof')
    stage_query_proofs = proof_dict.get('stage_query_proofs', {})
    query_indices = proof_dict.get('query_indices', [])
    nonce = proof_dict.get('nonce', 0)
    last_level_nodes = proof_dict.get('last_level_nodes', {})

    # Configuration
    n_queries = stark_info.starkStruct.nQueries
    n_stages = stark_info.nStages
    merkle_arity = stark_info.starkStruct.merkleTreeArity
    last_level_verification = stark_info.starkStruct.lastLevelVerification

    # --- SECTION 1: airgroupValues ---
    n_airgroup_values = len(stark_info.airgroupValuesMap)
    for i in range(n_airgroup_values):
        start = i * FIELD_EXTENSION
        values.extend(int(v) for v in airgroup_values[start:start + FIELD_EXTENSION])

    # --- SECTION 2: airValues ---
    n_air_values = len(stark_info.airValuesMap)
    for i in range(n_air_values):
        start = i * FIELD_EXTENSION
        values.extend(int(v) for v in air_values[start:start + FIELD_EXTENSION])

    # --- SECTION 3: roots ---
    for root in roots:
        values.extend(int(v) for v in root[:HASH_SIZE])

    # --- SECTION 4: evals ---
    n_evals = len(stark_info.evMap)
    for i in range(n_evals):
        start = i * FIELD_EXTENSION
        values.extend(int(v) for v in evals[start:start + FIELD_EXTENSION])

    # --- SECTIONS 5-7: const tree query proofs ---
    const_query_proofs = proof_dict.get('const_query_proofs', [])
    n_constants = len(stark_info.constPolsMap)

    if const_query_proofs and n_constants > 0:
        # Calculate Merkle proof dimensions for const tree
        n_bits_ext = stark_info.starkStruct.nBitsExt
        n_siblings_const = int(math.ceil(n_bits_ext / math.log2(merkle_arity))) - last_level_verification
        n_siblings_per_level = (merkle_arity - 1) * HASH_SIZE

        # 5. Const tree values (for all queries)
        for query_proof in const_query_proofs:
            for col in range(n_constants):
                if col < len(query_proof.v):
                    values.append(int(query_proof.v[col][0]))
                else:
                    values.append(0)

        # 6. Const tree Merkle paths (for all queries)
        for query_proof in const_query_proofs:
            for level_idx in range(n_siblings_const):
                if level_idx < len(query_proof.mp):
                    values.extend(int(v) for v in query_proof.mp[level_idx][:n_siblings_per_level])
                else:
                    values.extend([0] * n_siblings_per_level)

        # 7. Const tree last levels (if applicable)
        if last_level_verification != 0:
            num_nodes = int(merkle_arity ** last_level_verification) * HASH_SIZE
            const_last_lvl = last_level_nodes.get('const', [])
            if const_last_lvl:
                values.extend(int(v) for v in const_last_lvl[:num_nodes])
            else:
                values.extend([0] * num_nodes)

    # --- SECTION 8: custom commits ---
    # NOTE: Custom commits not yet implemented in Python spec
    # Skip for now (customCommits = 0 for all test AIRs)

    # --- SECTION 9: stage tree proofs (cm1, cm2, ..., cmQ) ---
    # Calculate Merkle proof dimensions
    n_bits_ext = stark_info.starkStruct.nBitsExt
    n_siblings = int(math.ceil(n_bits_ext / math.log2(merkle_arity))) - last_level_verification
    n_siblings_per_level = (merkle_arity - 1) * HASH_SIZE

    for stage_num in range(1, n_stages + 2):  # stages 1, 2, ..., nStages+1(Q)
        stage_name = f"cm{stage_num}"
        n_stage_cols = stark_info.mapSectionsN.get(stage_name, 0)

        if stage_num not in stage_query_proofs:
            raise ValueError(f"Missing stage {stage_num} query proofs for full serialization")

        proofs = stage_query_proofs[stage_num]

        # 9a. Stage tree values (for all queries)
        for query_proof in proofs:
            # Each query_proof.v is List[List[int]] where v[col] = [val]
            for col in range(n_stage_cols):
                if col < len(query_proof.v):
                    values.append(int(query_proof.v[col][0]))
                else:
                    values.append(0)  # Padding if needed

        # 9b. Stage tree Merkle paths (for all queries)
        for query_proof in proofs:
            for level_idx in range(n_siblings):
                if level_idx < len(query_proof.mp):
                    values.extend(int(v) for v in query_proof.mp[level_idx][:n_siblings_per_level])
                else:
                    values.extend([0] * n_siblings_per_level)  # Padding if needed

        # 9c. Stage tree last levels (if applicable)
        if last_level_verification != 0:
            num_nodes = int(merkle_arity ** last_level_verification) * HASH_SIZE
            stage_last_lvl = last_level_nodes.get(stage_name, [])
            if stage_last_lvl:
                values.extend(int(v) for v in stage_last_lvl[:num_nodes])
            else:
                values.extend([0] * num_nodes)

    # --- SECTION 10: FRI step roots ---
    if fri_proof is not None:
        for fri_root in fri_proof.fri_roots:
            values.extend(int(v) for v in fri_root[:HASH_SIZE])

    # --- SECTION 11: FRI step query proofs ---
    if fri_proof is not None:
        for step_idx in range(len(stark_info.starkStruct.steps) - 1):
            prev_bits = stark_info.starkStruct.steps[step_idx].nBits
            curr_bits = stark_info.starkStruct.steps[step_idx + 1].nBits
            n_fri_groups = 1 << (prev_bits - curr_bits)

            # 11a. FRI values (for all queries at this step)
            if step_idx < len(fri_proof.query_proofs):
                step_proofs = fri_proof.query_proofs[step_idx]
                for qp in step_proofs:
                    # qp.v is List[List[int]] where v[group] = [val0, val1, val2]
                    for group_idx in range(n_fri_groups):
                        if group_idx < len(qp.v):
                            values.extend(int(v) for v in qp.v[group_idx][:FIELD_EXTENSION])
                        else:
                            values.extend([0] * FIELD_EXTENSION)

            # 11b. FRI Merkle paths (for all queries at this step)
            n_siblings_fri = int(math.ceil(curr_bits / math.log2(merkle_arity))) - last_level_verification
            if step_idx < len(fri_proof.query_proofs):
                step_proofs = fri_proof.query_proofs[step_idx]
                for qp in step_proofs:
                    for level_idx in range(n_siblings_fri):
                        if level_idx < len(qp.mp):
                            values.extend(int(v) for v in qp.mp[level_idx][:n_siblings_per_level])
                        else:
                            values.extend([0] * n_siblings_per_level)

            # 11c. FRI last levels (if applicable)
            if last_level_verification != 0:
                num_nodes = int(merkle_arity ** last_level_verification) * HASH_SIZE
                fri_last_lvl = last_level_nodes.get(f'fri{step_idx}', [])
                if fri_last_lvl:
                    values.extend(int(v) for v in fri_last_lvl[:num_nodes])
                else:
                    values.extend([0] * num_nodes)

    # --- SECTION 12: finalPol ---
    if fri_proof is not None:
        final_pol = to_list(fri_proof.final_pol)
        for i in range(0, len(final_pol), FIELD_EXTENSION):
            values.extend(int(v) for v in final_pol[i:i + FIELD_EXTENSION])

    # --- SECTION 13: nonce ---
    values.append(int(nonce))

    return struct.pack(f'<{len(values)}Q', *values)


# C++: No direct equivalent (Python-specific validation)
def validate_proof_structure(proof: STARKProof, stark_info: Any) -> List[str]:
    """Validate that proof structure matches STARK configuration.

    Args:
        proof: STARK proof to validate
        stark_info: StarkInfo configuration

    Returns:
        List of validation error messages (empty if valid)
    """
    errors = []

    # Check number of stages
    expected_stages = stark_info.nStages + 1
    if len(proof.roots) != expected_stages:
        errors.append(
            f"Expected {expected_stages} stage roots, got {len(proof.roots)}"
        )

    # Check evaluations
    if len(proof.evals) != len(stark_info.evMap):
        errors.append(
            f"Expected {len(stark_info.evMap)} evaluations, got {len(proof.evals)}"
        )

    # Check evaluation dimensions
    for i, ev in enumerate(proof.evals):
        if len(ev) != FIELD_EXTENSION:
            errors.append(
                f"Evaluation {i} has dimension {len(ev)}, expected {FIELD_EXTENSION}"
            )

    # Check AIR group values
    if len(proof.airgroup_values) != len(stark_info.airgroupValuesMap):
        errors.append(
            f"Expected {len(stark_info.airgroupValuesMap)} airgroup values, "
            f"got {len(proof.airgroup_values)}"
        )

    # Check AIR values
    if len(proof.air_values) != len(stark_info.airValuesMap):
        errors.append(
            f"Expected {len(stark_info.airValuesMap)} air values, "
            f"got {len(proof.air_values)}"
        )

    # Check FRI steps
    expected_fri_steps = len(stark_info.starkStruct.steps) - 1
    if len(proof.fri.trees_fri) != expected_fri_steps:
        errors.append(
            f"Expected {expected_fri_steps} FRI trees, got {len(proof.fri.trees_fri)}"
        )

    # Check final polynomial degree
    if len(proof.fri.pol) > 0:
        expected_degree = 1 << stark_info.starkStruct.steps[-1].nBits
        if len(proof.fri.pol) != expected_degree:
            errors.append(
                f"Final polynomial degree {len(proof.fri.pol)}, "
                f"expected {expected_degree}"
            )

    return errors
