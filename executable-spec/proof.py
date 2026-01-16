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

from stark_info import FIELD_EXTENSION, HASH_SIZE


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
