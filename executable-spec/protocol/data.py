"""Clean data structures for constraint and witness module evaluation.

Architecture Overview:
    The STARK prover/verifier uses a two-layer data model:

    1. ProofContext (protocol/proof_context.py)
       - Buffer-based storage with C++ compatible layout
       - Used by: Merkle tree building, NTT, FRI polynomial computation
       - Efficient for bulk protocol operations

    2. ProverData / VerifierData (this module)
       - Dict-based storage with named columns
       - Used by: Constraint modules, witness modules
       - Readable for AIR-specific code

    The bridge functions (_build_prover_data_base, _build_prover_data_extended)
    convert from ProofContext to ProverData when needed for constraint/witness
    module evaluation.

Usage:
    # Prover: constraint module evaluation
    prover_data = _build_prover_data_extended(stark_info, params, constPolsExtended)
    ctx = ProverConstraintContext(prover_data)
    q = constraint_module.constraint_polynomial(ctx)

    # Verifier: constraint evaluation at single point
    verifier_data = _build_verifier_data(stark_info, evals, challenges, airgroup_values)
    ctx = VerifierConstraintContext(verifier_data)
    q_at_xi = constraint_module.constraint_polynomial(ctx)
"""

from dataclasses import dataclass, field

import numpy as np

from primitives.field import FF, FF3

# Type aliases
FF3Poly = FF3  # Array of extension field elements (polynomial over FF3)
FFPoly = FF    # Array of base field elements (polynomial over FF)


@dataclass
class ProverData:
    """Polynomial data for constraint/witness module evaluation.

    This provides a clean dict-based interface for AIR-specific code.
    Columns are keyed by (name, index) tuples for array columns like im_cluster.

    Attributes:
        columns: Polynomial columns keyed by (name, index)
        constants: Constant polynomials keyed by name
        challenges: Fiat-Shamir challenges keyed by name (e.g., 'std_alpha')
        public_inputs: Public inputs keyed by name
        airgroup_values: AIR group values keyed by index
        extend: Blowup factor (N_ext / N), 1 for base domain, 4+ for extended
    """
    columns: dict[tuple[str, int], FF3Poly] = field(default_factory=dict)
    constants: dict[str, FFPoly] = field(default_factory=dict)
    challenges: dict[str, FF3] = field(default_factory=dict)
    public_inputs: dict[str, FF] = field(default_factory=dict)
    airgroup_values: dict[int, FF3] = field(default_factory=dict)
    extend: int = 1

    def update_columns(self, new_columns: dict[tuple[str, int], FF3Poly]) -> None:
        """Add new columns (e.g., intermediates from witness generation)."""
        self.columns.update(new_columns)


@dataclass
class VerifierData:
    """Evaluation data for constraint module verification.

    This provides a clean dict-based interface for verifier constraint evaluation.
    Evaluations are keyed by (name, index, offset) where offset indicates row shift.

    Attributes:
        evals: Polynomial evaluations keyed by (name, index, offset)
        challenges: Fiat-Shamir challenges keyed by name
        public_inputs: Public inputs keyed by name
        airgroup_values: AIR group values keyed by index
    """
    evals: dict[tuple[str, int, int], FF3] = field(default_factory=dict)
    challenges: dict[str, FF3] = field(default_factory=dict)
    public_inputs: dict[str, FF] = field(default_factory=dict)
    airgroup_values: dict[int, FF3] = field(default_factory=dict)
    # Raw arrays for bytecode adapter (not used by hand-written modules)
    publics_flat: np.ndarray | None = None
    air_values_flat: np.ndarray | None = None
    proof_values_flat: np.ndarray | None = None
