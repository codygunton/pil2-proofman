"""ProofContext container for prover/verifier working data."""

from dataclasses import dataclass

import numpy as np

from primitives.field import FF, FF3, FIELD_EXTENSION_DEGREE

# Type aliases for documentation
FFArray = FF  # 1D array of base field elements
FF3Array = FF3  # 1D array of extension field elements


@dataclass
class ProofContext:
    """Container for all prover/verifier working data.

    This is the external interface for proof generation and verification.
    Internally, the prover converts this to ProverData for constraint/witness
    module evaluation.

    Buffer Layout:
    - trace: Stage 1 witness polynomials (base field, N rows × nCols)
    - auxTrace: Stages 2+ polynomials (interleaved FF/FF3, complex layout)
    - constPols: Constant polynomials (base field)
    - constPolsExtended: Extended constant polynomials (base field)

    C++ reference: pil2-stark/src/starkpil/steps.hpp::StepsParams
    """

    # --- Stage 1 witness (base field) ---
    trace: np.ndarray | None = None

    # --- Working buffer for stages 2+ ---
    # Interleaved FF/FF3 sections matching C++ buffer layout
    auxTrace: np.ndarray | None = None

    # --- Public inputs (base field) ---
    publicInputs: np.ndarray | None = None

    # --- Proof values (base field, application-specific) ---
    proofValues: np.ndarray | None = None

    # --- Fiat-Shamir challenges (interleaved FF3 coefficients) ---
    # Layout: [c0_0, c0_1, c0_2, c1_0, c1_1, c1_2, ...]
    challenges: np.ndarray | None = None

    # --- AIR group constraint values (interleaved FF3 coefficients) ---
    airgroupValues: np.ndarray | None = None

    # --- AIR constraint values (mixed: stage 1 = FF, others = FF3) ---
    airValues: np.ndarray | None = None

    # --- Polynomial evaluations at opening points (interleaved FF3) ---
    evals: np.ndarray | None = None

    # --- Precomputed x/(x-xi) denominators for verifier ---
    xDivXSub: np.ndarray | None = None

    # --- Constant polynomials (base field) ---
    constPols: np.ndarray | None = None
    constPolsExtended: np.ndarray | None = None

    # --- Custom commitment data (application-specific) ---
    customCommits: np.ndarray | None = None

    # --- Challenge Access Helpers ---

    def get_challenge(self, index: int) -> list[int]:
        """Get challenge at index as [c0, c1, c2] coefficients."""
        base = index * FIELD_EXTENSION_DEGREE
        return [int(self.challenges[base + j]) for j in range(FIELD_EXTENSION_DEGREE)]

    def set_challenge(self, index: int, value: list[int]) -> None:
        """Set challenge at index from [c0, c1, c2] coefficients."""
        base = index * FIELD_EXTENSION_DEGREE
        for j in range(FIELD_EXTENSION_DEGREE):
            self.challenges[base + j] = value[j]
