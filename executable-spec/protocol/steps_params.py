"""StepsParams container for prover/verifier working data."""

from dataclasses import dataclass
from typing import Optional, Union

import numpy as np

from primitives.field import FF, FF3, FIELD_EXTENSION_DEGREE

# Type aliases for documentation
# Note: FF and FF3 are galois FieldArray types from primitives.field
FFArray = FF  # 1D array of base field elements
FF3Array = FF3  # 1D array of extension field elements


@dataclass
class StepsParams:
    """Container for all prover/verifier working data.

    C++ reference: pil2-stark/src/starkpil/steps.hpp::StepsParams
    """

    # --- Stage 1 witness (base field) ---
    trace: Optional[Union[FFArray, np.ndarray]] = None

    # --- Working buffer for stages 2+ (mixed FF and FF3 sections) ---
    # Keep as uint64 for now - complex multi-section layout with interleaved
    # base field and extension field values. TODO: May need phased migration.
    auxTrace: Optional[np.ndarray] = None

    # --- Public inputs (base field) ---
    # A: Union[FFArray, np.ndarray] exists because we're in a transitional state -
    # some callers (tests, expression_evaluator) still pass np.ndarray. The goal is
    # to use FF/FF3 exclusively here, with np.ndarray only in auxTrace (which has
    # interleaved FF/FF3 sections for C++ buffer compatibility).
    # TODO: Remove Union types, make all fields strictly FF or FF3, fix all callers
    publicInputs: Optional[Union[FFArray, np.ndarray]] = None

    # --- Proof values (base field, application-specific) ---
    proofValues: Optional[Union[FFArray, np.ndarray]] = None

    # --- Fiat-Shamir challenges (extension field) ---
    # Shape: (n_challenges,) as FF3 elements
    challenges: Optional[Union[FF3Array, np.ndarray]] = None

    # --- AIR group constraint values (extension field) ---
    airgroupValues: Optional[Union[FF3Array, np.ndarray]] = None

    # --- AIR constraint values (mixed: stage 1 = base field, others = extension) ---
    # Complex layout: stage 1 values are single Fe, stage 2+ values are Fe3.
    # Keep as np.ndarray for now - needs careful handling in expression evaluator.
    airValues: Optional[np.ndarray] = None

    # --- Polynomial evaluations at opening points (extension field) ---
    # Shape: (n_evals,) as FF3 elements
    evals: Optional[Union[FF3Array, np.ndarray]] = None

    # --- Precomputed x/(x-xi) denominators for verifier (extension field) ---
    xDivXSub: Optional[Union[FF3Array, np.ndarray]] = None

    # --- Constant polynomials (base field) ---
    constPols: Optional[Union[FFArray, np.ndarray]] = None
    constPolsExtended: Optional[Union[FFArray, np.ndarray]] = None

    # --- Custom commitment data (base field, application-specific) ---
    customCommits: Optional[Union[FFArray, np.ndarray]] = None

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
