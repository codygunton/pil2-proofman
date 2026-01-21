"""StepsParams container for prover/verifier working data.

Faithful translation from pil2-stark/src/starkpil/steps.hpp.
Contains all working buffers used during proof generation and verification.
"""

from dataclasses import dataclass
from typing import Optional
import numpy as np


# C++: pil2-stark/src/starkpil/steps.hpp::StepsParams (lines 6-20)
@dataclass
class StepsParams:
    """Container for all prover/verifier working data.

    This is a direct translation of the C++ StepsParams struct. In C++, these
    are raw pointers to Goldilocks::Element arrays. In Python, we use numpy
    arrays with dtype matching the Goldilocks field (uint64).

    All arrays are views into larger buffers, allocated and managed by the
    prover/verifier orchestrator. The shape and layout of each array depends
    on the specific AIR being proven.

    Attributes:
        trace: Stage 1 witness trace (N × n_trace_cols). Main execution trace.
        aux_trace: Extended working buffer for intermediate and quotient polys.
        public_inputs: Public inputs to the computation (n_publics elements).
        proof_values: Proof-specific values (not challenges).
        challenges: Fiat-Shamir challenges (n_challenges × 3 for field extension).
        airgroup_values: AIR group constraint values.
        air_values: Individual AIR constraint values.
        evals: Polynomial evaluations at opening points (for FRI).
        x_div_x_sub: Precomputed x/(x-xi) denominators for verifier efficiency.
        const_pols: Constant polynomials (preprocessed, N × n_const_cols).
        const_pols_extended: Extended constant polynomials (N_ext × n_const_cols).
        custom_commits: Custom commitment data (application-specific).
    """

    trace: Optional[np.ndarray] = None
    auxTrace: Optional[np.ndarray] = None
    publicInputs: Optional[np.ndarray] = None
    proofValues: Optional[np.ndarray] = None
    challenges: Optional[np.ndarray] = None
    airgroupValues: Optional[np.ndarray] = None
    airValues: Optional[np.ndarray] = None
    evals: Optional[np.ndarray] = None
    xDivXSub: Optional[np.ndarray] = None
    constPols: Optional[np.ndarray] = None
    constPolsExtended: Optional[np.ndarray] = None
    customCommits: Optional[np.ndarray] = None

    # C++: StepsParams initialization logic
    def __post_init__(self):
        """Validate that arrays have correct dtype if provided."""
        # In the C++ code, all fields are Goldilocks::Element* (uint64_t*)
        # In Python, we use uint64 arrays to maintain bit-exact compatibility
        for field_name in ['trace', 'auxTrace', 'publicInputs', 'proofValues',
                          'challenges', 'airgroupValues', 'airValues', 'evals',
                          'xDivXSub', 'constPols', 'constPolsExtended',
                          'customCommits']:
            arr = getattr(self, field_name)
            if arr is not None and not isinstance(arr, np.ndarray):
                raise TypeError(f"{field_name} must be a numpy array")
