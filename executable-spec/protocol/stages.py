"""Polynomial commitment stage orchestration.

This module provides the Starks class which manages the polynomial commitment
phase of STARK proof generation. For each "stage" of the protocol, Starks:

1. Takes polynomial evaluations from ProofContext
2. Extends them to the evaluation domain (via NTT)
3. Builds a Merkle tree commitment
4. Returns the Merkle root

Stages in the STARK protocol:
- Stage 1: Witness polynomials (execution trace)
- Stage 2: Intermediate polynomials (lookup/permutation support)
- Stage Q (nStages+1): Quotient polynomial (constraint checking)

The Merkle trees are retained for later query proof generation during FRI.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import numpy as np

from primitives.field import FF, FF3, ff3_from_interleaved_numpy
from primitives.merkle_tree import MerkleRoot, MerkleTree, QueryProof
from primitives.ntt import NTT
from primitives.pol_map import EvMap
from protocol.air_config import FIELD_EXTENSION_DEGREE, AirConfig, ProverHelpers
from protocol.data import ProverData
from protocol.proof_context import ProofContext

if TYPE_CHECKING:
    from protocol.stark_info import StarkInfo

# Late imports to avoid circular dependency:
# - constraints.base imports protocol.data
# - protocol.__init__ imports protocol.stages
# So we import get_constraint_module and get_witness_module inside functions


# --- Type Aliases ---
BufferOffset = int
StageIndex = int

# Backward compatibility alias
SetupCtx = AirConfig


def _build_prover_data_extended(
    stark_info: StarkInfo,
    params: ProofContext,
    constPolsExtended: np.ndarray
) -> ProverData:
    """Build ProverData from extended domain buffers.

    Extracts polynomial values from the extended domain buffers (after NTT)
    for constraint polynomial evaluation.

    Args:
        stark_info: StarkInfo with polynomial mappings
        params: ProofContext with trace buffers
        constPolsExtended: Extended constant polynomials

    Returns:
        ProverData ready for constraint evaluation
    """
    N = 1 << stark_info.starkStruct.nBits
    N_ext = 1 << stark_info.starkStruct.nBitsExt
    extend = N_ext // N  # Blowup factor for extended domain
    columns = {}
    constants = {}
    challenges = {}

    # Extract committed polynomials (all stages)
    for pol_info in stark_info.cmPolsMap:
        name = pol_info.name
        stage = pol_info.stage
        dim = pol_info.dim
        stage_pos = pol_info.stagePos

        section = f"cm{stage}"
        n_cols = stark_info.mapSectionsN.get(section, 0)
        offset = stark_info.mapOffsets.get((section, True), 0)  # Extended offset

        # Read polynomial values from buffer
        values = np.zeros(N_ext * dim, dtype=np.uint64)
        for j in range(N_ext):
            src_idx = offset + j * n_cols + stage_pos
            values[j * dim:(j + 1) * dim] = params.auxTrace[src_idx:src_idx + dim]

        # Find or compute the index for this polynomial name
        # Multiple columns may share the same name (e.g., im_cluster[0], im_cluster[1])
        index = 0
        for other in stark_info.cmPolsMap:
            if other.name == name and other.stagePos < stage_pos:
                index += 1

        if dim == 1:
            columns[(name, index)] = FF3(np.asarray(values, dtype=np.uint64))
        else:
            columns[(name, index)] = ff3_from_interleaved_numpy(values, N_ext)

    # Extract constant polynomials
    for pol_info in stark_info.constPolsMap:
        name = pol_info.name
        dim = pol_info.dim
        stage_pos = pol_info.stagePos
        n_cols = stark_info.nConstants

        values = np.zeros(N_ext * dim, dtype=np.uint64)
        for j in range(N_ext):
            src_idx = j * n_cols + stage_pos
            values[j * dim:(j + 1) * dim] = constPolsExtended[src_idx:src_idx + dim]

        if dim == 1:
            constants[name] = FF(np.asarray(values, dtype=np.uint64))
        else:
            # Constants are typically dim=1, but handle dim>1 if needed
            constants[name] = ff3_from_interleaved_numpy(values, N_ext)

    # Extract challenges
    for i, chal_info in enumerate(stark_info.challengesMap):
        name = chal_info.name
        idx = i * FIELD_EXTENSION_DEGREE
        coeff0 = int(params.challenges[idx])
        coeff1 = int(params.challenges[idx + 1])
        coeff2 = int(params.challenges[idx + 2])
        challenges[name] = FF3.Vector([coeff2, coeff1, coeff0])

    # Extract airgroup values (accumulated results across AIR instances)
    airgroup_values = {}
    n_airgroup_values = len(stark_info.airgroupValuesMap)
    for i in range(n_airgroup_values):
        idx = i * FIELD_EXTENSION_DEGREE
        coeff0 = int(params.airgroupValues[idx])
        coeff1 = int(params.airgroupValues[idx + 1])
        coeff2 = int(params.airgroupValues[idx + 2])
        airgroup_values[i] = FF3.Vector([coeff2, coeff1, coeff0])

    return ProverData(columns=columns, constants=constants, challenges=challenges,
                      airgroup_values=airgroup_values, extend=extend)


def _build_prover_data_base(
    stark_info: StarkInfo,
    params: ProofContext,
) -> ProverData:
    """Build ProverData from base domain buffers.

    Extracts polynomial values from the base domain buffers (before NTT extension)
    for witness generation. Stage 1 columns come from trace, stage 2 from auxTrace.

    Args:
        stark_info: StarkInfo with polynomial mappings
        params: ProofContext with trace buffers

    Returns:
        ProverData ready for witness computation
    """
    N = 1 << stark_info.starkStruct.nBits
    columns = {}
    constants = {}
    challenges = {}

    # Extract committed polynomials (all stages, base domain)
    for pol_info in stark_info.cmPolsMap:
        name = pol_info.name
        stage = pol_info.stage
        dim = pol_info.dim
        stage_pos = pol_info.stagePos

        section = f"cm{stage}"
        n_cols = stark_info.mapSectionsN.get(section, 0)

        if stage == 1:
            # Stage 1: read from trace buffer
            buffer = params.trace
            base_offset = 0
        else:
            # Stage 2+: read from auxTrace at non-extended offset
            base_offset = stark_info.mapOffsets.get((section, False), 0)
            buffer = params.auxTrace

        # Read polynomial values from buffer
        values = np.zeros(N * dim, dtype=np.uint64)
        for j in range(N):
            src_idx = base_offset + j * n_cols + stage_pos
            values[j * dim:(j + 1) * dim] = buffer[src_idx:src_idx + dim]

        # Find or compute the index for this polynomial name
        index = 0
        for other in stark_info.cmPolsMap:
            if other.name == name and other.stagePos < stage_pos:
                index += 1

        if dim == 1:
            columns[(name, index)] = FF3(np.asarray(values, dtype=np.uint64))
        else:
            columns[(name, index)] = ff3_from_interleaved_numpy(values, N)

    # Extract constant polynomials (base domain)
    for pol_info in stark_info.constPolsMap:
        name = pol_info.name
        dim = pol_info.dim
        stage_pos = pol_info.stagePos
        n_cols = stark_info.nConstants

        values = np.zeros(N * dim, dtype=np.uint64)
        for j in range(N):
            src_idx = j * n_cols + stage_pos
            values[j * dim:(j + 1) * dim] = params.constPols[src_idx:src_idx + dim]

        if dim == 1:
            constants[name] = FF(np.asarray(values, dtype=np.uint64))
        else:
            constants[name] = ff3_from_interleaved_numpy(values, N)

    # Extract challenges
    for i, chal_info in enumerate(stark_info.challengesMap):
        name = chal_info.name
        idx = i * FIELD_EXTENSION_DEGREE
        coeff0 = int(params.challenges[idx])
        coeff1 = int(params.challenges[idx + 1])
        coeff2 = int(params.challenges[idx + 2])
        challenges[name] = FF3.Vector([coeff2, coeff1, coeff0])

    return ProverData(columns=columns, constants=constants, challenges=challenges)


def _write_witness_to_buffer(
    stark_info: StarkInfo,
    params: ProofContext,
    intermediates: dict,
    grand_sums: dict
) -> None:
    """Write witness module results back to auxTrace buffer.

    Args:
        stark_info: StarkInfo with polynomial mappings
        params: ProofContext with auxTrace buffer
        intermediates: Dict like {'im_cluster': {0: poly0, 1: poly1, ...}}
        grand_sums: Dict like {'gsum': gsum_poly}
    """
    from primitives.field import ff3_to_interleaved_numpy

    N = 1 << stark_info.starkStruct.nBits

    # Build mapping from (name, index) to cmPolsMap entry
    name_to_pol_info = {}
    for pol_info in stark_info.cmPolsMap:
        # Count index for this name
        index = 0
        for other in stark_info.cmPolsMap:
            if other.name == pol_info.name and other.stagePos < pol_info.stagePos:
                index += 1
        name_to_pol_info[(pol_info.name, index)] = pol_info

    # Write intermediate columns (im_cluster, im_single, etc.)
    for col_name, col_dict in intermediates.items():
        for col_idx, values in col_dict.items():
            key = (col_name, col_idx)
            if key not in name_to_pol_info:
                continue

            pol_info = name_to_pol_info[key]
            stage = pol_info.stage
            dim = pol_info.dim
            stage_pos = pol_info.stagePos
            section = f"cm{stage}"
            n_cols = stark_info.mapSectionsN.get(section, 0)
            base_offset = stark_info.mapOffsets.get((section, False), 0)

            # Convert FF3 to interleaved numpy
            interleaved = ff3_to_interleaved_numpy(values)

            # Write to buffer
            for j in range(N):
                dst_idx = base_offset + j * n_cols + stage_pos
                params.auxTrace[dst_idx:dst_idx + dim] = interleaved[j * dim:(j + 1) * dim]

    # Write grand sum columns (gsum, gprod)
    for col_name, values in grand_sums.items():
        key = (col_name, 0)
        if key not in name_to_pol_info:
            continue

        pol_info = name_to_pol_info[key]
        stage = pol_info.stage
        dim = pol_info.dim
        stage_pos = pol_info.stagePos
        section = f"cm{stage}"
        n_cols = stark_info.mapSectionsN.get(section, 0)
        base_offset = stark_info.mapOffsets.get((section, False), 0)

        interleaved = ff3_to_interleaved_numpy(values)

        for j in range(N):
            dst_idx = base_offset + j * n_cols + stage_pos
            params.auxTrace[dst_idx:dst_idx + dim] = interleaved[j * dim:(j + 1) * dim]

    # Write final gsum/gprod values to airgroupValues
    # These are the running sum/product result used in constraint checking
    from primitives.field import FIELD_EXTENSION_DEGREE, ff3_to_numpy_coeffs
    for i, av in enumerate(stark_info.airgroupValuesMap):
        # airgroupValues names are like "Simple.gsum_result" or "Permutation.gprod_result"
        # Extract the column name (gsum or gprod) from the name
        if '_result' in av.name:
            parts = av.name.rsplit('.', 1)
            if len(parts) == 2:
                col_type = parts[1].replace('_result', '')  # 'gsum' or 'gprod'
                if col_type in grand_sums:
                    values = grand_sums[col_type]
                    # Get the final value (last row)
                    final_val = values[N - 1]
                    # Convert FF3 scalar to numpy coefficients
                    coeffs = ff3_to_numpy_coeffs(final_val)
                    # Write to airgroupValues
                    idx = i * FIELD_EXTENSION_DEGREE
                    params.airgroupValues[idx:idx + FIELD_EXTENSION_DEGREE] = coeffs


def calculate_witness_with_module(
    stark_info: StarkInfo,
    params: ProofContext,
) -> None:
    """Calculate witness polynomials using per-AIR witness modules.

    Replaces calculate_witness_std for computing im_cluster and gsum columns.

    Args:
        stark_info: StarkInfo with AIR name and polynomial mappings
        params: ProofContext with trace buffers and challenges
    """
    from constraints import ProverConstraintContext
    from witness import get_witness_module

    air_name = stark_info.name

    # Get witness module for this AIR
    witness_module = get_witness_module(air_name)

    # Build context with base domain data
    prover_data = _build_prover_data_base(stark_info, params)
    ctx = ProverConstraintContext(prover_data)

    # Compute intermediates (im_cluster columns)
    intermediates = witness_module.compute_intermediates(ctx)

    # Compute grand sums (gsum/gprod columns)
    grand_sums = witness_module.compute_grand_sums(ctx)

    # Write results back to buffer
    _write_witness_to_buffer(stark_info, params, intermediates, grand_sums)


class Starks:
    """Polynomial commitment orchestrator for STARK proof generation.

    The Starks class manages polynomial commitment via Merkle trees:
    - Maintains one Merkle tree per polynomial commitment stage
    - Handles polynomial extension (NTT) and tree construction
    - Provides query proof generation for FRI verification

    NTT (Number Theoretic Transform) objects are created internally to hide
    FFT implementation details from the protocol layer. The protocol only
    needs to know about polynomial commitment, not how it's implemented.

    Attributes:
        setupCtx: AIR configuration with domain sizes and parameters
        stage_trees: Merkle trees for each commitment stage (1, 2, Q)
        const_tree: Merkle tree for constant polynomials (if present)
    """

    def __init__(self, setupCtx: AirConfig) -> None:
        """Initialize polynomial commitment orchestrator.

        Args:
            setupCtx: AIR configuration with domain sizes and parameters
        """
        self.setupCtx = setupCtx
        self.stage_trees: dict[StageIndex, MerkleTree] = {}
        self.const_tree: MerkleTree | None = None

        # Internal NTT instances for polynomial operations
        # These precompute FFT twiddle factors for efficient polynomial
        # interpolation, evaluation, and extension.
        si = setupCtx.stark_info
        N = 1 << si.starkStruct.nBits
        N_extended = 1 << si.starkStruct.nBitsExt
        self._ntt = NTT(N)
        self._ntt_extended = NTT(N_extended)

    # --- Constant Polynomial Tree ---

    def build_const_tree(self, constPolsExtended: np.ndarray) -> MerkleRoot:
        """Build Merkle tree for constant polynomials."""
        NExtended = 1 << self.setupCtx.stark_info.starkStruct.nBitsExt
        nCols = self.setupCtx.stark_info.mapSectionsN.get("const", 0)

        if nCols == 0:
            return [0] * 4

        constData = [int(x) for x in constPolsExtended[:NExtended * nCols]]
        last_lvl = self.setupCtx.stark_info.starkStruct.lastLevelVerification
        self.const_tree = MerkleTree(arity=4, last_level_verification=last_lvl)
        self.const_tree.merkelize(constData, NExtended, nCols, n_cols=nCols)

        return self.const_tree.get_root()

    def get_const_query_proof(self, idx: int, elem_size: int = 1) -> QueryProof:
        """Extract query proof from constant polynomial tree."""
        if self.const_tree is None:
            raise ValueError("Constant tree not built. Call build_const_tree() first.")
        return self.const_tree.get_query_proof(idx, elem_size)

    # --- Stage Commitment ---

    def extendAndMerkelize(self, step: int, trace: np.ndarray, auxTrace: np.ndarray,
                          pBuffHelper: np.ndarray | None = None) -> MerkleRoot:
        """Extend polynomial from N to N_ext and build Merkle tree commitment."""
        N = 1 << self.setupCtx.stark_info.starkStruct.nBits
        NExtended = 1 << self.setupCtx.stark_info.starkStruct.nBitsExt

        section = f"cm{step}"
        nCols = self.setupCtx.stark_info.mapSectionsN[section]

        # Stage 1 uses trace buffer directly, other stages use auxTrace
        if step == 1:
            pBuff = trace
        else:
            offset = self.setupCtx.stark_info.mapOffsets[(section, False)]
            pBuff = auxTrace[offset:]

        offsetExt = self.setupCtx.stark_info.mapOffsets[(section, True)]
        pBuffExtended = auxTrace[offsetExt:]

        # Extend: INTT(pBuff) -> coeffs -> zero-pad -> NTT(coeffs_extended)
        pBuff_2d = pBuff[:N * nCols].reshape(N, nCols)
        pBuffExtended_result = self._ntt.extend_pol(pBuff_2d, NExtended, N, nCols)
        pBuffExtended[:NExtended * nCols] = pBuffExtended_result.flatten()

        # Build Merkle tree
        extendedData = [int(x) for x in pBuffExtended[:NExtended * nCols]]
        last_lvl = self.setupCtx.stark_info.starkStruct.lastLevelVerification
        tree = MerkleTree(arity=4, last_level_verification=last_lvl)
        tree.merkelize(extendedData, NExtended, nCols, n_cols=nCols)
        self.stage_trees[step] = tree

        return tree.get_root()

    def get_stage_query_proof(self, step: int, idx: int, elem_size: int = 1) -> QueryProof:
        """Extract query proof from a stored stage tree."""
        if step not in self.stage_trees:
            raise KeyError(f"Stage {step} tree not found. Has commitStage been called?")
        return self.stage_trees[step].get_query_proof(idx, elem_size)

    def get_stage_tree(self, step: int) -> MerkleTree:
        """Get the Merkle tree for a specific stage."""
        if step not in self.stage_trees:
            raise KeyError(f"Stage {step} tree not found. Has commitStage been called?")
        return self.stage_trees[step]

    def commitStage(self, step: int, params: ProofContext,
                   pBuffHelper: np.ndarray | None = None) -> MerkleRoot:
        """Execute a commitment stage (witness or quotient polynomial).

        Args:
            step: Stage number (1 = witness, 2 = intermediate, nStages+1 = quotient)
            params: Proof context with polynomial data
            pBuffHelper: Optional helper buffer (unused, for API compatibility)

        Returns:
            Merkle root (HASH_SIZE integers)
        """
        if step <= self.setupCtx.stark_info.nStages:
            return self.extendAndMerkelize(step, params.trace, params.auxTrace, pBuffHelper)

        # Quotient polynomial stage - uses extended NTT
        self.computeFriPol(params, pBuffHelper)

        NExtended = 1 << self.setupCtx.stark_info.starkStruct.nBitsExt
        section = f"cm{step}"
        nCols = self.setupCtx.stark_info.mapSectionsN.get(section, 0)

        if nCols > 0:
            cmQOffset = self.setupCtx.stark_info.mapOffsets[(section, True)]
            cmQ = params.auxTrace[cmQOffset:]
            extendedData = [int(x) for x in cmQ[:NExtended * nCols]]

            last_lvl = self.setupCtx.stark_info.starkStruct.lastLevelVerification
            tree = MerkleTree(arity=4, last_level_verification=last_lvl)
            tree.merkelize(extendedData, NExtended, nCols, n_cols=nCols)
            self.stage_trees[step] = tree

            return tree.get_root()

        return [0] * 4

    # --- Quotient Polynomial ---

    def computeFriPol(self, params: ProofContext,
                     pBuffHelper: np.ndarray | None = None) -> None:
        """Compute quotient polynomial Q for FRI commitment.

        1. INTT constraint polynomial (extended domain -> coefficients)
        2. Apply shift factors S[p] = (shift^-1)^(N*p) for coset correction
        3. Reorganize from degree-major to evaluation-major layout
        4. NTT back to extended domain evaluations
        """
        from primitives.field import FF, FF3, SHIFT_INV, ff3_from_buffer_at, ff3_store_to_buffer

        N = 1 << self.setupCtx.stark_info.starkStruct.nBits
        NExtended = 1 << self.setupCtx.stark_info.starkStruct.nBitsExt
        qDim = self.setupCtx.stark_info.qDim
        qDeg = self.setupCtx.stark_info.qDeg

        section = f"cm{self.setupCtx.stark_info.nStages + 1}"
        nCols = self.setupCtx.stark_info.mapSectionsN[section]

        qOffset = self.setupCtx.stark_info.mapOffsets[("q", True)]
        qPol = params.auxTrace[qOffset:]

        cmQOffset = self.setupCtx.stark_info.mapOffsets[(section, True)]
        cmQ = params.auxTrace[cmQOffset:]

        # Step 1: INTT constraint polynomial (uses extended NTT)
        qPolReshaped = qPol[:NExtended * qDim].reshape(NExtended, qDim)
        qCoeffs = self._ntt_extended.intt(qPolReshaped, n_cols=qDim)
        qPol[:NExtended * qDim] = qCoeffs.flatten()

        # Step 2: Compute shift factors S[p] = (shift^-1)^(N*p)
        shiftIn = FF(SHIFT_INV) ** N
        S = np.zeros(qDeg, dtype=np.uint64)
        S[0] = 1
        for i in range(1, qDeg):
            S[i] = int(FF(int(S[i - 1])) * shiftIn)

        # Step 3: Apply shifts and reorganize layout
        # cmQ[(i * qDeg + p) * 3] = qPol[(p * N + i) * 3] * S[p]
        # Vectorized: process all N elements per degree p in one batch
        for p in range(qDeg):
            shift_p = FF3(int(S[p]))

            # Batch read: indices (p * N + i) * 3 for i in [0, N)
            read_indices = [(p * N + i) * FIELD_EXTENSION_DEGREE for i in range(N)]
            qVals = ff3_from_buffer_at(qPol, read_indices)

            # Batch multiply by scalar shift
            results = qVals * shift_p

            # Batch write: indices (i * qDeg + p) * 3 for i in [0, N)
            write_indices = [(i * qDeg + p) * FIELD_EXTENSION_DEGREE for i in range(N)]
            ff3_store_to_buffer(results, cmQ, write_indices)

        # Step 4: Zero-pad remaining coefficients
        cmQ[N * qDeg * qDim:NExtended * qDeg * qDim] = 0

        # Step 5: NTT to extended domain (uses extended NTT)
        cmQReshaped = cmQ[:NExtended * nCols].reshape(NExtended, nCols)
        cmQEvaluations = self._ntt_extended.ntt(cmQReshaped, n_cols=nCols)
        cmQ[:NExtended * nCols] = cmQEvaluations.flatten()

    # --- Constraint and FRI Polynomials ---

    def calculateQuotientPolynomial(self, params: ProofContext,
                                   prover_helpers: ProverHelpers = None) -> None:
        """Evaluate constraint expression across the extended domain.

        Args:
            params: ProofContext with trace buffers
            prover_helpers: ProverHelpers with zerofiers
        """
        # Late import to avoid circular dependency
        from constraints import ProverConstraintContext, get_constraint_module
        from primitives.field import ff3_to_interleaved_numpy

        qOffset = self.setupCtx.stark_info.mapOffsets[("q", True)]
        qPol = params.auxTrace[qOffset:]
        stark_info = self.setupCtx.stark_info
        N_ext = 1 << stark_info.starkStruct.nBitsExt
        air_name = stark_info.name

        # Use per-AIR constraint modules
        prover_data = _build_prover_data_extended(
            stark_info, params, params.constPolsExtended
        )

        # Get constraint module for this AIR
        constraint_module = get_constraint_module(air_name)

        # Create prover context and evaluate constraints
        ctx = ProverConstraintContext(prover_data)
        constraint_poly = constraint_module.constraint_polynomial(ctx)

        # Multiply by zerofier 1/Z_H(x) to get the quotient polynomial
        # zi contains 1/(x^N - 1) for "everyRow" boundary (index 0)
        zi_np = np.asarray(prover_helpers.zi[:N_ext], dtype=np.uint64)
        zi = FF3(zi_np.tolist())  # Embed base field in extension field
        constraint_poly = constraint_poly * zi

        # Convert FF3 result to interleaved numpy format
        result = ff3_to_interleaved_numpy(constraint_poly)
        qPol[:len(result)] = result

    def calculateFRIPolynomial(self, params: ProofContext,
                              prover_helpers: ProverHelpers = None) -> None:
        """Compute FRI polynomial F = linear combination of committed polys at xi*w^offset.

        Args:
            params: ProofContext with trace buffers
            prover_helpers: ProverHelpers with precomputed domain values
        """
        from protocol.fri_polynomial import compute_fri_polynomial

        stark_info = self.setupCtx.stark_info
        N_ext = 1 << stark_info.starkStruct.nBitsExt

        # Compute FRI polynomial on extended domain
        fri_result = compute_fri_polynomial(
            stark_info, params, N_ext, extended=True,
            prover_helpers=prover_helpers
        )

        # Write result to FRI polynomial buffer
        fOffset = stark_info.mapOffsets[("f", True)]
        fPol = params.auxTrace[fOffset:]
        fPol[:len(fri_result)] = fri_result

    # --- Polynomial Evaluations ---

    def computeLEv(self, xiChallenge: np.ndarray, openingPoints: list) -> np.ndarray:
        """Compute Lagrange evaluation coefficients.

        LEv[k, i] = ((xi * w^openingPoint[i]) * shift^-1)^k

        Vectorized: compute all opening points in parallel for each k.

        Args:
            xiChallenge: Challenge point (FF3 as numpy array)
            openingPoints: List of opening point indices

        Returns:
            Lagrange evaluation coefficients in flattened numpy array
        """
        from primitives.field import (
            FF,
            FF3,
            SHIFT_INV,
            ff3_from_numpy_coeffs,
            ff3_to_interleaved_numpy,
            get_omega,
        )

        N = 1 << self.setupCtx.stark_info.starkStruct.nBits
        nOpeningPoints = len(openingPoints)

        w = FF(get_omega(self.setupCtx.stark_info.starkStruct.nBits))
        shiftInv = FF(SHIFT_INV)
        xiFF3 = ff3_from_numpy_coeffs(xiChallenge)

        # Compute xisShifted[i] = xi * w^openingPoint[i] * shift^-1 for all opening points
        wPowers = []
        for openingPoint in openingPoints:
            wPower = w ** abs(openingPoint)
            if openingPoint < 0:
                wPower = wPower ** -1
            wPowers.append(int(wPower))

        # Embed in extension field and multiply by xi * shift^-1
        wPowers_ff3 = FF3(wPowers)  # Base field values embedded in FF3
        xisShiftedVals = xiFF3 * wPowers_ff3 * FF3(int(shiftInv))

        # Build LEv using FF3 arrays - one array per row k
        # LEv[k, :] = LEv[k-1, :] * xisShiftedVals (element-wise)
        LEv_rows = [FF3.Ones(nOpeningPoints)]  # LEv[0, :] = [1, 1, ..., 1]

        for k in range(1, N):
            LEv_rows.append(LEv_rows[k - 1] * xisShiftedVals)

        # Convert to interleaved numpy format for INTT
        # Layout: [LEv[0,0], LEv[0,1], ..., LEv[1,0], LEv[1,1], ...]
        LEv = np.zeros(N * nOpeningPoints * FIELD_EXTENSION_DEGREE, dtype=np.uint64)
        for k in range(N):
            row_interleaved = ff3_to_interleaved_numpy(LEv_rows[k])
            LEv[k * nOpeningPoints * FIELD_EXTENSION_DEGREE:(k + 1) * nOpeningPoints * FIELD_EXTENSION_DEGREE] = row_interleaved

        # INTT to coefficient form (uses base domain NTT)
        LEvReshaped = LEv.reshape(N, nOpeningPoints * FIELD_EXTENSION_DEGREE)
        LEvCoeffs = self._ntt.intt(LEvReshaped, n_cols=nOpeningPoints * FIELD_EXTENSION_DEGREE)
        return LEvCoeffs.flatten()

    def computeEvals(self, params: ProofContext, LEv: np.ndarray, openingPoints: list) -> None:
        """Compute polynomial evaluations at opening points."""
        self.evmap(params, LEv, openingPoints)

    def evmap(self, params: ProofContext, LEv: np.ndarray, openingPoints: list) -> None:
        """Evaluate polynomials at opening points using vectorized operations."""
        from primitives.field import ff3_array, ff3_coeffs

        N = 1 << self.setupCtx.stark_info.starkStruct.nBits
        extendBits = self.setupCtx.stark_info.starkStruct.nBitsExt - self.setupCtx.stark_info.starkStruct.nBits
        nOpeningPoints = len(openingPoints)

        # Build evaluation task list
        evalsToCalculate = [
            i for i, evMap in enumerate(self.setupCtx.stark_info.evMap)
            if evMap.prime in openingPoints
        ]

        if not evalsToCalculate:
            return

        # Precompute row indices: rows[k] = k << extendBits
        rows = np.arange(N, dtype=np.int64) << extendBits

        # Precompute LEv arrays per opening point
        LEv_arrays = {}
        for openingPointIdx in range(nOpeningPoints):
            indices = (np.arange(N) * nOpeningPoints + openingPointIdx) * FIELD_EXTENSION_DEGREE
            c0 = LEv[indices].tolist()
            c1 = LEv[indices + 1].tolist()
            c2 = LEv[indices + 2].tolist()
            LEv_arrays[openingPointIdx] = ff3_array(c0, c1, c2)

        # Evaluate each polynomial
        for evMapIdx in evalsToCalculate:
            evMap = self.setupCtx.stark_info.evMap[evMapIdx]
            openingPosIdx = openingPoints.index(evMap.prime)

            pol_arr = self._load_evmap_poly(params, evMap, rows)
            products = LEv_arrays[openingPosIdx] * pol_arr
            result = np.sum(products)

            dstIdx = evMapIdx * FIELD_EXTENSION_DEGREE
            coeffs = ff3_coeffs(result)
            params.evals[dstIdx:dstIdx + 3] = coeffs

    def _load_evmap_poly(self, params: ProofContext, evMap: EvMap, rows: np.ndarray) -> FF3:
        """Load polynomial values for evmap evaluation."""
        from primitives.field import ff3_array, ff3_array_from_base

        if evMap.type == EvMap.Type.cm:
            polInfo = self.setupCtx.stark_info.cmPolsMap[evMap.id]
            section = f"cm{polInfo.stage}"
            offset = self.setupCtx.stark_info.mapOffsets[(section, True)]
            nCols = self.setupCtx.stark_info.mapSectionsN[section]
            base_indices = offset + rows * nCols + polInfo.stagePos

            if polInfo.dim == 1:
                return ff3_array_from_base(params.auxTrace[base_indices].tolist())
            else:
                c0 = params.auxTrace[base_indices].tolist()
                c1 = params.auxTrace[base_indices + 1].tolist()
                c2 = params.auxTrace[base_indices + 2].tolist()
                return ff3_array(c0, c1, c2)

        elif evMap.type == EvMap.Type.const_:
            polInfo = self.setupCtx.stark_info.constPolsMap[evMap.id]
            offset = self.setupCtx.stark_info.mapOffsets[("const", True)]
            nCols = self.setupCtx.stark_info.mapSectionsN["const"]
            base_indices = offset + rows * nCols + polInfo.stagePos
            return ff3_array_from_base(params.constPolsExtended[base_indices].tolist())

        elif evMap.type == EvMap.Type.custom:
            polInfo = self.setupCtx.stark_info.customCommitsMap[evMap.commitId][evMap.id]
            commitName = self.setupCtx.stark_info.customCommits[polInfo.commitId].name
            section = commitName + "0"
            offset = self.setupCtx.stark_info.mapOffsets[(section, True)]
            nCols = self.setupCtx.stark_info.mapSectionsN[section]
            base_indices = offset + rows * nCols + polInfo.stagePos
            return ff3_array_from_base(params.customCommits[base_indices].tolist())

        else:
            raise ValueError(f"Unknown evMap type: {evMap.type}")
