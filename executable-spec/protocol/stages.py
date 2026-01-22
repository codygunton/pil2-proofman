"""Starks orchestrator for STARK proof generation.

Faithful translation from:
- pil2-stark/src/starkpil/starks.hpp (class definition and implementation)

This is the core orchestrator that manages STARK proof stages, coordinating:
- NTT operations for polynomial transformations
- Merkle tree construction for commitments
- Expression evaluation for constraints
- FRI polynomial computation
"""

from typing import Optional, Dict, List
import numpy as np

from protocol.setup_ctx import SetupCtx, ProverHelpers, FIELD_EXTENSION
from primitives.ntt import NTT
from protocol.expression_evaluator import ExpressionsPack
from protocol.steps_params import StepsParams
from primitives.pol_map import EvMap
from primitives.merkle_tree import MerkleTree, MerkleRoot


# C++: pil2-stark/src/starkpil/starks.hpp::Starks<ElementType> (lines 24-112)
class Starks:
    """STARK proof orchestrator.

    Corresponds to C++ class Starks<ElementType> in starks.hpp (lines 24-112).

    This class manages the core STARK proving workflow:
    1. Commit stages: Extend and merkelize witness polynomials
    2. Constraint evaluation: Compute quotient polynomial Q
    3. FRI polynomial: Prepare polynomial for FRI commitment

    The Python version omits Merkle tree management (handled separately in C++).
    This focuses on the polynomial operations and expression evaluation.

    Attributes:
        setupCtx: Setup context with StarkInfo and ExpressionsBin
    """

    # C++: Starks constructor
    def __init__(self, setupCtx: SetupCtx):
        """Initialize Starks orchestrator.

        Corresponds to C++ constructor (lines 36-73).

        Args:
            setupCtx: Setup context with configuration
        """
        self.setupCtx = setupCtx

        # Storage for Merkle trees built during stage commitment.
        # Key: stage number (1, 2, ..., nStages + 1)
        # Value: MerkleTree instance with tree nodes and source data
        self.stage_trees: Dict[int, MerkleTree] = {}

        # Constant polynomial tree (built from constPolsExtended)
        self.const_tree: Optional[MerkleTree] = None

    # C++: Starks::buildConstTree
    def build_const_tree(self, constPolsExtended: np.ndarray) -> MerkleRoot:
        """Build Merkle tree for constant polynomials.

        This method should be called once at the start of proving to construct
        the constant polynomial tree. The tree is needed for query proof extraction.

        Args:
            constPolsExtended: Extended constant polynomials (N_ext × n_const columns)

        Returns:
            Merkle root for the constant tree
        """
        NExtended = 1 << self.setupCtx.stark_info.starkStruct.nBitsExt
        nCols = self.setupCtx.stark_info.mapSectionsN.get("const", 0)

        if nCols == 0:
            # No constant polynomials
            return [0] * 4

        # Convert to list of ints for Merkle tree
        constData = [int(x) for x in constPolsExtended[:NExtended * nCols]]

        # Build tree with last_level_verification from STARK config
        last_lvl = self.setupCtx.stark_info.starkStruct.lastLevelVerification
        self.const_tree = MerkleTree(arity=4, last_level_verification=last_lvl)
        self.const_tree.merkelize(constData, NExtended, nCols, n_cols=nCols)

        return self.const_tree.get_root()

    # C++: Starks::getConstQueryProof
    def get_const_query_proof(self, idx: int, elem_size: int = 1):
        """Extract query proof from constant polynomial tree.

        Args:
            idx: Query index
            elem_size: Elements per column (1 for base field)

        Returns:
            QueryProof with values and Merkle path

        Raises:
            ValueError: If const tree not built
        """
        from primitives.merkle_tree import QueryProof

        if self.const_tree is None:
            raise ValueError("Constant tree not built. Call build_const_tree() first.")

        return self.const_tree.get_query_proof(idx, elem_size)

    # C++: Starks::extendAndMerkelize (line 90)
    def extendAndMerkelize(self, step: int, trace: np.ndarray, auxTrace: np.ndarray,
                          ntt: NTT, pBuffHelper: Optional[np.ndarray] = None) -> MerkleRoot:
        """Extend polynomial from domain N to N_ext and build Merkle tree commitment.

        Corresponds to C++ Starks::extendAndMerkelize() (lines 143-171).

        This method:
        1. Identifies the polynomial buffer for this stage (cm1, cm2, etc.)
        2. Performs NTT extension from N to N_extended using the provided NTT engine
        3. Transposes data for Merkle tree layout
        4. Builds and stores Merkle tree for later query proof extraction
        5. Returns the Merkle root commitment

        Args:
            step: Stage number (1 = first witness stage, 2+ = subsequent stages)
            trace: Stage 1 witness trace (N × n_cols)
            auxTrace: Auxiliary buffer containing extended polynomials
            ntt: NTT engine for polynomial operations
            pBuffHelper: Optional helper buffer for NTT operations

        Returns:
            Merkle root commitment (HASH_SIZE field elements)
        """
        N = 1 << self.setupCtx.stark_info.starkStruct.nBits
        NExtended = 1 << self.setupCtx.stark_info.starkStruct.nBitsExt

        # Identify source and destination buffers (lines 149-153)
        section = f"cm{step}"
        nCols = self.setupCtx.stark_info.mapSectionsN[section]

        # Stage 1 uses trace buffer directly, other stages use auxTrace
        if step == 1:
            pBuff = trace
        else:
            offset = self.setupCtx.stark_info.mapOffsets[(section, False)]
            pBuff = auxTrace[offset:]

        # Get extended buffer location
        offsetExt = self.setupCtx.stark_info.mapOffsets[(section, True)]
        pBuffExtended = auxTrace[offsetExt:]

        # Reshape for NTT operations (C++ operates on flat arrays)
        pBuff_2d = pBuff[:N * nCols].reshape(N, nCols)

        # Perform polynomial extension: N → N_extended (lines 156-160)
        # This is: INTT(pBuff) → coeffs, zero-pad → NTT(coeffs_extended)
        pBuffExtended_result = ntt.extend_pol(pBuff_2d, NExtended, N, nCols)

        # Flatten and store in auxTrace
        pBuffExtended[:NExtended * nCols] = pBuffExtended_result.flatten()

        # Build Merkle tree for this stage
        # Data is already in row-major format: NExtended rows, nCols columns per row
        extendedData = [int(x) for x in pBuffExtended[:NExtended * nCols]]

        # Create and build tree with last_level_verification from STARK config
        last_lvl = self.setupCtx.stark_info.starkStruct.lastLevelVerification
        tree = MerkleTree(arity=4, last_level_verification=last_lvl)
        tree.merkelize(extendedData, NExtended, nCols, n_cols=nCols)

        # Store tree for later query proof extraction
        self.stage_trees[step] = tree

        return tree.get_root()

    # C++: Starks::getStageQueryProof
    def get_stage_query_proof(self, step: int, idx: int, elem_size: int = 1):
        """Extract query proof from a stored stage tree.

        Args:
            step: Stage number (1, 2, ..., nStages + 1)
            idx: Query index (leaf index in the tree)
            elem_size: Elements per column (1 for base field, 3 for extension)

        Returns:
            QueryProof with leaf values and Merkle path

        Raises:
            KeyError: If stage tree not found (not yet committed)
        """
        from primitives.merkle_tree import QueryProof

        if step not in self.stage_trees:
            raise KeyError(f"Stage {step} tree not found. Has commitStage been called?")

        return self.stage_trees[step].get_query_proof(idx, elem_size)

    # C++: Starks::getStageTree
    def get_stage_tree(self, step: int) -> MerkleTree:
        """Get the Merkle tree for a specific stage.

        Args:
            step: Stage number

        Returns:
            MerkleTree instance

        Raises:
            KeyError: If stage tree not found
        """
        if step not in self.stage_trees:
            raise KeyError(f"Stage {step} tree not found. Has commitStage been called?")
        return self.stage_trees[step]

    # C++: Starks::commitStage (line 92)
    def commitStage(self, step: int, params: StepsParams, ntt: NTT,
                   pBuffHelper: Optional[np.ndarray] = None) -> MerkleRoot:
        """Execute a commitment stage.

        Corresponds to C++ Starks::commitStage() (lines 173-185).

        This delegates to either:
        - extendAndMerkelize for witness stages (step <= nStages)
        - computeFriPol + merkelize for quotient polynomial stage (step = nStages + 1)

        Args:
            step: Stage number
            params: Working parameters with all polynomial data
            ntt: NTT engine for polynomial operations
            pBuffHelper: Optional helper buffer for NTT operations

        Returns:
            Merkle root for the committed stage
        """
        if step <= self.setupCtx.stark_info.nStages:
            # Witness commitment stage
            return self.extendAndMerkelize(step, params.trace, params.auxTrace, ntt, pBuffHelper)
        else:
            # Quotient polynomial stage
            self.computeFriPol(params, ntt, pBuffHelper)

            # Build Merkle tree for Q polynomial
            NExtended = 1 << self.setupCtx.stark_info.starkStruct.nBitsExt
            section = f"cm{step}"
            nCols = self.setupCtx.stark_info.mapSectionsN.get(section, 0)

            if nCols > 0:
                cmQOffset = self.setupCtx.stark_info.mapOffsets[(section, True)]
                cmQ = params.auxTrace[cmQOffset:]
                extendedData = [int(x) for x in cmQ[:NExtended * nCols]]

                # Create and build tree with last_level_verification from STARK config
                last_lvl = self.setupCtx.stark_info.starkStruct.lastLevelVerification
                tree = MerkleTree(arity=4, last_level_verification=last_lvl)
                tree.merkelize(extendedData, NExtended, nCols, n_cols=nCols)
                self.stage_trees[step] = tree

                return tree.get_root()

            return [0] * 4

    # C++: Starks::computeFriPol
    def computeFriPol(self, params: StepsParams, nttExtended: NTT,
                     pBuffHelper: Optional[np.ndarray] = None):
        """Compute Q polynomial for FRI commitment.

        Corresponds to C++ Starks::computeQ() (lines 187-240).

        This method computes the quotient polynomial Q from the constraint
        evaluations, applies the shift factors, and prepares it for commitment.

        Algorithm:
        1. INTT the constraint polynomial (extended domain → coefficients)
        2. Apply shift factors S[p] = (shift^-1)^(N*p) to each degree component
        3. Zero-pad to extended domain
        4. NTT back to extended domain evaluations

        Args:
            params: Working parameters with constraint polynomial in auxTrace
            nttExtended: NTT engine for extended domain
            pBuffHelper: Optional helper buffer
        """
        N = 1 << self.setupCtx.stark_info.starkStruct.nBits
        NExtended = 1 << self.setupCtx.stark_info.starkStruct.nBitsExt

        # Get buffer locations (lines 193-195)
        section = f"cm{self.setupCtx.stark_info.nStages + 1}"
        nCols = self.setupCtx.stark_info.mapSectionsN[section]

        # Q polynomial lives in "q" section (constraint evaluations)
        qOffset = self.setupCtx.stark_info.mapOffsets[("q", True)]
        qPol = params.auxTrace[qOffset:]

        # cmQ is the final quotient polynomial to commit
        cmQOffset = self.setupCtx.stark_info.mapOffsets[(section, True)]
        cmQ = params.auxTrace[cmQOffset:]

        # Step 1: INTT constraint polynomial (lines 197-201)
        # Transform from extended domain evaluations to coefficients
        qPolReshaped = qPol[:NExtended * self.setupCtx.stark_info.qDim].reshape(NExtended, self.setupCtx.stark_info.qDim)
        qCoeffs = nttExtended.intt(qPolReshaped, n_cols=self.setupCtx.stark_info.qDim)

        # Copy back to buffer
        qPol[:NExtended * self.setupCtx.stark_info.qDim] = qCoeffs.flatten()

        # Step 2: Compute shift factors (lines 203-208)
        # S[p] = (shift^-1)^(N*p) for p in [0, qDeg)
        # These account for the coset shifting in polynomial division
        from primitives.field import FF, SHIFT_INV

        S = np.zeros(self.setupCtx.stark_info.qDeg, dtype=np.uint64)
        shiftIn = FF(SHIFT_INV) ** N
        S[0] = 1
        # Note: Must convert numpy uint64 to Python int before creating FF
        for i in range(1, self.setupCtx.stark_info.qDeg):
            S[i] = int(FF(int(S[i - 1])) * shiftIn)

        # Step 3: Apply shift factors and reorganize (lines 210-217)
        # cmQ[(i * qDeg + p) * FIELD_EXTENSION] = qPol[(p * N + i) * FIELD_EXTENSION] * S[p]
        # This rearranges from degree-major to evaluation-major layout
        from primitives.field import FF3, ff3, ff3_coeffs

        for p in range(self.setupCtx.stark_info.qDeg):
            for i in range(N):
                # Load q polynomial value (field extension element)
                qIdx = (p * N + i) * FIELD_EXTENSION
                qVal = ff3([
                    int(qPol[qIdx]),
                    int(qPol[qIdx + 1]),
                    int(qPol[qIdx + 2])
                ])

                # Multiply by shift factor S[p]
                result = qVal * ff3([int(S[p]), 0, 0])
                resultCoeffs = ff3_coeffs(result)

                # Store in cmQ
                cmQIdx = (i * self.setupCtx.stark_info.qDeg + p) * FIELD_EXTENSION
                cmQ[cmQIdx] = resultCoeffs[0]
                cmQ[cmQIdx + 1] = resultCoeffs[1]
                cmQ[cmQIdx + 2] = resultCoeffs[2]

        # Step 4: Zero-pad remaining coefficients (lines 219-222)
        zeroStart = N * self.setupCtx.stark_info.qDeg * self.setupCtx.stark_info.qDim
        zeroEnd = NExtended * self.setupCtx.stark_info.qDeg * self.setupCtx.stark_info.qDim
        cmQ[zeroStart:zeroEnd] = 0

        # Step 5: NTT to extended domain (lines 223-227)
        cmQReshaped = cmQ[:NExtended * nCols].reshape(NExtended, nCols)
        cmQEvaluations = nttExtended.ntt(cmQReshaped, n_cols=nCols)

        # Store back to buffer
        cmQ[:NExtended * nCols] = cmQEvaluations.flatten()

    # C++: Starks::calculateImPolsExpressions (line 95)
    def calculateImPolsExpressions(self, step: int, params: StepsParams,
                                  expressionsCtx: ExpressionsPack):
        """Calculate intermediate polynomial expressions for a stage.

        Corresponds to C++ Starks::calculateImPolsExpressions() (lines 401-413).

        This evaluates the expression assignments for witness polynomials that
        are computed from other polynomials (rather than provided directly).

        Args:
            step: Stage number
            params: Working parameters
            expressionsCtx: Expression evaluation context
        """
        from protocol.expression_evaluator import Dest

        domainSize = 1 << self.setupCtx.stark_info.starkStruct.nBits

        # Find all intermediate polynomials for this stage (lines 404-411)
        for i, polMap in enumerate(self.setupCtx.stark_info.cmPolsMap):
            if polMap.imPol and polMap.stage == step:
                # Get destination buffer
                if polMap.stage == 1:
                    pAddress = params.trace
                else:
                    pAddress = params.auxTrace

                # Compute offset to this polynomial
                section = f"cm{step}"
                offset = self.setupCtx.stark_info.mapOffsets[(section, False)]
                destBuffer = pAddress[offset + polMap.stagePos:]

                # Create destination specification
                nCols = self.setupCtx.stark_info.mapSectionsN[section]
                destStruct = Dest(
                    dest=destBuffer,
                    domain_size=domainSize,
                    offset=0,
                    stage_pos=polMap.stagePos,
                    stage_cols=nCols,
                    exp_id=polMap.expId,
                    dim=polMap.dim
                )

                # Add expression parameter
                from protocol.expression_evaluator import Params
                param = Params(
                    exp_id=polMap.expId,
                    dim=polMap.dim,
                    batch=True,
                    op="tmp"
                )
                destStruct.params.append(param)

                # Evaluate expression
                expressionsCtx.calculate_expressions(params, destStruct, domainSize, False, False)

    # C++: Starks::calculateQuotientPolynomial (line 96)
    def calculateQuotientPolynomial(self, params: StepsParams,
                                   expressionsCtx: ExpressionsPack):
        """Calculate quotient polynomial from constraints.

        Corresponds to C++ Starks::calculateQuotientPolynomial() (lines 415-418).

        This evaluates the constraint expression (all AIR constraints combined)
        across the extended domain.

        Args:
            params: Working parameters
            expressionsCtx: Expression evaluation context
        """
        qOffset = self.setupCtx.stark_info.mapOffsets[("q", True)]
        qPol = params.auxTrace[qOffset:]

        # Evaluate constraint expression
        expressionsCtx.calculate_expression(
            params,
            qPol,
            self.setupCtx.stark_info.cExpId
        )

    # C++: Starks::calculateFRIPolynomial (line 97)
    def calculateFRIPolynomial(self, params: StepsParams,
                              expressionsCtx: ExpressionsPack):
        """Calculate FRI polynomial for commitment.

        Corresponds to C++ Starks::calculateFRIPolynomial() (lines 420-457).

        This computes the FRI polynomial F which is a linear combination of
        all committed polynomials, evaluated at xi shifted by opening points.

        Algorithm:
        1. Find xi challenge (from challenges array)
        2. Compute xis[i] = xi * w^(openingPoint[i]) for each opening point
        3. Set xis in expression context
        4. Evaluate FRI expression

        Args:
            params: Working parameters with challenges
            expressionsCtx: Expression evaluation context
        """
        from primitives.field import FF, FF3, ff3, ff3_coeffs, get_omega

        # Step 1: Find xi challenge index (lines 422-428)
        # Xi is the challenge from stage nStages + 2, stageId 0
        xiChallengeIndex = 0
        for i, challengeMap in enumerate(self.setupCtx.stark_info.challengesMap):
            if challengeMap.stage == self.setupCtx.stark_info.nStages + 2:
                if challengeMap.stageId == 0:
                    xiChallengeIndex = i
                    break

        # Get xi from challenges array (line 430)
        xiChallenge = params.challenges[xiChallengeIndex * FIELD_EXTENSION:]

        # Step 2: Compute xis for each opening point (lines 432-441)
        nOpeningPoints = len(self.setupCtx.stark_info.openingPoints)
        xis = np.zeros(nOpeningPoints * FIELD_EXTENSION, dtype=np.uint64)

        w = FF(get_omega(self.setupCtx.stark_info.starkStruct.nBits))
        xiFF3 = ff3([
            int(xiChallenge[0]),
            int(xiChallenge[1]),
            int(xiChallenge[2])
        ])

        for i in range(nOpeningPoints):
            openingPoint = self.setupCtx.stark_info.openingPoints[i]
            openingAbs = abs(openingPoint)

            # Compute w^openingPoint
            wPower = FF(1)
            for _ in range(openingAbs):
                wPower = wPower * w

            if openingPoint < 0:
                wPower = wPower ** -1

            # xis[i] = xi * w^openingPoint
            wPowerFF3 = ff3([int(wPower), 0, 0])
            xisVal = xiFF3 * wPowerFF3
            xisCoeffs = ff3_coeffs(xisVal)

            xis[i * FIELD_EXTENSION] = xisCoeffs[0]
            xis[i * FIELD_EXTENSION + 1] = xisCoeffs[1]
            xis[i * FIELD_EXTENSION + 2] = xisCoeffs[2]

        # Step 3: Set xis in expression context (line 443)
        expressionsCtx.set_xi(xis)

        # Step 4: Evaluate FRI expression (line 445)
        fOffset = self.setupCtx.stark_info.mapOffsets[("f", True)]
        fPol = params.auxTrace[fOffset:]

        expressionsCtx.calculate_expression(
            params,
            fPol,
            self.setupCtx.stark_info.friExpId
        )

    # C++: Starks::computeLEv
    def computeLEv(self, xiChallenge: np.ndarray, openingPoints: list,
                  ntt: NTT) -> np.ndarray:
        """Compute Lagrange evaluation coefficients.

        Corresponds to C++ Starks::computeLEv() (lines 244-280).

        Computes LEv[k, i] = ((xi * w^openingPoint[i]) * shift^-1)^k
        for all k in [0, N) and i in [0, len(openingPoints)).

        This is used for computing polynomial evaluations via NTT.

        Args:
            xiChallenge: Xi challenge value (3 elements for field extension)
            openingPoints: List of opening point offsets
            ntt: NTT engine

        Returns:
            LEv array (N × len(openingPoints) × FIELD_EXTENSION)
        """
        from primitives.field import FF, FF3, ff3, ff3_coeffs, get_omega, SHIFT_INV

        N = 1 << self.setupCtx.stark_info.starkStruct.nBits
        nOpeningPoints = len(openingPoints)

        # Allocate LEv array
        LEv = np.zeros(N * nOpeningPoints * FIELD_EXTENSION, dtype=np.uint64)

        # Step 1: Compute xis and xisShifted (lines 247-263)
        xis = np.zeros(nOpeningPoints * FIELD_EXTENSION, dtype=np.uint64)
        xisShifted = np.zeros(nOpeningPoints * FIELD_EXTENSION, dtype=np.uint64)

        w = FF(get_omega(self.setupCtx.stark_info.starkStruct.nBits))
        shiftInv = FF(SHIFT_INV)
        xiFF3 = ff3([
            int(xiChallenge[0]),
            int(xiChallenge[1]),
            int(xiChallenge[2])
        ])

        for i in range(nOpeningPoints):
            openingPoint = openingPoints[i]
            openingAbs = abs(openingPoint)

            # Compute w^openingPoint
            wPower = FF(1)
            for _ in range(openingAbs):
                wPower = wPower * w

            if openingPoint < 0:
                wPower = wPower ** -1

            # xis[i] = xi * w^openingPoint
            wPowerFF3 = ff3([int(wPower), 0, 0])
            xisVal = xiFF3 * wPowerFF3
            xisCoeffs = ff3_coeffs(xisVal)

            xis[i * FIELD_EXTENSION] = xisCoeffs[0]
            xis[i * FIELD_EXTENSION + 1] = xisCoeffs[1]
            xis[i * FIELD_EXTENSION + 2] = xisCoeffs[2]

            # xisShifted[i] = xis[i] * shift^-1
            shiftInvFF3 = ff3([int(shiftInv), 0, 0])
            xisShiftedVal = xisVal * shiftInvFF3
            xisShiftedCoeffs = ff3_coeffs(xisShiftedVal)

            xisShifted[i * FIELD_EXTENSION] = xisShiftedCoeffs[0]
            xisShifted[i * FIELD_EXTENSION + 1] = xisShiftedCoeffs[1]
            xisShifted[i * FIELD_EXTENSION + 2] = xisShiftedCoeffs[2]

        # Step 2: Compute powers LEv[k, i] = xisShifted[i]^k (lines 265-277)
        # C++ uses chunking for cache efficiency, we simplify here
        for i in range(nOpeningPoints):
            xisShiftedFF3 = ff3([
                int(xisShifted[i * FIELD_EXTENSION]),
                int(xisShifted[i * FIELD_EXTENSION + 1]),
                int(xisShifted[i * FIELD_EXTENSION + 2])
            ])

            # LEv[0, i] = 1
            LEv[i * FIELD_EXTENSION] = 1
            LEv[i * FIELD_EXTENSION + 1] = 0
            LEv[i * FIELD_EXTENSION + 2] = 0

            # LEv[k, i] = LEv[k-1, i] * xisShifted[i]
            for k in range(1, N):
                prevIdx = ((k - 1) * nOpeningPoints + i) * FIELD_EXTENSION
                currIdx = (k * nOpeningPoints + i) * FIELD_EXTENSION

                prevVal = ff3([
                    int(LEv[prevIdx]),
                    int(LEv[prevIdx + 1]),
                    int(LEv[prevIdx + 2])
                ])

                currVal = prevVal * xisShiftedFF3
                currCoeffs = ff3_coeffs(currVal)

                LEv[currIdx] = currCoeffs[0]
                LEv[currIdx + 1] = currCoeffs[1]
                LEv[currIdx + 2] = currCoeffs[2]

        # Step 3: INTT to convert to coefficient form (line 279)
        LEvReshaped = LEv.reshape(N, nOpeningPoints * FIELD_EXTENSION)
        LEvCoeffs = ntt.intt(LEvReshaped, n_cols=nOpeningPoints * FIELD_EXTENSION)

        return LEvCoeffs.flatten()

    # C++: Starks::computeEvals (line 100)
    def computeEvals(self, params: StepsParams, LEv: np.ndarray,
                    openingPoints: list):
        """Compute polynomial evaluations at opening points.

        Corresponds to C++ Starks::computeEvals() (lines 283-287).

        This delegates to evmap() which computes the evaluations.

        Args:
            params: Working parameters
            LEv: Lagrange evaluation coefficients
            openingPoints: Opening point offsets
        """
        self.evmap(params, LEv, openingPoints)

    # C++: Starks::evmap
    def evmap(self, params: StepsParams, LEv: np.ndarray, openingPoints: list):
        """Evaluate polynomials at opening points using evaluation map.

        Corresponds to C++ Starks::evmap() (lines 289-367).

        This computes evaluations of committed polynomials at the opening points
        specified in the evaluation map. Uses the precomputed LEv coefficients
        to efficiently compute evaluations via inner products.

        Vectorized implementation: processes all N rows at once using galois arrays.

        Args:
            params: Working parameters
            LEv: Lagrange evaluation coefficients (N × nOpeningPoints × FIELD_EXTENSION)
            openingPoints: Opening point offsets
        """
        from primitives.field import FF3, ff3, ff3_coeffs, GOLDILOCKS_PRIME

        N = 1 << self.setupCtx.stark_info.starkStruct.nBits
        extendBits = self.setupCtx.stark_info.starkStruct.nBitsExt - self.setupCtx.stark_info.starkStruct.nBits
        nOpeningPoints = len(openingPoints)

        # Build evaluation task list (lines 293-323)
        evalsToCalculate = []
        for i, evMap in enumerate(self.setupCtx.stark_info.evMap):
            if evMap.prime not in openingPoints:
                continue
            evalsToCalculate.append(i)

        nEvals = len(evalsToCalculate)
        if nEvals == 0:
            return

        # Precompute row indices in extended domain: rows[k] = k << extendBits
        rows = np.arange(N, dtype=np.int64) << extendBits

        # Precompute LEv arrays for each opening point
        # LEv is stored as (N * nOpeningPoints * FIELD_EXTENSION) flat array
        # We need LEv[k, openingPointIdx] for each k
        p = GOLDILOCKS_PRIME
        p2 = p * p
        LEv_arrays = {}
        for openingPointIdx in range(nOpeningPoints):
            # Extract LEv values for this opening point across all N rows
            # Index: (k * nOpeningPoints + openingPointIdx) * FIELD_EXTENSION
            indices = (np.arange(N) * nOpeningPoints + openingPointIdx) * FIELD_EXTENSION
            c0 = LEv[indices].tolist()
            c1 = LEv[indices + 1].tolist()
            c2 = LEv[indices + 2].tolist()
            ints = [c0[k] + c1[k] * p + c2[k] * p2 for k in range(N)]
            LEv_arrays[openingPointIdx] = FF3(ints)

        # Process each evaluation using vectorized operations
        for evalIdx, evMapIdx in enumerate(evalsToCalculate):
            evMap = self.setupCtx.stark_info.evMap[evMapIdx]
            openingPosIdx = openingPoints.index(evMap.prime)

            # Get polynomial values for all N rows at once
            if evMap.type == EvMap.Type.cm:
                polInfo = self.setupCtx.stark_info.cmPolsMap[evMap.id]
                section = f"cm{polInfo.stage}"
                offset = self.setupCtx.stark_info.mapOffsets[(section, True)]
                nCols = self.setupCtx.stark_info.mapSectionsN[section]

                # Compute indices for all rows: offset + rows[k] * nCols + stagePos
                base_indices = offset + rows * nCols + polInfo.stagePos

                if polInfo.dim == 1:
                    # Scalar polynomial - embed in FF3 as (val, 0, 0)
                    vals = params.auxTrace[base_indices].tolist()
                    pol_arr = FF3(vals)  # FF3 encoding: val = c0 when c1=c2=0
                else:
                    # Field extension polynomial
                    c0 = params.auxTrace[base_indices].tolist()
                    c1 = params.auxTrace[base_indices + 1].tolist()
                    c2 = params.auxTrace[base_indices + 2].tolist()
                    ints = [c0[k] + c1[k] * p + c2[k] * p2 for k in range(N)]
                    pol_arr = FF3(ints)

            elif evMap.type == EvMap.Type.const_:
                polInfo = self.setupCtx.stark_info.constPolsMap[evMap.id]
                offset = self.setupCtx.stark_info.mapOffsets[("const", True)]
                nCols = self.setupCtx.stark_info.mapSectionsN["const"]

                base_indices = offset + rows * nCols + polInfo.stagePos
                vals = params.constPolsExtended[base_indices].tolist()
                pol_arr = FF3(vals)

            elif evMap.type == EvMap.Type.custom:
                polInfo = self.setupCtx.stark_info.customCommitsMap[evMap.commitId][evMap.id]
                commitName = self.setupCtx.stark_info.customCommits[polInfo.commitId].name
                section = commitName + "0"
                offset = self.setupCtx.stark_info.mapOffsets[(section, True)]
                nCols = self.setupCtx.stark_info.mapSectionsN[section]

                base_indices = offset + rows * nCols + polInfo.stagePos
                vals = params.customCommits[base_indices].tolist()
                pol_arr = FF3(vals)

            else:
                raise ValueError(f"Unknown evMap type: {evMap.type}")

            # Vectorized multiply: LEv[k] * pol[k] for all k
            products = LEv_arrays[openingPosIdx] * pol_arr

            # Sum all products to get the evaluation
            # galois arrays support np.sum
            result = np.sum(products)

            # Store result
            dstIdx = evMapIdx * FIELD_EXTENSION
            coeffs = ff3_coeffs(result)
            params.evals[dstIdx] = coeffs[0]
            params.evals[dstIdx + 1] = coeffs[1]
            params.evals[dstIdx + 2] = coeffs[2]
