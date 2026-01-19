"""Starks orchestrator for STARK proof generation.

Faithful translation from:
- pil2-stark/src/starkpil/starks.hpp (class definition and implementation)

This is the core orchestrator that manages STARK proof stages, coordinating:
- NTT operations for polynomial transformations
- Merkle tree construction for commitments
- Expression evaluation for constraints
- FRI polynomial computation
"""

from typing import Optional
import numpy as np

from setup_ctx import SetupCtx, ProverHelpers, FIELD_EXTENSION
from ntt import NTT
from expressions import ExpressionsPack
from steps_params import StepsParams
from pol_map import EvMap


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

    def __init__(self, setupCtx: SetupCtx):
        """Initialize Starks orchestrator.

        Corresponds to C++ constructor (lines 36-73).

        Note: The C++ version initializes Merkle trees here. The Python spec
        focuses on the polynomial operations, not tree construction.

        Args:
            setupCtx: Setup context with configuration
        """
        self.setupCtx = setupCtx

    def extendAndMerkelize(self, step: int, trace: np.ndarray, auxTrace: np.ndarray,
                          ntt: NTT, pBuffHelper: Optional[np.ndarray] = None) -> np.ndarray:
        """Extend polynomial from domain N to N_ext and prepare for commitment.

        Corresponds to C++ Starks::extendAndMerkelize() (lines 143-171).

        This method:
        1. Identifies the polynomial buffer for this stage (cm1, cm2, etc.)
        2. Performs NTT extension from N to N_extended using the provided NTT engine
        3. Returns the extended polynomial (merkleization happens elsewhere)

        Args:
            step: Stage number (1 = first witness stage, 2+ = subsequent stages)
            trace: Stage 1 witness trace (N × n_cols)
            auxTrace: Auxiliary buffer containing extended polynomials
            ntt: NTT engine for polynomial operations
            pBuffHelper: Optional helper buffer for NTT operations

        Returns:
            Extended polynomial evaluations (N_extended × n_cols)
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

        return pBuffExtended[:NExtended * nCols]

    def commitStage(self, step: int, params: StepsParams, ntt: NTT,
                   pBuffHelper: Optional[np.ndarray] = None):
        """Execute a commitment stage.

        Corresponds to C++ Starks::commitStage() (lines 173-185).

        This delegates to either:
        - extendAndMerkelize for witness stages (step <= nStages)
        - computeQ for quotient polynomial stage (step = nStages + 1)

        Args:
            step: Stage number
            params: Working parameters with all polynomial data
            ntt: NTT engine for polynomial operations
            pBuffHelper: Optional helper buffer for NTT operations
        """
        if step <= self.setupCtx.stark_info.nStages:
            # Witness commitment stage
            self.extendAndMerkelize(step, params.trace, params.auxTrace, ntt, pBuffHelper)
        else:
            # Quotient polynomial stage
            self.computeFriPol(params, ntt, pBuffHelper)

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
        from field import FF, SHIFT_INV

        S = np.zeros(self.setupCtx.stark_info.qDeg, dtype=np.uint64)
        shiftIn = FF(SHIFT_INV) ** N
        S[0] = 1
        # Note: Must convert numpy uint64 to Python int before creating FF
        for i in range(1, self.setupCtx.stark_info.qDeg):
            S[i] = int(FF(int(S[i - 1])) * shiftIn)

        # Step 3: Apply shift factors and reorganize (lines 210-217)
        # cmQ[(i * qDeg + p) * FIELD_EXTENSION] = qPol[(p * N + i) * FIELD_EXTENSION] * S[p]
        # This rearranges from degree-major to evaluation-major layout
        from field import FF3, ff3, ff3_coeffs

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
        from expressions import Dest

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
                from expressions import Params
                param = Params(
                    exp_id=polMap.expId,
                    dim=polMap.dim,
                    batch=True,
                    op="tmp"
                )
                destStruct.params.append(param)

                # Evaluate expression
                expressionsCtx.calculate_expressions(params, destStruct, domainSize, False, False)

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
        from field import FF, FF3, ff3, ff3_coeffs, get_omega

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
        from field import FF, FF3, ff3, ff3_coeffs, get_omega, SHIFT_INV

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

    def evmap(self, params: StepsParams, LEv: np.ndarray, openingPoints: list):
        """Evaluate polynomials at opening points using evaluation map.

        Corresponds to C++ Starks::evmap() (lines 289-367).

        This computes evaluations of committed polynomials at the opening points
        specified in the evaluation map. Uses the precomputed LEv coefficients
        to efficiently compute evaluations via inner products.

        Args:
            params: Working parameters
            LEv: Lagrange evaluation coefficients (N × nOpeningPoints × FIELD_EXTENSION)
            openingPoints: Opening point offsets
        """
        from field import FF3, ff3, ff3_coeffs

        N = 1 << self.setupCtx.stark_info.starkStruct.nBits
        extendBits = self.setupCtx.stark_info.starkStruct.nBitsExt - self.setupCtx.stark_info.starkStruct.nBits
        nOpeningPoints = len(openingPoints)

        # Build evaluation task list (lines 293-323)
        evalsToCalculate = []
        for i, evMap in enumerate(self.setupCtx.stark_info.evMap):
            # Check if this evaluation is needed (opening point must be in list)
            if evMap.prime not in openingPoints:
                continue

            evalsToCalculate.append(i)

        nEvals = len(evalsToCalculate)
        if nEvals == 0:
            return

        # Allocate accumulator (lines 325-328)
        # C++ uses thread-local accumulators, we use single accumulator
        evalsAcc = np.zeros(nEvals * FIELD_EXTENSION, dtype=np.uint64)

        # Main evaluation loop (lines 330-355)
        for k in range(N):
            # Load LEv values for this row
            LEvRow = []
            for o in range(nOpeningPoints):
                idx = (k * nOpeningPoints + o) * FIELD_EXTENSION
                LEvRow.append(ff3([
                    int(LEv[idx]),
                    int(LEv[idx + 1]),
                    int(LEv[idx + 2])
                ]))

            # Compute row index in extended domain
            row = k << extendBits

            # Process each evaluation (lines 345-354)
            for evalIdx, evMapIdx in enumerate(evalsToCalculate):
                evMap = self.setupCtx.stark_info.evMap[evMapIdx]

                # Find opening point index
                openingPosIdx = openingPoints.index(evMap.prime)

                # Get polynomial value
                if evMap.type == EvMap.Type.cm:
                    polInfo = self.setupCtx.stark_info.cmPolsMap[evMap.id]
                    section = f"cm{polInfo.stage}"
                    offset = self.setupCtx.stark_info.mapOffsets[(section, True)]
                    nCols = self.setupCtx.stark_info.mapSectionsN[section]

                    if polInfo.dim == 1:
                        polVal = ff3([int(params.auxTrace[offset + row * nCols + polInfo.stagePos]), 0, 0])
                    else:
                        polVal = ff3([
                            int(params.auxTrace[offset + row * nCols + polInfo.stagePos]),
                            int(params.auxTrace[offset + row * nCols + polInfo.stagePos + 1]),
                            int(params.auxTrace[offset + row * nCols + polInfo.stagePos + 2])
                        ])

                elif evMap.type == EvMap.Type.const_:
                    polInfo = self.setupCtx.stark_info.constPolsMap[evMap.id]
                    offset = self.setupCtx.stark_info.mapOffsets[("const", True)]
                    nCols = self.setupCtx.stark_info.mapSectionsN["const"]

                    polVal = ff3([int(params.constPolsExtended[offset + row * nCols + polInfo.stagePos]), 0, 0])

                elif evMap.type == EvMap.Type.custom:
                    polInfo = self.setupCtx.stark_info.customCommitsMap[evMap.commitId][evMap.id]
                    commitName = self.setupCtx.stark_info.customCommits[polInfo.commitId].name
                    section = commitName + "0"
                    offset = self.setupCtx.stark_info.mapOffsets[(section, True)]
                    nCols = self.setupCtx.stark_info.mapSectionsN[section]

                    polVal = ff3([int(params.customCommits[offset + row * nCols + polInfo.stagePos]), 0, 0])

                else:
                    raise ValueError(f"Unknown evMap type: {evMap.type}")

                # Multiply by LEv coefficient and accumulate (line 353)
                res = LEvRow[openingPosIdx] * polVal

                accIdx = evalIdx * FIELD_EXTENSION
                accVal = ff3([
                    int(evalsAcc[accIdx]),
                    int(evalsAcc[accIdx + 1]),
                    int(evalsAcc[accIdx + 2])
                ])

                accVal = accVal + res
                accCoeffs = ff3_coeffs(accVal)

                evalsAcc[accIdx] = accCoeffs[0]
                evalsAcc[accIdx + 1] = accCoeffs[1]
                evalsAcc[accIdx + 2] = accCoeffs[2]

        # Store results to params.evals (lines 356-365)
        for evalIdx, evMapIdx in enumerate(evalsToCalculate):
            srcIdx = evalIdx * FIELD_EXTENSION
            dstIdx = evMapIdx * FIELD_EXTENSION

            params.evals[dstIdx] = evalsAcc[srcIdx]
            params.evals[dstIdx + 1] = evalsAcc[srcIdx + 1]
            params.evals[dstIdx + 2] = evalsAcc[srcIdx + 2]
