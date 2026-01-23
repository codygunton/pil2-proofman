"""STARK prover stage orchestration."""

from typing import Optional, Dict
import numpy as np

from protocol.setup_ctx import SetupCtx, FIELD_EXTENSION
from primitives.ntt import NTT
from protocol.expression_evaluator import ExpressionsPack
from protocol.steps_params import StepsParams
from primitives.pol_map import EvMap
from primitives.merkle_tree import MerkleTree, MerkleRoot


# --- Type Aliases ---
BufferOffset = int
StageIndex = int


class Starks:
    """STARK proof orchestrator managing polynomial operations and commitments."""

    def __init__(self, setupCtx: SetupCtx):
        self.setupCtx = setupCtx
        self.stage_trees: Dict[StageIndex, MerkleTree] = {}
        self.const_tree: Optional[MerkleTree] = None

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

    def get_const_query_proof(self, idx: int, elem_size: int = 1):
        """Extract query proof from constant polynomial tree."""
        if self.const_tree is None:
            raise ValueError("Constant tree not built. Call build_const_tree() first.")
        return self.const_tree.get_query_proof(idx, elem_size)

    # --- Stage Commitment ---

    def extendAndMerkelize(self, step: int, trace: np.ndarray, auxTrace: np.ndarray,
                          ntt: NTT, pBuffHelper: Optional[np.ndarray] = None) -> MerkleRoot:
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
        pBuffExtended_result = ntt.extend_pol(pBuff_2d, NExtended, N, nCols)
        pBuffExtended[:NExtended * nCols] = pBuffExtended_result.flatten()

        # Build Merkle tree
        extendedData = [int(x) for x in pBuffExtended[:NExtended * nCols]]
        last_lvl = self.setupCtx.stark_info.starkStruct.lastLevelVerification
        tree = MerkleTree(arity=4, last_level_verification=last_lvl)
        tree.merkelize(extendedData, NExtended, nCols, n_cols=nCols)
        self.stage_trees[step] = tree

        return tree.get_root()

    def get_stage_query_proof(self, step: int, idx: int, elem_size: int = 1):
        """Extract query proof from a stored stage tree."""
        if step not in self.stage_trees:
            raise KeyError(f"Stage {step} tree not found. Has commitStage been called?")
        return self.stage_trees[step].get_query_proof(idx, elem_size)

    def get_stage_tree(self, step: int) -> MerkleTree:
        """Get the Merkle tree for a specific stage."""
        if step not in self.stage_trees:
            raise KeyError(f"Stage {step} tree not found. Has commitStage been called?")
        return self.stage_trees[step]

    def commitStage(self, step: int, params: StepsParams, ntt: NTT,
                   pBuffHelper: Optional[np.ndarray] = None) -> MerkleRoot:
        """Execute a commitment stage (witness or quotient polynomial)."""
        if step <= self.setupCtx.stark_info.nStages:
            return self.extendAndMerkelize(step, params.trace, params.auxTrace, ntt, pBuffHelper)

        # Quotient polynomial stage
        self.computeFriPol(params, ntt, pBuffHelper)

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

    def computeFriPol(self, params: StepsParams, nttExtended: NTT,
                     pBuffHelper: Optional[np.ndarray] = None):
        """Compute quotient polynomial Q for FRI commitment.

        1. INTT constraint polynomial (extended domain -> coefficients)
        2. Apply shift factors S[p] = (shift^-1)^(N*p) for coset correction
        3. Reorganize from degree-major to evaluation-major layout
        4. NTT back to extended domain evaluations
        """
        from primitives.field import FF, ff3, ff3_coeffs, SHIFT_INV

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

        # Step 1: INTT constraint polynomial
        qPolReshaped = qPol[:NExtended * qDim].reshape(NExtended, qDim)
        qCoeffs = nttExtended.intt(qPolReshaped, n_cols=qDim)
        qPol[:NExtended * qDim] = qCoeffs.flatten()

        # Step 2: Compute shift factors S[p] = (shift^-1)^(N*p)
        shiftIn = FF(SHIFT_INV) ** N
        S = np.zeros(qDeg, dtype=np.uint64)
        S[0] = 1
        for i in range(1, qDeg):
            S[i] = int(FF(int(S[i - 1])) * shiftIn)

        # Step 3: Apply shifts and reorganize layout
        # cmQ[(i * qDeg + p) * 3] = qPol[(p * N + i) * 3] * S[p]
        for p in range(qDeg):
            shift_p = ff3([int(S[p]), 0, 0])
            for i in range(N):
                qIdx = (p * N + i) * FIELD_EXTENSION
                qVal = ff3([int(qPol[qIdx]), int(qPol[qIdx + 1]), int(qPol[qIdx + 2])])
                result = ff3_coeffs(qVal * shift_p)

                cmQIdx = (i * qDeg + p) * FIELD_EXTENSION
                cmQ[cmQIdx] = result[0]
                cmQ[cmQIdx + 1] = result[1]
                cmQ[cmQIdx + 2] = result[2]

        # Step 4: Zero-pad remaining coefficients
        cmQ[N * qDeg * qDim:NExtended * qDeg * qDim] = 0

        # Step 5: NTT to extended domain
        cmQReshaped = cmQ[:NExtended * nCols].reshape(NExtended, nCols)
        cmQEvaluations = nttExtended.ntt(cmQReshaped, n_cols=nCols)
        cmQ[:NExtended * nCols] = cmQEvaluations.flatten()

    # --- Intermediate Polynomial Expressions ---

    def calculateImPolsExpressions(self, step: int, params: StepsParams,
                                  expressionsCtx: ExpressionsPack):
        """Calculate intermediate polynomial expressions for a stage."""
        from protocol.expression_evaluator import Dest, Params

        domainSize = 1 << self.setupCtx.stark_info.starkStruct.nBits

        for polMap in self.setupCtx.stark_info.cmPolsMap:
            if not (polMap.imPol and polMap.stage == step):
                continue

            pAddress = params.trace if polMap.stage == 1 else params.auxTrace
            section = f"cm{step}"
            offset = self.setupCtx.stark_info.mapOffsets[(section, False)]
            destBuffer = pAddress[offset + polMap.stagePos:]

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

            destStruct.params.append(Params(
                exp_id=polMap.expId,
                dim=polMap.dim,
                batch=True,
                op="tmp"
            ))

            expressionsCtx.calculate_expressions(params, destStruct, domainSize, False, False)

    # --- Constraint and FRI Polynomials ---

    def calculateQuotientPolynomial(self, params: StepsParams,
                                   expressionsCtx: ExpressionsPack):
        """Evaluate constraint expression across the extended domain."""
        qOffset = self.setupCtx.stark_info.mapOffsets[("q", True)]
        qPol = params.auxTrace[qOffset:]
        expressionsCtx.calculate_expression(params, qPol, self.setupCtx.stark_info.cExpId)

    def calculateFRIPolynomial(self, params: StepsParams,
                              expressionsCtx: ExpressionsPack):
        """Compute FRI polynomial F = linear combination of committed polys at xi*w^offset."""
        from primitives.field import FF, ff3, ff3_coeffs, get_omega

        # Find xi challenge index (stage nStages + 2, stageId 0)
        xiChallengeIndex = next(
            i for i, cm in enumerate(self.setupCtx.stark_info.challengesMap)
            if cm.stage == self.setupCtx.stark_info.nStages + 2 and cm.stageId == 0
        )

        xiChallenge = params.challenges[xiChallengeIndex * FIELD_EXTENSION:]
        xiFF3 = ff3([int(xiChallenge[0]), int(xiChallenge[1]), int(xiChallenge[2])])

        # Compute xis[i] = xi * w^openingPoint[i]
        w = FF(get_omega(self.setupCtx.stark_info.starkStruct.nBits))
        nOpeningPoints = len(self.setupCtx.stark_info.openingPoints)
        xis = np.zeros(nOpeningPoints * FIELD_EXTENSION, dtype=np.uint64)

        for i, openingPoint in enumerate(self.setupCtx.stark_info.openingPoints):
            wPower = w ** abs(openingPoint)
            if openingPoint < 0:
                wPower = wPower ** -1

            xisVal = xiFF3 * ff3([int(wPower), 0, 0])
            xisCoeffs = ff3_coeffs(xisVal)
            xis[i * FIELD_EXTENSION:(i + 1) * FIELD_EXTENSION] = xisCoeffs

        expressionsCtx.set_xi(xis)

        fOffset = self.setupCtx.stark_info.mapOffsets[("f", True)]
        fPol = params.auxTrace[fOffset:]
        expressionsCtx.calculate_expression(params, fPol, self.setupCtx.stark_info.friExpId)

    # --- Polynomial Evaluations ---

    def computeLEv(self, xiChallenge: np.ndarray, openingPoints: list,
                  ntt: NTT) -> np.ndarray:
        """Compute Lagrange evaluation coefficients.

        LEv[k, i] = ((xi * w^openingPoint[i]) * shift^-1)^k
        """
        from primitives.field import FF, ff3, ff3_coeffs, get_omega, SHIFT_INV

        N = 1 << self.setupCtx.stark_info.starkStruct.nBits
        nOpeningPoints = len(openingPoints)
        LEv = np.zeros(N * nOpeningPoints * FIELD_EXTENSION, dtype=np.uint64)

        w = FF(get_omega(self.setupCtx.stark_info.starkStruct.nBits))
        shiftInv = FF(SHIFT_INV)
        xiFF3 = ff3([int(xiChallenge[0]), int(xiChallenge[1]), int(xiChallenge[2])])

        for i, openingPoint in enumerate(openingPoints):
            wPower = w ** abs(openingPoint)
            if openingPoint < 0:
                wPower = wPower ** -1

            # xisShifted[i] = xi * w^openingPoint * shift^-1
            xisVal = xiFF3 * ff3([int(wPower), 0, 0])
            xisShiftedVal = xisVal * ff3([int(shiftInv), 0, 0])

            # LEv[0, i] = 1
            LEv[i * FIELD_EXTENSION] = 1
            LEv[i * FIELD_EXTENSION + 1] = 0
            LEv[i * FIELD_EXTENSION + 2] = 0

            # LEv[k, i] = LEv[k-1, i] * xisShifted[i]
            for k in range(1, N):
                prevIdx = ((k - 1) * nOpeningPoints + i) * FIELD_EXTENSION
                currIdx = (k * nOpeningPoints + i) * FIELD_EXTENSION

                prevVal = ff3([int(LEv[prevIdx]), int(LEv[prevIdx + 1]), int(LEv[prevIdx + 2])])
                currVal = ff3_coeffs(prevVal * xisShiftedVal)
                LEv[currIdx:currIdx + 3] = currVal

        # INTT to coefficient form
        LEvReshaped = LEv.reshape(N, nOpeningPoints * FIELD_EXTENSION)
        LEvCoeffs = ntt.intt(LEvReshaped, n_cols=nOpeningPoints * FIELD_EXTENSION)
        return LEvCoeffs.flatten()

    def computeEvals(self, params: StepsParams, LEv: np.ndarray, openingPoints: list):
        """Compute polynomial evaluations at opening points."""
        self.evmap(params, LEv, openingPoints)

    def evmap(self, params: StepsParams, LEv: np.ndarray, openingPoints: list):
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
            indices = (np.arange(N) * nOpeningPoints + openingPointIdx) * FIELD_EXTENSION
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

            dstIdx = evMapIdx * FIELD_EXTENSION
            coeffs = ff3_coeffs(result)
            params.evals[dstIdx:dstIdx + 3] = coeffs

    def _load_evmap_poly(self, params: StepsParams, evMap: EvMap, rows: np.ndarray):
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
