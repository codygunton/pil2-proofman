"""STARK configuration parser."""

import json
import math
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from primitives.pol_map import PolMap, EvMap, ChallengeMap, CustomCommits, Boundary, FieldType

# --- Constants ---
from primitives.field import FIELD_EXTENSION_DEGREE
HASH_SIZE = 4


def _field_type_from_dim(dim: int) -> FieldType:
    """Convert dim int to FieldType enum."""
    return FieldType.FF if dim == 1 else FieldType.FF3


# --- Data Structures ---
@dataclass
class FriFoldStep:
    """FRI recursive folding layer configuration."""
    domainBits: int


@dataclass
class StarkStruct:
    """Core STARK protocol parameters."""
    nBits: int
    nBitsExt: int
    nQueries: int
    verificationHashType: str
    friFoldSteps: List[FriFoldStep] = field(default_factory=list)
    merkleTreeArity: int = 16
    merkleTreeCustom: bool = False
    transcriptArity: int = 16
    lastLevelVerification: int = 0
    powBits: int = 0
    hashCommits: bool = False


# --- StarkInfo ---
class StarkInfo:
    """STARK configuration loaded from starkinfo.json."""

    def __init__(self):
        # Core parameters
        self.starkStruct = StarkStruct(0, 0, 0, "GL")
        self.airgroupId = 0
        self.airId = 0

        # Polynomial counts
        self.nPublics = 0
        self.nConstants = 0
        self.nStages = 0

        # Proof size
        self.maxProofBuffSize = 0
        self.maxProofSize = 0
        self.maxTreeWidth = 0
        self.proofSize = 0

        # Polynomial mappings
        self.customCommits: List[CustomCommits] = []
        self.cmPolsMap: List[PolMap] = []
        self.constPolsMap: List[PolMap] = []
        self.challengesMap: List[ChallengeMap] = []
        self.airgroupValuesMap: List[PolMap] = []
        self.airValuesMap: List[PolMap] = []
        self.proofValuesMap: List[PolMap] = []
        self.publicsMap: List[PolMap] = []
        self.customCommitsMap: List[List[PolMap]] = []
        self.evMap: List[EvMap] = []

        # Opening points and boundaries
        self.openingPoints: List[int] = []
        self.boundaries: List[Boundary] = []

        # Quotient polynomial
        self.qDeg = 0
        self.qDim = 0

        # Expression IDs
        self.friExpId = 0
        self.cExpId = 0

        # Memory layout
        self.mapSectionsN: Dict[str, int] = {}
        self.mapOffsets: Dict[Tuple[str, bool], int] = {}
        self.mapTotalN = 0
        self.mapTotalNCustomCommitsFixed = 0

        # Value sizes
        self.airValuesSize = 0
        self.airgroupValuesSize = 0
        self.proofValuesSize = 0

        # Execution parameters
        self.maxNBlocks = 0
        self.nrowsPack = 0

        # Configuration flags
        self.recursive = False
        self.recursive_final = False
        self.verify_constraints = False
        self.verify = False
        self.gpu = False
        self.preallocate = False
        self.calculateFixedExtended = False

    @classmethod
    def from_json(
        cls,
        path: str,
        recursive_final: bool = False,
        recursive: bool = False,
        verify_constraints: bool = False,
        verify: bool = False,
        gpu: bool = False,
        preallocate: bool = False,
    ) -> "StarkInfo":
        """Load StarkInfo from starkinfo.json file."""
        info = cls()
        info.recursive = recursive
        info.recursive_final = recursive_final
        info.verify_constraints = verify_constraints
        info.verify = verify
        info.gpu = gpu
        info.preallocate = preallocate

        with open(path, "r") as f:
            j = json.load(f)

        info._load(j)
        return info

    def _load(self, j: dict) -> None:
        """Load configuration from parsed JSON."""
        self._parse_stark_struct(j["starkStruct"])
        self._parse_basic_params(j)
        self._parse_custom_commits(j)
        self._parse_opening_points_and_boundaries(j)
        self._parse_challenges(j)
        self._parse_publics(j)
        self._parse_values_maps(j)
        self._parse_polynomial_maps(j)
        self._parse_ev_map(j)
        self._parse_map_sections(j)

        self._compute_proof_size()
        self._compute_map_offsets()

    def _parse_stark_struct(self, ss: dict) -> None:
        """Parse StarkStruct from JSON."""
        self.starkStruct.nBits = ss["nBits"]
        self.starkStruct.nBitsExt = ss["nBitsExt"]
        self.starkStruct.nQueries = ss["nQueries"]
        self.starkStruct.verificationHashType = ss["verificationHashType"]
        self.starkStruct.powBits = ss["powBits"]

        if ss["verificationHashType"] == "BN128":
            self.starkStruct.merkleTreeArity = ss.get("merkleTreeArity", 16)
            self.starkStruct.transcriptArity = ss.get("transcriptArity", 16)
            self.starkStruct.merkleTreeCustom = ss.get("merkleTreeCustom", False)
            self.starkStruct.lastLevelVerification = 0
        else:
            self.starkStruct.merkleTreeArity = ss["merkleTreeArity"]
            self.starkStruct.transcriptArity = ss["transcriptArity"]
            self.starkStruct.merkleTreeCustom = ss["merkleTreeCustom"]
            self.starkStruct.lastLevelVerification = ss["lastLevelVerification"]

        self.starkStruct.hashCommits = ss.get("hashCommits", False)
        self.starkStruct.friFoldSteps = [FriFoldStep(domainBits=s["nBits"]) for s in ss["steps"]]

    def _parse_basic_params(self, j: dict) -> None:
        """Parse basic polynomial parameters."""
        self.nPublics = j["nPublics"]
        self.nConstants = j["nConstants"]
        self.nStages = j["nStages"]
        self.qDeg = j["qDeg"]
        self.qDim = j["qDim"]
        self.friExpId = j["friExpId"]
        self.cExpId = j["cExpId"]

    def _parse_custom_commits(self, j: dict) -> None:
        """Parse custom commits configuration."""
        for c_data in j.get("customCommits", []):
            c = CustomCommits(name=c_data["name"])
            c.publicValues = [pv["idx"] for pv in c_data.get("publicValues", [])]
            c.stageWidths = list(c_data.get("stageWidths", []))
            self.customCommits.append(c)

    def _parse_opening_points_and_boundaries(self, j: dict) -> None:
        """Parse opening points and constraint boundaries."""
        self.openingPoints = list(j.get("openingPoints", []))

        for b_data in j.get("boundaries", []):
            b = Boundary(name=b_data["name"])
            if b.name == "everyFrame":
                b.offsetMin = b_data["offsetMin"]
                b.offsetMax = b_data["offsetMax"]
            self.boundaries.append(b)

    def _parse_challenges(self, j: dict) -> None:
        """Parse challenge derivation map."""
        self.challengesMap = [
            ChallengeMap(
                name=ch["name"],
                stage=ch["stage"],
                field_type=_field_type_from_dim(ch["dim"]),
                stageId=ch["stageId"],
            )
            for ch in j.get("challengesMap", [])
        ]

    def _parse_publics(self, j: dict) -> None:
        """Parse publics map."""
        for p_data in j.get("publicsMap", []):
            p = PolMap(stage=0, name=p_data["name"], field_type=FieldType.FF, stagePos=0, stageId=0)
            if "lengths" in p_data:
                p.lengths = list(p_data["lengths"])
            self.publicsMap.append(p)

    def _parse_values_maps(self, j: dict) -> None:
        """Parse airgroup, air, and proof values maps."""
        # Airgroup values
        self.airgroupValuesSize = 0
        for av_data in j.get("airgroupValuesMap", []):
            ft = FieldType.FF if av_data["stage"] == 1 else FieldType.FF3
            av = PolMap(
                stage=av_data["stage"],
                name=av_data["name"],
                field_type=ft,
                stagePos=0,
                stageId=0,
            )
            self.airgroupValuesMap.append(av)
            self.airgroupValuesSize += ft.value

        # Air values
        self.airValuesSize = 0
        for av_data in j.get("airValuesMap", []):
            ft = FieldType.FF if av_data["stage"] == 1 else FieldType.FF3
            av = PolMap(
                stage=av_data["stage"],
                name=av_data["name"],
                field_type=ft,
                stagePos=0,
                stageId=0,
            )
            self.airValuesMap.append(av)
            self.airValuesSize += ft.value

        # Proof values
        self.proofValuesSize = 0
        for pv_data in j.get("proofValuesMap", []):
            ft = FieldType.FF if pv_data["stage"] == 1 else FieldType.FF3
            pv = PolMap(
                stage=pv_data["stage"],
                name=pv_data["name"],
                field_type=ft,
                stagePos=0,
                stageId=0,
            )
            self.proofValuesMap.append(pv)
            self.proofValuesSize += ft.value

    def _parse_polynomial_maps(self, j: dict) -> None:
        """Parse committed and constant polynomial maps."""
        # Committed polynomials
        for cm_data in j.get("cmPolsMap", []):
            cm = PolMap(
                stage=cm_data["stage"],
                name=cm_data["name"],
                field_type=_field_type_from_dim(cm_data["dim"]),
                stagePos=cm_data["stagePos"],
                stageId=cm_data["stageId"],
                imPol="imPol" in cm_data,
                polsMapId=cm_data["polsMapId"],
            )
            if "expId" in cm_data:
                cm.expId = cm_data["expId"]
            if "lengths" in cm_data:
                cm.lengths = list(cm_data["lengths"])
            self.cmPolsMap.append(cm)

        # Custom commits
        for commit_idx, cc_data in enumerate(j.get("customCommitsMap", [])):
            cc_pols = []
            for pol_data in cc_data:
                pol = PolMap(
                    stage=pol_data["stage"],
                    name=pol_data["name"],
                    field_type=_field_type_from_dim(pol_data["dim"]),
                    stagePos=pol_data["stagePos"],
                    stageId=pol_data["stageId"],
                    imPol=False,
                    polsMapId=pol_data["polsMapId"],
                    commitId=commit_idx,
                )
                if "expId" in pol_data:
                    pol.expId = pol_data["expId"]
                if "lengths" in pol_data:
                    pol.lengths = list(pol_data["lengths"])
                cc_pols.append(pol)
            self.customCommitsMap.append(cc_pols)

        # Constant polynomials
        for const_data in j.get("constPolsMap", []):
            const = PolMap(
                stage=const_data["stage"],
                name=const_data["name"],
                field_type=_field_type_from_dim(const_data["dim"]),
                stagePos=const_data["stageId"],
                stageId=const_data["stageId"],
                imPol=False,
                polsMapId=const_data["polsMapId"],
            )
            if "lengths" in const_data:
                const.lengths = list(const_data["lengths"])
            self.constPolsMap.append(const)

    def _parse_ev_map(self, j: dict) -> None:
        """Parse evaluation map."""
        for ev_data in j.get("evMap", []):
            ev = EvMap(
                type=EvMap.type_from_string(ev_data["type"]),
                id=ev_data["id"],
                prime=ev_data["prime"],
            )

            if ev_data["type"] == "custom":
                ev.commitId = ev_data["commitId"]

            if "openingPos" in ev_data:
                ev.openingPos = ev_data["openingPos"]
            else:
                try:
                    ev.openingPos = self.openingPoints.index(ev.prime)
                except ValueError:
                    raise ValueError(
                        f"Opening point {ev.prime} not found in openingPoints"
                    )

            self.evMap.append(ev)

    def _parse_map_sections(self, j: dict) -> None:
        """Parse mapSectionsN."""
        self.mapSectionsN = dict(j.get("mapSectionsN", {}))

    def _compute_proof_size(self) -> None:
        """Calculate total proof size in field elements."""
        ss = self.starkStruct
        self.proofSize = 0

        # Values and roots
        self.proofSize += len(self.airgroupValuesMap) * FIELD_EXTENSION_DEGREE
        self.proofSize += len(self.airValuesMap) * FIELD_EXTENSION_DEGREE
        self.proofSize += (self.nStages + 1) * HASH_SIZE

        # Evaluations
        self.proofSize += len(self.evMap) * FIELD_EXTENSION_DEGREE

        # Merkle proof siblings
        nSiblings = (
            math.ceil(ss.friFoldSteps[0].domainBits / math.log2(ss.merkleTreeArity))
            - ss.lastLevelVerification
        )
        nSiblingsPerLevel = (ss.merkleTreeArity - 1) * HASH_SIZE

        # Constants Merkle proofs
        self.proofSize += ss.nQueries * self.nConstants
        self.proofSize += ss.nQueries * nSiblings * nSiblingsPerLevel

        # Custom commits Merkle proofs
        for cc in self.customCommits:
            self.proofSize += ss.nQueries * self.mapSectionsN[cc.name + "0"]
            self.proofSize += ss.nQueries * nSiblings * nSiblingsPerLevel

        # Stage commitments Merkle proofs
        for i in range(self.nStages + 1):
            self.proofSize += ss.nQueries * self.mapSectionsN[f"cm{i + 1}"]
            self.proofSize += ss.nQueries * nSiblings * nSiblingsPerLevel

        # FRI roots
        self.proofSize += (len(ss.friFoldSteps) - 1) * HASH_SIZE

        # Last level verification nodes
        if ss.lastLevelVerification > 0:
            numNodesLevel = int(ss.merkleTreeArity**ss.lastLevelVerification)
            self.proofSize += (len(ss.friFoldSteps) - 1) * numNodesLevel * HASH_SIZE
            self.proofSize += (
                (self.nStages + 2 + len(self.customCommits)) * numNodesLevel * HASH_SIZE
            )

        # FRI query proofs
        for i in range(1, len(ss.friFoldSteps)):
            nSiblings = (
                math.ceil(ss.friFoldSteps[i].domainBits / math.log2(ss.merkleTreeArity))
                - ss.lastLevelVerification
            )
            nSiblingsPerLevel = (ss.merkleTreeArity - 1) * HASH_SIZE
            fold_factor = 1 << (ss.friFoldSteps[i - 1].domainBits - ss.friFoldSteps[i].domainBits)
            self.proofSize += ss.nQueries * fold_factor * FIELD_EXTENSION_DEGREE
            self.proofSize += ss.nQueries * nSiblings * nSiblingsPerLevel

        # Final polynomial + nonce
        final_pol_degree = 1 << ss.friFoldSteps[-1].domainBits
        self.proofSize += final_pol_degree * FIELD_EXTENSION_DEGREE
        self.proofSize += 1

    def _compute_map_offsets(self) -> None:
        """Compute memory layout offsets for polynomial buffers."""
        N = 1 << self.starkStruct.nBits
        NExtended = 1 << self.starkStruct.nBitsExt

        self.mapOffsets[("const", False)] = 0
        self.mapOffsets[("const", True)] = 0
        self.mapOffsets[("cm1", False)] = 0

        # Custom commits offsets
        self.mapTotalNCustomCommitsFixed = 0
        for cc in self.customCommits:
            if cc.stageWidths and cc.stageWidths[0] > 0:
                self.mapOffsets[(cc.name + "0", False)] = (
                    self.mapTotalNCustomCommitsFixed
                )
                self.mapTotalNCustomCommitsFixed += cc.stageWidths[0] * N
                self.mapOffsets[(cc.name + "0", True)] = (
                    self.mapTotalNCustomCommitsFixed
                )
                self.mapTotalNCustomCommitsFixed += (
                    cc.stageWidths[0] * NExtended + self._merkle_tree_nodes(NExtended)
                )

        # Stage offsets (non-extended, then extended)
        self.mapTotalN = 0
        for stage in range(1, self.nStages + 2):
            section = f"cm{stage}"
            if section in self.mapSectionsN:
                self.mapOffsets[(section, False)] = self.mapTotalN
                self.mapTotalN += N * self.mapSectionsN[section]

        for stage in range(1, self.nStages + 2):
            section = f"cm{stage}"
            if section in self.mapSectionsN:
                self.mapOffsets[(section, True)] = self.mapTotalN
                self.mapTotalN += NExtended * self.mapSectionsN[section]

        # Quotient and FRI polynomial offsets
        self.mapOffsets[("q", True)] = self.mapTotalN
        self.mapTotalN += NExtended * self.qDim

        self.mapOffsets[("f", True)] = self.mapTotalN
        self.mapTotalN += NExtended * FIELD_EXTENSION_DEGREE

    def _merkle_tree_nodes(self, height: int) -> int:
        """Calculate total Merkle tree node count * HASH_SIZE."""
        arity = self.starkStruct.merkleTreeArity
        numNodes = height
        nodesLevel = height

        while nodesLevel > 1:
            extraZeros = (arity - (nodesLevel % arity)) % arity
            numNodes += extraZeros
            nodesLevel = (nodesLevel + arity - 1) // arity
            numNodes += nodesLevel

        return numNodes * HASH_SIZE

    def get_offset(self, section: str, extended: bool) -> int:
        """Get buffer offset for a section."""
        return self.mapOffsets[(section, extended)]

    def get_n_cols(self, section: str) -> int:
        """Get number of columns in a section."""
        return self.mapSectionsN[section]
