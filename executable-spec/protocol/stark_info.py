"""
STARK configuration parser.

This module provides a faithful Python translation of the C++ StarkInfo class
from pil2-stark/src/starkpil/stark_info.hpp and stark_info.cpp.

The StarkInfo class parses and represents the complete STARK configuration
from starkinfo.json files, including polynomial maps, evaluation points,
challenges, and FRI parameters.
"""

import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from primitives.pol_map import PolMap, EvMap, ChallengeMap, CustomCommits, Boundary


# Field extension size (Goldilocks3)
FIELD_EXTENSION = 3

# Hash size in field elements
HASH_SIZE = 4


@dataclass
class StepStruct:
    """FRI folding step configuration.

    Corresponds to C++ class StepStruct in stark_info.hpp (lines 68-72).

    Attributes:
        nBits: Number of bits for this FRI step domain
    """
    nBits: int


@dataclass
class StarkStruct:
    """Core STARK protocol parameters.

    Corresponds to C++ class StarkStruct in stark_info.hpp (lines 74-88).

    Attributes:
        nBits: Log2 of trace domain size (N = 2^nBits)
        nBitsExt: Log2 of extended domain size (N_ext = 2^nBitsExt)
        nQueries: Number of FRI queries for soundness
        verificationHashType: Hash function type ("GL" or "BN128")
        steps: FRI folding step configurations
        merkleTreeArity: Branching factor for Merkle trees
        merkleTreeCustom: Use custom Merkle tree implementation
        transcriptArity: Arity for transcript hashing
        lastLevelVerification: Last level to include in verification
        powBits: Proof-of-work difficulty bits
        hashCommits: Whether to hash commitments
    """
    nBits: int
    nBitsExt: int
    nQueries: int
    verificationHashType: str
    steps: List[StepStruct] = field(default_factory=list)
    merkleTreeArity: int = 16
    merkleTreeCustom: bool = False
    transcriptArity: int = 16
    lastLevelVerification: int = 0
    powBits: int = 0
    hashCommits: bool = False


class StarkInfo:
    """STARK configuration and metadata.

    Corresponds to C++ class StarkInfo in stark_info.hpp (lines 137-217).

    This class parses starkinfo.json and provides all configuration needed
    for STARK proving and verification, including polynomial mappings,
    evaluation points, challenge derivation, and memory layout.
    """

    def __init__(self):
        """Initialize empty StarkInfo.

        Corresponds to C++ default constructor (line 203).
        """
        # Core STARK parameters
        self.starkStruct: StarkStruct = StarkStruct(0, 0, 0, "GL")

        # AIR identification
        self.airgroupId: int = 0
        self.airId: int = 0

        # Polynomial counts
        self.nPublics: int = 0
        self.nConstants: int = 0
        self.nStages: int = 0

        # Proof size parameters
        self.maxProofBuffSize: int = 0
        self.maxProofSize: int = 0
        self.maxTreeWidth: int = 0
        self.proofSize: int = 0

        # Custom commits
        self.customCommits: List[CustomCommits] = []

        # Polynomial mappings
        self.cmPolsMap: List[PolMap] = []
        self.constPolsMap: List[PolMap] = []
        self.challengesMap: List[ChallengeMap] = []
        self.airgroupValuesMap: List[PolMap] = []
        self.airValuesMap: List[PolMap] = []
        self.proofValuesMap: List[PolMap] = []
        self.publicsMap: List[PolMap] = []
        self.customCommitsMap: List[List[PolMap]] = []

        # Evaluation map
        self.evMap: List[EvMap] = []

        # Opening points and boundaries
        self.openingPoints: List[int] = []
        self.boundaries: List[Boundary] = []

        # Quotient polynomial parameters
        self.qDeg: int = 0
        self.qDim: int = 0

        # Expression IDs
        self.friExpId: int = 0
        self.cExpId: int = 0

        # Section metadata
        self.mapSectionsN: Dict[str, int] = {}

        # Memory layout (computed)
        self.mapOffsets: Dict[Tuple[str, bool], int] = {}
        self.mapTotalN: int = 0
        self.mapTotalNCustomCommitsFixed: int = 0

        # Value sizes
        self.airValuesSize: int = 0
        self.airgroupValuesSize: int = 0
        self.proofValuesSize: int = 0

        # Execution parameters
        self.maxNBlocks: int = 0
        self.nrowsPack: int = 0

        # Configuration flags
        self.recursive: bool = False
        self.recursive_final: bool = False
        self.verify_constraints: bool = False
        self.verify: bool = False
        self.gpu: bool = False
        self.preallocate: bool = False
        self.calculateFixedExtended: bool = False

    @classmethod
    def from_json(cls,
                  path: str,
                  recursive_final: bool = False,
                  recursive: bool = False,
                  verify_constraints: bool = False,
                  verify: bool = False,
                  gpu: bool = False,
                  preallocate: bool = False) -> 'StarkInfo':
        """Load StarkInfo from starkinfo.json file.

        Corresponds to C++ constructor (lines 8-22 of stark_info.cpp).

        Args:
            path: Path to starkinfo.json file
            recursive_final: Final recursion flag
            recursive: Recursion flag
            verify_constraints: Verify constraints flag
            verify: Verify mode flag
            gpu: GPU mode flag
            preallocate: Preallocate buffers flag

        Returns:
            Loaded StarkInfo instance
        """
        info = cls()
        info.recursive = recursive
        info.recursive_final = recursive_final
        info.verify_constraints = verify_constraints
        info.verify = verify
        info.gpu = gpu
        info.preallocate = preallocate

        # Load and parse JSON
        with open(path, 'r') as f:
            j = json.load(f)

        info._load(j)
        return info

    def _load(self, j: dict) -> None:
        """Load configuration from parsed JSON.

        Corresponds to C++ StarkInfo::load() (lines 24-308 of stark_info.cpp).

        Args:
            j: Parsed JSON dictionary
        """
        # Parse StarkStruct (lines 26-62)
        ss = j["starkStruct"]
        self.starkStruct.nBits = ss["nBits"]
        self.starkStruct.nBitsExt = ss["nBitsExt"]
        self.starkStruct.nQueries = ss["nQueries"]
        self.starkStruct.verificationHashType = ss["verificationHashType"]
        self.starkStruct.powBits = ss["powBits"]

        if self.starkStruct.verificationHashType == "BN128":
            # BN128 defaults (lines 31-44)
            self.starkStruct.merkleTreeArity = ss.get("merkleTreeArity", 16)
            self.starkStruct.transcriptArity = ss.get("transcriptArity", 16)
            self.starkStruct.merkleTreeCustom = ss.get("merkleTreeCustom", False)
            self.starkStruct.lastLevelVerification = 0
        else:
            # Goldilocks (lines 45-49)
            self.starkStruct.merkleTreeArity = ss["merkleTreeArity"]
            self.starkStruct.transcriptArity = ss["transcriptArity"]
            self.starkStruct.merkleTreeCustom = ss["merkleTreeCustom"]
            self.starkStruct.lastLevelVerification = ss["lastLevelVerification"]

        self.starkStruct.hashCommits = ss.get("hashCommits", False)

        # Parse FRI steps (lines 57-62)
        for step_data in ss["steps"]:
            step = StepStruct(nBits=step_data["nBits"])
            self.starkStruct.steps.append(step)

        # Parse basic parameters (lines 64-73)
        self.nPublics = j["nPublics"]
        self.nConstants = j["nConstants"]
        self.nStages = j["nStages"]
        self.qDeg = j["qDeg"]
        self.qDim = j["qDim"]
        self.friExpId = j["friExpId"]
        self.cExpId = j["cExpId"]

        # Parse custom commits (lines 76-86)
        for c_data in j.get("customCommits", []):
            c = CustomCommits(name=c_data["name"])
            for pv in c_data.get("publicValues", []):
                c.publicValues.append(pv["idx"])
            for sw in c_data.get("stageWidths", []):
                c.stageWidths.append(sw)
            self.customCommits.append(c)

        # Parse opening points (lines 88-90)
        for op in j.get("openingPoints", []):
            self.openingPoints.append(op)

        # Parse boundaries (lines 92-100)
        for b_data in j.get("boundaries", []):
            b = Boundary(name=b_data["name"])
            if b.name == "everyFrame":
                b.offsetMin = b_data["offsetMin"]
                b.offsetMax = b_data["offsetMax"]
            self.boundaries.append(b)

        # Parse challenges map (lines 102-110)
        for ch_data in j.get("challengesMap", []):
            ch = ChallengeMap(
                name=ch_data["name"],
                stage=ch_data["stage"],
                dim=ch_data["dim"],
                stageId=ch_data["stageId"]
            )
            self.challengesMap.append(ch)

        # Parse publics map (lines 112-122)
        for p_data in j.get("publicsMap", []):
            p = PolMap(
                stage=0,
                name=p_data["name"],
                dim=1,
                stagePos=0,
                stageId=0
            )
            if "lengths" in p_data:
                p.lengths = list(p_data["lengths"])
            self.publicsMap.append(p)

        # Parse airgroup values map (lines 124-136)
        self.airgroupValuesSize = 0
        for av_data in j.get("airgroupValuesMap", []):
            av = PolMap(
                stage=av_data["stage"],
                name=av_data["name"],
                dim=1 if av_data["stage"] == 1 else FIELD_EXTENSION,
                stagePos=0,
                stageId=0
            )
            self.airgroupValuesMap.append(av)
            if av.stage == 1:
                self.airgroupValuesSize += 1
            else:
                self.airgroupValuesSize += FIELD_EXTENSION

        # Parse air values map (lines 138-150)
        self.airValuesSize = 0
        for av_data in j.get("airValuesMap", []):
            av = PolMap(
                stage=av_data["stage"],
                name=av_data["name"],
                dim=1 if av_data["stage"] == 1 else FIELD_EXTENSION,
                stagePos=0,
                stageId=0
            )
            self.airValuesMap.append(av)
            if av.stage == 1:
                self.airValuesSize += 1
            else:
                self.airValuesSize += FIELD_EXTENSION

        # Parse proof values map (lines 152-164)
        self.proofValuesSize = 0
        for pv_data in j.get("proofValuesMap", []):
            pv = PolMap(
                stage=pv_data["stage"],
                name=pv_data["name"],
                dim=1 if pv_data["stage"] == 1 else FIELD_EXTENSION,
                stagePos=0,
                stageId=0
            )
            self.proofValuesMap.append(pv)
            if pv.stage == 1:
                self.proofValuesSize += 1
            else:
                self.proofValuesSize += FIELD_EXTENSION

        # Parse committed polynomials map (lines 166-185)
        for cm_data in j.get("cmPolsMap", []):
            cm = PolMap(
                stage=cm_data["stage"],
                name=cm_data["name"],
                dim=cm_data["dim"],
                stagePos=cm_data["stagePos"],
                stageId=cm_data["stageId"],
                imPol="imPol" in cm_data,
                polsMapId=cm_data["polsMapId"]
            )
            if "expId" in cm_data:
                cm.expId = cm_data["expId"]
            if "lengths" in cm_data:
                cm.lengths = list(cm_data["lengths"])
            self.cmPolsMap.append(cm)

        # Parse custom commits map (lines 187-210)
        for cc_data in j.get("customCommitsMap", []):
            cc_pols = []
            for pol_data in cc_data:
                pol = PolMap(
                    stage=pol_data["stage"],
                    name=pol_data["name"],
                    dim=pol_data["dim"],
                    stagePos=pol_data["stagePos"],
                    stageId=pol_data["stageId"],
                    imPol=False,
                    polsMapId=pol_data["polsMapId"]
                )
                # Note: C++ sets commitId from loop index (line 197)
                # We'll need to set this after the loop
                if "expId" in pol_data:
                    pol.expId = pol_data["expId"]
                if "lengths" in pol_data:
                    pol.lengths = list(pol_data["lengths"])
                cc_pols.append(pol)

            # Set commitId for all polynomials in this custom commit
            commit_idx = len(self.customCommitsMap)
            for pol in cc_pols:
                pol.commitId = commit_idx

            self.customCommitsMap.append(cc_pols)

        # Parse constant polynomials map (lines 213-229)
        for const_data in j.get("constPolsMap", []):
            const = PolMap(
                stage=const_data["stage"],
                name=const_data["name"],
                dim=const_data["dim"],
                stagePos=const_data["stageId"],
                stageId=const_data["stageId"],
                imPol=False,
                polsMapId=const_data["polsMapId"]
            )
            if "lengths" in const_data:
                const.lengths = list(const_data["lengths"])
            self.constPolsMap.append(const)

        # Parse evaluation map (lines 231-253)
        for ev_data in j.get("evMap", []):
            ev = EvMap(
                type=EvMap.type_from_string(ev_data["type"]),
                id=ev_data["id"],
                prime=ev_data["prime"]
            )

            if ev_data["type"] == "custom":
                ev.commitId = ev_data["commitId"]

            # Compute openingPos if not provided (lines 240-251)
            if "openingPos" in ev_data:
                ev.openingPos = ev_data["openingPos"]
            else:
                prime = ev.prime
                # Find index in openingPoints
                try:
                    ev.openingPos = self.openingPoints.index(prime)
                except ValueError:
                    raise ValueError(f"Opening point {prime} not found in openingPoints")

            self.evMap.append(ev)

        # Parse mapSectionsN (lines 255-258)
        for key, value in j.get("mapSectionsN", {}).items():
            self.mapSectionsN[key] = value

        # Compute proof size and set memory offsets
        # These correspond to getProofSize() and setMapOffsets() calls
        # For now, we'll implement simplified versions for the spec
        self._get_proof_size()
        self._set_map_offsets()

    def _get_proof_size(self) -> None:
        """Calculate proof size.

        Corresponds to C++ StarkInfo::getProofSize() (lines 310-352).
        """
        self.proofSize = 0

        # Airgroup and air values
        self.proofSize += len(self.airgroupValuesMap) * FIELD_EXTENSION
        self.proofSize += len(self.airValuesMap) * FIELD_EXTENSION

        # Stage roots
        self.proofSize += (self.nStages + 1) * HASH_SIZE

        # Evaluations
        self.proofSize += len(self.evMap) * FIELD_EXTENSION

        # Merkle proof elements
        nSiblings = math.ceil(
            self.starkStruct.steps[0].nBits /
            math.log2(self.starkStruct.merkleTreeArity)
        ) - self.starkStruct.lastLevelVerification
        nSiblingsPerLevel = (self.starkStruct.merkleTreeArity - 1) * HASH_SIZE

        # Constants
        self.proofSize += self.starkStruct.nQueries * self.nConstants
        self.proofSize += self.starkStruct.nQueries * nSiblings * nSiblingsPerLevel

        # Custom commits
        for cc in self.customCommits:
            self.proofSize += self.starkStruct.nQueries * self.mapSectionsN[cc.name + "0"]
            self.proofSize += self.starkStruct.nQueries * nSiblings * nSiblingsPerLevel

        # Stage commitments
        for i in range(self.nStages + 1):
            self.proofSize += self.starkStruct.nQueries * self.mapSectionsN[f"cm{i+1}"]
            self.proofSize += self.starkStruct.nQueries * nSiblings * nSiblingsPerLevel

        # FRI roots
        self.proofSize += (len(self.starkStruct.steps) - 1) * HASH_SIZE

        # Last level verification
        if self.starkStruct.lastLevelVerification > 0:
            numNodesLevel = int(
                self.starkStruct.merkleTreeArity ** self.starkStruct.lastLevelVerification
            )
            self.proofSize += (len(self.starkStruct.steps) - 1) * numNodesLevel * HASH_SIZE
            self.proofSize += (self.nStages + 2 + len(self.customCommits)) * numNodesLevel * HASH_SIZE

        # FRI query proofs
        for i in range(1, len(self.starkStruct.steps)):
            nSiblings = math.ceil(
                self.starkStruct.steps[i].nBits /
                math.log2(self.starkStruct.merkleTreeArity)
            ) - self.starkStruct.lastLevelVerification
            nSiblingsPerLevel = (self.starkStruct.merkleTreeArity - 1) * HASH_SIZE

            fold_factor = 1 << (self.starkStruct.steps[i-1].nBits - self.starkStruct.steps[i].nBits)
            self.proofSize += self.starkStruct.nQueries * fold_factor * FIELD_EXTENSION
            self.proofSize += self.starkStruct.nQueries * nSiblings * nSiblingsPerLevel

        # Final polynomial
        final_pol_degree = 1 << self.starkStruct.steps[-1].nBits
        self.proofSize += final_pol_degree * FIELD_EXTENSION

        # Nonce
        self.proofSize += 1

    def _set_map_offsets(self) -> None:
        """Set memory layout offsets.

        Corresponds to C++ StarkInfo::setMapOffsets() (lines 407-615).

        This is a simplified version for the executable spec.
        The full C++ version handles complex memory layout optimization
        for GPU and different execution modes. We implement a basic
        version that sets up offsets for the main sections.
        """
        N = 1 << self.starkStruct.nBits
        NExtended = 1 << self.starkStruct.nBitsExt

        # Initialize offsets
        self.mapOffsets[("const", False)] = 0
        self.mapOffsets[("const", True)] = 0
        self.mapOffsets[("cm1", False)] = 0

        self.mapTotalNCustomCommitsFixed = 0

        # Set offsets for custom commits (lines 419-425)
        for cc in self.customCommits:
            if len(cc.stageWidths) > 0 and cc.stageWidths[0] > 0:
                self.mapOffsets[(cc.name + "0", False)] = self.mapTotalNCustomCommitsFixed
                self.mapTotalNCustomCommitsFixed += cc.stageWidths[0] * N
                self.mapOffsets[(cc.name + "0", True)] = self.mapTotalNCustomCommitsFixed
                self.mapTotalNCustomCommitsFixed += cc.stageWidths[0] * NExtended + self._get_num_nodes_mt(NExtended)

        self.mapTotalN = 0

        # Set non-extended offsets for trace stages
        # These are used during initial witness computation
        for stage in range(1, self.nStages + 2):
            section_name = f"cm{stage}"
            if section_name in self.mapSectionsN:
                self.mapOffsets[(section_name, False)] = self.mapTotalN
                self.mapTotalN += N * self.mapSectionsN[section_name]

        # Set extended offsets for trace stages
        # These are used after polynomial extension (N -> N_ext)
        for stage in range(1, self.nStages + 2):
            section_name = f"cm{stage}"
            if section_name in self.mapSectionsN:
                self.mapOffsets[(section_name, True)] = self.mapTotalN
                self.mapTotalN += NExtended * self.mapSectionsN[section_name]

        # Quotient polynomial offset (extended domain only)
        self.mapOffsets[("q", True)] = self.mapTotalN
        self.mapTotalN += NExtended * self.qDim

        # FRI polynomial offset (extended domain only)
        self.mapOffsets[("f", True)] = self.mapTotalN
        self.mapTotalN += NExtended * FIELD_EXTENSION

    def _get_num_nodes_mt(self, height: int) -> int:
        """Calculate number of Merkle tree nodes.

        Corresponds to C++ StarkInfo::getNumNodesMT() (lines 666-679).

        Args:
            height: Number of leaves in the tree

        Returns:
            Total number of nodes (including internal nodes) * HASH_SIZE
        """
        numNodes = height
        nodesLevel = height

        while nodesLevel > 1:
            extraZeros = (self.starkStruct.merkleTreeArity -
                         (nodesLevel % self.starkStruct.merkleTreeArity)) % self.starkStruct.merkleTreeArity
            numNodes += extraZeros
            nextN = (nodesLevel + self.starkStruct.merkleTreeArity - 1) // self.starkStruct.merkleTreeArity
            numNodes += nextN
            nodesLevel = nextN

        return numNodes * HASH_SIZE

    def get_offset(self, section: str, extended: bool) -> int:
        """Get buffer offset for a section.

        Args:
            section: Section name (e.g., "cm1", "const", "q")
            extended: True for extended domain, False for normal domain

        Returns:
            Offset into the buffer

        Raises:
            KeyError: If section is not found
        """
        return self.mapOffsets[(section, extended)]

    def get_n_cols(self, section: str) -> int:
        """Get number of columns in a section.

        Args:
            section: Section name (e.g., "cm1", "const")

        Returns:
            Number of columns in the section

        Raises:
            KeyError: If section is not found
        """
        return self.mapSectionsN[section]
