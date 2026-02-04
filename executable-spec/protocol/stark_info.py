"""STARK configuration parser."""

import json
import math
from dataclasses import dataclass, field

# --- Constants ---
from primitives.field import FIELD_EXTENSION_DEGREE
from primitives.pol_map import Boundary, ChallengeMap, CustomCommits, EvMap, FieldType, PolMap

HASH_SIZE = 4


def _field_type_from_dim(dim: int) -> FieldType:
    """Convert dim int to FieldType enum."""
    return FieldType.FF if dim == 1 else FieldType.FF3


# --- Data Structures ---
@dataclass
class FriFoldStep:
    """FRI recursive folding layer configuration."""
    domain_bits: int


@dataclass
class StarkStruct:
    """Core STARK protocol parameters."""
    n_bits: int
    n_bits_ext: int
    n_queries: int
    verification_hash_type: str
    fri_fold_steps: list[FriFoldStep] = field(default_factory=list)
    merkle_tree_arity: int = 16
    merkle_tree_custom: bool = False
    transcript_arity: int = 16
    last_level_verification: int = 0
    pow_bits: int = 0
    hash_commits: bool = False


# --- StarkInfo ---
class StarkInfo:
    """STARK configuration loaded from starkinfo.json."""

    def __init__(self) -> None:
        # Core parameters
        self.stark_struct = StarkStruct(0, 0, 0, "GL")
        self.name = ""

        # Polynomial counts
        self.n_publics = 0
        self.n_constants = 0
        self.n_stages = 0

        # Proof size
        self.proof_size = 0

        # Polynomial mappings
        self.custom_commits: list[CustomCommits] = []
        self.cm_pols_map: list[PolMap] = []
        self.const_pols_map: list[PolMap] = []
        self.challenges_map: list[ChallengeMap] = []
        self.airgroup_values_map: list[PolMap] = []
        self.air_values_map: list[PolMap] = []
        self.custom_commits_map: list[list[PolMap]] = []
        self.ev_map: list[EvMap] = []

        # Opening points and boundaries
        self.opening_points: list[int] = []
        self.boundaries: list[Boundary] = []

        # Quotient polynomial
        self.q_deg = 0
        self.q_dim = 0

        # Memory layout
        self.map_sections_n: dict[str, int] = {}
        self.map_offsets: dict[tuple[str, bool], int] = {}
        self.map_total_n = 0
        self.map_total_n_custom_commits_fixed = 0

        # Value sizes
        self.air_values_size = 0
        self.airgroup_values_size = 0

    @classmethod
    def from_json(cls, path: str) -> "StarkInfo":
        """Load StarkInfo from starkinfo.json file."""
        info = cls()

        with open(path) as f:
            j = json.load(f)

        info._load(j)
        return info

    def _load(self, j: dict) -> None:
        """Load configuration from parsed JSON."""
        self._parse_stark_struct(j["starkStruct"])
        self._parse_basic_params(j)
        self._parse_custom_commits(j)
        self._parse_opening_points(j)
        self._parse_boundaries(j)
        self._parse_challenges(j)
        self._parse_values_maps(j)
        self._parse_polynomial_maps(j)
        self._parse_ev_map(j)
        self._parse_map_sections(j)

        self._compute_proof_size()
        self._compute_map_offsets()

    def _parse_stark_struct(self, ss: dict) -> None:
        """Parse StarkStruct from JSON."""
        self.stark_struct.n_bits = ss["nBits"]
        self.stark_struct.n_bits_ext = ss["nBitsExt"]
        self.stark_struct.n_queries = ss["nQueries"]
        self.stark_struct.verification_hash_type = ss["verificationHashType"]
        self.stark_struct.pow_bits = ss["powBits"]

        if ss["verificationHashType"] == "BN128":
            self.stark_struct.merkle_tree_arity = ss.get("merkleTreeArity", 16)
            self.stark_struct.transcript_arity = ss.get("transcriptArity", 16)
            self.stark_struct.merkle_tree_custom = ss.get("merkleTreeCustom", False)
            self.stark_struct.last_level_verification = 0
        else:
            self.stark_struct.merkle_tree_arity = ss["merkleTreeArity"]
            self.stark_struct.transcript_arity = ss["transcriptArity"]
            self.stark_struct.merkle_tree_custom = ss["merkleTreeCustom"]
            self.stark_struct.last_level_verification = ss["lastLevelVerification"]

        self.stark_struct.hash_commits = ss.get("hashCommits", False)
        self.stark_struct.fri_fold_steps = [FriFoldStep(domain_bits=s["nBits"]) for s in ss["steps"]]

    def _parse_basic_params(self, j: dict) -> None:
        """Parse basic polynomial parameters."""
        self.name = j["name"]
        self.n_publics = j["nPublics"]
        self.n_constants = j["nConstants"]
        self.n_stages = j["nStages"]
        self.q_deg = j["qDeg"]
        self.q_dim = j["qDim"]

    def _parse_custom_commits(self, j: dict) -> None:
        """Parse custom commits configuration."""
        for c_data in j.get("customCommits", []):
            c = CustomCommits(name=c_data["name"])
            c.public_values = [pv["idx"] for pv in c_data.get("publicValues", [])]
            c.stage_widths = list(c_data.get("stageWidths", []))
            self.custom_commits.append(c)

    def _parse_opening_points(self, j: dict) -> None:
        """Parse opening points."""
        self.opening_points = list(j.get("openingPoints", []))

    def _parse_boundaries(self, j: dict) -> None:
        """Parse constraint boundaries."""
        for b_data in j.get("boundaries", []):
            b = Boundary(name=b_data["name"])
            if b.name == "everyFrame":
                b.offset_min = b_data["offsetMin"]
                b.offset_max = b_data["offsetMax"]
            self.boundaries.append(b)

    def _parse_challenges(self, j: dict) -> None:
        """Parse challenge derivation map."""
        self.challenges_map = [
            ChallengeMap(
                name=ch["name"],
                stage=ch["stage"],
                field_type=_field_type_from_dim(ch["dim"]),
                stage_id=ch["stageId"],
            )
            for ch in j.get("challengesMap", [])
        ]

    def _parse_values_maps(self, j: dict) -> None:
        """Parse airgroup and air values maps."""
        # Airgroup values
        self.airgroup_values_size = 0
        for av_data in j.get("airgroupValuesMap", []):
            ft = FieldType.FF if av_data["stage"] == 1 else FieldType.FF3
            av = PolMap(
                stage=av_data["stage"],
                name=av_data["name"],
                field_type=ft,
                stage_pos=0,
                stage_id=0,
            )
            self.airgroup_values_map.append(av)
            self.airgroup_values_size += ft.value

        # Air values
        self.air_values_size = 0
        for av_data in j.get("airValuesMap", []):
            ft = FieldType.FF if av_data["stage"] == 1 else FieldType.FF3
            av = PolMap(
                stage=av_data["stage"],
                name=av_data["name"],
                field_type=ft,
                stage_pos=0,
                stage_id=0,
            )
            self.air_values_map.append(av)
            self.air_values_size += ft.value

    def _parse_polynomial_maps(self, j: dict) -> None:
        """Parse committed and constant polynomial maps."""
        # Committed polynomials
        for cm_data in j.get("cmPolsMap", []):
            cm = PolMap(
                stage=cm_data["stage"],
                name=cm_data["name"],
                field_type=_field_type_from_dim(cm_data["dim"]),
                stage_pos=cm_data["stagePos"],
                stage_id=cm_data["stageId"],
                im_pol="imPol" in cm_data,
                pols_map_id=cm_data["polsMapId"],
            )
            if "expId" in cm_data:
                cm.exp_id = cm_data["expId"]
            if "lengths" in cm_data:
                cm.lengths = list(cm_data["lengths"])
            self.cm_pols_map.append(cm)

        # Custom commits
        for commit_idx, cc_data in enumerate(j.get("customCommitsMap", [])):
            cc_pols = []
            for pol_data in cc_data:
                pol = PolMap(
                    stage=pol_data["stage"],
                    name=pol_data["name"],
                    field_type=_field_type_from_dim(pol_data["dim"]),
                    stage_pos=pol_data["stagePos"],
                    stage_id=pol_data["stageId"],
                    im_pol=False,
                    pols_map_id=pol_data["polsMapId"],
                    commit_id=commit_idx,
                )
                if "expId" in pol_data:
                    pol.exp_id = pol_data["expId"]
                if "lengths" in pol_data:
                    pol.lengths = list(pol_data["lengths"])
                cc_pols.append(pol)
            self.custom_commits_map.append(cc_pols)

        # Constant polynomials
        for const_data in j.get("constPolsMap", []):
            const = PolMap(
                stage=const_data["stage"],
                name=const_data["name"],
                field_type=_field_type_from_dim(const_data["dim"]),
                stage_pos=const_data["stageId"],
                stage_id=const_data["stageId"],
                im_pol=False,
                pols_map_id=const_data["polsMapId"],
            )
            if "lengths" in const_data:
                const.lengths = list(const_data["lengths"])
            self.const_pols_map.append(const)

    def _parse_ev_map(self, j: dict) -> None:
        """Parse evaluation map."""
        for ev_data in j.get("evMap", []):
            ev = EvMap(
                type=EvMap.type_from_string(ev_data["type"]),
                id=ev_data["id"],
                prime=ev_data["prime"],
            )

            if ev_data["type"] == "custom":
                ev.commit_id = ev_data["commitId"]

            if "openingPos" in ev_data:
                ev.opening_pos = ev_data["openingPos"]
            else:
                try:
                    ev.opening_pos = self.opening_points.index(ev.prime)
                except ValueError:
                    raise ValueError(
                        f"Opening point {ev.prime} not found in opening_points"
                    )

            self.ev_map.append(ev)

    def _parse_map_sections(self, j: dict) -> None:
        """Parse map_sections_n."""
        self.map_sections_n = dict(j.get("mapSectionsN", {}))

    def _compute_proof_size(self) -> None:
        """Calculate total proof size in field elements."""
        ss = self.stark_struct
        self.proof_size = 0

        # Values and roots
        self.proof_size += len(self.airgroup_values_map) * FIELD_EXTENSION_DEGREE
        self.proof_size += len(self.air_values_map) * FIELD_EXTENSION_DEGREE
        self.proof_size += (self.n_stages + 1) * HASH_SIZE

        # Evaluations
        self.proof_size += len(self.ev_map) * FIELD_EXTENSION_DEGREE

        # Merkle proof siblings
        n_siblings = (
            math.ceil(ss.fri_fold_steps[0].domain_bits / math.log2(ss.merkle_tree_arity))
            - ss.last_level_verification
        )
        n_siblings_per_level = (ss.merkle_tree_arity - 1) * HASH_SIZE

        # Constants Merkle proofs
        self.proof_size += ss.n_queries * self.n_constants
        self.proof_size += ss.n_queries * n_siblings * n_siblings_per_level

        # Custom commits Merkle proofs
        for cc in self.custom_commits:
            self.proof_size += ss.n_queries * self.map_sections_n[cc.name + "0"]
            self.proof_size += ss.n_queries * n_siblings * n_siblings_per_level

        # Stage commitments Merkle proofs
        for i in range(self.n_stages + 1):
            self.proof_size += ss.n_queries * self.map_sections_n[f"cm{i + 1}"]
            self.proof_size += ss.n_queries * n_siblings * n_siblings_per_level

        # FRI roots
        self.proof_size += (len(ss.fri_fold_steps) - 1) * HASH_SIZE

        # Last level verification nodes
        if ss.last_level_verification > 0:
            num_nodes_level = int(ss.merkle_tree_arity**ss.last_level_verification)
            self.proof_size += (len(ss.fri_fold_steps) - 1) * num_nodes_level * HASH_SIZE
            self.proof_size += (
                (self.n_stages + 2 + len(self.custom_commits)) * num_nodes_level * HASH_SIZE
            )

        # FRI query proofs
        for i in range(1, len(ss.fri_fold_steps)):
            n_siblings = (
                math.ceil(ss.fri_fold_steps[i].domain_bits / math.log2(ss.merkle_tree_arity))
                - ss.last_level_verification
            )
            n_siblings_per_level = (ss.merkle_tree_arity - 1) * HASH_SIZE
            fold_factor = 1 << (ss.fri_fold_steps[i - 1].domain_bits - ss.fri_fold_steps[i].domain_bits)
            self.proof_size += ss.n_queries * fold_factor * FIELD_EXTENSION_DEGREE
            self.proof_size += ss.n_queries * n_siblings * n_siblings_per_level

        # Final polynomial + nonce
        final_pol_degree = 1 << ss.fri_fold_steps[-1].domain_bits
        self.proof_size += final_pol_degree * FIELD_EXTENSION_DEGREE
        self.proof_size += 1

    def _compute_map_offsets(self) -> None:
        """Compute memory layout offsets for polynomial buffers."""
        N = 1 << self.stark_struct.n_bits
        N_extended = 1 << self.stark_struct.n_bits_ext

        self.map_offsets[("const", False)] = 0
        self.map_offsets[("const", True)] = 0
        self.map_offsets[("cm1", False)] = 0

        # Custom commits offsets
        self.map_total_n_custom_commits_fixed = 0
        for cc in self.custom_commits:
            if cc.stage_widths and cc.stage_widths[0] > 0:
                self.map_offsets[(cc.name + "0", False)] = (
                    self.map_total_n_custom_commits_fixed
                )
                self.map_total_n_custom_commits_fixed += cc.stage_widths[0] * N
                self.map_offsets[(cc.name + "0", True)] = (
                    self.map_total_n_custom_commits_fixed
                )
                self.map_total_n_custom_commits_fixed += (
                    cc.stage_widths[0] * N_extended + self._merkle_tree_nodes(N_extended)
                )

        # Stage offsets (non-extended, then extended)
        self.map_total_n = 0
        for stage in range(1, self.n_stages + 2):
            section = f"cm{stage}"
            if section in self.map_sections_n:
                self.map_offsets[(section, False)] = self.map_total_n
                self.map_total_n += N * self.map_sections_n[section]

        for stage in range(1, self.n_stages + 2):
            section = f"cm{stage}"
            if section in self.map_sections_n:
                self.map_offsets[(section, True)] = self.map_total_n
                self.map_total_n += N_extended * self.map_sections_n[section]

        # Quotient and FRI polynomial offsets
        self.map_offsets[("q", True)] = self.map_total_n
        self.map_total_n += N_extended * self.q_dim

        self.map_offsets[("f", True)] = self.map_total_n
        self.map_total_n += N_extended * FIELD_EXTENSION_DEGREE

    def _merkle_tree_nodes(self, height: int) -> int:
        """Calculate total Merkle tree node count * HASH_SIZE."""
        arity = self.stark_struct.merkle_tree_arity
        num_nodes = height
        nodes_level = height

        while nodes_level > 1:
            extra_zeros = (arity - (nodes_level % arity)) % arity
            num_nodes += extra_zeros
            nodes_level = (nodes_level + arity - 1) // arity
            num_nodes += nodes_level

        return num_nodes * HASH_SIZE

    def get_offset(self, section: str, extended: bool) -> int:
        """Get buffer offset for a section."""
        return self.map_offsets[(section, extended)]

    def get_n_cols(self, section: str) -> int:
        """Get number of columns in a section."""
        return self.map_sections_n[section]

    def get_column_key(self, name: str, index: int = 0) -> tuple[str, int]:
        """Get the (name, index) key for a column.

        Args:
            name: Column name (e.g., 'a', 'im_cluster')
            index: Index for array columns (default 0)

        Returns:
            Tuple (name, index) for use as dict key
        """
        return (name, index)

    def has_challenge(self, name: str) -> bool:
        """Check if a challenge with given name exists."""
        return any(cm.name == name for cm in self.challenges_map)

    def get_challenge_index(self, name: str) -> int:
        """Get the index of a challenge by name."""
        for i, cm in enumerate(self.challenges_map):
            if cm.name == name:
                return i
        raise KeyError(f"Challenge '{name}' not found")

    def build_column_name_map(self) -> dict[str, list[int]]:
        """Build mapping from column names to their pols_map_id indices.

        Returns:
            Dict mapping name -> list of pols_map_id values
            e.g., {'a': [0], 'im_cluster': [16, 17, 18, 19, 20, 21]}
        """
        name_map: dict[str, list[int]] = {}
        for cm in self.cm_pols_map:
            if cm.name not in name_map:
                name_map[cm.name] = []
            name_map[cm.name].append(cm.pols_map_id)
        return name_map
