"""GlobalInfo parser for pilout.globalInfo.json configuration."""

import json
from dataclasses import dataclass, field
from typing import Optional, List, Any


@dataclass
class GlobalInfo:
    """Global configuration from pilout.globalInfo.json.

    Matches C++ GlobalInfo struct from common/src/global_info.rs

    Fields:
        name: Build name (e.g., "build")
        curve: Curve type ("None", "BN128", "BLS12-381")
        lattice_size: Size for lattice expansion (368 for CurveType::None)
        n_publics: Number of public inputs
        num_challenges: Challenge counts per stage
        transcript_arity: Poseidon2 transcript arity (typically 4)
    """
    name: str
    curve: str  # "None", "BN128", "BLS12-381", etc.
    lattice_size: int  # Default 368 for CurveType::None
    n_publics: int
    num_challenges: List[int]
    transcript_arity: int

    # Optional fields (may be empty for simple AIRs)
    air_groups: Optional[List[str]] = None
    airs: Optional[List[List[Any]]] = None
    agg_types: Optional[List[List[Any]]] = None
    publics_map: Optional[List[Any]] = field(default_factory=list)
    proof_values_map: Optional[List[Any]] = field(default_factory=list)

    @classmethod
    def from_json(cls, path: str) -> 'GlobalInfo':
        """Load from pilout.globalInfo.json file.

        Example JSON structure:
        {
          "name": "build",
          "curve": "None",
          "latticeSize": 368,
          "nPublics": 0,
          "numChallenges": [0, 2],
          "transcriptArity": 4,
          "air_groups": ["Simple"],
          "publicsMap": [],
          "proofValuesMap": []
        }
        """
        with open(path, 'r') as f:
            data = json.load(f)

        return cls(
            name=data.get('name', ''),
            curve=data.get('curve', 'None'),
            lattice_size=data.get('latticeSize', 368),
            n_publics=data.get('nPublics', 0),
            num_challenges=data.get('numChallenges', []),
            transcript_arity=data.get('transcriptArity', 4),
            air_groups=data.get('air_groups'),
            airs=data.get('airs'),
            agg_types=data.get('aggTypes'),
            publics_map=data.get('publicsMap', []),
            proof_values_map=data.get('proofValuesMap', []),
        )

    @classmethod
    def default(cls) -> 'GlobalInfo':
        """Create default GlobalInfo for tests without globalInfo.json.

        Uses latticeSize=368 which is standard for CurveType::None.
        """
        return cls(
            name='default',
            curve='None',
            lattice_size=368,
            n_publics=0,
            num_challenges=[],
            transcript_arity=4,
        )
