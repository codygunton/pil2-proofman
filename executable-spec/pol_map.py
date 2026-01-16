"""
Polynomial mapping data structures.

This module provides faithful Python translations of the C++ mapping structures
from pil2-stark/src/starkpil/stark_info.hpp.

These structures describe how polynomials are organized in memory and how they
map to different stages of the STARK proof system.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


@dataclass
class PolMap:
    """Maps a polynomial to its location in the proof system.

    Corresponds to C++ class PolMap in stark_info.hpp (lines 93-106).

    Attributes:
        stage: Proof stage (0=constants, 1=trace, 2=intermediate, 3=quotient)
        name: Polynomial name
        dim: Field dimension (1 for Goldilocks, 3 for Goldilocks3)
        stagePos: Position within stage columns
        stageId: Identifier within stage
        imPol: True if this is an intermediate polynomial
        lengths: Optional array indices for multi-dimensional polynomials
        commitId: Commitment identifier (for custom commits)
        expId: Expression ID (if polynomial is computed from expression)
        polsMapId: Global polynomial map identifier
    """
    stage: int
    name: str
    dim: int
    stagePos: int
    stageId: int
    imPol: bool = False
    lengths: List[int] = field(default_factory=list)
    commitId: int = 0
    expId: int = 0
    polsMapId: int = 0


@dataclass
class EvMap:
    """Maps an evaluation point to its polynomial source.

    Corresponds to C++ class EvMap in stark_info.hpp (lines 108-135).

    Attributes:
        type: Source type (cm=committed, const_=constant, custom=custom commit)
        id: Polynomial ID within source type
        prime: Opening point offset (index into openingPoints array)
        commitId: Commitment ID (only for custom type)
        openingPos: Position in opening points array
    """

    class Type(Enum):
        """Evaluation source type.

        Corresponds to C++ enum eType in EvMap (lines 111-116).
        """
        cm = 0          # Committed polynomial
        const_ = 1      # Constant polynomial
        custom = 2      # Custom commit

    type: Type
    id: int
    prime: int
    commitId: int = 0
    openingPos: int = 0

    @staticmethod
    def type_from_string(s: str) -> 'EvMap.Type':
        """Convert string to Type enum.

        Corresponds to C++ EvMap::setType() (lines 124-134).

        Args:
            s: Type string ("cm", "const", or "custom")

        Returns:
            Corresponding Type enum value

        Raises:
            ValueError: If string is not a valid type
        """
        if s == "cm":
            return EvMap.Type.cm
        elif s == "const":
            return EvMap.Type.const_
        elif s == "custom":
            return EvMap.Type.custom
        else:
            raise ValueError(f"EvMap: invalid type string: {s}")


@dataclass
class ChallengeMap:
    """Maps a challenge to its derivation stage.

    In C++, challenges use the PolMap structure but only a subset of fields.
    This dedicated class improves clarity for the executable spec.

    Attributes:
        name: Challenge name (e.g., "std_alpha", "std_gamma")
        stage: Stage at which this challenge is derived
        dim: Field dimension (1 for Goldilocks, 3 for Goldilocks3)
        stageId: Identifier within stage challenges
    """
    name: str
    stage: int
    dim: int
    stageId: int


@dataclass
class CustomCommits:
    """Custom commitment configuration.

    Corresponds to C++ class CustomCommits in stark_info.hpp (lines 52-58).

    Attributes:
        name: Custom commit name
        stageWidths: Number of columns at each stage
        publicValues: Indices of public values used
    """
    name: str
    stageWidths: List[int] = field(default_factory=list)
    publicValues: List[int] = field(default_factory=list)


@dataclass
class Boundary:
    """Constraint boundary specification.

    Corresponds to C++ class Boundary in stark_info.hpp (lines 60-66).

    Attributes:
        name: Boundary name (e.g., "everyRow", "everyFrame")
        offsetMin: Minimum row offset (only for "everyFrame")
        offsetMax: Maximum row offset (only for "everyFrame")
    """
    name: str
    offsetMin: int = 0
    offsetMax: int = 0
