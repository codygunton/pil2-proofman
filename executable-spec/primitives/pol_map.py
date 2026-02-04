"""
Polynomial mapping data structures.

This module provides faithful Python translations of the C++ mapping structures
from pil2-stark/src/starkpil/stark_info.hpp.

These structures describe how polynomials are organized in memory and how they
map to different stages of the STARK proof system.
"""

from dataclasses import dataclass, field
from enum import Enum


# --- Field Type Enum ---
class FieldType(Enum):
    """Field element type for type-safe field discrimination."""
    FF = 1   # Base field (Goldilocks)
    FF3 = 3  # Cubic extension (Goldilocks3)


# C++: pil2-stark/src/starkpil/stark_info.hpp::PolMap (lines 93-106)
@dataclass
class PolMap:
    """Maps a polynomial to its location in the proof system."""
    stage: int
    name: str
    field_type: FieldType
    stagePos: int
    stageId: int
    imPol: bool = False
    lengths: list[int] = field(default_factory=list)
    commitId: int = 0
    expId: int = 0
    polsMapId: int = 0

    @property
    def dim(self) -> int:
        """Backwards compatibility: returns 1 for FF, 3 for FF3."""
        return self.field_type.value


# C++: pil2-stark/src/starkpil/stark_info.hpp::EvMap (lines 108-135)
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

    # C++: stark_info.hpp::EvMap::eType (lines 109-114)
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

    # C++: stark_info.hpp::EvMap::setType (lines 124-134)
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


# C++: No direct equivalent (challenge info embedded in StarkInfo)
@dataclass
class ChallengeMap:
    """Maps a challenge to its derivation stage."""
    name: str
    stage: int
    field_type: FieldType
    stageId: int

    @property
    def dim(self) -> int:
        """Backwards compatibility: returns 1 for FF, 3 for FF3."""
        return self.field_type.value


# C++: pil2-stark/src/starkpil/stark_info.hpp::CustomCommits (lines 52-58)
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
    stageWidths: list[int] = field(default_factory=list)
    publicValues: list[int] = field(default_factory=list)


# C++: pil2-stark/src/starkpil/stark_info.hpp::Boundary (lines 60-66)
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
