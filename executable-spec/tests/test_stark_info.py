"""
Tests for STARK configuration parser.

Validates that stark_info.py correctly parses starkinfo.json files
from the test AIRs and produces the expected data structures.
"""

from pathlib import Path

import pytest

from primitives.pol_map import EvMap
from protocol.stark_info import FIELD_EXTENSION_DEGREE, StarkInfo

# Test data paths
SIMPLE_STARKINFO = Path(__file__).parent.parent.parent / \
    "pil2-components/test/simple/build/provingKey/build/Simple/airs/SimpleLeft/air/SimpleLeft.starkinfo.json"


class TestStarkInfoSimple:
    """Test StarkInfo parsing with SimpleLeft AIR."""

    @pytest.fixture
    def stark_info(self) -> StarkInfo:
        """Load SimpleLeft starkinfo."""
        if not SIMPLE_STARKINFO.exists():
            pytest.fail(f"SimpleLeft starkinfo not found at {SIMPLE_STARKINFO}")
        return StarkInfo.from_json(str(SIMPLE_STARKINFO))

    def test_loads_successfully(self, stark_info: StarkInfo) -> None:
        """Verify starkinfo loads without errors."""
        assert stark_info is not None

    def test_stark_struct_basic_params(self, stark_info: StarkInfo) -> None:
        """Verify basic STARK parameters."""
        ss = stark_info.starkStruct
        assert ss.nBits == 3  # 8 rows
        assert ss.nBitsExt == 4  # 16 extended
        assert ss.nQueries == 228
        assert ss.verificationHashType == "GL"
        assert ss.merkleTreeArity == 4
        assert ss.transcriptArity == 4
        assert ss.merkleTreeCustom is True
        assert ss.lastLevelVerification == 2
        assert ss.powBits == 16
        assert ss.hashCommits is True

    def test_fri_round_log_sizes(self, stark_info: StarkInfo) -> None:
        """Verify FRI folding steps."""
        assert len(stark_info.starkStruct.friFoldSteps) == 1
        assert stark_info.starkStruct.friFoldSteps[0].domainBits == 4

    def test_basic_counts(self, stark_info: StarkInfo) -> None:
        """Verify polynomial counts."""
        assert stark_info.nPublics == 0
        assert stark_info.nConstants == 1
        assert stark_info.nStages == 2

    def test_quotient_params(self, stark_info: StarkInfo) -> None:
        """Verify quotient polynomial parameters."""
        assert stark_info.qDeg == 2
        assert stark_info.qDim == 3

    def test_expression_ids(self, stark_info: StarkInfo) -> None:
        """Verify expression IDs."""
        assert stark_info.friExpId == 313
        assert stark_info.cExpId == 312

    def test_opening_points(self, stark_info: StarkInfo) -> None:
        """Verify opening points."""
        assert stark_info.openingPoints == [-1, 0, 1]

    def test_boundaries(self, stark_info: StarkInfo) -> None:
        """Verify constraint boundaries."""
        assert len(stark_info.boundaries) == 1
        assert stark_info.boundaries[0].name == "everyRow"

    def test_challenges_map(self, stark_info: StarkInfo) -> None:
        """Verify challenge derivation map."""
        assert len(stark_info.challengesMap) == 6

        # Check first few challenges
        ch0 = stark_info.challengesMap[0]
        assert ch0.name == "std_alpha"
        assert ch0.stage == 2
        assert ch0.dim == 3
        assert ch0.stageId == 0

        ch1 = stark_info.challengesMap[1]
        assert ch1.name == "std_gamma"
        assert ch1.stage == 2
        assert ch1.dim == 3
        assert ch1.stageId == 1

    def test_cm_pols_map(self, stark_info: StarkInfo) -> None:
        """Verify committed polynomials map."""
        # SimpleLeft has 15 stage 1, 7 stage 2, and 2 quotient polys
        stage1_pols = [p for p in stark_info.cmPolsMap if p.stage == 1]
        stage2_pols = [p for p in stark_info.cmPolsMap if p.stage == 2]
        stage3_pols = [p for p in stark_info.cmPolsMap if p.stage == 3]

        assert len(stage1_pols) == 15
        assert len(stage2_pols) == 7
        assert len(stage3_pols) == 2

        # Check first stage 1 polynomial
        pol0 = stark_info.cmPolsMap[0]
        assert pol0.name == "a"
        assert pol0.stage == 1
        assert pol0.dim == 1
        assert pol0.stageId == 0
        assert pol0.stagePos == 0
        assert pol0.polsMapId == 0
        assert pol0.imPol is False

        # Check first stage 2 polynomial (gsum)
        gsum = next(p for p in stark_info.cmPolsMap if p.name == "gsum")
        assert gsum.stage == 2
        assert gsum.dim == 3
        assert gsum.stageId == 0
        assert gsum.stagePos == 0

    def test_const_pols_map(self, stark_info: StarkInfo) -> None:
        """Verify constant polynomials map."""
        assert len(stark_info.constPolsMap) == 1
        const_pol = stark_info.constPolsMap[0]
        assert const_pol.name == "__L1__"
        assert const_pol.stage == 0
        assert const_pol.dim == 1

    def test_ev_map(self, stark_info: StarkInfo) -> None:
        """Verify evaluation map."""
        # SimpleLeft has 27 evaluations
        assert len(stark_info.evMap) == 27

        # Check first evaluation (gsum at prime=-1)
        ev0 = stark_info.evMap[0]
        assert ev0.type == EvMap.Type.cm
        assert ev0.id == 15
        assert ev0.prime == -1
        assert ev0.openingPos == 0

        # Check a const evaluation
        const_ev = next(ev for ev in stark_info.evMap if ev.type == EvMap.Type.const_)
        assert const_ev.id == 0
        assert const_ev.prime in [0, 1]

    def test_airgroup_values(self, stark_info: StarkInfo) -> None:
        """Verify airgroup values."""
        assert len(stark_info.airgroupValuesMap) == 1
        assert stark_info.airgroupValuesMap[0].name == "Simple.gsum_result"
        assert stark_info.airgroupValuesMap[0].stage == 2
        assert stark_info.airgroupValuesSize == FIELD_EXTENSION_DEGREE

    def test_map_sections(self, stark_info: StarkInfo) -> None:
        """Verify section column counts."""
        assert stark_info.mapSectionsN["const"] == 1
        assert stark_info.mapSectionsN["cm1"] == 15
        assert stark_info.mapSectionsN["cm2"] == 21
        assert stark_info.mapSectionsN["cm3"] == 6

    def test_get_n_cols(self, stark_info: StarkInfo) -> None:
        """Verify get_n_cols accessor."""
        assert stark_info.get_n_cols("cm1") == 15
        assert stark_info.get_n_cols("cm2") == 21
        assert stark_info.get_n_cols("const") == 1

    def test_get_offset(self, stark_info: StarkInfo) -> None:
        """Verify get_offset accessor."""
        # Check that offsets are set
        offset_cm1 = stark_info.get_offset("cm1", False)
        assert isinstance(offset_cm1, int)
        assert offset_cm1 >= 0

        # Extended domain offsets should also be set
        offset_q = stark_info.get_offset("q", True)
        assert isinstance(offset_q, int)
        assert offset_q >= 0

    def test_get_column_key_by_name(self, stark_info: StarkInfo) -> None:
        """Test resolving column name to (name, index) key."""
        # 'a' is the first committed polynomial
        key = stark_info.get_column_key('a')
        assert key == ('a', 0)

        # 'im_cluster' has multiple instances
        key = stark_info.get_column_key('im_cluster', index=3)
        assert key == ('im_cluster', 3)

    def test_get_challenge_by_name(self, stark_info: StarkInfo) -> None:
        """Test resolving challenge name."""
        # Should find std_alpha in challengesMap
        assert stark_info.has_challenge('std_alpha')
        assert stark_info.has_challenge('std_gamma')
        assert not stark_info.has_challenge('nonexistent')

    def test_build_column_name_map(self, stark_info: StarkInfo) -> None:
        """Test building complete name -> indices mapping."""
        name_map = stark_info.build_column_name_map()

        # Single columns
        assert 'a' in name_map
        assert name_map['a'] == [0]  # Just index 0

        # Array columns (im_cluster appears multiple times)
        assert 'im_cluster' in name_map
        assert len(name_map['im_cluster']) == 6  # 6 im_cluster columns


class TestStarkInfoLookup:
    """Test StarkInfo parsing with Lookup AIR (if available)."""

    @pytest.fixture
    def lookup_starkinfo_path(self) -> str:
        """Get path to Lookup2_12 starkinfo."""
        path = Path(__file__).parent.parent.parent / \
            "pil2-components/test/lookup/build/provingKey/lookup/Lookup/airs/Lookup2_12/air/Lookup2_12.starkinfo.json"
        if not path.exists():
            pytest.fail(f"Lookup starkinfo not found at {path}")
        return str(path)

    def test_lookup_loads(self, lookup_starkinfo_path: str) -> None:
        """Verify Lookup2_12 loads successfully."""
        info = StarkInfo.from_json(lookup_starkinfo_path)
        assert info is not None
        assert info.starkStruct.nBits == 12  # 4096 rows


class TestStarkInfoPermutation:
    """Test StarkInfo parsing with Permutation AIR (if available)."""

    @pytest.fixture
    def permutation_starkinfo_path(self) -> str:
        """Get path to Permutation1_6 starkinfo."""
        path = Path(__file__).parent.parent.parent / \
            "pil2-components/test/permutation/build/provingKey/permutation/Permutation/airs/Permutation1_6/air/Permutation1_6.starkinfo.json"
        if not path.exists():
            pytest.fail(f"Permutation starkinfo not found at {path}")
        return str(path)

    def test_permutation_loads(self, permutation_starkinfo_path: str) -> None:
        """Verify Permutation1_6 loads successfully."""
        info = StarkInfo.from_json(permutation_starkinfo_path)
        assert info is not None
        assert info.starkStruct.nBits == 6  # 64 rows


class TestEvMapTypeConversion:
    """Test EvMap type string conversion."""

    def test_cm_type(self) -> None:
        """Test 'cm' string conversion."""
        assert EvMap.type_from_string("cm") == EvMap.Type.cm

    def test_const_type(self) -> None:
        """Test 'const' string conversion."""
        assert EvMap.type_from_string("const") == EvMap.Type.const_

    def test_custom_type(self) -> None:
        """Test 'custom' string conversion."""
        assert EvMap.type_from_string("custom") == EvMap.Type.custom

    def test_invalid_type(self) -> None:
        """Test invalid type string raises error."""
        with pytest.raises(ValueError, match="invalid type"):
            EvMap.type_from_string("invalid")
