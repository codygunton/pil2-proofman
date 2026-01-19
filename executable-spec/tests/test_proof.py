"""
Tests for STARK proof JSON loading and serialization.

Validates that Python can correctly load and serialize proofs
in C++ format for cross-validation.
"""

import json
import pytest
from pathlib import Path

from protocol.proof import (
    STARKProof,
    proof_to_json,
    load_proof_from_json,
    validate_proof_structure,
)
from protocol.stark_info import StarkInfo


class TestProofSerialization:
    """Test proof JSON serialization and deserialization."""

    def test_proof_to_json_minimal(self):
        """Test JSON serialization of minimal proof."""
        proof = STARKProof(
            roots=[[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12]],
            evals=[[100, 200, 300]],
            nonce=42
        )

        j = proof_to_json(proof, n_stages=3)

        assert "root1" in j
        assert "root2" in j
        assert "root3" in j
        assert "evals" in j
        assert "nonce" in j
        assert j["nonce"] == "42"
        assert len(j["evals"]) == 1
        assert j["evals"][0] == ["100", "200", "300"]

    def test_proof_to_json_with_air_values(self):
        """Test JSON serialization with AIR values."""
        proof = STARKProof(
            roots=[[1, 2, 3, 4]],
            evals=[],
            airgroup_values=[[10, 20, 30], [40, 50, 60]],
            air_values=[[100, 200, 300]],
            nonce=0
        )

        j = proof_to_json(proof, n_stages=1)

        assert "airgroupvalues" in j
        assert "airvalues" in j
        assert len(j["airgroupvalues"]) == 2
        assert len(j["airvalues"]) == 1
        assert j["airgroupvalues"][0] == ["10", "20", "30"]

    def test_proof_to_json_with_final_pol(self):
        """Test JSON serialization with final polynomial."""
        proof = STARKProof(
            roots=[[1, 2, 3, 4]],
            evals=[],
            nonce=0
        )
        proof.fri.pol = [[1, 2, 3], [4, 5, 6], [7, 8, 9]]

        j = proof_to_json(proof, n_stages=1)

        assert "finalPol" in j
        assert len(j["finalPol"]) == 3
        assert j["finalPol"][0] == ["1", "2", "3"]
        assert j["finalPol"][2] == ["7", "8", "9"]

    def test_json_round_trip(self):
        """Test that proof survives JSON round-trip."""
        import tempfile

        proof = STARKProof(
            roots=[[1, 2, 3, 4], [5, 6, 7, 8]],
            evals=[[100, 200, 300], [400, 500, 600]],
            air_values=[[10, 20, 30]],
            nonce=42
        )
        proof.fri.pol = [[1, 2, 3], [4, 5, 6]]

        # Serialize to JSON
        j = proof_to_json(proof, n_stages=2)

        # Write to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(j, f)
            temp_path = f.name

        try:
            # Load back
            loaded_proof, metadata = load_proof_from_json(temp_path)

            # Verify structure
            assert len(loaded_proof.roots) == 2
            assert len(loaded_proof.evals) == 2
            assert len(loaded_proof.air_values) == 1
            assert loaded_proof.nonce == 42
            assert len(loaded_proof.fri.pol) == 2

            # Verify values
            assert loaded_proof.roots[0] == [1, 2, 3, 4]
            assert loaded_proof.evals[1] == [400, 500, 600]
            assert loaded_proof.air_values[0] == [10, 20, 30]
            assert loaded_proof.fri.pol[1] == [4, 5, 6]

        finally:
            Path(temp_path).unlink()


class TestProofLoading:
    """Test loading proofs from actual test data files."""

    @pytest.fixture
    def test_data_dir(self):
        """Get test data directory."""
        return Path(__file__).parent / "test-data"

    def test_load_simple_left_proof_structure(self, test_data_dir):
        """Test loading SimpleLeft proof has correct structure."""
        proof_path = test_data_dir / "simple-left.json"

        if not proof_path.exists():
            pytest.fail("Test data file not generated yet")

        # Load raw JSON to check structure
        with open(proof_path) as f:
            data = json.load(f)

        # Test data files have metadata section
        assert "metadata" in data
        metadata = data["metadata"]
        assert metadata["air_name"] == "SimpleLeft"

        # Test data files have expected section with proof results
        assert "expected" in data
        expected = data["expected"]

        # Check expected proof components
        assert "final_pol" in expected
        assert "nonce" in expected
        assert expected["nonce"] > 0  # Should have proof-of-work

        # The test data format doesn't match proof JSON format exactly,
        # so we just verify it has the expected structure
        assert isinstance(expected["final_pol"], list)

    def test_load_lookup_proof_structure(self, test_data_dir):
        """Test loading Lookup2_12 proof has FRI folding."""
        proof_path = test_data_dir / "lookup2-12.json"

        if not proof_path.exists():
            pytest.fail("Test data file not generated yet")

        # Load raw JSON to check structure
        with open(proof_path) as f:
            data = json.load(f)

        # Check metadata
        assert "metadata" in data
        metadata = data["metadata"]
        assert metadata["air_name"] == "Lookup2_12"

        # Lookup2_12 should have FRI folding steps
        assert "num_fri_steps" in metadata
        # Lookup has larger domain, so may have more FRI steps
        assert metadata["num_fri_steps"] >= 1

    def test_load_permutation_proof_structure(self, test_data_dir):
        """Test loading Permutation1_6 proof structure."""
        proof_path = test_data_dir / "permutation1-6.json"

        if not proof_path.exists():
            pytest.fail("Test data file not generated yet")

        # Load raw JSON to check structure
        with open(proof_path) as f:
            data = json.load(f)

        # Check metadata
        assert "metadata" in data
        metadata = data["metadata"]
        assert metadata["air_name"] == "Permutation1_6"

        # Check expected section exists
        assert "expected" in data
        assert "nonce" in data["expected"]
        assert data["expected"]["nonce"] > 0

    def test_load_nonexistent_file(self):
        """Test loading non-existent file raises error."""
        with pytest.raises(FileNotFoundError):
            load_proof_from_json("/nonexistent/path.json")

    def test_load_invalid_json(self):
        """Test loading invalid JSON raises error."""
        import tempfile

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("{invalid json")
            temp_path = f.name

        try:
            with pytest.raises(json.JSONDecodeError):
                load_proof_from_json(temp_path)
        finally:
            Path(temp_path).unlink()

    def test_load_cpp_proof_format(self):
        """Test loading proof in C++ JSON format (from pointer2json)."""
        import tempfile

        # Create a proof in C++ format (from pointer2json in proof2zkinStark.cpp)
        cpp_proof = {
            "root1": ["1", "2", "3", "4"],
            "root2": ["5", "6", "7", "8"],
            "root3": ["9", "10", "11", "12"],
            "evals": [
                ["100", "200", "300"],
                ["400", "500", "600"]
            ],
            "airgroupvalues": [
                ["10", "20", "30"]
            ],
            "airvalues": [
                ["40", "50", "60"]
            ],
            "finalPol": [
                ["1000", "2000", "3000"],
                ["4000", "5000", "6000"]
            ],
            "nonce": "42"
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(cpp_proof, f)
            temp_path = f.name

        try:
            proof, metadata = load_proof_from_json(temp_path)

            # Verify structure
            assert len(proof.roots) == 3
            assert len(proof.evals) == 2
            assert len(proof.airgroup_values) == 1
            assert len(proof.air_values) == 1
            assert len(proof.fri.pol) == 2
            assert proof.nonce == 42

            # Verify values
            assert proof.roots[0] == [1, 2, 3, 4]
            assert proof.roots[2] == [9, 10, 11, 12]
            assert proof.evals[0] == [100, 200, 300]
            assert proof.airgroup_values[0] == [10, 20, 30]
            assert proof.air_values[0] == [40, 50, 60]
            assert proof.fri.pol[0] == [1000, 2000, 3000]
            assert proof.fri.pol[1] == [4000, 5000, 6000]

        finally:
            Path(temp_path).unlink()


class TestProofValidation:
    """Test proof structure validation."""

    @pytest.fixture
    def simple_stark_info(self):
        """Create a simple StarkInfo for testing."""
        info = StarkInfo()
        info.nStages = 2
        info.starkStruct.steps = [type('obj', (object,), {'nBits': 4})()]
        info.evMap = [None, None, None]  # 3 evaluations
        info.airgroupValuesMap = []
        info.airValuesMap = []
        return info

    def test_validate_correct_proof(self, simple_stark_info):
        """Test validation passes for correct proof."""
        proof = STARKProof(
            roots=[[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12]],  # 3 stages
            evals=[[1, 2, 3], [4, 5, 6], [7, 8, 9]],  # 3 evals
            nonce=42
        )
        proof.fri.pol = [[i, i+1, i+2] for i in range(16)]  # Degree 16

        errors = validate_proof_structure(proof, simple_stark_info)
        assert errors == []

    def test_validate_wrong_stage_count(self, simple_stark_info):
        """Test validation catches wrong stage count."""
        proof = STARKProof(
            roots=[[1, 2, 3, 4]],  # Only 1 root, expected 3
            evals=[[1, 2, 3], [4, 5, 6], [7, 8, 9]],
            nonce=42
        )

        errors = validate_proof_structure(proof, simple_stark_info)
        assert len(errors) > 0
        assert any("stage roots" in err for err in errors)

    def test_validate_wrong_eval_count(self, simple_stark_info):
        """Test validation catches wrong evaluation count."""
        proof = STARKProof(
            roots=[[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12]],
            evals=[[1, 2, 3]],  # Only 1 eval, expected 3
            nonce=42
        )

        errors = validate_proof_structure(proof, simple_stark_info)
        assert len(errors) > 0
        assert any("evaluations" in err for err in errors)

    def test_validate_wrong_eval_dimension(self, simple_stark_info):
        """Test validation catches wrong evaluation dimension."""
        proof = STARKProof(
            roots=[[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12]],
            evals=[[1, 2], [4, 5], [7, 8]],  # Dim 2, expected 3
            nonce=42
        )

        errors = validate_proof_structure(proof, simple_stark_info)
        assert len(errors) > 0
        assert any("dimension" in err for err in errors)

    def test_validate_wrong_final_pol_degree(self, simple_stark_info):
        """Test validation catches wrong final polynomial degree."""
        proof = STARKProof(
            roots=[[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12]],
            evals=[[1, 2, 3], [4, 5, 6], [7, 8, 9]],
            nonce=42
        )
        # Wrong degree: 8 instead of 16
        proof.fri.pol = [[i, i+1, i+2] for i in range(8)]

        errors = validate_proof_structure(proof, simple_stark_info)
        assert len(errors) > 0
        assert any("degree" in err for err in errors)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
