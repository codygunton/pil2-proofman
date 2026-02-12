"""End-to-end test for VADCOP final proof verification.

Tests that the Python verifier correctly verifies the aggregated VADCOP final
proof — the outermost STARK proof that binds all per-AIR recursive proofs
into a single cryptographic statement.

The VadcopFinal proof differs from per-AIR proofs in two ways:
1. Transcript initialization: seeds with verkey + hashed publics + root1
   (instead of global_challenge)
2. Binary format: prepends [n_publics, publics...] header before standard body

Requires:
    - VadcopFinal setup artifacts in provingKey/zisk/vadcop_final/
    - Binary proof fixture at tests/test-data/zisk/vadcop_final.proof.bin
"""

import json
from pathlib import Path

import pytest

from protocol.air_config import AirConfig
from protocol.proof import from_vadcop_final_bytes
from protocol.verifier import stark_verify
from tests.conftest import ZISK_PROVING_KEY

TEST_DATA_DIR = Path(__file__).parent / "test-data" / "zisk"

VADCOP_FINAL_DIR = ZISK_PROVING_KEY / "zisk" / "vadcop_final"
STARKINFO_PATH = VADCOP_FINAL_DIR / "vadcop_final.starkinfo.json"
VERKEY_PATH = VADCOP_FINAL_DIR / "vadcop_final.verkey.json"
PROOF_BIN_PATH = TEST_DATA_DIR / "vadcop_final.proof.bin"

# Skip entire module if setup artifacts or proof fixture are missing
pytestmark = pytest.mark.skipif(
    not STARKINFO_PATH.exists() or not VERKEY_PATH.exists() or not PROOF_BIN_PATH.exists(),
    reason=(
        f"VadcopFinal artifacts missing: "
        f"starkinfo={STARKINFO_PATH.exists()}, "
        f"verkey={VERKEY_PATH.exists()}, "
        f"proof={PROOF_BIN_PATH.exists()}"
    ),
)


def _load_verkey() -> list[int]:
    """Load VadcopFinal verification key (Merkle root of const tree)."""
    with open(VERKEY_PATH) as f:
        return json.load(f)


class TestZiskVadcopFinalE2E:
    """End-to-end VADCOP final verifier test."""

    def test_verify_vadcop_final_proof(self) -> None:
        """Test that stark_verify returns True for a valid VadcopFinal proof."""
        air_config = AirConfig.from_starkinfo(str(STARKINFO_PATH))
        stark_info = air_config.stark_info

        with open(PROOF_BIN_PATH, "rb") as f:
            proof_bytes = f.read()

        proof, publics = from_vadcop_final_bytes(proof_bytes, stark_info)
        verkey = _load_verkey()

        result = stark_verify(
            proof=proof,
            air_config=air_config,
            verkey=verkey,
            global_challenge=None,  # VadcopFinal: transcript seeds with verkey
            publics=publics,
        )

        assert result is True, "Valid VadcopFinal proof should verify"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
