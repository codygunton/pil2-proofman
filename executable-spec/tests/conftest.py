"""
Pytest configuration for executable-spec tests.

C++ Reference: NO CORRESPONDING FUNCTION
               (Python test infrastructure)
"""

import sys
from pathlib import Path

# Add the executable-spec directory to the path so absolute imports work
# (tests/ is inside executable-spec/, so parent is executable-spec/)
exec_spec_dir = Path(__file__).parent.parent
if str(exec_spec_dir) not in sys.path:
    sys.path.insert(0, str(exec_spec_dir))

# Zisk v0.15.0 proving key — always available on this machine.
ZISK_PROVING_KEY = Path("/home/cody/zisk-for-spec/provingKey")
