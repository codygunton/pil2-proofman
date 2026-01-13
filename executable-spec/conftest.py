"""Pytest configuration for executable-spec tests."""

import sys
from pathlib import Path

# Add the executable-spec directory to the path so absolute imports work
spec_dir = Path(__file__).parent
if str(spec_dir) not in sys.path:
    sys.path.insert(0, str(spec_dir))

# Also add parent directory for package imports
parent_dir = spec_dir.parent
if str(parent_dir) not in sys.path:
    sys.path.insert(0, str(parent_dir))
