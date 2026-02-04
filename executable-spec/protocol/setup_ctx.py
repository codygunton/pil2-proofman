"""Deprecated: Use air_config.py instead.

This module re-exports from air_config for backward compatibility.
All new code should import from protocol.air_config directly.

Example migration:
    # Before (deprecated):
    from protocol.setup_ctx import SetupCtx, ProverHelpers

    # After (preferred):
    from protocol.air_config import AirConfig, ProverHelpers
    # Or use the SetupCtx alias if you prefer minimal changes:
    from protocol.air_config import SetupCtx, ProverHelpers
"""

import warnings

# Re-export all public symbols for backward compatibility
from protocol.air_config import (  # noqa: E402
    FIELD_EXTENSION_DEGREE,
    AirConfig,
    ProverHelpers,
    SetupCtx,
)

warnings.warn(
    "setup_ctx module is deprecated, use air_config instead",
    DeprecationWarning,
    stacklevel=2
)

__all__ = ['AirConfig', 'SetupCtx', 'ProverHelpers', 'FIELD_EXTENSION_DEGREE']
