"""
Shared package root.
Exports network utilities and wire protocol abstractions.
"""

from .network_utils import get_primary_local_ip, get_all_local_ips
from .protocol import (
    SecureMessageEnvelope,
    compute_aad,
    b64encode_str,
    b64decode_bytes,
    PROTOCOL_VERSION,
    MAX_TIMESTAMP_DRIFT_SECONDS
)

__all__ = [
    "get_primary_local_ip",
    "get_all_local_ips",
    "SecureMessageEnvelope",
    "compute_aad",
    "b64encode_str",
    "b64decode_bytes",
    "PROTOCOL_VERSION",
    "MAX_TIMESTAMP_DRIFT_SECONDS"
]
