"""
Backward-compatibility shim.

All identity logic now lives in identity.identity_engine.
This module re-exports everything so existing imports continue to work
without modification (packet_parser, main, etc.).
"""

from identity.identity_engine import (  # noqa: F401
    normalize_identity_value,
    infer_reverse_dns,
    build_identity_candidate,
    merge_identity_evidence,
    choose_best_identity_value,
    resolve_device_identity,
    select_best_device_name_from_packets,
    select_best_hostname_from_packets,
)
