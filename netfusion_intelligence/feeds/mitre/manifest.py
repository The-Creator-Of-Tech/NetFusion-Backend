"""
MITRE ATT&CK Enterprise Intelligence Feed Manifest definition.
"""

from typing import List
from netfusion_intelligence.models.manifest import FeedManifest


def get_mitre_manifest() -> FeedManifest:
    """Returns official FeedManifest for MITRE ATT&CK Enterprise STIX 2.1 Feed."""
    return FeedManifest(
        name="MITRE ATT&CK Enterprise Intelligence",
        description="Official MITRE ATT&CK Enterprise STIX 2.1 dataset threat intelligence feed.",
        vendor="MITRE / NetFusion",
        version="2.1.0",
        feed_type="stix_2.1_mitre_attack",
        supports_incremental_updates=True,
        supports_full_sync=True,
        supports_relationship_building=True,
        supports_checksum_verification=True,
        supports_signature_verification=False,
        supports_rollback=True,
        supports_delta_updates=True,
        entity_types=[
            "attack-pattern",
            "x-mitre-tactic",
            "intrusion-set",
            "malware",
            "tool",
            "campaign",
            "course-of-action",
            "x-mitre-data-source",
            "x-mitre-data-component",
            "x-mitre-asset",
        ],
        relationship_types=[
            "uses",
            "mitigates",
            "attributed-to",
            "detects",
            "subtechnique-of",
            "revoked-by",
        ],
        default_schedule="0 0 * * *",  # Daily sync
        recommended_retry_count=3,
        timeout=600.0,
        validation_rules=[
            "STIX_2.1_SCHEMA_VALIDATION",
            "ATTACK_ID_PRESENT",
            "UNIQUE_ATTACK_ID",
            "RELATIONSHIP_REFERENTIAL_INTEGRITY",
            "NO_UNKNOWN_STIX_TYPES",
        ],
        dependencies=[],
    )
