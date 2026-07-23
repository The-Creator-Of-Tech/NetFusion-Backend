"""
CWE Enterprise Intelligence Feed Manifest definition.
"""

from netfusion_intelligence.models.manifest import FeedManifest


def get_cwe_manifest() -> FeedManifest:
    """Returns official FeedManifest for MITRE CWE Enterprise Intelligence Feed."""
    return FeedManifest(
        name="MITRE CWE Enterprise Intelligence",
        description=(
            "Official MITRE Common Weakness Enumeration (CWE) XML dataset. "
            "Provides weaknesses, relationships, mitigations, and detection guidance."
        ),
        vendor="MITRE / NetFusion",
        version="1.0.0",
        feed_type="mitre_cwe_xml",
        supports_incremental_updates=True,
        supports_full_sync=True,
        supports_relationship_building=True,
        supports_checksum_verification=True,
        supports_signature_verification=False,
        supports_rollback=True,
        supports_delta_updates=False,
        entity_types=[
            "CWE",
        ],
        relationship_types=[
            "ChildOf",
            "ParentOf",
            "StartsWith",
            "CanPrecede",
            "CanFollow",
            "RequiredBy",
            "Requires",
            "CanAlsoBe",
            "PeerOf",
        ],
        default_schedule="0 1 * * 0",  # Weekly Sunday 1 AM UTC
        recommended_retry_count=3,
        timeout=300.0,
        validation_rules=[
            "CWE_XML_SCHEMA_VALIDATION",
            "CWE_ID_PRESENT",
            "CWE_NAME_PRESENT",
            "UNIQUE_CWE_ID",
            "RELATIONSHIP_REFERENTIAL_INTEGRITY",
            "NO_ORPHAN_RELATIONSHIPS",
        ],
        dependencies=[],
    )
