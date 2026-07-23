"""
CAPEC Enterprise Intelligence Feed Manifest definition.
"""

from netfusion_intelligence.models.manifest import FeedManifest


def get_capec_manifest() -> FeedManifest:
    """Returns official FeedManifest for MITRE CAPEC Enterprise Intelligence Feed."""
    return FeedManifest(
        name="MITRE CAPEC Enterprise Intelligence",
        description=(
            "Official MITRE Common Attack Pattern Enumeration and Classification (CAPEC) XML dataset. "
            "Provides attack patterns, execution flows, mitigations, and ATT&CK cross-references."
        ),
        vendor="MITRE / NetFusion",
        version="1.0.0",
        feed_type="mitre_capec_xml",
        supports_incremental_updates=True,
        supports_full_sync=True,
        supports_relationship_building=True,
        supports_checksum_verification=True,
        supports_signature_verification=False,
        supports_rollback=True,
        supports_delta_updates=False,
        entity_types=[
            "CAPEC",
        ],
        relationship_types=[
            "ChildOf",
            "ParentOf",
            "CanPrecede",
            "CanFollow",
            "PeerOf",
            "Abstracts",
            "HasMember",
            "capec_to_cwe",
            "capec_to_attack",
        ],
        default_schedule="0 2 * * 0",  # Weekly Sunday 2 AM UTC
        recommended_retry_count=3,
        timeout=300.0,
        validation_rules=[
            "CAPEC_XML_SCHEMA_VALIDATION",
            "CAPEC_ID_PRESENT",
            "CAPEC_NAME_PRESENT",
            "UNIQUE_CAPEC_ID",
            "RELATIONSHIP_REFERENTIAL_INTEGRITY",
            "NO_UNKNOWN_CWE_REFERENCES",
            "NO_UNKNOWN_ATTACK_REFERENCES",
        ],
        dependencies=["mitre_cwe_xml"],
    )
