"""
Manifest configuration for official CISA KEV Enterprise Intelligence Feed.
"""

from netfusion_intelligence.models.manifest import FeedManifest


def get_kev_manifest() -> FeedManifest:
    """
    Returns FeedManifest declaration for official CISA KEV Enterprise Intelligence Pipeline.
    """
    return FeedManifest(
        name="CISA Known Exploited Vulnerabilities Catalog",
        description="Official CISA KEV catalog intelligence pipeline enriching canonical CVE entities with active exploitation threat context.",
        vendor="CISA / DHS / NetFusion",
        version="1.0.0",
        feed_type="cisa_kev_1.0",
        supports_incremental_updates=True,
        supports_full_sync=True,
        supports_relationship_building=True,
        supports_checksum_verification=True,
        supports_signature_verification=False,
        supports_rollback=True,
        supports_delta_updates=True,
        entity_types=[
            "CVE",
            "EXPLOIT",
            "VENDOR",
            "PRODUCT",
        ],
        relationship_types=[
            "known_exploited_in_wild",
            "associated_ransomware_campaign",
            "affects_product",
            "affects_vendor",
        ],
        default_schedule="0 */6 * * *",  # Every 6 hours
        recommended_retry_count=3,
        timeout=300.0,
        validation_rules=[
            "CISA_KEV_SCHEMA_VALIDATION",
            "CVE_ID_PRESENT",
            "CIIL_CANONICAL_CVE_EXISTS",
            "MALFORMED_DATE_CHECK",
            "DUPLICATE_KEV_RECORD_CHECK",
            "BROKEN_REFERENCE_CHECK",
        ],
        dependencies=["nvd_cve_2.0"],
    )
