"""
Manifest configuration for official NVD Enterprise CVE Intelligence Feed.
"""

from netfusion_intelligence.models.manifest import FeedManifest


def get_nvd_manifest() -> FeedManifest:
    """
    Returns immutable FeedManifest declaration for official NVD Enterprise CVE Intelligence Pipeline.
    """
    return FeedManifest(
        name="NVD Enterprise CVE Intelligence",
        description="Authoritative vulnerability intelligence pipeline sourcing official NVD CVE JSON 2.0 API datasets.",
        vendor="NIST / NVD / NetFusion",
        version="2.0.0",
        feed_type="nvd_cve_2.0",
        supports_incremental_updates=True,
        supports_full_sync=True,
        supports_relationship_building=True,
        supports_checksum_verification=True,
        supports_signature_verification=False,
        supports_rollback=True,
        supports_delta_updates=True,
        entity_types=[
            "CVE",
            "CWE",
            "VENDOR",
            "PRODUCT",
        ],
        relationship_types=[
            "has_weakness",
            "affects_product",
            "affects_vendor",
        ],
        default_schedule="0 * * * *",  # Hourly sync
        recommended_retry_count=3,
        timeout=300.0,
        validation_rules=[
            "NVD_JSON_2.0_SCHEMA_VALIDATION",
            "CVE_ID_PRESENT",
            "UNIQUE_CVE_ID",
            "VALID_CVSS_SCORES",
            "CPE_TREE_INTEGRITY",
        ],
        dependencies=[],
    )
