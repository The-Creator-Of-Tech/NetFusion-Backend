"""
Manifest configuration for official FIRST EPSS Enterprise Intelligence Feed.
"""

from netfusion_intelligence.models.manifest import FeedManifest


def get_epss_manifest() -> FeedManifest:
    """
    Returns FeedManifest declaration for official FIRST EPSS Enterprise Intelligence Pipeline.
    """
    return FeedManifest(
        name="FIRST Exploit Prediction Scoring System",
        description="Official FIRST EPSS exploit probability intelligence pipeline enriching canonical CVE entities with probabilistic threat scoring.",
        vendor="FIRST / NetFusion",
        version="1.0.0",
        feed_type="first_epss_1.0",
        supports_incremental_updates=True,
        supports_full_sync=True,
        supports_relationship_building=True,
        supports_checksum_verification=True,
        supports_signature_verification=False,
        supports_rollback=True,
        supports_delta_updates=True,
        entity_types=[
            "CVE",
            "EPSS_SCORE",
            "EXPLOIT_PREDICTION",
        ],
        relationship_types=[
            "has_epss_score",
            "exploit_probability",
            "risk_ranking",
        ],
        default_schedule="0 2 * * *",  # Daily at 2 AM UTC
        recommended_retry_count=3,
        timeout=600.0,
        validation_rules=[
            "EPSS_SCHEMA_VALIDATION",
            "CVE_ID_PRESENT",
            "CIIL_CANONICAL_CVE_EXISTS",
            "EPSS_SCORE_RANGE_CHECK",
            "EPSS_PERCENTILE_RANGE_CHECK",
            "DUPLICATE_EPSS_RECORD_CHECK",
            "ORPHAN_CVE_CHECK",
        ],
        dependencies=["nvd_cve_2.0"],
    )
