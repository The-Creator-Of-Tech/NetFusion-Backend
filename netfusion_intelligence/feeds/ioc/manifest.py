"""
IL-7 IOC Enterprise Intelligence Feed Manifest.
Declares feed capabilities, entity/relationship schemas, scheduling, and dependencies.
"""

from netfusion_intelligence.models.manifest import FeedManifest


def get_ioc_manifest() -> FeedManifest:
    """Returns the official FeedManifest for the IOC Enterprise Intelligence Feed."""
    return FeedManifest(
        name="NetFusion IOC Enterprise Intelligence",
        description=(
            "Production-grade Indicator of Compromise (IOC) intelligence pipeline. "
            "Ingests, normalizes, validates, correlates, and enriches IOCs from MISP, "
            "OpenCTI, STIX 2.1 bundles, TAXII collections, CSV, JSON, YAML, and offline imports. "
            "Every IOC becomes a first-class Canonical Entity within CIIL with full "
            "reputation, sighting, confidence, and correlation support."
        ),
        vendor="NetFusion Intelligence / Community",
        version="1.0.0",
        feed_type="netfusion_ioc_v1",
        supports_incremental_updates=True,
        supports_full_sync=True,
        supports_relationship_building=True,
        supports_checksum_verification=True,
        supports_signature_verification=False,
        supports_rollback=True,
        supports_delta_updates=True,
        entity_types=[
            "IOC",
        ],
        relationship_types=[
            "ioc_to_malware",
            "ioc_to_campaign",
            "ioc_to_threat_actor",
            "ioc_to_attack_technique",
            "ioc_to_capec",
            "ioc_to_cwe",
            "ioc_to_cve",
            "ioc_to_ioc",
            "ip_to_domain",
            "domain_to_url",
            "url_to_hash",
            "hash_to_file",
        ],
        default_schedule="0 */6 * * *",   # Every 6 hours
        recommended_retry_count=3,
        timeout=600.0,
        validation_rules=[
            "IOC_VALUE_PRESENT",
            "IOC_TYPE_VALID",
            "IPV4_FORMAT_VALID",
            "IPV6_FORMAT_VALID",
            "DOMAIN_FORMAT_VALID",
            "URL_FORMAT_VALID",
            "HASH_FORMAT_VALID",
            "EMAIL_FORMAT_VALID",
            "NO_DUPLICATE_INDICATORS",
            "CONFIDENCE_RANGE_VALID",
            "SEVERITY_VALID",
            "EXPIRATION_FUTURE_IF_SET",
        ],
        dependencies=[
            "mitre_attack_enterprise",
            "mitre_capec_xml",
            "mitre_cwe_xml",
            "nvd_cve_2.0",
        ],
    )
