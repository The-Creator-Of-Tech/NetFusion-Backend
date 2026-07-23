"""
Tests for CisaKevCiilMapper identity resolution and canonical entity enrichment.
"""

from netfusion_intelligence.feeds.kev.mapper import CisaKevCiilMapper
from netfusion_intelligence.feeds.kev.models import KevRecord
from netfusion_intelligence.identity.models import ExternalIdentifier
from netfusion_intelligence.identity.repository import IdentityRepository
from netfusion_intelligence.identity.resolver import IdentityResolver


def test_mapper_enrichment():
    repo = IdentityRepository(":memory:")
    resolver = IdentityResolver(repo)

    # First, create a Canonical CVE entity (as if created by NVD feed)
    cve_entity = resolver.resolve(
        entity_type="CVE",
        display_name="CVE-2021-44228",
        external_identifiers=[
            ExternalIdentifier(source="NVD", identifier="CVE-2021-44228", identifier_type="CVE_ID")
        ],
        description="Original NVD Log4j description",
        feed_source="nvd_cve_2.0",
    )
    assert cve_entity.metadata.get("known_exploited") is not True

    # Now enrich with KEV record
    mapper = CisaKevCiilMapper(resolver=resolver)
    rec = KevRecord(
        cve_id="CVE-2021-44228",
        vendor_project="Apache",
        product="Log4j",
        vulnerability_name="Log4j RCE",
        required_action="Patch immediately",
        due_date="2021-12-24",
        known_ransomware_campaign_use="Known",
    )

    enriched = mapper.enrich_canonical_cve(rec, dataset_version="1.0.0")
    assert enriched is not None
    assert enriched.canonical_uuid == cve_entity.canonical_uuid  # Same UUID preserved!
    assert enriched.metadata["known_exploited"] is True
    assert enriched.metadata["exploitation_status"] == "Known Exploited"
    assert enriched.metadata["required_remediation"] == "Patch immediately"
    assert enriched.metadata["due_date"] == "2021-12-24"
    assert "cisa_kev" in enriched.tags


def test_mapper_no_duplicate_creation_on_unknown():
    repo = IdentityRepository(":memory:")
    resolver = IdentityResolver(repo)
    mapper = CisaKevCiilMapper(resolver=resolver)

    rec = KevRecord(cve_id="CVE-2099-00001", vulnerability_name="Unknown CVE")
    enriched = mapper.enrich_canonical_cve(rec)
    assert enriched is None  # Does NOT create duplicate CVE!
