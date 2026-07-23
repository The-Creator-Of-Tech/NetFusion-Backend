"""
CIIL Identity Mapper for CISA KEV Enterprise Intelligence Pipeline.
Enriches existing Canonical CVE entities in NetFusion CIIL with exploitation intelligence.
"""

from typing import Any, Dict, List, Optional
from netfusion_intelligence.feeds.kev.models import KevRecord
from netfusion_intelligence.identity.models import CanonicalEntity, ExternalIdentifier
from netfusion_intelligence.identity.resolver import IdentityResolver


class CisaKevCiilMapper:
    """
    Maps CISA KEV records into NetFusion CIIL Canonical CVE entities.
    STRICT RULE: Every KEV record MUST resolve against an existing Canonical CVE entity.
    Never creates duplicate CVEs.
    """

    def __init__(self, resolver: Optional[IdentityResolver] = None):
        self.resolver = resolver

    def enrich_canonical_cve(
        self,
        record: KevRecord,
        dataset_version: str = "1.0.0",
        feed_source: str = "cisa_kev_1.0",
    ) -> Optional[CanonicalEntity]:
        """
        Resolves KEV record against an existing Canonical CVE entity and enriches it.
        If no existing Canonical CVE is found, returns None (rejecting duplicate creation).
        """
        if not self.resolver:
            return None

        # Look up existing Canonical CVE entity in CIIL
        existing_entity = self._find_existing_canonical_cve(record.cve_id)
        if not existing_entity:
            # Reject orphan KEV record that cannot resolve into CIIL
            return None

        # Build external identifiers for references
        ext_ids: List[ExternalIdentifier] = [
            ExternalIdentifier(
                source="CISA_KEV",
                identifier=record.cve_id,
                identifier_type="CVE_ID",
                url=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            )
        ]
        for url in record.reference_urls:
            ext_ids.append(
                ExternalIdentifier(
                    source="CISA_KEV_REFERENCE",
                    identifier=url,
                    identifier_type="URL",
                    url=url,
                )
            )

        # Build enrichment metadata
        existing_meta = dict(existing_entity.metadata) if existing_entity.metadata else {}
        existing_meta.update({
            "known_exploited": True,
            "exploitation_status": "Known Exploited",
            "required_remediation": record.required_action,
            "due_date": record.due_date,
            "ransomware_association": record.known_ransomware_campaign_use,
            "kev_metadata": {
                "vulnerability_name": record.vulnerability_name,
                "vendor_project": record.vendor_project,
                "product": record.product,
                "date_added": record.date_added,
                "short_description": record.short_description,
                "notes": record.notes,
                "catalog_version": record.catalog_version,
            },
        })

        existing_tags = set(existing_entity.tags)
        existing_tags.update(["cisa_kev", "known_exploited"])
        if "known" in record.known_ransomware_campaign_use.lower():
            existing_tags.add("ransomware")

        existing_aliases = list(existing_entity.aliases)
        if record.vulnerability_name and record.vulnerability_name not in existing_aliases:
            existing_aliases.append(record.vulnerability_name)

        # Pass through resolver to merge & save updated CanonicalEntity with CISA KEV provenance
        enriched = self.resolver.resolve(
            entity_type="CVE",
            display_name=existing_entity.display_name,
            external_identifiers=ext_ids,
            aliases=existing_aliases,
            description=existing_entity.description or record.short_description,
            tags=list(existing_tags),
            metadata=existing_meta,
            feed_source=feed_source,
            dataset_version=dataset_version,
            original_object_id=record.cve_id,
            confidence=1.0,
        )

        return enriched

    def _find_existing_canonical_cve(self, cve_id: str) -> Optional[CanonicalEntity]:
        """
        Searches CIIL repository for an existing CanonicalEntity of type CVE matching the cve_id.
        """
        if not self.resolver or not self.resolver.repository:
            return None

        # Search by external identifier source NVD
        ext_matches = self.resolver.repository.find_by_external_id("NVD", cve_id)
        if ext_matches:
            return ext_matches[0]

        ext_matches_generic = self.resolver.repository.find_by_external_id("CISA_KEV", cve_id)
        if ext_matches_generic:
            return ext_matches_generic[0]

        # Search by identifier value directly
        id_matches = self.resolver.repository.find_by_identifier_value(cve_id)
        if id_matches:
            return id_matches[0]

        # Search by alias
        alias_matches = self.resolver.repository.find_by_alias(cve_id)
        if alias_matches:
            return alias_matches[0]

        return None

