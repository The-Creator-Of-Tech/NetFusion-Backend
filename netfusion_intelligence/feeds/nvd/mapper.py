"""
CIIL Identity Mapper for NVD Enterprise CVE Intelligence Pipeline.
Maps NvdCve domain objects into Canonical Entities in NetFusion CIIL.
"""

from typing import Any, Dict, List, Optional, Tuple
from netfusion_intelligence.feeds.nvd.models import NvdCve
from netfusion_intelligence.identity.models import CanonicalEntity, ExternalIdentifier
from netfusion_intelligence.identity.resolver import IdentityResolver


class NvdCiilMapper:
    """
    Maps NVD CVE domain models, CWEs, vendors, and products to Canonical Entities in NetFusion CIIL.
    Uses IdentityResolver for duplicate prevention, identity merging, and provenance tracking.
    """

    def __init__(self, resolver: Optional[IdentityResolver] = None):
        self.resolver = resolver

    def resolve_cve_entity(
        self,
        cve: NvdCve,
        dataset_version: str = "2.0.0",
        feed_source: str = "NVD_CVE_2.0",
    ) -> Optional[CanonicalEntity]:
        """
        Resolves an NvdCve object into a CanonicalEntity of type CVE.
        """
        if not self.resolver:
            return None

        ext_ids = [
            ExternalIdentifier(
                source="NVD",
                identifier=cve.cve_id,
                identifier_type="CVE_ID",
                url=f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}",
            )
        ]

        # Add reference links as external identifiers
        for ref in cve.references:
            ext_ids.append(
                ExternalIdentifier(
                    source="REFERENCE",
                    identifier=ref.url,
                    identifier_type="URL",
                    url=ref.url,
                )
            )

        aliases = [cve.cve_id]
        if cve.title:
            aliases.append(cve.title)

        meta = {
            "published": cve.published,
            "last_modified": cve.last_modified,
            "severity": cve.severity,
            "cvss_score": cve.cvss_score,
            "cwes": list(cve.cwes),
            "vendors": list(cve.vendors),
            "products": list(cve.products),
            "vuln_status": cve.vuln_status,
            "source_identifier": cve.source_identifier,
        }

        tags = ["nvd", "cve", cve.severity.lower()]

        entity = self.resolver.resolve(
            entity_type="CVE",
            display_name=cve.cve_id,
            external_identifiers=ext_ids,
            aliases=aliases,
            description=cve.description,
            tags=tags,
            metadata=meta,
            feed_source=feed_source,
            dataset_version=dataset_version,
            original_object_id=cve.cve_id,
            confidence=1.0,
        )

        # Resolve associated CWE canonical entities
        for cwe_id in cve.cwes:
            self.resolve_cwe_entity(cwe_id, dataset_version=dataset_version, feed_source=feed_source)

        return entity

    def resolve_cwe_entity(
        self,
        cwe_id: str,
        dataset_version: str = "2.0.0",
        feed_source: str = "NVD_CVE_2.0",
    ) -> Optional[CanonicalEntity]:
        """
        Resolves a CWE identifier into a CanonicalEntity of type CWE.
        """
        if not self.resolver or not cwe_id:
            return None

        ext_ids = [
            ExternalIdentifier(
                source="CWE",
                identifier=cwe_id.upper(),
                identifier_type="CWE_ID",
                url=f"https://cwe.mitre.org/data/definitions/{cwe_id.upper().replace('CWE-', '')}.html",
            )
        ]

        return self.resolver.resolve(
            entity_type="CWE",
            display_name=cwe_id.upper(),
            external_identifiers=ext_ids,
            aliases=[cwe_id.upper()],
            description=f"Common Weakness Enumeration {cwe_id.upper()}",
            tags=["cwe", "weakness"],
            metadata={"cwe_id": cwe_id.upper()},
            feed_source=feed_source,
            dataset_version=dataset_version,
            original_object_id=cwe_id.upper(),
        )
