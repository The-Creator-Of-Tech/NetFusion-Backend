"""
CIIL Mapper for FIRST EPSS Intelligence Pipeline.
Maps EPSS records to canonical CVE entities via the CIIL Identity Resolver.
NEVER creates duplicate CVEs - only enriches existing canonical entities.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from netfusion_intelligence.feeds.epss.models import EpssRecord
from netfusion_intelligence.identity.models import ExternalIdentifier
from netfusion_intelligence.identity.resolver import IdentityResolver

logger = logging.getLogger(__name__)


class EpssCiilMapper:
    """
    Maps EPSS records to the CIIL canonical identity layer.
    Enforces the rule: EPSS NEVER creates duplicate CVE entities.
    All enrichment targets existing canonical CVE entities.
    """

    def __init__(self, resolver: Optional[IdentityResolver] = None):
        self.resolver = resolver
        self._enriched_count: int = 0
        self._skipped_count: int = 0

    @property
    def enriched_count(self) -> int:
        return self._enriched_count

    @property
    def skipped_count(self) -> int:
        return self._skipped_count

    def enrich_canonical_cve(
        self,
        record: EpssRecord,
        dataset_version: str = "",
        feed_source: str = "first_epss_1.0",
    ) -> bool:
        """
        Enriches an existing canonical CVE entity with EPSS score data.

        Workflow:
          1. Resolve canonical CVE by CVE ID
          2. Update existing entity's metadata with EPSS data
          3. Store provenance
          4. Return True if enriched, False if no canonical entity found

        NEVER creates a new canonical CVE entity.
        """
        if not self.resolver:
            logger.debug(f"No resolver configured, skipping CIIL enrichment for {record.cve_id}")
            return False

        # Find existing canonical CVE entity via CIIL
        existing_entities = self.resolver.repository.find_by_identifier_value(record.cve_id)

        # Filter to CVE entity types
        cve_entities = [
            e for e in existing_entities
            if e.entity_type.upper() == "CVE" and e.active
        ]

        if not cve_entities:
            logger.debug(f"No canonical CVE entity for {record.cve_id} — skipping EPSS enrichment")
            self._skipped_count += 1
            return False

        # Pick the primary canonical entity
        canonical = cve_entities[0]

        # Build EPSS enrichment metadata
        epss_metadata = {
            "epss": {
                "score": record.current_score,
                "percentile": record.current_percentile,
                "trend": record.trend,
                "model_version": record.model_version,
                "dataset_version": dataset_version,
                "publication_date": record.publication_date,
                "moving_avg_7d": record.moving_avg_7d,
                "moving_avg_30d": record.moving_avg_30d,
                "historical_high": record.historical_high,
                "historical_low": record.historical_low,
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "source": "FIRST EPSS",
                # Composite risk foundation fields - preserved for future scoring
                "composite_risk_inputs": {
                    "epss_score": record.current_score,
                    "epss_percentile": record.current_percentile,
                    "epss_trend": record.trend,
                    # CVSS - supplied by NVD (IL-3)
                    # KEV status - supplied by CISA KEV (IL-4)
                    # Asset criticality - future: from asset inventory
                    # Business context - future: from business layer
                    # Exposure - future: from scan data
                },
            }
        }

        # Build EPSS external identifier
        epss_ext_id = ExternalIdentifier(
            source="FIRST_EPSS",
            identifier=record.cve_id,
            identifier_type="CVE_ID",
            url=f"https://api.first.org/data/v1/epss?cve={record.cve_id}",
            version=record.model_version,
            confidence=0.95,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )

        # Enrich existing canonical entity without creating a new one
        try:
            updated = self.resolver._merge_incoming_data(
                target=canonical,
                display_name=canonical.display_name,
                description=canonical.description,
                incoming_ext_ids=[epss_ext_id],
                incoming_aliases=[],
                incoming_tags=["epss", "exploit_probability"],
                incoming_metadata=epss_metadata,
                feed_source=feed_source,
            )

            from netfusion_intelligence.identity.models import EntityProvenance
            provenance = EntityProvenance.create(
                canonical_uuid=canonical.canonical_uuid,
                feed=feed_source,
                dataset_version=dataset_version,
                original_object_id=record.cve_id,
                trust_score=0.95,
            )

            self.resolver.repository.save_entity(updated, provenance=provenance)
            self._enriched_count += 1

            logger.debug(
                f"Enriched canonical CVE {record.cve_id} with EPSS score "
                f"{record.current_score:.4f} (percentile: {record.current_percentile:.4f})"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to enrich canonical CVE {record.cve_id}: {e}")
            return False

    def reset_counters(self) -> None:
        """Resets enrichment counters."""
        self._enriched_count = 0
        self._skipped_count = 0
