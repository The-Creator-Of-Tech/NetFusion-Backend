"""
Normalizer for FIRST EPSS parsed data.
Transforms parsed scores into canonical EpssRecord domain models.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from netfusion_intelligence.feeds.epss.models import EpssRecord, EpssScore
from netfusion_intelligence.interfaces.normalizer import NormalizerInterface

logger = logging.getLogger(__name__)


class EpssNormalizer(NormalizerInterface):
    """
    Normalizes parsed EPSS data into EpssRecord domain models.
    Handles data transformation, deduplication, and enrichment.
    """

    def normalize(self, parsed_data: Any) -> Dict[str, Any]:
        """
        Normalizes parsed EPSS scores into EpssRecord entities.
        Returns dict with 'entities', 'metadata', and statistics.
        """
        if not parsed_data:
            logger.warning("EPSS normalizer received empty parsed_data")
            return {"entities": {}, "metadata": {}}

        scores: List[EpssScore] = parsed_data.get("scores", [])
        metadata = parsed_data.get("metadata", {})

        if not scores:
            logger.warning("EPSS normalizer received no scores to normalize")
            return {"entities": {}, "metadata": metadata}

        entities: Dict[str, EpssRecord] = {}
        duplicate_count = 0

        for score in scores:
            cve_id = score.cve_id.upper()

            # Check for duplicates within the dataset
            if cve_id in entities:
                duplicate_count += 1
                logger.debug(f"Duplicate EPSS record for {cve_id}, keeping first occurrence")
                continue

            # Create EpssRecord from EpssScore
            record = EpssRecord.from_score(score)
            entities[cve_id] = record

        logger.info(
            f"EPSS normalizer processed {len(scores)} scores → {len(entities)} entities "
            f"({duplicate_count} duplicates)"
        )

        return {
            "entities": entities,
            "metadata": metadata,
            "model_version": parsed_data.get("model_version", "v2023.03.01"),
            "score_date": parsed_data.get("score_date", ""),
            "total_cves": len(entities),
            "duplicate_count": duplicate_count,
            "statistics": {
                "total_parsed": len(scores),
                "total_normalized": len(entities),
                "duplicates_removed": duplicate_count,
            },
        }

    def _enrich_record(self, record: EpssRecord, metadata: Dict[str, Any]) -> EpssRecord:
        """
        Optional enrichment hook for future extensions.
        Can add computed fields, trends, or metadata annotations.
        """
        # Placeholder for future enrichment logic
        return record

    def _calculate_statistics(self, entities: Dict[str, EpssRecord]) -> Dict[str, Any]:
        """
        Calculates statistical summary of normalized EPSS records.
        """
        if not entities:
            return {
                "total_records": 0,
                "average_score": 0.0,
                "average_percentile": 0.0,
                "high_probability_cves": 0,
                "low_probability_cves": 0,
            }

        scores = [rec.current_score for rec in entities.values()]
        percentiles = [rec.current_percentile for rec in entities.values()]

        avg_score = sum(scores) / len(scores) if scores else 0.0
        avg_percentile = sum(percentiles) / len(percentiles) if percentiles else 0.0

        high_prob = sum(1 for s in scores if s >= 0.5)
        low_prob = sum(1 for s in scores if s < 0.1)

        return {
            "total_records": len(entities),
            "average_score": round(avg_score, 6),
            "average_percentile": round(avg_percentile, 6),
            "high_probability_cves": high_prob,
            "low_probability_cves": low_prob,
            "highest_score": max(scores) if scores else 0.0,
            "lowest_score": min(scores) if scores else 0.0,
        }
