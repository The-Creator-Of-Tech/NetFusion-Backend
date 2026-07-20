"""
NetFusion Evidence Selector
Filters, scores, ranks, and selects critical evidence items for context assembly.
"""

from typing import Any, Dict, List, Optional, Union
from netfusion_workflow.domain import Evidence, TimelineEvent
from netfusion_ai.domain import EvidenceReference


class EvidenceSelector:
    """Intelligent selector and filter for investigation evidence."""

    def __init__(self, default_max_items: int = 50):
        self.default_max_items = default_max_items

    def select_top_evidence(
        self,
        evidence_list: List[Union[Evidence, Dict[str, Any]]],
        max_items: Optional[int] = None,
        source_filter: Optional[str] = None,
    ) -> List[EvidenceReference]:
        """Filters and ranks workflow evidence objects by relevance and integrity."""
        max_items = max_items or self.default_max_items
        selected: List[EvidenceReference] = []

        for item in evidence_list:
            ev_id = self._get_attr(item, "evidence_id", "EV-001")
            name = self._get_attr(item, "name", "Artifact")
            file_name = self._get_attr(item, "file_name", "")
            checksum = self._get_attr(item, "checksum_sha256", "")
            source = self._get_attr(item, "source", "evidence")
            source_str = source.value if hasattr(source, "value") else str(source)
            created_at = self._get_attr(item, "created_at", None)

            if source_filter and source_str != source_filter:
                continue

            score = 0.5
            integrity = self._get_attr(item, "integrity_status", None)
            if integrity and (hasattr(integrity, "value") and integrity.value == "VERIFIED" or str(integrity) == "VERIFIED"):
                score += 0.3

            ref = EvidenceReference(
                evidence_id=ev_id,
                source_type=source_str,
                summary=f"Evidence '{name}' ({file_name}) - Hash: {checksum[:16] if checksum else 'N/A'}",
                relevance_score=min(score, 1.0),
                timestamp=created_at,
                metadata={
                    "checksum": checksum,
                    "mime_type": self._get_attr(item, "mime_type", ""),
                    "tags": self._get_attr(item, "tags", []),
                },
            )
            selected.append(ref)

        selected.sort(key=lambda x: x.relevance_score, reverse=True)
        return selected[:max_items]

    def select_key_timeline_events(
        self,
        timeline_events: List[Union[TimelineEvent, Dict[str, Any]]],
        max_items: Optional[int] = None,
    ) -> List[EvidenceReference]:
        """Ranks timeline events by severity and tactical significance."""
        max_items = max_items or self.default_max_items
        selected: List[EvidenceReference] = []

        for event in timeline_events:
            ev_id = self._get_attr(event, "event_id", "TL-001")
            title = self._get_attr(event, "title", "Timeline Event")
            summary = self._get_attr(event, "summary", "")
            timestamp = self._get_attr(event, "timestamp", None)
            sev = self._get_attr(event, "severity", "medium")
            sev_str = (sev.value if hasattr(sev, "value") else str(sev)).lower()

            score = 0.5
            if sev_str == "critical":
                score = 1.0
            elif sev_str == "high":
                score = 0.85
            elif sev_str == "medium":
                score = 0.65

            ref = EvidenceReference(
                evidence_id=ev_id,
                source_type="timeline",
                summary=f"[{sev_str.upper()}] {title}: {summary}",
                relevance_score=score,
                timestamp=timestamp,
                metadata={
                    "source_collector": self._get_attr(event, "source_collector", ""),
                    "mitre_technique": self._get_attr(event, "mitre_technique", ""),
                },
            )
            selected.append(ref)

        selected.sort(key=lambda x: (x.relevance_score, x.timestamp or 0.0), reverse=True)
        return selected[:max_items]

    def _get_attr(self, obj: Any, key: str, default: Any = None) -> Any:
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)
