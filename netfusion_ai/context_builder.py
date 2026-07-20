"""
NetFusion Investigation Context Builder
Assembles structured investigation context across all 15 investigation sources:
Investigation, Timeline, Evidence, Canonical Objects, IOC, Threat Intelligence,
Sysmon, Nmap, TShark, Tasks, Notes, Risk, MITRE, Configuration.
Supports configurable token budget and automatic context window truncation.
"""

import json
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Union

from netfusion_workflow.domain import (
    Investigation,
    Task,
    AnalystNote,
    Evidence,
    TimelineEvent,
    MITREMapping,
    RiskAssessment,
)
from netfusion_ai.exceptions import ContextOverflowError
from netfusion_ai.evidence_selector import EvidenceSelector


@dataclass
class ContextConfig:
    """Configurable size and weighting constraints for context assembly."""
    max_token_budget: int = 4000
    max_timeline_events: int = 25
    max_evidence_items: int = 20
    max_canonical_objects: int = 30
    max_iocs: int = 25
    max_notes: int = 15
    max_tasks: int = 15
    include_sysmon: bool = True
    include_nmap: bool = True
    include_tshark: bool = True
    include_threat_intel: bool = True


@dataclass
class InvestigationContextContainer:
    """Structured container holding all 15 investigation context sources."""
    investigation: Optional[Dict[str, Any]] = None
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    canonical_objects: List[Dict[str, Any]] = field(default_factory=list)
    iocs: List[Dict[str, Any]] = field(default_factory=list)
    threat_intelligence: List[Dict[str, Any]] = field(default_factory=list)
    sysmon_events: List[Dict[str, Any]] = field(default_factory=list)
    nmap_scans: List[Dict[str, Any]] = field(default_factory=list)
    tshark_captures: List[Dict[str, Any]] = field(default_factory=list)
    tasks: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[Dict[str, Any]] = field(default_factory=list)
    risk_assessment: Optional[Dict[str, Any]] = None
    mitre_mappings: List[Dict[str, Any]] = field(default_factory=list)
    configuration: Dict[str, Any] = field(default_factory=dict)
    summary_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ContextBuilder:
    """Context Builder engine for AI prompts."""

    def __init__(self, config: Optional[ContextConfig] = None):
        self.config = config or ContextConfig()
        self.evidence_selector = EvidenceSelector()

    def build_context(
        self,
        investigation: Optional[Union[Investigation, Dict[str, Any]]] = None,
        timeline: Optional[List[Union[TimelineEvent, Dict[str, Any]]]] = None,
        evidence: Optional[List[Union[Evidence, Dict[str, Any]]]] = None,
        canonical_objects: Optional[List[Dict[str, Any]]] = None,
        iocs: Optional[List[Dict[str, Any]]] = None,
        threat_intelligence: Optional[List[Dict[str, Any]]] = None,
        sysmon_events: Optional[List[Dict[str, Any]]] = None,
        nmap_scans: Optional[List[Dict[str, Any]]] = None,
        tshark_captures: Optional[List[Dict[str, Any]]] = None,
        tasks: Optional[List[Union[Task, Dict[str, Any]]]] = None,
        notes: Optional[List[Union[AnalystNote, Dict[str, Any]]]] = None,
        risk_assessment: Optional[Union[RiskAssessment, Dict[str, Any]]] = None,
        mitre_mappings: Optional[List[Union[MITREMapping, Dict[str, Any]]]] = None,
        configuration: Optional[Dict[str, Any]] = None,
    ) -> InvestigationContextContainer:
        """Assembles unified context container from all 15 investigation sources."""

        # 1. Investigation metadata
        inv_dict = self._to_dict(investigation) if investigation else {}

        # 2. Timeline
        norm_timeline = [self._to_dict(t) for t in (timeline or [])][: self.config.max_timeline_events]

        # 3. Evidence
        norm_evidence = [self._to_dict(e) for e in (evidence or [])][: self.config.max_evidence_items]

        # 4. Canonical Objects
        norm_canonical = (canonical_objects or [])[: self.config.max_canonical_objects]

        # 5. IOCs
        norm_iocs = (iocs or [])[: self.config.max_iocs]

        # 6. Threat Intel
        norm_ti = (threat_intelligence or []) if self.config.include_threat_intel else []

        # 7. Sysmon
        norm_sysmon = (sysmon_events or []) if self.config.include_sysmon else []

        # 8. Nmap
        norm_nmap = (nmap_scans or []) if self.config.include_nmap else []

        # 9. TShark
        norm_tshark = (tshark_captures or []) if self.config.include_tshark else []

        # 10. Tasks
        norm_tasks = [self._to_dict(t) for t in (tasks or [])][: self.config.max_tasks]

        # 11. Notes
        norm_notes = [self._to_dict(n) for n in (notes or [])][: self.config.max_notes]

        # 12. Risk Assessment
        norm_risk = self._to_dict(risk_assessment) if risk_assessment else None

        # 13. MITRE Mappings
        norm_mitre = [self._to_dict(m) for m in (mitre_mappings or [])]

        # 14. Configuration
        norm_config = configuration or {}

        # 15. Summary metadata
        summary_meta = {
            "timeline_count": len(norm_timeline),
            "evidence_count": len(norm_evidence),
            "canonical_object_count": len(norm_canonical),
            "ioc_count": len(norm_iocs),
            "sysmon_event_count": len(norm_sysmon),
            "nmap_scan_count": len(norm_nmap),
            "tshark_capture_count": len(norm_tshark),
            "task_count": len(norm_tasks),
            "note_count": len(norm_notes),
            "mitre_count": len(norm_mitre),
        }

        container = InvestigationContextContainer(
            investigation=inv_dict,
            timeline=norm_timeline,
            evidence=norm_evidence,
            canonical_objects=norm_canonical,
            iocs=norm_iocs,
            threat_intelligence=norm_ti,
            sysmon_events=norm_sysmon,
            nmap_scans=norm_nmap,
            tshark_captures=norm_tshark,
            tasks=norm_tasks,
            notes=norm_notes,
            risk_assessment=norm_risk,
            mitre_mappings=norm_mitre,
            configuration=norm_config,
            summary_metadata=summary_meta,
        )

        return self._enforce_token_budget(container)

    def format_as_markdown(self, container: InvestigationContextContainer) -> str:
        """Renders investigation context container into structured Markdown for LLM prompt insertion."""
        lines = []
        inv = container.investigation or {}
        lines.append(f"### Investigation Context: {inv.get('title', 'Untitled Investigation')}")
        lines.append(f"- **ID**: {inv.get('investigation_id', 'N/A')}")
        lines.append(f"- **Status**: {inv.get('status', 'ACTIVE')}")
        lines.append(f"- **Severity**: {inv.get('severity', 'MEDIUM')}")
        lines.append(f"- **Description**: {inv.get('description', 'N/A')}\n")

        if container.risk_assessment:
            ra = container.risk_assessment
            lines.append(f"#### Risk Assessment")
            lines.append(f"- Score: {ra.get('overall_score', 'N/A')} | Impact: {ra.get('business_impact', 'N/A')} | Likelihood: {ra.get('likelihood', 'N/A')}\n")

        if container.iocs:
            lines.append(f"#### Identified IOCs ({len(container.iocs)})")
            for ioc in container.iocs[:15]:
                lines.append(f"- `{ioc.get('type', 'IOC')}`: `{ioc.get('value', '')}` (Confidence: {ioc.get('confidence', 'N/A')})")
            lines.append("")

        if container.timeline:
            lines.append(f"#### Timeline Highlights ({len(container.timeline)})")
            for t in container.timeline[:10]:
                lines.append(f"- [{t.get('timestamp', 'N/A')}] {t.get('title', 'Event')}: {t.get('summary', '')}")
            lines.append("")

        if container.evidence:
            lines.append(f"#### Key Evidence ({len(container.evidence)})")
            for ev in container.evidence[:10]:
                lines.append(f"- Evidence ID `{ev.get('evidence_id', '')}`: {ev.get('name', 'Artifact')} ({ev.get('source', '')})")
            lines.append("")

        if container.sysmon_events:
            lines.append(f"#### Sysmon Events ({len(container.sysmon_events)})")
            for s in container.sysmon_events[:5]:
                lines.append(f"- EventID {s.get('event_id', 'N/A')}: Process `{s.get('image', '')}` -> Cmd: `{s.get('command_line', '')}`")
            lines.append("")

        if container.nmap_scans:
            lines.append(f"#### Nmap Discoveries ({len(container.nmap_scans)})")
            for n in container.nmap_scans[:5]:
                lines.append(f"- Host `{n.get('host', '')}`: Open Ports {n.get('open_ports', [])}")
            lines.append("")

        if container.tshark_captures:
            lines.append(f"#### TShark Network Flows ({len(container.tshark_captures)})")
            for ts in container.tshark_captures[:5]:
                lines.append(f"- Flow `{ts.get('src_ip', '')}:{ts.get('src_port', '')}` -> `{ts.get('dst_ip', '')}:{ts.get('dst_port', '')}` ({ts.get('protocol', '')})")
            lines.append("")

        if container.notes:
            lines.append(f"#### Analyst Notes ({len(container.notes)})")
            for note in container.notes[:5]:
                lines.append(f"- [{note.get('author', 'analyst')}]: {note.get('title', '')} - {note.get('content', '')}")
            lines.append("")

        return "\n".join(lines)

    def _enforce_token_budget(
        self, container: InvestigationContextContainer
    ) -> InvestigationContextContainer:
        """Truncates list lengths if estimated token count exceeds max_token_budget."""
        estimated_tokens = len(json.dumps(container.to_dict())) // 4
        if estimated_tokens > self.config.max_token_budget:
            # Progressively slice largest lists
            container.timeline = container.timeline[:10]
            container.evidence = container.evidence[:10]
            container.canonical_objects = container.canonical_objects[:10]
            container.sysmon_events = container.sysmon_events[:5]
            container.tshark_captures = container.tshark_captures[:5]
            container.nmap_scans = container.nmap_scans[:5]

        return container

    def _to_dict(self, obj: Any) -> Dict[str, Any]:
        """Converts dataclass or dictionary to pure Python dictionary."""
        if hasattr(obj, "to_dict") and callable(obj.to_dict):
            return obj.to_dict()
        if hasattr(obj, "__dataclass_fields__"):
            return asdict(obj)
        if isinstance(obj, dict):
            return obj
        return {"value": str(obj)}
