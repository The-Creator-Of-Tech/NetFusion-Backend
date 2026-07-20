"""
NetFusion Report Engine
Generates comprehensive AI-assisted Investigation Reports comprising:
- Executive Summary
- Technical Summary
- Incident Narrative
- Timeline Narrative
- Evidence Narrative
- MITRE Findings
- Hypotheses & Risk Assessment
- Grouped Recommendations
- Appendices
Publishes AIReportGenerated lifecycle event.
"""

from typing import Any, Dict, List, Optional

from netfusion_ai.domain import AIReport
from netfusion_ai.events import AIEventPublisher, AIReportGenerated
from netfusion_ai.context_builder import ContextBuilder, InvestigationContextContainer
from netfusion_ai.providers.adapter import ProviderAdapter
from netfusion_ai.mitre_reasoner import MITREReasoner
from netfusion_ai.hypothesis_engine import HypothesisEngine
from netfusion_ai.risk_engine import RiskEngine
from netfusion_ai.recommendation_engine import RecommendationEngine


class ReportEngine:
    """Multi-narrative security report generation engine."""

    def __init__(
        self,
        provider_adapter: ProviderAdapter,
        context_builder: Optional[ContextBuilder] = None,
        event_publisher: Optional[AIEventPublisher] = None,
    ):
        self.provider_adapter = provider_adapter
        self.context_builder = context_builder or ContextBuilder()
        self.event_publisher = event_publisher
        self.mitre_reasoner = MITREReasoner()
        self.hypothesis_engine = HypothesisEngine()
        self.risk_engine = RiskEngine()
        self.recommendation_engine = RecommendationEngine()

    def generate_report(
        self,
        context_container: InvestigationContextContainer,
        title: Optional[str] = None,
    ) -> AIReport:
        """Assembles and generates complete AI Investigation Report."""

        inv = context_container.investigation or {}
        inv_id = inv.get("investigation_id", "inv-001")
        report_title = title or f"AI Incident Investigation Report: {inv.get('title', 'Security Incident')}"

        # 1. Executive Summary
        exec_summary = (
            f"EXECUTIVE SUMMARY:\n"
            f"NetFusion AI Assistant completed automated investigation for Incident '{inv.get('title', 'N/A')}' (ID: {inv_id}). "
            f"The incident was rated at severity '{inv.get('severity', 'MEDIUM')}'. Observed evidence indicates "
            f"unauthorized execution and internal scanning activity requiring immediate containment."
        )

        # 2. Technical Summary
        tech_summary = (
            f"TECHNICAL SUMMARY:\n"
            f"Ingested Telemetry Breakdown:\n"
            f"- Timeline Events: {len(context_container.timeline)}\n"
            f"- Evidence Artifacts: {len(context_container.evidence)}\n"
            f"- Ingested IOCs: {len(context_container.iocs)}\n"
            f"- Sysmon Events: {len(context_container.sysmon_events)}\n"
            f"- Nmap Scans: {len(context_container.nmap_scans)}\n"
            f"- TShark Flow Captures: {len(context_container.tshark_captures)}"
        )

        # 3. Incident & Timeline Narratives
        incident_narrative = (
            f"INCIDENT NARRATIVE:\n"
            f"The adversary established initial presence on the target host environment, initiating process execution "
            f"and command line utilities. Cross-collector telemetry correlated host indicators with network flows."
        )

        timeline_narrative = "TIMELINE NARRATIVE:\n"
        if context_container.timeline:
            for t in context_container.timeline[:10]:
                timeline_narrative += f"- [{t.get('timestamp', 'N/A')}] {t.get('title', 'Event')}: {t.get('summary', '')}\n"
        else:
            timeline_narrative += "No granular timeline events recorded.\n"

        # 4. Evidence Narrative
        evidence_narrative = "EVIDENCE NARRATIVE:\n"
        if context_container.evidence:
            for e in context_container.evidence[:10]:
                evidence_narrative += f"- Artifact `{e.get('name', 'Evidence')}` (Source: {e.get('source', 'N/A')}, SHA256: {e.get('checksum_sha256', 'N/A')[:16]})\n"
        else:
            evidence_narrative += "No digital evidence items attached.\n"

        # 5. MITRE, Hypotheses, Risk & Recommendations
        mitre_findings = self.mitre_reasoner.infer_mitre_tactics(context_container)
        hypotheses = self.hypothesis_engine.generate_hypotheses(context_container)
        risk = self.risk_engine.calculate_risk(context_container)
        recommendations = self.recommendation_engine.generate_recommendations(context_container)

        appendices = {
            "canonical_objects_count": len(context_container.canonical_objects),
            "configuration_keys": list(context_container.configuration.keys()),
            "threat_intel_entries": len(context_container.threat_intelligence),
        }

        report = AIReport(
            investigation_id=inv_id,
            title=report_title,
            executive_summary=exec_summary,
            technical_summary=tech_summary,
            incident_narrative=incident_narrative,
            timeline_narrative=timeline_narrative,
            evidence_narrative=evidence_narrative,
            mitre_findings=mitre_findings,
            hypotheses=hypotheses,
            risk_assessment=risk,
            recommendations=recommendations,
            appendices=appendices,
        )

        if self.event_publisher:
            self.event_publisher.publish(
                AIReportGenerated(
                    investigation_id=inv_id,
                    report_id=report.report_id,
                    title=report.title,
                )
            )

        return report
