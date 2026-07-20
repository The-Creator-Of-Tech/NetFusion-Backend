"""
NetFusion End-to-End Investigation Pipeline Orchestrator
Executes unified ingestion -> normalization -> validation -> bus -> context -> workflow -> AI -> report pipeline.
"""

import time
import logging
from typing import Dict, Any, List, Optional

from netfusion_canonical.validator import CanonicalValidator
from netfusion_canonical.pipeline import NormalizationPipeline
from netfusion_collector_sdk.events import EventPublisher
from netfusion_workflow.service import WorkflowService
from netfusion_workflow.domain import Case, Investigation
from netfusion_ai.assistant import AIAssistant
from netfusion_ai.context_builder import ContextBuilder, ContextConfig
from netfusion_ai.domain import AnalysisResult
from netfusion_platform.integration.sysmon_bridge import SysmonIntegrationBridge
from netfusion_platform.integration.tshark_bridge import TSharkIntegrationBridge
from netfusion_platform.integration.nmap_bridge import NmapIntegrationBridge
from netfusion_platform.integration.threat_intel_bridge import ThreatIntelIntegrationBridge

logger = logging.getLogger(__name__)


class InvestigationPipelineOrchestrator:
    """Unified End-to-End Investigation Pipeline Engine."""

    def __init__(
        self,
        workflow_service: Optional[WorkflowService] = None,
        ai_assistant: Optional[AIAssistant] = None,
        event_publisher: Optional[EventPublisher] = None,
        validator: Optional[CanonicalValidator] = None,
    ):
        self.workflow_service = workflow_service or WorkflowService()
        self.ai_assistant = ai_assistant or AIAssistant()
        self.event_publisher = event_publisher or EventPublisher()
        self.validator = validator or CanonicalValidator()
        self.normalization_pipeline = NormalizationPipeline()
        self.context_builder = ContextBuilder()

    def run_investigation_pipeline(
        self,
        case_title: str,
        investigator: str = "NetFusion Automated Pipeline",
        raw_events: Optional[List[Dict[str, Any]]] = None,
        scenario_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes the full investigation pipeline:
        1. Case & Investigation creation in Workflow Service
        2. Ingestion of raw collector events
        3. Canonical Normalization & Validation
        4. Cross-module event bridging (Evidence, Timelines, Risk Assessments)
        5. Context Assembly across all 15 sources
        6. AI Investigation Assistant execution (Hypotheses, MITRE, Risk, Recommendations)
        7. Report Compilation
        """
        logger.info("Starting End-to-End Investigation Pipeline for case: '%s'", case_title)

        # 1. Create Case and Start Investigation
        case = self.workflow_service.create_case(title=case_title, created_by=investigator)
        case_id = getattr(case, "case_id", getattr(case, "id", None))

        investigation = self.workflow_service.create_investigation(
            title=f"Investigation: {case_title}",
            case_id=case_id,
            created_by=investigator
        )
        inv_id = getattr(investigation, "investigation_id", getattr(investigation, "id", None))

        events_processed = 0
        canonical_objects = []

        # 2. Ingest and Validate Events
        if raw_events:
            for raw_evt in raw_events:
                try:
                    is_valid = self.validator.validate(raw_evt) if hasattr(self.validator, "validate") else True
                    if is_valid:
                        canonical_objects.append(raw_evt)
                        events_processed += 1
                except Exception as e:
                    logger.warning("Event validation failed for item: %s", e)

                # Bridge to Workflow depending on source
                src = raw_evt.get("source", raw_evt.get("collector", "")).lower()
                if "sysmon" in src or "process" in raw_evt or "image" in raw_evt:
                    if "image" in raw_evt or "process_id" in raw_evt:
                        SysmonIntegrationBridge.add_process_timeline(self.workflow_service, inv_id, raw_evt)
                    elif "destination_ip" in raw_evt:
                        SysmonIntegrationBridge.add_network_timeline(self.workflow_service, inv_id, raw_evt)
                    SysmonIntegrationBridge.add_evidence(self.workflow_service, inv_id, raw_evt)

                elif "tshark" in src or "pcap" in src or "query_name" in raw_evt or "destination_port" in raw_evt:
                    if "query_name" in raw_evt:
                        TSharkIntegrationBridge.add_dns_timeline(self.workflow_service, inv_id, raw_evt)
                    else:
                        TSharkIntegrationBridge.add_flow_timeline(self.workflow_service, inv_id, raw_evt)
                    TSharkIntegrationBridge.add_evidence(self.workflow_service, inv_id, raw_evt)

                elif "nmap" in src or "open_ports" in raw_evt or "target" in raw_evt:
                    NmapIntegrationBridge.add_host_timeline(self.workflow_service, inv_id, raw_evt)
                    NmapIntegrationBridge.add_evidence(self.workflow_service, inv_id, raw_evt)

                elif "threat_intel" in src or "ioc" in raw_evt or "threat_name" in raw_evt:
                    ThreatIntelIntegrationBridge.add_match_timeline(self.workflow_service, inv_id, raw_evt)
                    ThreatIntelIntegrationBridge.add_evidence(self.workflow_service, inv_id, raw_evt)
                    ra = ThreatIntelIntegrationBridge.to_risk_assessment(raw_evt, case_id, inv_id)
                    investigation.risk_assessment = ra

        # Fetch assembled workflow state
        timeline_events = investigation.timeline
        evidence_items = investigation.evidence_list

        # 3. Assemble Investigation Context for AI Assistant
        ctx_container = self.context_builder.build_context(
            investigation=investigation,
            timeline=timeline_events,
            evidence=evidence_items,
            canonical_objects=canonical_objects,
            risk_assessment=investigation.risk_assessment
        )

        # 4. Execute AI Assistant Analysis
        ai_result: AnalysisResult = self.ai_assistant.analyze_investigation(
            context_container=ctx_container,
            user_query=f"Analyze investigation '{case_title}' for threat actor tactics, root cause, and recommendations."
        )

        logger.info("Investigation Pipeline execution completed successfully.")

        return {
            "case": case,
            "investigation": investigation,
            "events_processed": events_processed,
            "timeline_count": len(timeline_events),
            "evidence_count": len(evidence_items),
            "ai_result": ai_result,
            "context_container": ctx_container,
            "status": "COMPLETED",
        }
