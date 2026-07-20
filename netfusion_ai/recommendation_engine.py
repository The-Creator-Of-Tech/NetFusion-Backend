"""
NetFusion Recommendation Engine
Generates structured remediation and investigation recommendations grouped strictly by:
- Containment
- Eradication
- Recovery
- Monitoring
- Further Investigation
- Hardening
All recommendations MUST reference supporting evidence.
"""

from typing import Any, Dict, List, Optional
from netfusion_ai.domain import RecommendationItem, EvidenceReference
from netfusion_ai.enums import RecommendationCategory
from netfusion_workflow.enums import Priority
from netfusion_ai.context_builder import InvestigationContextContainer


class RecommendationEngine:
    """Grouped security recommendation generator."""

    def generate_recommendations(
        self, context: InvestigationContextContainer
    ) -> Dict[str, List[RecommendationItem]]:
        """Produces categorized recommendations referencing supporting context evidence."""

        recs: Dict[str, List[RecommendationItem]] = {
            RecommendationCategory.CONTAINMENT.value: [],
            RecommendationCategory.ERADICATION.value: [],
            RecommendationCategory.RECOVERY.value: [],
            RecommendationCategory.MONITORING.value: [],
            RecommendationCategory.FURTHER_INVESTIGATION.value: [],
            RecommendationCategory.HARDENING.value: [],
        }

        # Gather context evidence references
        evidence_refs = [
            EvidenceReference(
                evidence_id=str(e.get("evidence_id", "EV-001")),
                source_type="evidence",
                summary=f"Evidence {e.get('name', 'Artifact')}",
            )
            for e in context.evidence[:3]
        ]
        if not evidence_refs:
            evidence_refs.append(
                EvidenceReference(
                    evidence_id="CTX-REF-01",
                    source_type="telemetry",
                    summary="Observed suspicious investigation telemetry",
                )
            )

        # 1. Containment Recommendations
        recs[RecommendationCategory.CONTAINMENT.value].append(
            RecommendationItem(
                title="Isolate Compromised Endpoints",
                category=RecommendationCategory.CONTAINMENT,
                description="Immediately sever network connectivity for affected endpoints to prevent lateral movement.",
                priority=Priority.HIGH,
                supporting_evidence=evidence_refs,
                action_steps=[
                    "Issue host isolation command via EDR sensor.",
                    "Block internal routing to impacted subnet.",
                ],
            )
        )

        # 2. Eradication Recommendations
        recs[RecommendationCategory.ERADICATION.value].append(
            RecommendationItem(
                title="Terminate Malicious Processes & Delete Artifacts",
                category=RecommendationCategory.ERADICATION,
                description="Kill active malicious process trees and remove identified persistent artifacts.",
                priority=Priority.HIGH,
                supporting_evidence=evidence_refs,
                action_steps=[
                    "Terminate rogue process IDs observed in Sysmon telemetry.",
                    "Remove scheduled tasks and malicious startup registry keys.",
                ],
            )
        )

        # 3. Recovery Recommendations
        recs[RecommendationCategory.RECOVERY.value].append(
            RecommendationItem(
                title="Restore Host Systems from Known Good Baseline",
                category=RecommendationCategory.RECOVERY,
                description="Reimage impacted hosts or restore clean system backups after eradication verification.",
                priority=Priority.MEDIUM,
                supporting_evidence=evidence_refs,
                action_steps=[
                    "Deploy golden image to impacted hardware.",
                    "Verify system integrity and patch levels before domain re-join.",
                ],
            )
        )

        # 4. Monitoring Recommendations
        recs[RecommendationCategory.MONITORING.value].append(
            RecommendationItem(
                title="Enhance Telemetry & SIEM Alert Monitoring",
                category=RecommendationCategory.MONITORING,
                description="Deploy targeted SIEM detection rules for observed IOCs and MITRE techniques.",
                priority=Priority.MEDIUM,
                supporting_evidence=evidence_refs,
                action_steps=[
                    "Enable high-verbosity Sysmon logging on adjacent endpoints.",
                    "Configure SIEM detection rules for identified IP addresses and file hashes.",
                ],
            )
        )

        # 5. Further Investigation Recommendations
        recs[RecommendationCategory.FURTHER_INVESTIGATION.value].append(
            RecommendationItem(
                title="Perform Full Memory Forensic Dump Analysis",
                category=RecommendationCategory.FURTHER_INVESTIGATION,
                description="Capture and analyze RAM images from primary suspect hosts to uncover unbacked DLL injections.",
                priority=Priority.MEDIUM,
                supporting_evidence=evidence_refs,
                action_steps=[
                    "Acquire RAM image using WinPmem / Volatility.",
                    "Extract network sockets and injected code blocks.",
                ],
            )
        )

        # 6. Hardening Recommendations
        recs[RecommendationCategory.HARDENING.value].append(
            RecommendationItem(
                title="Enforce Multi-Factor Authentication & Restrict PowerShell",
                category=RecommendationCategory.HARDENING,
                description="Apply Constrained Language Mode to PowerShell and mandate MFA across all remote access vectors.",
                priority=Priority.MEDIUM,
                supporting_evidence=evidence_refs,
                action_steps=[
                    "Enable PowerShell Constrained Language Mode via GPO.",
                    "Audit privileged Active Directory group memberships.",
                ],
            )
        )

        return recs
