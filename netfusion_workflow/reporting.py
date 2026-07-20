"""
NetFusion Reporting Preparation Engine
Aggregates report-ready metadata covering Executive Summary, Technical Summary,
Evidence Inventory, Timeline Snapshots, MITRE Coverage Matrices, Recommendations, and Appendices.
"""

from datetime import datetime
import time
from typing import Any, Dict, List, Optional

from .domain import Investigation, ReportReference
from .enums import CaseLifecycle, Priority, Severity


class ReportingEngine:
    """Engine for preparing structured executive and technical report metadata from an investigation."""

    @classmethod
    def generate_report_metadata(
        cls,
        investigation: Investigation,
        report_type: str = "EXECUTIVE",
        author: str = "SOC Analyst",
    ) -> Dict[str, Any]:
        """Generates comprehensive report-ready metadata structure."""
        now_ts = time.time()
        now_str = datetime.fromtimestamp(now_ts).strftime("%Y-%m-%d %H:%M:%S UTC")
        created_str = datetime.fromtimestamp(investigation.created_time).strftime("%Y-%m-%d %H:%M:%S UTC")
        closed_str = (
            datetime.fromtimestamp(investigation.closed_time).strftime("%Y-%m-%d %H:%M:%S UTC")
            if investigation.closed_time
            else "N/A"
        )

        # Executive Summary
        executive_summary = {
            "title": f"Security Incident Investigation Report: {investigation.title}",
            "investigation_id": investigation.investigation_id,
            "case_id": investigation.case_id or "N/A",
            "author": author,
            "report_date": now_str,
            "investigation_period": f"{created_str} to {closed_str}",
            "status": investigation.status.value if isinstance(investigation.status, CaseLifecycle) else str(investigation.status),
            "priority": investigation.priority.value if isinstance(investigation.priority, Priority) else str(investigation.priority),
            "severity": investigation.severity.value if isinstance(investigation.severity, Severity) else str(investigation.severity),
            "final_verdict": investigation.final_verdict or "Under Investigation",
            "summary_narrative": investigation.summary or investigation.description or "No summary provided.",
            "impact_overview": {
                "affected_assets_count": len(investigation.affected_assets),
                "affected_users_count": len(investigation.affected_users),
                "risk_score": investigation.risk_assessment.risk_score if investigation.risk_assessment else 0.0,
            },
        }

        # Technical Summary
        technical_summary = {
            "root_cause": investigation.root_cause or "Under Analysis",
            "findings": investigation.findings,
            "affected_assets": investigation.affected_assets,
            "affected_users": investigation.affected_users,
            "task_completion_status": {
                "total_tasks": len(investigation.tasks),
                "completed_tasks": sum(1 for t in investigation.tasks if t.status.value == "COMPLETED"),
            },
        }

        # Evidence Inventory
        evidence_list = [ev.to_dict() for ev in investigation.evidence_list]

        # Timeline Snapshot
        timeline_snapshot = [
            ev.to_dict() for ev in sorted(investigation.timeline, key=lambda x: x.timestamp)
        ]

        # MITRE ATT&CK Coverage
        mitre_coverage = {
            "tactics": list(set(m.tactic for m in investigation.mitre_mappings if m.tactic)),
            "techniques": [
                {
                    "technique_id": m.technique_id,
                    "technique_name": m.technique,
                    "tactic": m.tactic,
                    "sub_technique_id": m.sub_technique_id,
                }
                for m in investigation.mitre_mappings
            ],
            "total_techniques_mapped": len(investigation.mitre_mappings),
        }

        # Recommendations
        recommendations = [r.to_dict() for r in investigation.recommendations]

        # Appendices
        appendices = {
            "analyst_notes_count": len(investigation.notes),
            "audit_trail_reference": f"Audit logs for {investigation.investigation_id}",
            "raw_collector_sources": list(set(ev.source.value if hasattr(ev.source, "value") else str(ev.source) for ev in investigation.evidence_list)),
        }

        metadata = {
            "report_reference": ReportReference(
                title=executive_summary["title"],
                report_type=report_type,
            ).to_dict(),
            "executive_summary": executive_summary,
            "technical_summary": technical_summary,
            "evidence_list": evidence_list,
            "timeline": timeline_snapshot,
            "mitre_coverage": mitre_coverage,
            "recommendations": recommendations,
            "appendices": appendices,
        }

        return metadata
