"""
NETFUSION IL-10: Enterprise Investigation Lifecycle Manager - Report Engine

Module to format, generate, and structure investigation reports across JSON, Markdown, HTML, and PDF formats.
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, Optional

from netfusion_investigation.lifecycle.models import Investigation, InvestigationLinks, Priority, Severity


class ReportEngine:
    """Renders investigation reports in various formats."""

    @staticmethod
    def generate_json_report(investigation: Investigation, extra_context: Optional[Dict[str, Any]] = None) -> str:
        data = {
            "report_type": "INVESTIGATION_LIFECYCLE_SUMMARY",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "investigation": investigation.to_dict(),
            "context": extra_context or {},
        }
        return json.dumps(data, indent=2)

    @staticmethod
    def generate_markdown_report(investigation: Investigation, extra_context: Optional[Dict[str, Any]] = None) -> str:
        ctx = extra_context or {}
        links = investigation.links
        md = f"""# Investigation Report: {investigation.title}

**Case ID:** {investigation.case_id}  
**Investigation ID:** `{investigation.id}`  
**Status:** `{investigation.status.value if hasattr(investigation.status, 'value') else investigation.status}`  
**Priority:** `{investigation.priority.value if hasattr(investigation.priority, 'value') else investigation.priority}`  
**Severity:** `{investigation.severity.value if hasattr(investigation.severity, 'value') else investigation.severity}`  
**Owner:** {investigation.owner} ({investigation.team})  
**Created:** {investigation.created_at}  

---

## Executive Summary
{investigation.description or 'No description provided.'}

## Linked Intelligence & Artifacts
- **Reasoning Sessions:** {len(links.reasoning_session_ids)}
- **Reasoning Traces:** {len(links.reasoning_trace_ids)}
- **Evidence Items:** {len(links.evidence_ids)}
- **Timeline Events:** {len(links.timeline_event_ids)}
- **Graph Nodes:** {len(links.graph_node_ids)}
- **Reports Generated:** {len(links.report_ids)}
- **Workflows:** {len(links.workflow_ids)}
- **IOCs:** {', '.join(links.ioc_values) if links.ioc_values else 'None'}
- **CVEs:** {', '.join(links.cve_ids) if links.cve_ids else 'None'}
- **Threat Actors:** {', '.join(links.threat_actors) if links.threat_actors else 'None'}

---

## Key Findings & Findings Context
{ctx.get('findings', 'No additional findings recorded.')}
"""
        return md

    @staticmethod
    def generate_html_report(investigation: Investigation, extra_context: Optional[Dict[str, Any]] = None) -> str:
        md = ReportEngine.generate_markdown_report(investigation, extra_context)
        # Convert simple markdown to basic clean HTML wrapper
        html_content = md.replace("# ", "<h1>").replace("\n\n", "<br/><br/>").replace("**", "<b>")
        return f"<!DOCTYPE html><html><head><title>{investigation.title}</title></head><body>{html_content}</body></html>"
