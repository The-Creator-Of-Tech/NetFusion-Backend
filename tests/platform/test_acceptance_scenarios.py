"""
Integration test suite executing all 5 NetFusion Acceptance Investigation Scenarios.
"""

import pytest
from netfusion_platform.scenarios.runner import AcceptanceScenarioRunner


def test_all_five_acceptance_scenarios():
    runner = AcceptanceScenarioRunner()
    summaries = runner.run_all_scenarios()

    assert len(summaries) == 5, "Expected exactly 5 executed acceptance scenarios"

    for summary in summaries:
        assert summary.is_successful, f"Scenario {summary.scenario_id} ({summary.title}) failed quality gates."
        assert summary.timeline_count > 0
        assert summary.evidence_count > 0
        assert summary.has_ai_analysis
        assert summary.report is not None
        
        # Verify Report output markdown rendering
        md = summary.report.to_markdown()
        assert "## 1. Executive Summary" in md
        assert "## 2. Technical Deep-Dive" in md
        assert "## 3. Incident Timeline" in md
        assert "## 4. Evidence Appendix" in md
        assert "## 5. MITRE ATT&CK Matrix Mapping" in md
        assert "## 6. Indicator of Compromise (IOC) Summary" in md
        assert "## 7. Recommendations" in md
        assert "## 8. Compliance & Audit Appendix" in md
