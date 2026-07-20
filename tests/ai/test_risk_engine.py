"""
Tests for NetFusion RiskEngine.
"""

import pytest

from netfusion_ai import RiskEngine, ContextBuilder
from netfusion_workflow.enums import Priority, BusinessImpact, Likelihood


def test_risk_engine_calculation():
    engine = RiskEngine()
    cb = ContextBuilder()

    context = cb.build_context(
        investigation={"investigation_id": "INV-RISK", "severity": "CRITICAL"},
        timeline=[{"title": f"Event {i}", "summary": "Alert"} for i in range(15)],
        iocs=[{"type": "ip", "value": f"1.1.1.{i}"} for i in range(10)],
    )

    risk = engine.calculate_risk(context)

    assert 0.0 <= risk.risk_score <= 10.0
    assert risk.risk_score >= 7.0
    assert risk.priority in (Priority.CRITICAL, Priority.HIGH)
    assert risk.business_impact == BusinessImpact.HIGH
    assert len(risk.suggested_response) > 0
    assert len(risk.contributing_factors) > 0
