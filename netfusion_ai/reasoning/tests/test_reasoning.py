"""
Tests for ATRE Reasoning Service & Intent Planner.
"""

import pytest
from netfusion_ai.reasoning import (
    ATREService,
    QuestionType,
    ReasoningPlanner,
    ReasoningRequest,
)


def test_intent_detection():
    planner = ReasoningPlanner()
    assert planner.detect_intent("What happened on server-01?") == QuestionType.WHAT_HAPPENED
    assert planner.detect_intent("Why did it happen?") == QuestionType.WHY_HAPPENED
    assert planner.detect_intent("What assets are at risk?") == QuestionType.ASSETS_AT_RISK
    assert planner.detect_intent("Which vulnerabilities are involved?") == QuestionType.VULNERABILITIES_INVOLVED
    assert planner.detect_intent("Show attack chain") == QuestionType.SHOW_ATTACK_CHAIN
    assert planner.detect_intent("Recommend containment actions") == QuestionType.RECOMMEND_CONTAINMENT
    assert planner.detect_intent("Generate executive summary") == QuestionType.EXEC_SUMMARY


def test_service_query_end_to_end():
    service = ATREService()
    req = ReasoningRequest(user_question="What happened regarding CVE-2023-34362 on host-web-01?")
    result = service.query(req)

    assert result is not None
    assert result.intent == QuestionType.WHAT_HAPPENED
    assert len(result.resolved_entities) >= 1
    assert result.confidence.overall_score > 0.0
    assert len(result.hypotheses) >= 1
    assert result.attack_chain.total_stages == 11
    assert len(result.recommendations) >= 5
    assert result.explanation.formatted_output != ""


def test_supported_question_types():
    service = ATREService()
    questions = [
        "What happened?",
        "Why did it happen?",
        "What is affected?",
        "What assets are at risk?",
        "What evidence supports this?",
        "Which vulnerabilities are involved?",
        "Which ATT&CK techniques are present?",
        "Which campaigns match?",
        "Which threat actor is most likely?",
        "Which malware families fit?",
        "Show attack chain.",
        "Show confidence.",
        "Recommend next investigation step.",
        "Recommend containment.",
        "Recommend remediation.",
        "Generate executive summary.",
        "Generate SOC report.",
        "Generate IR report.",
        "Generate analyst notes.",
    ]

    for q in questions:
        res = service.query(ReasoningRequest(user_question=q))
        assert res.intent != QuestionType.GENERAL_QUERY or q == "What happened?"
        assert res.explanation.formatted_output != ""
