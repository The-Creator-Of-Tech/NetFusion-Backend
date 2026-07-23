"""
Tests for ATRE Contradiction Engine.
"""

from netfusion_ai.reasoning import (
    ContradictionEngine,
    ContradictionType,
    GraphEvidence,
    Timeline,
)


def test_detect_conflicting_iocs():
    engine = ContradictionEngine()
    evidence = [
        GraphEvidence(
            evidence_id="ev-1",
            source_type="IOC",
            node_id="1.1.1.1",
            label="1.1.1.1",
            description="Benign IP",
            properties={"reputation": "BENIGN"},
        ),
        GraphEvidence(
            evidence_id="ev-2",
            source_type="IOC",
            node_id="1.1.1.1",
            label="1.1.1.1",
            description="Malicious C2 IP",
            properties={"reputation": "MALICIOUS"},
        ),
    ]

    contradictions = engine.detect_contradictions(
        evidence=evidence,
        subgraph={"nodes": [], "edges": []},
        timeline=Timeline(),
    )

    assert len(contradictions) >= 1
    assert contradictions[0].type == ContradictionType.CONFLICTING_IOCS
    assert len(contradictions[0].conflicting_evidence) == 2


def test_detect_missing_prerequisites():
    engine = ContradictionEngine()
    evidence = [
        GraphEvidence(
            evidence_id="ev-pers",
            source_type="ATTACK_PATTERN",
            node_id="T1543.003",
            label="Persistence Service",
            description="Persistence mechanism",
        )
    ]

    contradictions = engine.detect_contradictions(
        evidence=evidence,
        subgraph={"nodes": [], "edges": []},
        timeline=Timeline(),
    )

    prereq = [c for c in contradictions if c.type == ContradictionType.MISSING_PREREQUISITES]
    assert len(prereq) == 1
