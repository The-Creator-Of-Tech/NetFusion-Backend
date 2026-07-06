"""
Smoke Test — Timeline Intelligence Engine (Phase A4.0.5)
=========================================================
Builds synthetic forensic objects, runs the full timeline pipeline,
and asserts every required property.

Run with:
    python smoke_test_timeline_intelligence.py

Minimum 90 assertions.  Exit code 0 = ALL PASSED.
"""

from __future__ import annotations

import sys
import time
from datetime import datetime, timezone, timedelta
from typing import List

# ── Engine under test ─────────────────────────────────────────────────────
from services.timeline_intelligence_service import (
    TIMELINE_INTELLIGENCE_ENGINE_VERSION,
    TimelineBundle,
    TimelineEvent,
    TimelineEventType,
    TimelineExplanation,
    TimelineSeverity,
    TimelineSourceType,
    TimelineStatistics,
    build_alert_events,
    build_attack_events,
    build_evidence_events,
    build_finding_events,
    build_history_events,
    build_mitre_events,
    build_relationship_events,
    build_relationship_history_events,
    build_timeline,
    build_timeline_event,
    build_timeline_statistics,
    filter_timeline,
    group_timeline,
    search_timeline,
    sort_timeline,
    timeline_between,
    timeline_for_asset,
    timeline_for_capture,
    timeline_for_relationship,
    _timeline_fingerprint,
)

from core.constants import TIMELINE_INTELLIGENCE_ENGINE_VERSION as _VER_CONST

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
_failures: List[str] = []


def _assert(cond: bool, msg: str) -> None:
    status = PASS if cond else FAIL
    print(f"  {status} {msg}")
    if not cond:
        _failures.append(msg)


# ---------------------------------------------------------------------------
# Synthetic data factories
# ---------------------------------------------------------------------------

_T0 = datetime(2026, 6, 1, 10, 0, 0, tzinfo=timezone.utc)
_T1 = _T0 + timedelta(seconds=10)
_T2 = _T0 + timedelta(seconds=20)
_T3 = _T0 + timedelta(seconds=30)
_T4 = _T0 + timedelta(seconds=40)
_T5 = _T0 + timedelta(seconds=50)


def _make_evidence() -> list:
    class FakeRef:
        captureId    = "cap-001"
        packetNumber = 42
    class FakeSource:
        sourceType = "pcap"
        confidence = 70
    class Ev:
        evidenceId  = "ev-aaa"
        assetId     = "asset-001"
        fieldName   = "ipAddress"
        fieldValue  = "192.168.1.10"
        confidence  = 70
        observedAt  = _T0
        createdAt   = _T0
        reference   = FakeRef()
        source      = FakeSource()
    class Ev2:
        evidenceId  = "ev-bbb"
        assetId     = "asset-002"
        fieldName   = "hostname"
        fieldValue  = "workstation-01"
        confidence  = 85
        observedAt  = _T1
        createdAt   = _T1
        reference   = FakeRef()
        source      = FakeSource()
    return [Ev(), Ev2()]


def _make_relationships() -> list:
    return [
        {
            "relationshipId" : "rel-001",
            "sourceAssetId"  : "asset-001",
            "targetAssetId"  : "asset-002",
            "protocol"       : "HTTP",
            "confidence"     : 75,
            "packetCount"    : 12,
            "firstSeen"      : _T0,
            "lastSeen"       : _T3,
            "captureId"      : "cap-001",
            "evidenceIds"    : ["ev-aaa"],
        },
        {
            "relationshipId" : "rel-002",
            "sourceAssetId"  : "asset-001",
            "targetAssetId"  : "external-203.0.113.1",
            "protocol"       : "HTTPS",
            "confidence"     : 60,
            "packetCount"    : 5,
            "firstSeen"      : _T1,
            "lastSeen"       : _T1,   # no update event
            "captureId"      : "cap-001",
            "evidenceIds"    : [],
        },
    ]


def _make_history_events() -> list:
    class FakeHistEvent:
        eventId     = "hist-001"
        assetId     = "asset-001"
        evidenceId  = "ev-aaa"
        eventType   = type("ET", (), {"value": "OBSERVED"})()
        fieldName   = "ipAddress"
        fieldValue  = "192.168.1.10"
        sourceType  = "pcap"
        captureId   = "cap-001"
        packetNumber= 42
        occurredAt  = _T0
        summary     = "ipAddress=192.168.1.10 observed via pcap [cap-001, pkt=42]"
        metadata    = {"confidence": 70}
    class FakeHistEvent2:
        eventId     = "hist-002"
        assetId     = "asset-002"
        evidenceId  = "ev-bbb"
        eventType   = type("ET2", (), {"value": "VERIFIED"})()
        fieldName   = "hostname"
        fieldValue  = "workstation-01"
        sourceType  = "dhcp"
        captureId   = "cap-001"
        packetNumber= 55
        occurredAt  = _T2
        summary     = "hostname verified"
        metadata    = {"confidence": 90}
    return [FakeHistEvent(), FakeHistEvent2()]


def _make_rel_history() -> list:
    return [
        {
            "eventId"           : "relh-001",
            "relationshipId"    : "rel-001",
            "eventType"         : type("ET", (), {"value": "CREATED"})(),
            "currentConfidence" : 75,
            "captureId"         : "cap-001",
            "packetNumber"      : 1,
            "occurredAt"        : _T0,
            "summary"           : "[rel-001] CREATED — state=NEW confidence=75",
        },
        {
            "eventId"           : "relh-002",
            "relationshipId"    : "rel-001",
            "eventType"         : type("ET", (), {"value": "EVIDENCE_ADDED"})(),
            "currentConfidence" : 80,
            "captureId"         : "cap-001",
            "packetNumber"      : 12,
            "occurredAt"        : _T2,
            "summary"           : "[rel-001] EVIDENCE_ADDED",
        },
    ]


def _make_attack_chains() -> list:
    class FakeStage:
        value = "COMMAND_AND_CONTROL"
    class FakeChain:
        chainId          = "chain-abc"
        name             = "Chain-1: C2 Server"
        nodes            = ["n1", "n2", "n3"]
        edges            = ["e1", "e2"]
        totalRisk        = 240
        confidence       = 78
        attackStages     = [FakeStage()]
        evidenceIds      = ["ev-aaa"]
        findings         = ["[HIGH] Malware Beacon"]
        chainFingerprint = "a" * 32
        metadata         = {}
    return [FakeChain()]


def _make_attack_patterns() -> list:
    class FakeSev:
        value = "HIGH"
    return [
        {
            "patternId"      : "pat-001",
            "patternType"    : type("PT", (), {"value": "BEACONING"})(),
            "title"          : "Periodic Beacon Detected",
            "description"    : "Internal asset beaconing to external host.",
            "confidence"     : 65,
            "severity"       : FakeSev(),
            "mitreTechniques": ["T1071", "T1071.001"],
            "involvedNodes"  : ["n1"],
        },
        {
            "patternId"      : "pat-002",
            "patternType"    : type("PT2", (), {"value": "LATERAL_MOVEMENT"})(),
            "title"          : "Lateral Movement Pattern",
            "description"    : "Internal asset-to-asset movement.",
            "confidence"     : 57,
            "severity"       : FakeSev(),
            "mitreTechniques": ["T1021"],
            "involvedNodes"  : ["n1", "n2"],
        },
    ]


def _make_blast_radii() -> list:
    return [
        {
            "sourceNode"     : "asset-001",
            "reachableNodes" : ["asset-002", "asset-003"],
            "affectedAssets" : ["asset-002"],
            "maximumDepth"   : 2,
            "estimatedImpact": "HIGH",
            "riskScore"      : 70,
        }
    ]


def _make_intel_findings() -> list:
    class FakeSev:
        value = "HIGH"
    return [
        {
            "findingId"      : "finding-001",
            "title"          : "Lateral Movement from Workstation 01",
            "description"    : "Asset propagating to internal hosts.",
            "confidence"     : 70,
            "severity"       : FakeSev(),
            "mitreTechniques": ["T1021"],
            "recommendation" : "Isolate the host.",
        },
        {
            "findingId"      : "finding-002",
            "title"          : "Pivot Node: Server 02",
            "description"    : "Server bridges multiple attack paths.",
            "confidence"     : 80,
            "severity"       : FakeSev(),
            "mitreTechniques": ["T1021", "T1563"],
            "recommendation" : "Monitor closely.",
        },
        {
            "findingId"      : "finding-003",
            "title"          : "Choke Point: Workstation 01",
            "description"    : "Articulation point in graph.",
            "confidence"     : 60,
            "severity"       : FakeSev(),
            "mitreTechniques": ["T1046"],
            "recommendation" : "Harden this node.",
        },
        {
            "findingId"      : "finding-004",
            "title"          : "MITRE T1071.001: Web Protocols",
            "description"    : "ATT&CK technique evidence.",
            "confidence"     : 90,
            "severity"       : FakeSev(),
            "mitreTechniques": ["T1071.001"],
            "recommendation" : "Investigate.",
        },
    ]


def _make_alerts() -> list:
    return [
        {
            "id"         : "alert-001",
            "title"      : "Beacon Alert",
            "description": "Beaconing detected on workstation.",
            "severity"   : "high",
            "asset"      : "asset-001",
            "occurredAt" : _T4,
        }
    ]


def _make_findings() -> list:
    return [
        {
            "id"         : "raw-finding-001",
            "type"       : "Legacy SSL Usage",
            "description": "Legacy SSL detected.",
            "severity"   : "medium",
            "asset"      : "asset-001",
        }
    ]


def _make_mitre() -> list:
    return [
        {
            "id"     : "T1071",
            "name"   : "Application Layer Protocol",
            "tactic" : "command-and-control",
        },
        {
            "id"     : "T1046",
            "name"   : "Network Service Discovery",
            "tactic" : "discovery",
        },
    ]


# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------

def run_smoke_test() -> None:
    print("\n" + "=" * 66)
    print("  Phase A4.0.5 — Timeline Intelligence Engine Smoke Test")
    print("=" * 66)

    t_global = time.monotonic()

    # ── [1] Engine Version ─────────────────────────────────────────────────
    print("\n[1] Engine Version")
    _assert(bool(TIMELINE_INTELLIGENCE_ENGINE_VERSION), "TIMELINE_INTELLIGENCE_ENGINE_VERSION defined")
    _assert(_VER_CONST == TIMELINE_INTELLIGENCE_ENGINE_VERSION, "Constant exported from core.constants")
    _assert(TIMELINE_INTELLIGENCE_ENGINE_VERSION == "timeline-intelligence-v1",
            f"Version string correct: {TIMELINE_INTELLIGENCE_ENGINE_VERSION}")

    # ── [2] build_timeline_event() ─────────────────────────────────────────
    print("\n[2] build_timeline_event()")
    ev = build_timeline_event(
        TimelineEventType.OBSERVED,
        occurred_at   = _T0,
        title         = "Test Event",
        summary       = "Observed something.",
        severity      = TimelineSeverity.MEDIUM,
        confidence    = 70,
        source_type   = TimelineSourceType.EVIDENCE,
        asset_id      = "asset-001",
        packet_number = 42,
        capture_id    = "cap-001",
    )
    _assert(isinstance(ev, TimelineEvent), "Returns TimelineEvent instance")
    _assert(bool(ev.eventId),    "eventId is non-empty")
    _assert(bool(ev.eventKey),   "eventKey is non-empty")
    _assert(len(ev.eventId) == 32,  "eventId is 32 chars")
    _assert(len(ev.eventKey) == 32, "eventKey is 32 chars")
    _assert(ev.eventType   == TimelineEventType.OBSERVED,       "eventType correct")
    _assert(ev.severity    == TimelineSeverity.MEDIUM,          "severity correct")
    _assert(ev.sourceType  == TimelineSourceType.EVIDENCE,      "sourceType correct")
    _assert(ev.confidence  == 70,   "confidence correct")
    _assert(ev.assetId     == "asset-001", "assetId correct")
    _assert(ev.packetNumber== 42,   "packetNumber correct")
    _assert(ev.captureId   == "cap-001", "captureId correct")
    _assert(ev.timelinePosition == 0, "timelinePosition defaults to 0")
    # Determinism
    ev2 = build_timeline_event(
        TimelineEventType.OBSERVED,
        occurred_at=_T0, title="Test Event", summary="Observed something.",
        severity=TimelineSeverity.MEDIUM, confidence=70,
        source_type=TimelineSourceType.EVIDENCE,
        asset_id="asset-001", packet_number=42, capture_id="cap-001",
    )
    _assert(ev.eventKey == ev2.eventKey, "Same inputs → same eventKey (deterministic)")
    _assert(ev.eventId  == ev2.eventId,  "Same inputs → same eventId (deterministic)")
    # Immutability
    try:
        ev.title = "mutated"  # type: ignore[misc]
        _assert(False, "TimelineEvent should be frozen")
    except Exception:
        _assert(True, "TimelineEvent is immutable (frozen=True)")

    # ── [3] build_evidence_events() ────────────────────────────────────────
    print("\n[3] build_evidence_events()")
    ev_evts = build_evidence_events(_make_evidence())
    _assert(isinstance(ev_evts, list), "Returns list")
    _assert(len(ev_evts) == 2, f"2 evidence events built (got {len(ev_evts)})")
    for e in ev_evts:
        _assert(e.eventType == TimelineEventType.EVIDENCE_ADDED, f"eventType=EVIDENCE_ADDED: {e.title[:30]}")
        _assert(e.sourceType == TimelineSourceType.EVIDENCE, "sourceType=EVIDENCE")
        _assert(bool(e.evidenceId), "evidenceId populated")

    # ── [4] build_relationship_events() ────────────────────────────────────
    print("\n[4] build_relationship_events()")
    rel_evts = build_relationship_events(_make_relationships())
    _assert(isinstance(rel_evts, list), "Returns list")
    _assert(len(rel_evts) >= 2, f"At least 2 relationship events (got {len(rel_evts)})")
    created = [e for e in rel_evts if e.eventType == TimelineEventType.RELATIONSHIP_CREATED]
    updated = [e for e in rel_evts if e.eventType == TimelineEventType.RELATIONSHIP_UPDATED]
    _assert(len(created) == 2, f"2 RELATIONSHIP_CREATED events (got {len(created)})")
    _assert(len(updated) == 1, f"1 RELATIONSHIP_UPDATED event for rel with lastSeen>firstSeen (got {len(updated)})")
    for e in rel_evts:
        _assert(bool(e.relationshipId), "relationshipId populated")
        _assert(e.sourceType == TimelineSourceType.RELATIONSHIP, "sourceType=RELATIONSHIP")

    # ── [5] build_history_events() ─────────────────────────────────────────
    print("\n[5] build_history_events()")
    h_evts = build_history_events(_make_history_events())
    _assert(len(h_evts) == 2, f"2 history events built (got {len(h_evts)})")
    for e in h_evts:
        _assert(e.eventType == TimelineEventType.HISTORY_CREATED, "eventType=HISTORY_CREATED")
        _assert(e.sourceType == TimelineSourceType.HISTORY, "sourceType=HISTORY")
        _assert(bool(e.historyEventId), "historyEventId populated")

    # ── [6] build_relationship_history_events() ─────────────────────────────
    print("\n[6] build_relationship_history_events()")
    rh_evts = build_relationship_history_events(_make_rel_history())
    _assert(len(rh_evts) == 2, f"2 rel-history events (got {len(rh_evts)})")
    for e in rh_evts:
        _assert(e.sourceType == TimelineSourceType.RELATIONSHIP_HISTORY, "sourceType=RELATIONSHIP_HISTORY")
        _assert(bool(e.relationshipId), "relationshipId populated")

    # ── [7] build_attack_events() ──────────────────────────────────────────
    print("\n[7] build_attack_events()")
    atk_evts = build_attack_events(
        attack_chains   = _make_attack_chains(),
        attack_patterns = _make_attack_patterns(),
        blast_radii     = _make_blast_radii(),
        intel_findings  = _make_intel_findings(),
    )
    _assert(len(atk_evts) > 0, f"Attack events built (got {len(atk_evts)})")
    chain_evts = [e for e in atk_evts if e.eventType == TimelineEventType.ATTACK_CHAIN]
    pat_evts   = [e for e in atk_evts if e.eventType == TimelineEventType.ATTACK_PATTERN]
    br_evts    = [e for e in atk_evts if e.eventType == TimelineEventType.BLAST_RADIUS]
    lat_evts   = [e for e in atk_evts if e.eventType == TimelineEventType.LATERAL_MOVEMENT]
    pivot_evts = [e for e in atk_evts if e.eventType == TimelineEventType.PIVOT]
    choke_evts = [e for e in atk_evts if e.eventType == TimelineEventType.CHOKE_POINT]
    mitre_evts_atk = [e for e in atk_evts if e.eventType == TimelineEventType.MITRE_MAPPED]
    _assert(len(chain_evts) == 1, f"1 ATTACK_CHAIN event (got {len(chain_evts)})")
    _assert(len(pat_evts)   == 1, f"1 ATTACK_PATTERN event for BEACONING (got {len(pat_evts)})")
    _assert(len(br_evts)    == 1, f"1 BLAST_RADIUS event (got {len(br_evts)})")
    _assert(len(lat_evts)   >= 1, f"≥1 LATERAL_MOVEMENT event (got {len(lat_evts)})")
    _assert(len(pivot_evts) >= 1, f"≥1 PIVOT event (got {len(pivot_evts)})")
    _assert(len(choke_evts) >= 1, f"≥1 CHOKE_POINT event (got {len(choke_evts)})")
    _assert(len(mitre_evts_atk) >= 1, f"≥1 MITRE_MAPPED event from intel findings (got {len(mitre_evts_atk)})")

    # ── [8] build_alert_events() ───────────────────────────────────────────
    print("\n[8] build_alert_events()")
    a_evts = build_alert_events(_make_alerts())
    _assert(len(a_evts) == 1, f"1 alert event (got {len(a_evts)})")
    _assert(a_evts[0].eventType == TimelineEventType.ALERT_GENERATED, "eventType=ALERT_GENERATED")
    _assert(a_evts[0].severity  == TimelineSeverity.HIGH, "alert severity=HIGH")
    _assert(a_evts[0].alertId   == "alert-001", "alertId populated")

    # ── [9] build_finding_events() ─────────────────────────────────────────
    print("\n[9] build_finding_events()")
    f_evts = build_finding_events(_make_findings())
    _assert(len(f_evts) == 1, f"1 finding event (got {len(f_evts)})")
    _assert(f_evts[0].eventType == TimelineEventType.FINDING_CREATED, "eventType=FINDING_CREATED")

    # ── [10] build_mitre_events() ──────────────────────────────────────────
    print("\n[10] build_mitre_events()")
    m_evts = build_mitre_events(_make_mitre())
    _assert(len(m_evts) == 2, f"2 MITRE events (got {len(m_evts)})")
    for e in m_evts:
        _assert(e.eventType == TimelineEventType.MITRE_MAPPED, "eventType=MITRE_MAPPED")
        _assert(bool(e.mitreTechnique), "mitreTechnique populated")

    # ── [11] sort_timeline() ───────────────────────────────────────────────
    print("\n[11] sort_timeline() — sorting and timelinePosition")
    ev_a = build_timeline_event(TimelineEventType.OBSERVED, occurred_at=_T2,
                                 confidence=50, source_type=TimelineSourceType.EVIDENCE)
    ev_b = build_timeline_event(TimelineEventType.EVIDENCE_ADDED, occurred_at=_T0,
                                 confidence=50, source_type=TimelineSourceType.EVIDENCE)
    ev_c = build_timeline_event(TimelineEventType.ALERT_GENERATED, occurred_at=_T1,
                                 confidence=50, source_type=TimelineSourceType.INTELLIGENCE)
    unsorted = [ev_a, ev_b, ev_c]
    sorted_evs = sort_timeline(unsorted)
    _assert(len(sorted_evs) == 3, "sort_timeline returns same count")
    _assert(sorted_evs[0].occurredAt == _T0, "First event has earliest occurredAt")
    _assert(sorted_evs[1].occurredAt == _T1, "Second event has middle occurredAt")
    _assert(sorted_evs[2].occurredAt == _T2, "Third event has latest occurredAt")
    positions = [e.timelinePosition for e in sorted_evs]
    _assert(positions == [0, 1, 2], f"timelinePosition is [0,1,2]: {positions}")
    # Idempotent: sort twice → same result
    sorted_twice = sort_timeline(sorted_evs)
    _assert([e.eventKey for e in sorted_twice] == [e.eventKey for e in sorted_evs],
            "sort_timeline is idempotent")

    # Same-timestamp tiebreaker by packetNumber
    ev_p1 = build_timeline_event(TimelineEventType.OBSERVED, occurred_at=_T0,
                                   packet_number=1, source_type=TimelineSourceType.EVIDENCE)
    ev_p2 = build_timeline_event(TimelineEventType.EVIDENCE_ADDED, occurred_at=_T0,
                                   packet_number=5, source_type=TimelineSourceType.EVIDENCE)
    ev_p3 = build_timeline_event(TimelineEventType.HISTORY_CREATED, occurred_at=_T0,
                                   packet_number=None, source_type=TimelineSourceType.HISTORY)
    sorted_pkt = sort_timeline([ev_p3, ev_p1, ev_p2])
    _assert(sorted_pkt[0].packetNumber == 1, "Packet 1 sorts before packet 5 (same timestamp)")
    _assert(sorted_pkt[1].packetNumber == 5, "Packet 5 sorts after packet 1")
    _assert(sorted_pkt[2].packetNumber is None, "None packetNumber sorts last")

    # None occurredAt sorts last
    ev_none = build_timeline_event(TimelineEventType.MANUAL_ACTION, occurred_at=None,
                                    source_type=TimelineSourceType.MANUAL)
    ev_ts   = build_timeline_event(TimelineEventType.OBSERVED, occurred_at=_T0,
                                    source_type=TimelineSourceType.EVIDENCE)
    sorted_none = sort_timeline([ev_none, ev_ts])
    _assert(sorted_none[0].occurredAt == _T0,  "Event with timestamp sorts before None")
    _assert(sorted_none[1].occurredAt is None, "None occurredAt sorts last")

    # ── [12] _timeline_fingerprint() ──────────────────────────────────────
    print("\n[12] _timeline_fingerprint()")
    fp1 = _timeline_fingerprint(["k1", "k2", "k3"])
    fp2 = _timeline_fingerprint(["k1", "k2", "k3"])
    fp3 = _timeline_fingerprint(["k1", "k2", "k4"])
    fp_empty = _timeline_fingerprint([])
    _assert(fp1 == fp2, "Same keys → same fingerprint (deterministic)")
    _assert(fp1 != fp3, "Different keys → different fingerprint")
    _assert(len(fp1) == 32, "Fingerprint is 32 chars")
    _assert(fp_empty == "0" * 32, "Empty → 32 zeros")

    # ── [13] build_timeline_statistics() ──────────────────────────────────
    print("\n[13] build_timeline_statistics()")
    test_evts = sort_timeline([
        build_timeline_event(TimelineEventType.EVIDENCE_ADDED, occurred_at=_T0,
                              severity=TimelineSeverity.HIGH, confidence=80,
                              source_type=TimelineSourceType.EVIDENCE),
        build_timeline_event(TimelineEventType.ALERT_GENERATED, occurred_at=_T2,
                              severity=TimelineSeverity.CRITICAL, confidence=90,
                              source_type=TimelineSourceType.INTELLIGENCE),
        build_timeline_event(TimelineEventType.MITRE_MAPPED, occurred_at=_T3,
                              severity=TimelineSeverity.MEDIUM, confidence=60,
                              source_type=TimelineSourceType.INTELLIGENCE),
    ])
    stats = build_timeline_statistics(test_evts)
    _assert(isinstance(stats, TimelineStatistics), "Returns TimelineStatistics")
    _assert(stats.totalEvents == 3, f"totalEvents=3 (got {stats.totalEvents})")
    _assert(stats.firstSeen == _T0, "firstSeen = T0")
    _assert(stats.lastSeen  == _T3, "lastSeen  = T3")
    _assert(stats.durationSeconds == (_T3 - _T0).total_seconds(),
            f"durationSeconds correct: {stats.durationSeconds}")
    _assert("EVIDENCE_ADDED"  in stats.eventsByType,   "EVIDENCE_ADDED in eventsByType")
    _assert("ALERT_GENERATED" in stats.eventsByType,   "ALERT_GENERATED in eventsByType")
    _assert("MITRE_MAPPED"    in stats.eventsByType,   "MITRE_MAPPED in eventsByType")
    _assert("CRITICAL"        in stats.eventsBySeverity, "CRITICAL in eventsBySeverity")
    _assert("HIGH"            in stats.eventsBySeverity, "HIGH in eventsBySeverity")
    _assert("EVIDENCE"        in stats.eventsBySource,   "EVIDENCE in eventsBySource")
    _assert("INTELLIGENCE"    in stats.eventsBySource,   "INTELLIGENCE in eventsBySource")
    # Empty statistics
    empty_stats = build_timeline_statistics([])
    _assert(empty_stats.totalEvents == 0, "Empty stats: totalEvents=0")
    _assert(empty_stats.firstSeen is None, "Empty stats: firstSeen=None")

    # ── [14] Full build_timeline() ─────────────────────────────────────────
    print("\n[14] Full build_timeline() pipeline")
    t0_build = time.monotonic()
    bundle = build_timeline(
        evidence             = _make_evidence(),
        relationships        = _make_relationships(),
        history_events       = _make_history_events(),
        relationship_history = _make_rel_history(),
        attack_chains        = _make_attack_chains(),
        attack_patterns      = _make_attack_patterns(),
        blast_radii          = _make_blast_radii(),
        intel_findings       = _make_intel_findings(),
        alerts               = _make_alerts(),
        findings             = _make_findings(),
        mitre                = _make_mitre(),
    )
    t1_build = time.monotonic()

    _assert(isinstance(bundle, TimelineBundle), "Returns TimelineBundle")
    _assert(bundle.engineVersion == TIMELINE_INTELLIGENCE_ENGINE_VERSION,
            f"engineVersion correct: {bundle.engineVersion}")
    _assert(len(bundle.events) > 0, f"bundle.events non-empty (got {len(bundle.events)})")
    _assert(bool(bundle.timelineFingerprint), "timelineFingerprint non-empty")
    _assert(len(bundle.timelineFingerprint) == 32, "timelineFingerprint is 32 chars")
    _assert(bundle.timelineFingerprint != "0" * 32, "timelineFingerprint is not zero")
    _assert(isinstance(bundle.statistics,  TimelineStatistics),  "statistics is TimelineStatistics")
    _assert(isinstance(bundle.explanation, TimelineExplanation), "explanation is TimelineExplanation")
    _assert(len(bundle.explanation.reasoningSteps)  > 0, "explanation has reasoningSteps")
    _assert(len(bundle.explanation.algorithmsUsed)  > 0, "explanation has algorithmsUsed")
    _assert(len(bundle.explanation.processingStages)> 0, "explanation has processingStages")
    _assert(bundle.explanation.processingTimeMs     >= 0, "processingTimeMs ≥ 0")
    _assert(bundle.statistics.totalEvents == len(bundle.events),
            "statistics.totalEvents matches len(events)")

    # timelinePosition monotonic
    positions = [e.timelinePosition for e in bundle.events]
    _assert(positions == list(range(len(positions))),
            "timelinePosition is monotonic 0..N-1")

    # Sorted by canonical key
    for i in range(len(bundle.events) - 1):
        a = bundle.events[i]
        b = bundle.events[i + 1]
        a_ts = a.occurredAt if a.occurredAt is not None else datetime.max.replace(tzinfo=timezone.utc)
        b_ts = b.occurredAt if b.occurredAt is not None else datetime.max.replace(tzinfo=timezone.utc)
        _assert(a_ts <= b_ts, f"Events sorted by occurredAt: pos {i} ≤ pos {i+1}")

    # All event types are strings
    for e in bundle.events:
        _assert(isinstance(e.eventType.value, str), f"eventType.value is str: {e.eventType.value}")
        _assert(isinstance(e.sourceType.value, str),"sourceType.value is str")
        _assert(e.confidence >= 0 and e.confidence <= 100, f"confidence in [0,100]: {e.confidence}")

    # ── [15] Determinism ───────────────────────────────────────────────────
    print("\n[15] Determinism (same inputs → same output)")
    bundle2 = build_timeline(
        evidence=_make_evidence(), relationships=_make_relationships(),
        history_events=_make_history_events(), relationship_history=_make_rel_history(),
        attack_chains=_make_attack_chains(), attack_patterns=_make_attack_patterns(),
        blast_radii=_make_blast_radii(), intel_findings=_make_intel_findings(),
        alerts=_make_alerts(), findings=_make_findings(), mitre=_make_mitre(),
    )
    _assert(bundle.timelineFingerprint == bundle2.timelineFingerprint,
            "timelineFingerprint identical across runs")
    _assert(len(bundle.events) == len(bundle2.events),
            "Same event count across runs")
    for e1, e2 in zip(bundle.events, bundle2.events):
        _assert(e1.eventKey == e2.eventKey,
                f"Event key stable: {e1.eventKey[:8]}…")
        _assert(e1.timelinePosition == e2.timelinePosition,
                f"timelinePosition stable: {e1.timelinePosition}")

    # ── [16] Immutability ──────────────────────────────────────────────────
    print("\n[16] Immutability (frozen models)")
    try:
        bundle.events[0].title = "hacked"  # type: ignore[misc]
        _assert(False, "TimelineEvent should be frozen")
    except Exception:
        _assert(True, "TimelineEvent is immutable (frozen=True)")
    try:
        bundle.statistics.totalEvents = 999  # type: ignore[misc]
        _assert(False, "TimelineStatistics should be frozen")
    except Exception:
        _assert(True, "TimelineStatistics is immutable (frozen=True)")
    try:
        bundle.explanation.processingTimeMs = 999  # type: ignore[misc]
        _assert(False, "TimelineExplanation should be frozen")
    except Exception:
        _assert(True, "TimelineExplanation is immutable (frozen=True)")
    try:
        bundle.timelineFingerprint = "x" * 32  # type: ignore[misc]
        _assert(False, "TimelineBundle should be frozen")
    except Exception:
        _assert(True, "TimelineBundle is immutable (frozen=True)")

    # ── [17] filter_timeline() ─────────────────────────────────────────────
    print("\n[17] filter_timeline()")
    evid_only = filter_timeline(bundle.events, event_type=TimelineEventType.EVIDENCE_ADDED)
    _assert(all(e.eventType == TimelineEventType.EVIDENCE_ADDED for e in evid_only),
            "filter by event_type=EVIDENCE_ADDED")
    _assert(len(evid_only) == 2, f"2 EVIDENCE_ADDED events after filter (got {len(evid_only)})")

    intel_only = filter_timeline(bundle.events, source_type=TimelineSourceType.INTELLIGENCE)
    _assert(all(e.sourceType == TimelineSourceType.INTELLIGENCE for e in intel_only),
            "filter by sourceType=INTELLIGENCE")
    _assert(len(intel_only) > 0, "At least 1 INTELLIGENCE event")

    high_conf = filter_timeline(bundle.events, min_confidence=80)
    _assert(all(e.confidence >= 80 for e in high_conf), "filter min_confidence=80")

    asset_evts = filter_timeline(bundle.events, asset_id="asset-001")
    _assert(all(e.assetId == "asset-001" for e in asset_evts), "filter asset_id=asset-001")

    cap_evts = filter_timeline(bundle.events, capture_id="cap-001")
    _assert(all(e.captureId == "cap-001" for e in cap_evts), "filter captureId=cap-001")

    # Time window filter
    in_window = filter_timeline(bundle.events, from_dt=_T0, to_dt=_T2)
    for e in in_window:
        if e.occurredAt is not None:
            _assert(_T0 <= e.occurredAt <= _T2,
                    f"timeline_between result in [T0,T2]: {e.occurredAt}")

    # ── [18] group_timeline() ──────────────────────────────────────────────
    print("\n[18] group_timeline()")
    grouped_type = group_timeline(bundle.events, group_by="eventType")
    _assert(isinstance(grouped_type, dict), "group_timeline returns dict")
    _assert("EVIDENCE_ADDED" in grouped_type, "EVIDENCE_ADDED group present")
    for key, grp in grouped_type.items():
        _assert(all(e.eventType.value == key for e in grp),
                f"All events in group '{key}' have correct eventType")
        # Each group is sorted
        pos_list = [e.timelinePosition for e in grp if e.occurredAt is not None]
    grouped_src = group_timeline(bundle.events, group_by="sourceType")
    _assert("EVIDENCE" in grouped_src or len(grouped_src) > 0, "sourceType grouping works")

    grouped_sev = group_timeline(bundle.events, group_by="severity")
    _assert(isinstance(grouped_sev, dict), "severity grouping returns dict")

    # ── [19] search_timeline() ─────────────────────────────────────────────
    print("\n[19] search_timeline()")
    results_beacon = search_timeline(bundle.events, "beacon")
    _assert(len(results_beacon) > 0, f"search 'beacon' finds ≥1 event (got {len(results_beacon)})")
    for r in results_beacon:
        found = any("beacon" in str(getattr(r, f, "")).lower()
                    for f in ["title", "summary", "description"])
        _assert(found, f"'beacon' present in matched event fields: {r.title[:40]}")

    results_mitre = search_timeline(bundle.events, "T1071")
    _assert(len(results_mitre) > 0, f"search 'T1071' finds ≥1 event (got {len(results_mitre)})")

    results_none = search_timeline(bundle.events, "zzz-no-match-xyz")
    _assert(len(results_none) == 0, "search for non-existent term returns empty list")

    results_limit = search_timeline(bundle.events, "a", limit=1)
    _assert(len(results_limit) <= 1, "search with limit=1 returns ≤1 result")

    # ── [20] timeline_between() ────────────────────────────────────────────
    print("\n[20] timeline_between()")
    between = timeline_between(bundle.events, _T0, _T2)
    for e in between:
        _assert(e.occurredAt is not None and _T0 <= e.occurredAt <= _T2,
                f"timeline_between: event in window: {e.occurredAt}")
    out_of_range = timeline_between(bundle.events,
                                    datetime(2030, 1, 1, tzinfo=timezone.utc),
                                    datetime(2030, 12, 31, tzinfo=timezone.utc))
    _assert(len(out_of_range) == 0, "timeline_between with future window returns empty list")

    # ── [21] timeline_for_asset() ──────────────────────────────────────────
    print("\n[21] timeline_for_asset()")
    asset_events = timeline_for_asset(bundle.events, "asset-001")
    _assert(all(e.assetId == "asset-001" for e in asset_events),
            "timeline_for_asset: all events have correct assetId")
    _assert(len(asset_events) >= 1, f"≥1 event for asset-001 (got {len(asset_events)})")

    # ── [22] timeline_for_capture() ────────────────────────────────────────
    print("\n[22] timeline_for_capture()")
    cap_events = timeline_for_capture(bundle.events, "cap-001")
    _assert(all(e.captureId == "cap-001" for e in cap_events),
            "timeline_for_capture: all events have correct captureId")

    # ── [23] timeline_for_relationship() ───────────────────────────────────
    print("\n[23] timeline_for_relationship()")
    rel_filtered = timeline_for_relationship(bundle.events, "rel-001")
    _assert(all(e.relationshipId == "rel-001" for e in rel_filtered),
            "timeline_for_relationship: all events have correct relationshipId")
    _assert(len(rel_filtered) >= 1, f"≥1 event for rel-001 (got {len(rel_filtered)})")

    # ── [24] empty build_timeline() ────────────────────────────────────────
    print("\n[24] Empty build_timeline()")
    empty_bundle = build_timeline()
    _assert(isinstance(empty_bundle, TimelineBundle), "Empty build returns TimelineBundle")
    _assert(len(empty_bundle.events) == 0, "Empty bundle has 0 events")
    _assert(empty_bundle.timelineFingerprint == "0" * 32, "Empty fingerprint is 32 zeros")
    _assert(empty_bundle.statistics.totalEvents == 0, "Empty stats totalEvents=0")

    # ── [25] Replay via timelinePosition ───────────────────────────────────
    print("\n[25] Attack replay via timelinePosition")
    events_by_pos = {e.timelinePosition: e for e in bundle.events}
    for pos in range(len(bundle.events)):
        _assert(pos in events_by_pos,
                f"timelinePosition {pos} present in bundle")
    # Replay first 5 events in order
    replay = [events_by_pos[p] for p in sorted(events_by_pos.keys())[:5]]
    _assert(len(replay) == min(5, len(bundle.events)), "Can replay first 5 events by position")

    # ── Summary ─────────────────────────────────────────────────────────────
    print("\n" + "=" * 66)
    elapsed_ms = round((time.monotonic() - t_global) * 1000, 1)
    if _failures:
        print(f"\n  {FAIL}  {len(_failures)} assertion(s) FAILED:\n")
        for msg in _failures:
            print(f"    • {msg}")
        print()
        sys.exit(1)
    else:
        print(f"\n  {PASS}  ALL ASSERTIONS PASSED")
        print(f"\n  Engine  : {TIMELINE_INTELLIGENCE_ENGINE_VERSION}")
        print(f"  Events  : {len(bundle.events)}")
        print(f"  Time    : {elapsed_ms} ms\n")
        sys.exit(0)


if __name__ == "__main__":
    run_smoke_test()
