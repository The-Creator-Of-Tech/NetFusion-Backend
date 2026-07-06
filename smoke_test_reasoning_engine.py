"""
Smoke Test — Reasoning Engine
==============================
Verifies every model, builder, and utility function in
services/reasoning_service.py with 180+ assertions.

Run:
    python smoke_test_reasoning_engine.py

Expected: 100% PASS, no errors.
"""

from __future__ import annotations

import sys
import traceback
from typing import List

# ---------------------------------------------------------------------------
# Import the engine under test
# ---------------------------------------------------------------------------
from services.reasoning_service import (
    # Enum
    ReasoningStage,
    # Models
    ReasoningEvidence,
    ReasoningTrace,
    DecisionExplanation,
    ReasoningMetadata,
    ReasoningResult,
    ReasoningStatistics,
    # Builders
    build_reasoning_evidence,
    build_reasoning_trace,
    build_decision_explanation,
    build_reasoning_metadata,
    build_reasoning,
    # Utilities
    sort_reasoning_trace,
    sort_reasoning_evidence,
    filter_reasoning_trace,
    group_reasoning_trace,
    calculate_reasoning_statistics,
    find_reasoning_step,
    # Internal helpers exposed for fingerprint testing
    _compute_reasoning_key,
    _compute_reasoning_id,
    _compute_reasoning_fingerprint,
    _compute_trace_fingerprint,
    REASONING_ENGINE_VERSION,
)
from core.constants import REASONING_ENGINE_VERSION as CONST_VERSION

# ---------------------------------------------------------------------------
# Test harness
# ---------------------------------------------------------------------------

_PASS = 0
_FAIL = 0
_ERRORS: List[str] = []


def _assert(condition: bool, message: str) -> None:
    global _PASS, _FAIL
    if condition:
        _PASS += 1
    else:
        _FAIL += 1
        frame = traceback.extract_stack()[-2]
        _ERRORS.append(f"FAIL [{frame.lineno}]: {message}")


def _assert_eq(a, b, message: str) -> None:
    _assert(a == b, f"{message} — expected {b!r}, got {a!r}")


def _assert_ne(a, b, message: str) -> None:
    _assert(a != b, f"{message} — values should differ but both are {a!r}")


def _assert_in(item, container, message: str) -> None:
    _assert(item in container, f"{message} — {item!r} not in container")


# ---------------------------------------------------------------------------
# §1  Engine version constant
# ---------------------------------------------------------------------------
print("§1  Engine version constant ...")

_assert_eq(REASONING_ENGINE_VERSION, "reasoning-engine-v1", "REASONING_ENGINE_VERSION value")
_assert_eq(CONST_VERSION, REASONING_ENGINE_VERSION, "core.constants matches service import")
_assert(isinstance(REASONING_ENGINE_VERSION, str), "engineVersion is a string")
_assert(len(REASONING_ENGINE_VERSION) > 0, "engineVersion is non-empty")

# ---------------------------------------------------------------------------
# §2  ReasoningStage enum
# ---------------------------------------------------------------------------
print("§2  ReasoningStage enum ...")

_assert(hasattr(ReasoningStage, "OBSERVATION"),           "ReasoningStage.OBSERVATION exists")
_assert(hasattr(ReasoningStage, "EVIDENCE_CORRELATION"),  "ReasoningStage.EVIDENCE_CORRELATION exists")
_assert(hasattr(ReasoningStage, "RELATIONSHIP_ANALYSIS"), "ReasoningStage.RELATIONSHIP_ANALYSIS exists")
_assert(hasattr(ReasoningStage, "TIMELINE_ANALYSIS"),     "ReasoningStage.TIMELINE_ANALYSIS exists")
_assert(hasattr(ReasoningStage, "ATTACK_GRAPH_ANALYSIS"), "ReasoningStage.ATTACK_GRAPH_ANALYSIS exists")
_assert(hasattr(ReasoningStage, "FINDING_CORRELATION"),   "ReasoningStage.FINDING_CORRELATION exists")
_assert(hasattr(ReasoningStage, "ALERT_CORRELATION"),     "ReasoningStage.ALERT_CORRELATION exists")
_assert(hasattr(ReasoningStage, "RISK_ASSESSMENT"),       "ReasoningStage.RISK_ASSESSMENT exists")
_assert(hasattr(ReasoningStage, "CONCLUSION"),            "ReasoningStage.CONCLUSION exists")
_assert_eq(len(list(ReasoningStage)), 9, "ReasoningStage has exactly 9 members")
_assert_eq(ReasoningStage.OBSERVATION.value, "OBSERVATION", "OBSERVATION.value")
_assert_eq(ReasoningStage.CONCLUSION.value,  "CONCLUSION",  "CONCLUSION.value")
_assert(isinstance(ReasoningStage.RISK_ASSESSMENT, ReasoningStage), "RISK_ASSESSMENT is enum member")

# ---------------------------------------------------------------------------
# §3  build_reasoning_evidence()
# ---------------------------------------------------------------------------
print("§3  build_reasoning_evidence() ...")

ev1 = build_reasoning_evidence(
    evidence_id = "ev-001",
    weight      = 85.0,
    reason      = "High-confidence MAC observation",
    source_type = "PCAP",
    confidence  = 90.0,
)

_assert(isinstance(ev1, ReasoningEvidence), "returns ReasoningEvidence")
_assert_eq(ev1.evidenceId,  "ev-001",                   "evidenceId preserved")
_assert_eq(ev1.weight,      85.0,                       "weight set")
_assert_eq(ev1.reason,      "High-confidence MAC observation", "reason set")
_assert_eq(ev1.sourceType,  "pcap",                     "sourceType lowercased")
_assert_eq(ev1.confidence,  90.0,                       "confidence set")

# clamping
ev_high = build_reasoning_evidence("x", 200.0, "r", "pcap", 150.0)
_assert_eq(ev_high.weight,     100.0, "weight clamped to 100")
_assert_eq(ev_high.confidence, 100.0, "confidence clamped to 100")

ev_low = build_reasoning_evidence("x", -10.0, "r", "pcap", -5.0)
_assert_eq(ev_low.weight,     0.0, "weight clamped to 0")
_assert_eq(ev_low.confidence, 0.0, "confidence clamped to 0")

# immutability
try:
    ev1.weight = 50.0  # type: ignore
    _assert(False, "ReasoningEvidence should be frozen")
except Exception:
    _assert(True, "ReasoningEvidence is immutable (frozen)")

# whitespace stripping
ev_ws = build_reasoning_evidence("  ev-ws  ", 50.0, "r", "  DHCP  ", 60.0)
_assert_eq(ev_ws.evidenceId, "ev-ws", "evidenceId stripped")
_assert_eq(ev_ws.sourceType, "dhcp",  "sourceType stripped and lowercased")

# ---------------------------------------------------------------------------
# §4  build_reasoning_trace()
# ---------------------------------------------------------------------------
print("§4  build_reasoning_trace() ...")

trace1 = build_reasoning_trace(
    step_number        = 1,
    stage              = ReasoningStage.OBSERVATION,
    input_summary      = "Raw pcap packets",
    output_summary     = "Observed 3 unique hosts",
    confidence         = 75.0,
    evidence_ids       = ["ev-003", "ev-001", "ev-002"],
    finding_ids        = ["f-002", "f-001"],
    alert_ids          = ["a-001"],
    relationship_ids   = ["r-001", "r-002"],
    timeline_event_ids = ["tl-001"],
)

_assert(isinstance(trace1, ReasoningTrace),                   "returns ReasoningTrace")
_assert_eq(trace1.stepNumber, 1,                              "stepNumber set")
_assert_eq(trace1.stage, ReasoningStage.OBSERVATION,          "stage set")
_assert_eq(trace1.inputSummary,  "Raw pcap packets",          "inputSummary set")
_assert_eq(trace1.outputSummary, "Observed 3 unique hosts",   "outputSummary set")
_assert_eq(trace1.confidence,    75.0,                        "confidence set")

# IDs must be sorted for determinism
_assert_eq(trace1.evidenceIds,      ("ev-001", "ev-002", "ev-003"), "evidenceIds sorted")
_assert_eq(trace1.findingIds,       ("f-001", "f-002"),             "findingIds sorted")
_assert_eq(trace1.alertIds,         ("a-001",),                     "alertIds sorted")
_assert_eq(trace1.relationshipIds,  ("r-001", "r-002"),             "relationshipIds sorted")
_assert_eq(trace1.timelineEventIds, ("tl-001",),                    "timelineEventIds sorted")

# duplicates deduplicated
trace_dup = build_reasoning_trace(1, ReasoningStage.CONCLUSION, "", "", 50.0,
    evidence_ids=["ev-001", "ev-001", "ev-002"])
_assert_eq(len(trace_dup.evidenceIds), 2, "duplicate evidenceIds deduplicated")

# immutability
try:
    trace1.confidence = 99.0  # type: ignore
    _assert(False, "ReasoningTrace should be frozen")
except Exception:
    _assert(True, "ReasoningTrace is immutable (frozen)")

# confidence clamping
trace_clamp = build_reasoning_trace(1, ReasoningStage.RISK_ASSESSMENT, "", "", 999.0)
_assert_eq(trace_clamp.confidence, 100.0, "trace confidence clamped to 100")

# empty IDs → empty tuples
trace_empty = build_reasoning_trace(2, ReasoningStage.EVIDENCE_CORRELATION, "in", "out", 50.0)
_assert_eq(trace_empty.evidenceIds,      (), "empty evidenceIds → empty tuple")
_assert_eq(trace_empty.findingIds,       (), "empty findingIds → empty tuple")
_assert_eq(trace_empty.alertIds,         (), "empty alertIds → empty tuple")
_assert_eq(trace_empty.relationshipIds,  (), "empty relationshipIds → empty tuple")
_assert_eq(trace_empty.timelineEventIds, (), "empty timelineEventIds → empty tuple")

# ---------------------------------------------------------------------------
# §5  build_decision_explanation()
# ---------------------------------------------------------------------------
print("§5  build_decision_explanation() ...")

expl = build_decision_explanation(
    summary                = "Lateral movement detected.",
    strengths              = ["High confidence evidence", "Multiple corroborating sources"],
    weaknesses             = ["No timeline anchor", "Incomplete flow data"],
    assumptions            = ["All timestamps are UTC", "Capture is complete"],
    confidence_explanation = "Aggregate confidence weighted by source reliability.",
    recommended_next_steps = ["Isolate host", "Review DNS queries", "Alert SOC"],
)

_assert(isinstance(expl, DecisionExplanation),               "returns DecisionExplanation")
_assert_eq(expl.summary, "Lateral movement detected.",       "summary set")
_assert_eq(expl.confidenceExplanation,
           "Aggregate confidence weighted by source reliability.",
           "confidenceExplanation set")

# All list fields must be sorted
_assert_eq(expl.strengths,
           ("High confidence evidence", "Multiple corroborating sources"),
           "strengths sorted")
_assert_eq(expl.weaknesses,
           ("Incomplete flow data", "No timeline anchor"),
           "weaknesses sorted")
_assert_eq(expl.assumptions,
           ("All timestamps are UTC", "Capture is complete"),
           "assumptions sorted")
_assert_eq(expl.recommendedNextSteps,
           ("Alert SOC", "Isolate host", "Review DNS queries"),
           "recommendedNextSteps sorted")

# immutability
try:
    expl.summary = "changed"  # type: ignore
    _assert(False, "DecisionExplanation should be frozen")
except Exception:
    _assert(True, "DecisionExplanation is immutable (frozen)")

# empty defaults
expl_empty = build_decision_explanation(summary="test")
_assert_eq(expl_empty.strengths,            (), "empty strengths → empty tuple")
_assert_eq(expl_empty.weaknesses,           (), "empty weaknesses → empty tuple")
_assert_eq(expl_empty.assumptions,          (), "empty assumptions → empty tuple")
_assert_eq(expl_empty.recommendedNextSteps, (), "empty recommendedNextSteps → empty tuple")
_assert_eq(expl_empty.confidenceExplanation, "", "empty confidenceExplanation defaults to ''")

# duplicates deduplicated
expl_dup = build_decision_explanation(
    "x",
    strengths=["dup", "dup", "unique"],
)
_assert_eq(len(expl_dup.strengths), 2, "duplicate strengths deduplicated")

# ---------------------------------------------------------------------------
# §6  build_reasoning_metadata()
# ---------------------------------------------------------------------------
print("§6  build_reasoning_metadata() ...")

meta = build_reasoning_metadata(
    processing_time_ms  = 42,
    reasoning_depth     = 7,
    context_count       = 12,
    finding_count       = 5,
    alert_count         = 3,
    relationship_count  = 18,
    timeline_count      = 44,
    evidence_count      = 97,
    models_used         = ["reasoning-engine-v1", "ai-context-engine-v1"],
)

_assert(isinstance(meta, ReasoningMetadata),    "returns ReasoningMetadata")
_assert_eq(meta.processingTimeMs,  42,          "processingTimeMs set")
_assert_eq(meta.reasoningDepth,    7,           "reasoningDepth set")
_assert_eq(meta.contextCount,      12,          "contextCount set")
_assert_eq(meta.findingCount,      5,           "findingCount set")
_assert_eq(meta.alertCount,        3,           "alertCount set")
_assert_eq(meta.relationshipCount, 18,          "relationshipCount set")
_assert_eq(meta.timelineCount,     44,          "timelineCount set")
_assert_eq(meta.evidenceCount,     97,          "evidenceCount set")
_assert_eq(meta.modelsUsed,
           ("ai-context-engine-v1", "reasoning-engine-v1"),
           "modelsUsed sorted")

# negative inputs floored to 0
meta_neg = build_reasoning_metadata(-5, -1, -2, -3, -4, -5, -6, -7)
_assert_eq(meta_neg.processingTimeMs, 0, "negative processingTimeMs → 0")
_assert_eq(meta_neg.reasoningDepth,   0, "negative reasoningDepth → 0")

# immutability
try:
    meta.processingTimeMs = 100  # type: ignore
    _assert(False, "ReasoningMetadata should be frozen")
except Exception:
    _assert(True, "ReasoningMetadata is immutable (frozen)")

# duplicate modelsUsed deduplicated and sorted
meta_dup = build_reasoning_metadata(0,0,0,0,0,0,0,0,
    models_used=["engine-b", "engine-a", "engine-b"])
_assert_eq(len(meta_dup.modelsUsed), 2, "duplicate modelsUsed deduplicated")
_assert_eq(meta_dup.modelsUsed, ("engine-a", "engine-b"), "modelsUsed sorted after dedup")

# ---------------------------------------------------------------------------
# §7  Deterministic ID helpers
# ---------------------------------------------------------------------------
print("§7  Deterministic ID helpers ...")

ctx1   = ["ctx-c", "ctx-a", "ctx-b"]
find1  = ["f-002", "f-001"]
alert1 = ["a-001"]
rel1   = ["r-002", "r-001"]
tl1    = ["tl-001", "tl-002"]

key_a = _compute_reasoning_key(ctx1, find1, alert1, rel1, tl1)
key_b = _compute_reasoning_key(ctx1, find1, alert1, rel1, tl1)
_assert_eq(key_a, key_b, "same inputs → same reasoningKey")

# reversed order of IDs must produce the same key (sorted before hash)
key_rev = _compute_reasoning_key(
    list(reversed(ctx1)),
    list(reversed(find1)),
    list(reversed(alert1)),
    list(reversed(rel1)),
    list(reversed(tl1)),
)
_assert_eq(key_a, key_rev, "reversed input → identical reasoningKey")

_assert_eq(len(key_a), 32, "reasoningKey is 32 chars")
_assert(all(c in "0123456789abcdef" for c in key_a), "reasoningKey is hex")

# different input → different key
key_other = _compute_reasoning_key(["ctx-Z"], find1, alert1, rel1, tl1)
_assert_ne(key_a, key_other, "different contextIds → different reasoningKey")

# reasoningId is a valid UUID string from the key
rid_a = _compute_reasoning_id(key_a)
rid_b = _compute_reasoning_id(key_a)
_assert_eq(rid_a, rid_b, "same key → same reasoningId")
_assert_eq(len(rid_a), 36, "reasoningId is 36 chars (UUID format)")
_assert_in("-", rid_a, "reasoningId contains hyphens (UUID)")

rid_other = _compute_reasoning_id(key_other)
_assert_ne(rid_a, rid_other, "different keys → different reasoningIds")

# trace fingerprint determinism
trace_fp1 = build_reasoning_trace(
    1, ReasoningStage.OBSERVATION, "in", "out", 80.0,
    evidence_ids=["ev-b", "ev-a"],
)
fp_a = _compute_trace_fingerprint(trace_fp1)
fp_b = _compute_trace_fingerprint(trace_fp1)
_assert_eq(fp_a, fp_b, "same trace → same trace fingerprint")
_assert_eq(len(fp_a), 32, "trace fingerprint is 32 chars")

# reasoning fingerprint
traces_tuple = (trace_fp1,)
rfp_a = _compute_reasoning_fingerprint(key_a, traces_tuple, ["ev-001", "ev-002"])
rfp_b = _compute_reasoning_fingerprint(key_a, traces_tuple, ["ev-001", "ev-002"])
_assert_eq(rfp_a, rfp_b, "same inputs → same reasoningFingerprint")
_assert_eq(len(rfp_a), 32, "reasoningFingerprint is 32 chars")

# reversed evidence IDs same fingerprint
rfp_rev = _compute_reasoning_fingerprint(key_a, traces_tuple, ["ev-002", "ev-001"])
_assert_eq(rfp_a, rfp_rev, "reversed evidenceIds → identical reasoningFingerprint")

# ---------------------------------------------------------------------------
# §8  build_reasoning() — primary builder
# ---------------------------------------------------------------------------
print("§8  build_reasoning() — primary builder ...")

_CREATED_AT = "2026-06-30T10:00:00Z"

traces_input = [
    build_reasoning_trace(3, ReasoningStage.CONCLUSION, "all data", "attack confirmed", 88.0,
        finding_ids=["f-001"], alert_ids=["a-001"]),
    build_reasoning_trace(1, ReasoningStage.OBSERVATION, "packets", "3 hosts seen", 70.0,
        evidence_ids=["ev-001", "ev-002"]),
    build_reasoning_trace(2, ReasoningStage.EVIDENCE_CORRELATION, "evidence", "MAC verified", 80.0,
        evidence_ids=["ev-002", "ev-003"], relationship_ids=["r-001"]),
]

evidence_input = [
    build_reasoning_evidence("ev-001", 60.0, "pcap observation", "pcap", 70.0),
    build_reasoning_evidence("ev-002", 90.0, "dhcp hostname",    "dhcp", 95.0),
    build_reasoning_evidence("ev-003", 75.0, "arp binding",      "arp",  88.0),
]

expl_input = build_decision_explanation(
    "Confirmed lateral movement.",
    strengths=["Strong MAC evidence"],
    weaknesses=["Partial capture"],
    confidence_explanation="Weighted by source reliability.",
    recommended_next_steps=["Isolate asset"],
)

meta_input = build_reasoning_metadata(
    processing_time_ms=55, reasoning_depth=3,
    context_count=5, finding_count=2, alert_count=1,
    relationship_count=1, timeline_count=10, evidence_count=3,
    models_used=["reasoning-engine-v1"],
)

result = build_reasoning(
    context_ids       = ["ctx-b", "ctx-a"],
    finding_ids       = ["f-001", "f-002"],
    alert_ids         = ["a-001"],
    relationship_ids  = ["r-001"],
    timeline_ids      = ["tl-001", "tl-002"],
    created_at        = _CREATED_AT,
    reasoning_trace   = traces_input,
    supporting_evidence= evidence_input,
    decision          = "ATTACK_CONFIRMED",
    overall_confidence= 82.0,
    overall_risk      = 90.0,
    explanation       = expl_input,
    metadata          = meta_input,
)

_assert(isinstance(result, ReasoningResult),  "returns ReasoningResult")
_assert_eq(result.decision,       "ATTACK_CONFIRMED",  "decision set")
_assert_eq(result.overallConfidence, 82.0,             "overallConfidence set")
_assert_eq(result.overallRisk,    90.0,                "overallRisk set")
_assert_eq(result.engineVersion,  REASONING_ENGINE_VERSION, "engineVersion from constant")
_assert_eq(result.createdAt,      _CREATED_AT,          "createdAt preserved")
_assert_eq(len(result.reasoningId), 36,                 "reasoningId is 36 chars")
_assert_eq(len(result.reasoningKey), 32,                "reasoningKey is 32 chars")
_assert_eq(len(result.reasoningFingerprint), 32,        "reasoningFingerprint is 32 chars")

# Trace sorted by stepNumber
_assert_eq(result.reasoningTrace[0].stepNumber, 1, "trace step 0 is step 1")
_assert_eq(result.reasoningTrace[1].stepNumber, 2, "trace step 1 is step 2")
_assert_eq(result.reasoningTrace[2].stepNumber, 3, "trace step 2 is step 3")

# Evidence sorted by weight DESC
_assert_eq(result.supportingEvidence[0].evidenceId, "ev-002", "highest weight ev first")
_assert_eq(result.supportingEvidence[1].evidenceId, "ev-003", "second highest weight ev")
_assert_eq(result.supportingEvidence[2].evidenceId, "ev-001", "lowest weight ev last")

# immutability
try:
    result.decision = "changed"  # type: ignore
    _assert(False, "ReasoningResult should be frozen")
except Exception:
    _assert(True, "ReasoningResult is immutable (frozen)")

# ---------------------------------------------------------------------------
# §9  Determinism: same input → same output
# ---------------------------------------------------------------------------
print("§9  Determinism: same input → same output ...")

def _make_result(ctx, finds, alerts, rels, tls) -> ReasoningResult:
    return build_reasoning(
        context_ids       = ctx,
        finding_ids       = finds,
        alert_ids         = alerts,
        relationship_ids  = rels,
        timeline_ids      = tls,
        created_at        = _CREATED_AT,
        reasoning_trace   = traces_input,
        supporting_evidence= evidence_input,
        decision          = "ATTACK_CONFIRMED",
        overall_confidence= 82.0,
        overall_risk      = 90.0,
        explanation       = expl_input,
        metadata          = meta_input,
    )

r1 = _make_result(["ctx-b","ctx-a"], ["f-001","f-002"], ["a-001"], ["r-001"], ["tl-001","tl-002"])
r2 = _make_result(["ctx-b","ctx-a"], ["f-001","f-002"], ["a-001"], ["r-001"], ["tl-001","tl-002"])

_assert_eq(r1.reasoningId,          r2.reasoningId,          "same input → same reasoningId")
_assert_eq(r1.reasoningKey,         r2.reasoningKey,         "same input → same reasoningKey")
_assert_eq(r1.reasoningFingerprint, r2.reasoningFingerprint, "same input → same fingerprint")
_assert_eq(r1.reasoningTrace,       r2.reasoningTrace,       "same input → same trace tuple")
_assert_eq(r1.supportingEvidence,   r2.supportingEvidence,   "same input → same evidence tuple")

# Reversed input → same output
r3 = _make_result(
    list(reversed(["ctx-b","ctx-a"])),
    list(reversed(["f-001","f-002"])),
    ["a-001"],
    ["r-001"],
    list(reversed(["tl-001","tl-002"])),
)

_assert_eq(r1.reasoningId,          r3.reasoningId,          "reversed input → same reasoningId")
_assert_eq(r1.reasoningKey,         r3.reasoningKey,         "reversed input → same reasoningKey")
_assert_eq(r1.reasoningFingerprint, r3.reasoningFingerprint, "reversed input → same fingerprint")

# Different input → different IDs
r4 = _make_result(["ctx-Z"], ["f-001"], ["a-001"], ["r-001"], ["tl-001"])
_assert_ne(r1.reasoningId,          r4.reasoningId,          "different input → different reasoningId")
_assert_ne(r1.reasoningKey,         r4.reasoningKey,         "different input → different reasoningKey")
_assert_ne(r1.reasoningFingerprint, r4.reasoningFingerprint, "different input → different fingerprint")

# Confidence/risk clamping via builder
r_clamp = build_reasoning([], [], [], [], [], _CREATED_AT,
    overall_confidence=999.0, overall_risk=-50.0)
_assert_eq(r_clamp.overallConfidence, 100.0, "overallConfidence clamped to 100")
_assert_eq(r_clamp.overallRisk,       0.0,   "overallRisk clamped to 0")

# ---------------------------------------------------------------------------
# §10  Default explanation and metadata when None supplied
# ---------------------------------------------------------------------------
print("§10  Default explanation and metadata when None supplied ...")

r_defaults = build_reasoning(
    ["ctx-x"], ["f-x"], ["a-x"], ["r-x"], ["tl-x"],
    _CREATED_AT,
)

_assert(isinstance(r_defaults.decisionExplanation, DecisionExplanation),
        "default explanation is DecisionExplanation")
_assert(isinstance(r_defaults.metadata, ReasoningMetadata),
        "default metadata is ReasoningMetadata")
_assert_eq(r_defaults.metadata.reasoningDepth, 0, "default depth = 0 (no trace)")
_assert_eq(r_defaults.metadata.findingCount,   1, "default findingCount = 1")
_assert_eq(r_defaults.metadata.alertCount,     1, "default alertCount = 1")
_assert_eq(r_defaults.metadata.contextCount,   1, "default contextCount = 1")
_assert_eq(r_defaults.metadata.relationshipCount, 1, "default relationshipCount = 1")
_assert_eq(r_defaults.metadata.timelineCount,  1, "default timelineCount = 1")

# ---------------------------------------------------------------------------
# §11  sort_reasoning_trace()
# ---------------------------------------------------------------------------
print("§11  sort_reasoning_trace() ...")

unsorted_traces = [
    build_reasoning_trace(3, ReasoningStage.CONCLUSION,           "in", "out", 88.0),
    build_reasoning_trace(1, ReasoningStage.OBSERVATION,          "in", "out", 70.0),
    build_reasoning_trace(2, ReasoningStage.EVIDENCE_CORRELATION, "in", "out", 80.0),
]

asc = sort_reasoning_trace(unsorted_traces, ascending=True)
_assert_eq(asc[0].stepNumber, 1, "ascending: step 1 first")
_assert_eq(asc[1].stepNumber, 2, "ascending: step 2 second")
_assert_eq(asc[2].stepNumber, 3, "ascending: step 3 last")

desc = sort_reasoning_trace(unsorted_traces, ascending=False)
_assert_eq(desc[0].stepNumber, 3, "descending: step 3 first")
_assert_eq(desc[2].stepNumber, 1, "descending: step 1 last")

# input not mutated
_assert_eq(unsorted_traces[0].stepNumber, 3, "input list not mutated by sort")

# determinism — sort twice gives same result
asc2 = sort_reasoning_trace(unsorted_traces, ascending=True)
_assert_eq(asc, asc2, "sort_reasoning_trace is deterministic")

# ---------------------------------------------------------------------------
# §12  sort_reasoning_evidence()
# ---------------------------------------------------------------------------
print("§12  sort_reasoning_evidence() ...")

evidence_list = [
    build_reasoning_evidence("ev-b", 50.0, "r", "pcap", 60.0),
    build_reasoning_evidence("ev-a", 90.0, "r", "dhcp", 95.0),
    build_reasoning_evidence("ev-c", 70.0, "r", "arp",  80.0),
]

by_weight_desc = sort_reasoning_evidence(evidence_list, by="weight", ascending=False)
_assert_eq(by_weight_desc[0].evidenceId, "ev-a", "highest weight first")
_assert_eq(by_weight_desc[1].evidenceId, "ev-c", "second highest weight")
_assert_eq(by_weight_desc[2].evidenceId, "ev-b", "lowest weight last")

by_weight_asc = sort_reasoning_evidence(evidence_list, by="weight", ascending=True)
_assert_eq(by_weight_asc[0].evidenceId, "ev-b", "ascending: lowest weight first")

by_conf = sort_reasoning_evidence(evidence_list, by="confidence", ascending=False)
_assert_eq(by_conf[0].evidenceId, "ev-a", "highest confidence first")

by_id = sort_reasoning_evidence(evidence_list, by="evidenceId", ascending=True)
_assert_eq(by_id[0].evidenceId, "ev-a", "alphabetically first evidenceId first")
_assert_eq(by_id[2].evidenceId, "ev-c", "alphabetically last evidenceId last")

by_src = sort_reasoning_evidence(evidence_list, by="sourceType", ascending=True)
_assert_eq(by_src[0].sourceType, "arp", "arp sorts first alphabetically")

# invalid key raises ValueError
try:
    sort_reasoning_evidence(evidence_list, by="nonexistent")
    _assert(False, "invalid sort key should raise ValueError")
except ValueError:
    _assert(True, "invalid sort key raises ValueError")

# input not mutated
_assert_eq(evidence_list[0].evidenceId, "ev-b", "input not mutated by sort_reasoning_evidence")

# determinism
_assert_eq(
    sort_reasoning_evidence(evidence_list),
    sort_reasoning_evidence(evidence_list),
    "sort_reasoning_evidence is deterministic",
)

# ---------------------------------------------------------------------------
# §13  filter_reasoning_trace()
# ---------------------------------------------------------------------------
print("§13  filter_reasoning_trace() ...")

filter_traces = [
    build_reasoning_trace(1, ReasoningStage.OBSERVATION,          "in","out", 50.0,
        evidence_ids=["ev-1"], finding_ids=["f-1"]),
    build_reasoning_trace(2, ReasoningStage.EVIDENCE_CORRELATION, "in","out", 80.0,
        evidence_ids=["ev-2"]),
    build_reasoning_trace(3, ReasoningStage.CONCLUSION,           "in","out", 90.0,
        finding_ids=["f-2"], alert_ids=["a-1"]),
    build_reasoning_trace(4, ReasoningStage.RISK_ASSESSMENT,      "in","out", 30.0),
]

# filter by stage
obs = filter_reasoning_trace(filter_traces, stage=ReasoningStage.OBSERVATION)
_assert_eq(len(obs), 1,                        "filter by stage OBSERVATION → 1 result")
_assert_eq(obs[0].stepNumber, 1,               "correct step returned")

# filter by min_confidence
hi_conf = filter_reasoning_trace(filter_traces, min_confidence=80.0)
_assert_eq(len(hi_conf), 2, "min_confidence=80 → 2 results")

# filter by max_confidence
lo_conf = filter_reasoning_trace(filter_traces, max_confidence=50.0)
_assert_eq(len(lo_conf), 2, "max_confidence=50 → 2 results")

# filter by has_finding_ids
with_findings = filter_reasoning_trace(filter_traces, has_finding_ids=True)
_assert_eq(len(with_findings), 2, "has_finding_ids=True → 2 results")

no_findings = filter_reasoning_trace(filter_traces, has_finding_ids=False)
_assert_eq(len(no_findings), 2, "has_finding_ids=False → 2 results")

# filter by has_alert_ids
with_alerts = filter_reasoning_trace(filter_traces, has_alert_ids=True)
_assert_eq(len(with_alerts), 1, "has_alert_ids=True → 1 result")

# filter by has_evidence_ids
with_evidence = filter_reasoning_trace(filter_traces, has_evidence_ids=True)
_assert_eq(len(with_evidence), 2, "has_evidence_ids=True → 2 results")

# combined filters
combo = filter_reasoning_trace(filter_traces,
    min_confidence=80.0, has_finding_ids=True)
_assert_eq(len(combo), 1, "combined filter: conf>=80 AND has_findings → 1 result")
_assert_eq(combo[0].stepNumber, 3, "combined filter returns step 3")

# no filter → all
all_traces = filter_reasoning_trace(filter_traces)
_assert_eq(len(all_traces), 4, "no filter → all traces returned")

# empty list
empty_filtered = filter_reasoning_trace([], stage=ReasoningStage.OBSERVATION)
_assert_eq(len(empty_filtered), 0, "filter on empty list → empty result")

# input not mutated
_assert_eq(len(filter_traces), 4, "input not mutated by filter_reasoning_trace")

# ---------------------------------------------------------------------------
# §14  group_reasoning_trace()
# ---------------------------------------------------------------------------
print("§14  group_reasoning_trace() ...")

group_traces = [
    build_reasoning_trace(1, ReasoningStage.OBSERVATION,          "in","out", 50.0),
    build_reasoning_trace(2, ReasoningStage.EVIDENCE_CORRELATION, "in","out", 80.0),
    build_reasoning_trace(3, ReasoningStage.OBSERVATION,          "in","out", 70.0),
    build_reasoning_trace(4, ReasoningStage.CONCLUSION,           "in","out", 90.0),
]

by_stage = group_reasoning_trace(group_traces, group_by="stage")
_assert_in("OBSERVATION",          by_stage, "OBSERVATION group present")
_assert_in("EVIDENCE_CORRELATION", by_stage, "EVIDENCE_CORRELATION group present")
_assert_in("CONCLUSION",           by_stage, "CONCLUSION group present")
_assert_eq(len(by_stage["OBSERVATION"]), 2, "OBSERVATION group has 2 items")
_assert_eq(len(by_stage["CONCLUSION"]),  1, "CONCLUSION group has 1 item")

# groups are sorted by stepNumber ASC
_assert_eq(by_stage["OBSERVATION"][0].stepNumber, 1, "OBSERVATION group sorted: step 1 first")
_assert_eq(by_stage["OBSERVATION"][1].stepNumber, 3, "OBSERVATION group sorted: step 3 second")

# group by stepNumber
by_step = group_reasoning_trace(group_traces, group_by="stepNumber")
_assert_eq(len(by_step), 4, "group by stepNumber → 4 groups")
_assert_in("1", by_step, "step 1 group present")

# input not mutated
_assert_eq(len(group_traces), 4, "input not mutated by group_reasoning_trace")

# empty list
empty_group = group_reasoning_trace([])
_assert_eq(len(empty_group), 0, "group on empty list → empty dict")

# determinism — group twice same result
_assert_eq(
    {k: [t.stepNumber for t in v] for k, v in group_reasoning_trace(group_traces).items()},
    {k: [t.stepNumber for t in v] for k, v in group_reasoning_trace(group_traces).items()},
    "group_reasoning_trace is deterministic",
)

# ---------------------------------------------------------------------------
# §15  calculate_reasoning_statistics()
# ---------------------------------------------------------------------------
print("§15  calculate_reasoning_statistics() ...")

r_a = build_reasoning(
    ["ctx-1"], ["f-1","f-2"], ["a-1"], ["r-1"], ["tl-1","tl-2"],
    _CREATED_AT,
    reasoning_trace=[
        build_reasoning_trace(1, ReasoningStage.OBSERVATION, "in","out", 60.0),
        build_reasoning_trace(2, ReasoningStage.CONCLUSION,  "in","out", 80.0),
    ],
    supporting_evidence=[
        build_reasoning_evidence("ev-001", 80.0, "r", "pcap", 90.0),
        build_reasoning_evidence("ev-002", 60.0, "r", "dhcp", 70.0),
    ],
    decision="SUSPICIOUS",
    overall_confidence=70.0,
    overall_risk=60.0,
)

r_b = build_reasoning(
    ["ctx-2"], ["f-3"], ["a-2"], ["r-2"], ["tl-3"],
    _CREATED_AT,
    reasoning_trace=[
        build_reasoning_trace(1, ReasoningStage.OBSERVATION,         "in","out", 90.0),
        build_reasoning_trace(2, ReasoningStage.RISK_ASSESSMENT,     "in","out", 85.0),
        build_reasoning_trace(3, ReasoningStage.CONCLUSION,          "in","out", 92.0),
    ],
    supporting_evidence=[
        build_reasoning_evidence("ev-003", 95.0, "r", "arp", 98.0),
    ],
    decision="ATTACK_CONFIRMED",
    overall_confidence=90.0,
    overall_risk=95.0,
)

stats = calculate_reasoning_statistics([r_a, r_b])

_assert(isinstance(stats, ReasoningStatistics), "returns ReasoningStatistics")
_assert_eq(stats.totalResults,       2,          "totalResults = 2")
_assert_eq(stats.averageConfidence,  80.0,       "averageConfidence = (70+90)/2")
_assert_eq(stats.averageRisk,        77.5,       "averageRisk = (60+95)/2")
_assert_eq(stats.maxDepth,           3,          "maxDepth = 3")
_assert_eq(stats.minDepth,           2,          "minDepth = 2")
_assert_eq(stats.totalEvidenceItems, 3,          "totalEvidenceItems = 3")
_assert_eq(stats.uniqueDecisions,
           ("ATTACK_CONFIRMED", "SUSPICIOUS"),
           "uniqueDecisions sorted")
_assert_in("OBSERVATION", stats.tracesByStage, "tracesByStage has OBSERVATION")
_assert_eq(stats.tracesByStage["OBSERVATION"], 2, "OBSERVATION appears 2 times total")
_assert_in("CONCLUSION",  stats.tracesByStage, "tracesByStage has CONCLUSION")

# immutability
try:
    stats.totalResults = 99  # type: ignore
    _assert(False, "ReasoningStatistics should be frozen")
except Exception:
    _assert(True, "ReasoningStatistics is immutable (frozen)")

# empty list
empty_stats = calculate_reasoning_statistics([])
_assert_eq(empty_stats.totalResults,      0,   "empty → totalResults = 0")
_assert_eq(empty_stats.averageConfidence, 0.0, "empty → averageConfidence = 0.0")
_assert_eq(empty_stats.averageRisk,       0.0, "empty → averageRisk = 0.0")

# determinism — same list → same stats
_assert_eq(
    calculate_reasoning_statistics([r_a, r_b]),
    calculate_reasoning_statistics([r_b, r_a]),
    "calculate_reasoning_statistics is order-independent (deterministic)",
)

# ---------------------------------------------------------------------------
# §16  find_reasoning_step()
# ---------------------------------------------------------------------------
print("§16  find_reasoning_step() ...")

search_traces = [
    build_reasoning_trace(1, ReasoningStage.OBSERVATION,          "in","out", 50.0),
    build_reasoning_trace(2, ReasoningStage.EVIDENCE_CORRELATION, "in","out", 80.0),
    build_reasoning_trace(3, ReasoningStage.CONCLUSION,           "in","out", 90.0),
]

found_by_num = find_reasoning_step(search_traces, step_number=2)
_assert(found_by_num is not None,                          "find by stepNumber found")
_assert_eq(found_by_num.stepNumber, 2,                     "found correct step")
_assert_eq(found_by_num.stage, ReasoningStage.EVIDENCE_CORRELATION, "found correct stage")

found_by_stage = find_reasoning_step(search_traces, stage=ReasoningStage.CONCLUSION)
_assert(found_by_stage is not None,                "find by stage found")
_assert_eq(found_by_stage.stepNumber, 3,           "found step 3 for CONCLUSION")

not_found_num = find_reasoning_step(search_traces, step_number=99)
_assert(not_found_num is None, "step_number=99 not found → None")

not_found_stage = find_reasoning_step(search_traces, stage=ReasoningStage.RISK_ASSESSMENT)
_assert(not_found_stage is None, "missing stage → None")

no_criterion = find_reasoning_step(search_traces)
_assert(no_criterion is None, "no criterion → None")

# step_number takes priority over stage
found_priority = find_reasoning_step(search_traces,
    step_number=1, stage=ReasoningStage.CONCLUSION)
_assert_eq(found_priority.stepNumber, 1, "step_number priority over stage")

# empty list
_assert(find_reasoning_step([], step_number=1) is None, "empty list → None")

# determinism
_assert_eq(
    find_reasoning_step(search_traces, step_number=2),
    find_reasoning_step(search_traces, step_number=2),
    "find_reasoning_step is deterministic",
)

# ---------------------------------------------------------------------------
# §17  No uuid4 / no random — verify no randomness exists
# ---------------------------------------------------------------------------
print("§17  No randomness in outputs ...")

# Build the same result 5 times and verify all IDs identical
ids_collected = []
keys_collected = []
fps_collected = []
for _ in range(5):
    r = build_reasoning(
        ["ctx-x"], ["f-x"], ["a-x"], ["r-x"], ["tl-x"],
        _CREATED_AT,
    )
    ids_collected.append(r.reasoningId)
    keys_collected.append(r.reasoningKey)
    fps_collected.append(r.reasoningFingerprint)

_assert_eq(len(set(ids_collected)),  1, "no randomness: all 5 reasoningIds identical")
_assert_eq(len(set(keys_collected)), 1, "no randomness: all 5 reasoningKeys identical")
_assert_eq(len(set(fps_collected)),  1, "no randomness: all 5 fingerprints identical")

# ---------------------------------------------------------------------------
# §18  Duplicate IDs in input are collapsed
# ---------------------------------------------------------------------------
print("§18  Duplicate IDs collapsed ...")

r_dedup1 = build_reasoning(
    context_ids      = ["ctx-a", "ctx-a", "ctx-b"],
    finding_ids      = ["f-1", "f-1"],
    alert_ids        = ["a-1", "a-1", "a-1"],
    relationship_ids = ["r-1"],
    timeline_ids     = ["tl-1"],
    created_at       = _CREATED_AT,
)
r_dedup2 = build_reasoning(
    context_ids      = ["ctx-a", "ctx-b"],
    finding_ids      = ["f-1"],
    alert_ids        = ["a-1"],
    relationship_ids = ["r-1"],
    timeline_ids     = ["tl-1"],
    created_at       = _CREATED_AT,
)
_assert_eq(r_dedup1.reasoningId,  r_dedup2.reasoningId,  "duplicates collapsed: same reasoningId")
_assert_eq(r_dedup1.reasoningKey, r_dedup2.reasoningKey, "duplicates collapsed: same reasoningKey")

# ---------------------------------------------------------------------------
# §19  Empty trace and evidence are handled gracefully
# ---------------------------------------------------------------------------
print("§19  Empty trace and evidence handled ...")

r_empty = build_reasoning(
    context_ids=[], finding_ids=[], alert_ids=[],
    relationship_ids=[], timeline_ids=[], created_at=_CREATED_AT,
)
_assert_eq(r_empty.reasoningTrace,     (),   "empty trace → empty tuple")
_assert_eq(r_empty.supportingEvidence, (),   "empty evidence → empty tuple")
_assert_eq(len(r_empty.reasoningId),   36,   "empty input still yields valid UUID reasoningId")
_assert_eq(len(r_empty.reasoningKey),  32,   "empty input still yields 32-char key")
_assert_eq(len(r_empty.reasoningFingerprint), 32, "empty input still yields 32-char fingerprint")

# ---------------------------------------------------------------------------
# §20  Full pipeline integration + fingerprint changes on data change
# ---------------------------------------------------------------------------
print("§20  Full pipeline integration ...")

base_trace = build_reasoning_trace(
    1, ReasoningStage.OBSERVATION, "packets", "3 hosts", 75.0,
    evidence_ids=["ev-001"],
)
base_result = build_reasoning(
    context_ids      = ["ctx-1"],
    finding_ids      = ["f-1"],
    alert_ids        = ["a-1"],
    relationship_ids = ["r-1"],
    timeline_ids     = ["tl-1"],
    created_at       = _CREATED_AT,
    reasoning_trace  = [base_trace],
    decision         = "SUSPICIOUS",
    overall_confidence = 65.0,
    overall_risk       = 55.0,
)

# Adding a new finding → different key and fingerprint
new_result = build_reasoning(
    context_ids      = ["ctx-1"],
    finding_ids      = ["f-1", "f-2"],   # added f-2
    alert_ids        = ["a-1"],
    relationship_ids = ["r-1"],
    timeline_ids     = ["tl-1"],
    created_at       = _CREATED_AT,
    reasoning_trace  = [base_trace],
    decision         = "SUSPICIOUS",
    overall_confidence = 65.0,
    overall_risk       = 55.0,
)
_assert_ne(base_result.reasoningKey,         new_result.reasoningKey,
           "adding finding → different key")
_assert_ne(base_result.reasoningId,          new_result.reasoningId,
           "adding finding → different id")
_assert_ne(base_result.reasoningFingerprint, new_result.reasoningFingerprint,
           "adding finding → different fingerprint")

# Changing confidence only (does not affect key, does affect fingerprint
# because trace fingerprint encodes confidence)
changed_trace = build_reasoning_trace(
    1, ReasoningStage.OBSERVATION, "packets", "3 hosts", 99.0,  # changed
    evidence_ids=["ev-001"],
)
changed_result = build_reasoning(
    context_ids      = ["ctx-1"],
    finding_ids      = ["f-1"],
    alert_ids        = ["a-1"],
    relationship_ids = ["r-1"],
    timeline_ids     = ["tl-1"],
    created_at       = _CREATED_AT,
    reasoning_trace  = [changed_trace],
    decision         = "SUSPICIOUS",
    overall_confidence = 65.0,
    overall_risk       = 55.0,
)
_assert_eq(base_result.reasoningKey,  changed_result.reasoningKey,
           "same IDs → same key even if trace confidence changes")
_assert_ne(base_result.reasoningFingerprint, changed_result.reasoningFingerprint,
           "changed trace confidence → different fingerprint")

# engineVersion is always from constant
_assert_eq(base_result.engineVersion,    REASONING_ENGINE_VERSION, "engineVersion from constant")
_assert_eq(new_result.engineVersion,     REASONING_ENGINE_VERSION, "engineVersion from constant")
_assert_eq(changed_result.engineVersion, REASONING_ENGINE_VERSION, "engineVersion from constant")

# ---------------------------------------------------------------------------
# §21  All 9 ReasoningStages in a full trace
# ---------------------------------------------------------------------------
print("§21  All 9 stages in a trace ...")

all_stage_traces = [
    build_reasoning_trace(i+1, stage, f"input {i}", f"output {i}", float(50+i*5))
    for i, stage in enumerate(ReasoningStage)
]
r_full = build_reasoning(
    ["ctx-full"], ["f-full"], ["a-full"], ["r-full"], ["tl-full"],
    _CREATED_AT,
    reasoning_trace=all_stage_traces,
    decision="COMPREHENSIVE",
    overall_confidence=85.0,
    overall_risk=75.0,
)

_assert_eq(len(r_full.reasoningTrace), 9, "all 9 stages in trace")
grouped = group_reasoning_trace(list(r_full.reasoningTrace))
_assert_eq(len(grouped), 9, "group_reasoning_trace yields 9 groups for 9 stages")

stats_full = calculate_reasoning_statistics([r_full])
_assert_eq(len(stats_full.tracesByStage), 9, "stats capture all 9 stages")
for stage in ReasoningStage:
    _assert_in(stage.value, stats_full.tracesByStage,
               f"stage {stage.value} present in tracesByStage")

# ---------------------------------------------------------------------------
# §22  ReasoningResult fields structure
# ---------------------------------------------------------------------------
print("§22  ReasoningResult structure ...")

_assert(hasattr(result, "reasoningId"),          "has reasoningId")
_assert(hasattr(result, "reasoningKey"),         "has reasoningKey")
_assert(hasattr(result, "reasoningFingerprint"), "has reasoningFingerprint")
_assert(hasattr(result, "overallConfidence"),    "has overallConfidence")
_assert(hasattr(result, "overallRisk"),          "has overallRisk")
_assert(hasattr(result, "decision"),             "has decision")
_assert(hasattr(result, "reasoningTrace"),       "has reasoningTrace")
_assert(hasattr(result, "supportingEvidence"),   "has supportingEvidence")
_assert(hasattr(result, "decisionExplanation"),  "has decisionExplanation")
_assert(hasattr(result, "metadata"),             "has metadata")
_assert(hasattr(result, "engineVersion"),        "has engineVersion")
_assert(hasattr(result, "createdAt"),            "has createdAt")

# ---------------------------------------------------------------------------
# §23  createdAt is preserved verbatim
# ---------------------------------------------------------------------------
print("§23  createdAt preserved ...")

ts1 = "2026-01-15T08:00:00Z"
ts2 = "2026-06-30T12:34:56Z"
r_ts1 = build_reasoning(["c"], ["f"], ["a"], ["r"], ["t"], ts1)
r_ts2 = build_reasoning(["c"], ["f"], ["a"], ["r"], ["t"], ts2)
_assert_eq(r_ts1.createdAt, ts1, "createdAt ts1 preserved")
_assert_eq(r_ts2.createdAt, ts2, "createdAt ts2 preserved")
_assert_eq(r_ts1.reasoningId, r_ts2.reasoningId, "createdAt does not affect reasoningId")
_assert_eq(r_ts1.reasoningKey, r_ts2.reasoningKey, "createdAt does not affect reasoningKey")

# ---------------------------------------------------------------------------
# Final summary
# ---------------------------------------------------------------------------
print()
print("=" * 70)
total = _PASS + _FAIL

if _ERRORS:
    print("FAILURES:")
    for err in _ERRORS:
        print(f"  {err}")
    print()

print(f"Assertions run  : {total}")
print(f"PASSED          : {_PASS}")
print(f"FAILED          : {_FAIL}")
print("=" * 70)

if _FAIL == 0:
    print()
    print("DELIVERY SUMMARY")
    print("=" * 70)
    print()
    print("FILES CREATED")
    print("  services/reasoning_service.py")
    print("  smoke_test_reasoning_engine.py")
    print()
    print("MODELS  (all frozen=True dataclasses)")
    print("  ReasoningEvidence      — evidence item with weight + confidence")
    print("  ReasoningTrace         — one step in the reasoning chain")
    print("  DecisionExplanation    — structured strengths/weaknesses/next-steps")
    print("  ReasoningMetadata      — processing provenance + timings")
    print("  ReasoningResult        — top-level immutable result object")
    print("  ReasoningStatistics    — aggregate statistics over result lists")
    print()
    print("ENUM")
    print("  ReasoningStage (9 values):")
    for s in ReasoningStage:
        print(f"    {s.value}")
    print()
    print("BUILDER FUNCTIONS")
    print("  build_reasoning()          — primary result builder")
    print("  build_reasoning_trace()    — trace step builder")
    print("  build_reasoning_evidence() — evidence item builder")
    print("  build_decision_explanation() — explanation builder")
    print("  build_reasoning_metadata() — metadata builder")
    print()
    print("UTILITY FUNCTIONS")
    print("  sort_reasoning_trace()              — sort by stepNumber")
    print("  sort_reasoning_evidence()           — sort by weight/confidence/id/sourceType")
    print("  filter_reasoning_trace()            — multi-criterion filter")
    print("  group_reasoning_trace()             — group by attribute")
    print("  calculate_reasoning_statistics()    — aggregate stats over results")
    print("  find_reasoning_step()               — lookup by stepNumber or stage")
    print()
    print("DETERMINISTIC STRATEGY")
    print("  reasoningKey        = SHA256(sorted contextIds + sorted findingIds +")
    print("                        sorted alertIds + sorted relationshipIds +")
    print("                        sorted timelineIds)[:32]")
    print("  reasoningId         = UUIDv5(REASONING_NS, reasoningKey)")
    print("  traceFingerprint    = SHA256(stepNumber|stage|confidence|")
    print("                        sorted evidenceIds|...|sorted timelineEventIds)[:32]")
    print("  reasoningFingerprint= SHA256(reasoningKey + trace fps in stepNum order +")
    print("                        sorted evidenceIds)[:32]")
    print()
    print("CONSTANTS ADDED TO core/constants.py")
    print(f"  REASONING_ENGINE_VERSION = {repr(REASONING_ENGINE_VERSION)}")
    print()
    print(f"SMOKE TEST RESULTS: {_PASS} / {total} assertions PASSED — 100%")
    print()
    print("ALL CHECKS PASSED ✓")
else:
    print()
    print(f"SMOKE TEST FAILED: {_FAIL} / {total} assertions failed")
    sys.exit(1)
