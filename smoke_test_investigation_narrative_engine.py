"""
Smoke Test — Investigation Narrative Engine
============================================
Verifies every model, builder, and utility in
services/investigation_narrative_service.py with 220+ assertions.

Run:
    python smoke_test_investigation_narrative_engine.py
Expected: 100% PASS, no errors.
"""

from __future__ import annotations

import sys
import traceback
from typing import List

from services.investigation_narrative_service import (
    # Models
    NarrativeSection,
    NarrativeTimelineEntry,
    NarrativeSummary,
    NarrativeMetadata,
    NarrativeDocument,
    NarrativeStatistics,
    # Builders
    build_narrative_section,
    build_timeline_entry,
    build_narrative_summary,
    build_narrative_metadata,
    build_narrative_document,
    # Utilities
    sort_sections,
    sort_timeline,
    filter_sections,
    group_sections,
    calculate_narrative_statistics,
    find_section,
    # Internal helpers for determinism testing
    _compute_section_id,
    _compute_section_fingerprint,
    _compute_timeline_entry_id,
    _compute_timeline_fingerprint,
    _compute_summary_fingerprint,
    _compute_narrative_key,
    _compute_narrative_id,
    _compute_narrative_fingerprint,
    INVESTIGATION_NARRATIVE_ENGINE_VERSION,
)
from core.constants import INVESTIGATION_NARRATIVE_ENGINE_VERSION as CONST_VERSION

# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------
_PASS = 0
_FAIL = 0
_ERRORS: List[str] = []

def _assert(cond: bool, msg: str) -> None:
    global _PASS, _FAIL
    if cond:
        _PASS += 1
    else:
        _FAIL += 1
        frame = traceback.extract_stack()[-2]
        _ERRORS.append(f"FAIL [line {frame.lineno}]: {msg}")

def _eq(a, b, msg: str) -> None:
    _assert(a == b, f"{msg} — expected {b!r}, got {a!r}")

def _ne(a, b, msg: str) -> None:
    _assert(a != b, f"{msg} — both are {a!r}")

def _in(item, container, msg: str) -> None:
    _assert(item in container, f"{msg} — {item!r} not found")

_TS = "2026-06-30T12:00:00Z"

# ===========================================================================
# §1  Engine version constant
# ===========================================================================
print("§1  Engine version constant ...")
_eq(INVESTIGATION_NARRATIVE_ENGINE_VERSION, "investigation-narrative-v1", "engine version value")
_eq(CONST_VERSION, INVESTIGATION_NARRATIVE_ENGINE_VERSION, "core.constants matches service")
_assert(isinstance(INVESTIGATION_NARRATIVE_ENGINE_VERSION, str), "engine version is str")
_assert(len(INVESTIGATION_NARRATIVE_ENGINE_VERSION) > 0, "engine version non-empty")

# ===========================================================================
# §2  build_narrative_section()
# ===========================================================================
print("§2  build_narrative_section() ...")

s1 = build_narrative_section(
    title                   = "Attack Overview",
    content                 = "The attacker exploited DNS tunnelling to exfiltrate data.",
    order                   = 1,
    importance              = 90.0,
    related_evidence_ids    = ["ev-003", "ev-001", "ev-002"],
    related_finding_ids     = ["f-002", "f-001"],
    related_alert_ids       = ["a-001"],
    related_relationship_ids= ["r-002", "r-001"],
)
_assert(isinstance(s1, NarrativeSection),    "returns NarrativeSection")
_eq(s1.title,      "Attack Overview",        "title preserved")
_eq(s1.order,      1,                        "order set")
_eq(s1.importance, 90.0,                     "importance set")
_eq(len(s1.sectionId), 32,                   "sectionId is 32 chars")
_assert(all(c in "0123456789abcdef" for c in s1.sectionId), "sectionId is hex")

# IDs must be sorted
_eq(s1.relatedEvidenceIds,     ("ev-001","ev-002","ev-003"), "evidenceIds sorted")
_eq(s1.relatedFindingIds,      ("f-001","f-002"),            "findingIds sorted")
_eq(s1.relatedAlertIds,        ("a-001",),                   "alertIds sorted")
_eq(s1.relatedRelationshipIds, ("r-001","r-002"),            "relationshipIds sorted")

# Importance clamping
s_hi = build_narrative_section("T","c", 0, importance=999.0)
_eq(s_hi.importance, 100.0, "importance clamped to 100")
s_lo = build_narrative_section("T","c", 0, importance=-10.0)
_eq(s_lo.importance, 0.0, "importance clamped to 0")

# Immutability
try:
    s1.title = "changed"   # type: ignore
    _assert(False, "NarrativeSection should be frozen")
except Exception:
    _assert(True, "NarrativeSection is immutable")

# Title stripping
s_ws = build_narrative_section("  My Section  ", "body", 0)
_eq(s_ws.title, "My Section", "title stripped")

# Same inputs → same sectionId
s2 = build_narrative_section("Attack Overview",
    "The attacker exploited DNS tunnelling to exfiltrate data.", 1, 90.0)
_eq(s1.sectionId, s2.sectionId, "same inputs → same sectionId")

# Different content → different sectionId
s3 = build_narrative_section("Attack Overview", "Different content entirely!", 1, 90.0)
_ne(s1.sectionId, s3.sectionId, "different content → different sectionId")

# Duplicate IDs deduplicated
s_dup = build_narrative_section("T","c", 0, related_evidence_ids=["ev-1","ev-1","ev-2"])
_eq(len(s_dup.relatedEvidenceIds), 2, "duplicate evidenceIds deduplicated")

# Empty IDs → empty tuples
s_empty = build_narrative_section("T", "c", 0)
_eq(s_empty.relatedEvidenceIds,     (), "empty evidenceIds → ()")
_eq(s_empty.relatedFindingIds,      (), "empty findingIds → ()")
_eq(s_empty.relatedAlertIds,        (), "empty alertIds → ()")
_eq(s_empty.relatedRelationshipIds, (), "empty relationshipIds → ()")

# ===========================================================================
# §3  build_timeline_entry()
# ===========================================================================
print("§3  build_timeline_entry() ...")

te1 = build_timeline_entry(
    timestamp    = "2026-06-30T09:00:00Z",
    title        = "Initial Compromise",
    description  = "Attacker sent malicious DNS query to C2 server.",
    importance   = 95.0,
    evidence_ids = ["ev-002", "ev-001"],
)
_assert(isinstance(te1, NarrativeTimelineEntry), "returns NarrativeTimelineEntry")
_eq(te1.timestamp,  "2026-06-30T09:00:00Z", "timestamp preserved")
_eq(te1.title,      "Initial Compromise",   "title preserved")
_eq(te1.importance, 95.0,                   "importance set")
_eq(len(te1.eventId), 32,                   "eventId is 32 chars")
_eq(te1.evidenceIds, ("ev-001","ev-002"),    "evidenceIds sorted")

# Empty timestamp
te_no_ts = build_timeline_entry("", "Unknown Event", "desc", 50.0)
_eq(te_no_ts.timestamp, "", "empty timestamp preserved")
_eq(len(te_no_ts.eventId), 32, "eventId still 32 chars with empty timestamp")

# Importance clamping
te_hi = build_timeline_entry("", "T", "d", 200.0)
_eq(te_hi.importance, 100.0, "importance clamped to 100")
te_lo = build_timeline_entry("", "T", "d", -5.0)
_eq(te_lo.importance, 0.0, "importance clamped to 0")

# Immutability
try:
    te1.title = "changed"   # type: ignore
    _assert(False, "NarrativeTimelineEntry should be frozen")
except Exception:
    _assert(True, "NarrativeTimelineEntry is immutable")

# Same inputs → same eventId
te2 = build_timeline_entry("2026-06-30T09:00:00Z", "Initial Compromise",
    "Attacker sent malicious DNS query to C2 server.", 95.0)
_eq(te1.eventId, te2.eventId, "same inputs → same eventId")

# Different description → different eventId
te3 = build_timeline_entry("2026-06-30T09:00:00Z", "Initial Compromise",
    "Completely different description here.", 95.0)
_ne(te1.eventId, te3.eventId, "different description → different eventId")

# ===========================================================================
# §4  build_narrative_summary()
# ===========================================================================
print("§4  build_narrative_summary() ...")

summary = build_narrative_summary(
    title              = "Lateral Movement Investigation",
    overview           = "Attacker pivoted across 3 hosts over 5 minutes.",
    attack_summary     = "DNS tunnelling used for C2 and data exfiltration.",
    risk_summary       = "HIGH risk — 3 internal hosts compromised.",
    impact_summary     = "Sensitive data may have been exfiltrated.",
    confidence_summary = "85% confidence based on pcap and ARP evidence.",
    recommended_actions= ["Isolate hosts", "Block DNS to external resolvers", "Capture live traffic"],
)
_assert(isinstance(summary, NarrativeSummary),   "returns NarrativeSummary")
_eq(summary.title,    "Lateral Movement Investigation", "title set")
_eq(summary.overview, "Attacker pivoted across 3 hosts over 5 minutes.", "overview set")
_eq(summary.attackSummary,     "DNS tunnelling used for C2 and data exfiltration.", "attackSummary set")
_eq(summary.riskSummary,       "HIGH risk — 3 internal hosts compromised.", "riskSummary set")
_eq(summary.impactSummary,     "Sensitive data may have been exfiltrated.", "impactSummary set")
_eq(summary.confidenceSummary, "85% confidence based on pcap and ARP evidence.", "confidenceSummary set")

# recommendedActions sorted
_eq(summary.recommendedActions,
    ("Block DNS to external resolvers", "Capture live traffic", "Isolate hosts"),
    "recommendedActions sorted")

# Immutability
try:
    summary.title = "changed"   # type: ignore
    _assert(False, "NarrativeSummary should be frozen")
except Exception:
    _assert(True, "NarrativeSummary is immutable")

# Duplicate actions deduplicated
s_dup_sum = build_narrative_summary("T","o","a","r","i","c",
    recommended_actions=["Act A","Act A","Act B"])
_eq(len(s_dup_sum.recommendedActions), 2, "duplicate recommended_actions deduplicated")

# Empty actions → empty tuple
s_no_act = build_narrative_summary("T","o","a","r","i","c")
_eq(s_no_act.recommendedActions, (), "no actions → empty tuple")

# ===========================================================================
# §5  Deterministic ID helpers
# ===========================================================================
print("§5  Deterministic ID helpers ...")

# sectionId
sid_a = _compute_section_id("Attack Overview", 1, "The attacker pivoted.")
sid_b = _compute_section_id("Attack Overview", 1, "The attacker pivoted.")
_eq(sid_a, sid_b, "same inputs → same sectionId")
_eq(len(sid_a), 32, "sectionId is 32 chars")
_assert(all(c in "0123456789abcdef" for c in sid_a), "sectionId is hex")
sid_diff = _compute_section_id("Attack Overview", 1, "Something completely different!")
_ne(sid_a, sid_diff, "different content → different sectionId")

# section fingerprint
fp_s_a = _compute_section_fingerprint(s1)
fp_s_b = _compute_section_fingerprint(s1)
_eq(fp_s_a, fp_s_b, "same section → same fingerprint")
_eq(len(fp_s_a), 32, "section fingerprint is 32 chars")
fp_s_diff = _compute_section_fingerprint(s3)
_ne(fp_s_a, fp_s_diff, "different content → different section fingerprint")

# timeline entry id
eid_a = _compute_timeline_entry_id("2026-06-30T09:00:00Z", "Initial Compromise", "Attacker sent")
eid_b = _compute_timeline_entry_id("2026-06-30T09:00:00Z", "Initial Compromise", "Attacker sent")
_eq(eid_a, eid_b, "same inputs → same eventId")
_eq(len(eid_a), 32, "eventId is 32 chars")
eid_diff = _compute_timeline_entry_id("2026-06-30T09:00:00Z", "Initial Compromise", "Changed desc!")
_ne(eid_a, eid_diff, "different description → different eventId")

# timeline fingerprint
fp_t_a = _compute_timeline_fingerprint(te1)
fp_t_b = _compute_timeline_fingerprint(te1)
_eq(fp_t_a, fp_t_b, "same entry → same timeline fingerprint")
_eq(len(fp_t_a), 32, "timeline fingerprint is 32 chars")

# summary fingerprint
fp_sum_a = _compute_summary_fingerprint(summary)
fp_sum_b = _compute_summary_fingerprint(summary)
_eq(fp_sum_a, fp_sum_b, "same summary → same fingerprint")
_eq(len(fp_sum_a), 32, "summary fingerprint is 32 chars")

# narrativeKey
nk_a = _compute_narrative_key("r-001","ctx-001","inv-001",["sec-b","sec-a"],["tl-b","tl-a"])
nk_b = _compute_narrative_key("r-001","ctx-001","inv-001",["sec-b","sec-a"],["tl-b","tl-a"])
_eq(nk_a, nk_b, "same inputs → same narrativeKey")
nk_rev = _compute_narrative_key("r-001","ctx-001","inv-001",["sec-a","sec-b"],["tl-a","tl-b"])
_eq(nk_a, nk_rev, "reversed sectionIds/timelineIds → same narrativeKey (sorted)")
_eq(len(nk_a), 32, "narrativeKey is 32 chars")
nk_diff = _compute_narrative_key("r-999","ctx-001","inv-001",["sec-a"],["tl-a"])
_ne(nk_a, nk_diff, "different reasoningId → different narrativeKey")

# narrativeId
nid_a = _compute_narrative_id(nk_a)
nid_b = _compute_narrative_id(nk_a)
_eq(nid_a, nid_b, "same key → same narrativeId")
_eq(len(nid_a), 36, "narrativeId is UUID (36 chars)")
_in("-", nid_a, "narrativeId contains hyphens")
nid_diff = _compute_narrative_id(nk_diff)
_ne(nid_a, nid_diff, "different keys → different narrativeIds")

# narrativeFingerprint
secs_t = (s1,)
tl_t   = (te1,)
nfp_a = _compute_narrative_fingerprint(nk_a, summary, secs_t, tl_t)
nfp_b = _compute_narrative_fingerprint(nk_a, summary, secs_t, tl_t)
_eq(nfp_a, nfp_b, "same inputs → same narrativeFingerprint")
_eq(len(nfp_a), 32, "narrativeFingerprint is 32 chars")

# ===========================================================================
# §6  build_narrative_metadata()
# ===========================================================================
print("§6  build_narrative_metadata() ...")

meta_secs = (
    build_narrative_section("Overview", "content a", 0, 80.0),
    build_narrative_section("Timeline", "content b", 1, 70.0),
)
meta_tl = (
    build_timeline_entry("2026-06-30T09:00:00Z", "Event A", "desc a", 80.0),
)
meta_obj = build_narrative_metadata(
    processing_time_ms = 42,
    sections           = meta_secs,
    timeline           = meta_tl,
    finding_count      = 5,
    alert_count        = 3,
    relationship_count = 12,
    evidence_count     = 44,
)
_assert(isinstance(meta_obj, NarrativeMetadata), "returns NarrativeMetadata")
_eq(meta_obj.processingTimeMs,  42, "processingTimeMs set")
_eq(meta_obj.sectionCount,       2, "sectionCount = 2")
_eq(meta_obj.timelineEventCount, 1, "timelineEventCount = 1")
_eq(meta_obj.findingCount,       5, "findingCount = 5")
_eq(meta_obj.alertCount,         3, "alertCount = 3")
_eq(meta_obj.relationshipCount, 12, "relationshipCount = 12")
_eq(meta_obj.evidenceCount,     44, "evidenceCount = 44")
_eq(meta_obj.engineVersion, INVESTIGATION_NARRATIVE_ENGINE_VERSION, "engineVersion correct")

# Negative → 0
meta_neg = build_narrative_metadata(-10, meta_secs, meta_tl, -1, -2, -3, -4)
_eq(meta_neg.processingTimeMs, 0, "negative processingTimeMs → 0")
_eq(meta_neg.findingCount,     0, "negative findingCount → 0")

# Immutability
try:
    meta_obj.sectionCount = 99  # type: ignore
    _assert(False, "NarrativeMetadata should be frozen")
except Exception:
    _assert(True, "NarrativeMetadata is immutable")

# ===========================================================================
# §7  sort_sections()
# ===========================================================================
print("§7  sort_sections() ...")

sec_a = build_narrative_section("Section C", "c", order=3, importance=50.0)
sec_b = build_narrative_section("Section A", "a", order=1, importance=80.0)
sec_c = build_narrative_section("Section B", "b", order=2, importance=60.0)
unsorted_secs = [sec_a, sec_c, sec_b]

asc = sort_sections(unsorted_secs, ascending=True)
_eq(asc[0].order, 1, "ascending: order 1 first")
_eq(asc[1].order, 2, "ascending: order 2 second")
_eq(asc[2].order, 3, "ascending: order 3 last")

desc = sort_sections(unsorted_secs, ascending=False)
_eq(desc[0].order, 3, "descending: order 3 first")
_eq(desc[2].order, 1, "descending: order 1 last")

# Input not mutated
_eq(unsorted_secs[0].order, 3, "input not mutated by sort_sections")
# Determinism
_eq(sort_sections(unsorted_secs), sort_sections(unsorted_secs), "sort_sections deterministic")

# Tie-break by sectionId
sec_tie_a = build_narrative_section("Tie A", "same order content 1", order=5)
sec_tie_b = build_narrative_section("Tie B", "same order content 2", order=5)
tied = sort_sections([sec_tie_b, sec_tie_a], ascending=True)
_assert(tied[0].sectionId <= tied[1].sectionId, "tie-break by sectionId ASC")

# ===========================================================================
# §8  sort_timeline()
# ===========================================================================
print("§8  sort_timeline() ...")

te_early  = build_timeline_entry("2026-06-30T08:00:00Z", "Early Event",  "e", 70.0)
te_middle = build_timeline_entry("2026-06-30T09:00:00Z", "Middle Event", "m", 80.0)
te_late   = build_timeline_entry("2026-06-30T10:00:00Z", "Late Event",   "l", 90.0)
te_no_ts  = build_timeline_entry("",                     "Unknown",      "u", 50.0)

unsorted_tl = [te_late, te_no_ts, te_early, te_middle]
asc_tl = sort_timeline(unsorted_tl, ascending=True)
_eq(asc_tl[0].timestamp, "2026-06-30T08:00:00Z", "ascending: earliest first")
_eq(asc_tl[1].timestamp, "2026-06-30T09:00:00Z", "ascending: middle second")
_eq(asc_tl[2].timestamp, "2026-06-30T10:00:00Z", "ascending: late third")
_eq(asc_tl[3].timestamp, "",                     "ascending: empty timestamp last")

desc_tl = sort_timeline(unsorted_tl, ascending=False)
_eq(desc_tl[0].timestamp, "",                     "descending: empty timestamp first (sentinel)")
_eq(desc_tl[3].timestamp, "2026-06-30T08:00:00Z", "descending: earliest last")

# Input not mutated
_eq(unsorted_tl[0].timestamp, "2026-06-30T10:00:00Z", "input not mutated by sort_timeline")
# Determinism
_eq(sort_timeline(unsorted_tl), sort_timeline(unsorted_tl), "sort_timeline deterministic")

# ===========================================================================
# §9  filter_sections()
# ===========================================================================
print("§9  filter_sections() ...")

all_secs = [
    build_narrative_section("Attack Overview",   "c", 1, 90.0,
        related_finding_ids=["f-1"], related_alert_ids=["a-1"],
        related_evidence_ids=["ev-1"]),
    build_narrative_section("Evidence Details",  "c", 2, 70.0,
        related_evidence_ids=["ev-2","ev-3"]),
    build_narrative_section("Timeline Summary",  "c", 3, 60.0),
    build_narrative_section("Risk Assessment",   "c", 4, 80.0,
        related_finding_ids=["f-2"]),
    build_narrative_section("Recommendations",   "c", 5, 50.0),
]

# min_order
ge2 = filter_sections(all_secs, min_order=2)
_assert(all(s.order >= 2 for s in ge2), "min_order=2 filter")
_eq(len(ge2), 4, "min_order=2 → 4 sections")

# max_order
le3 = filter_sections(all_secs, max_order=3)
_assert(all(s.order <= 3 for s in le3), "max_order=3 filter")
_eq(len(le3), 3, "max_order=3 → 3 sections")

# min_importance
hi_imp = filter_sections(all_secs, min_importance=80.0)
_assert(all(s.importance >= 80.0 for s in hi_imp), "min_importance=80 filter")
_eq(len(hi_imp), 2, "min_importance=80 → 2 sections")

# title_contains
with_ev = filter_sections(all_secs, title_contains="evidence")
_eq(len(with_ev), 1, "title_contains 'evidence' → 1 section")
_eq(with_ev[0].title, "Evidence Details", "correct section returned")

# has_findings
with_f = filter_sections(all_secs, has_findings=True)
_eq(len(with_f), 2, "has_findings=True → 2 sections")
no_f = filter_sections(all_secs, has_findings=False)
_eq(len(no_f), 3, "has_findings=False → 3 sections")

# has_alerts
with_a = filter_sections(all_secs, has_alerts=True)
_eq(len(with_a), 1, "has_alerts=True → 1 section")

# has_evidence
with_e = filter_sections(all_secs, has_evidence=True)
_eq(len(with_e), 2, "has_evidence=True → 2 sections")

# combined
combo = filter_sections(all_secs, min_importance=70.0, has_findings=True)
_assert(all(s.importance >= 70.0 and s.relatedFindingIds for s in combo),
        "combined filter: min_importance + has_findings")

# no filter → all
_eq(len(filter_sections(all_secs)), 5, "no filter → all returned")
# empty
_eq(len(filter_sections([])), 0, "empty input → empty output")
# input not mutated
_eq(len(all_secs), 5, "input not mutated by filter_sections")

# ===========================================================================
# §10  group_sections()
# ===========================================================================
print("§10  group_sections() ...")

grp_secs = [
    build_narrative_section("Alpha", "c", order=1),
    build_narrative_section("Beta",  "c", order=2),
    build_narrative_section("Gamma", "c", order=1),
    build_narrative_section("Delta", "c", order=3),
]

by_order = group_sections(grp_secs, group_by="order")
_in("1", by_order, "order group '1' present")
_in("2", by_order, "order group '2' present")
_in("3", by_order, "order group '3' present")
_eq(len(by_order["1"]), 2, "two sections with order 1")

# groups sorted by order ASC, sectionId ASC
_assert(by_order["1"][0].sectionId <= by_order["1"][1].sectionId,
        "order=1 group sorted by sectionId")

by_title = group_sections(grp_secs, group_by="title")
_eq(len(by_title), 4, "group by title → 4 groups")

by_sid = group_sections(grp_secs, group_by="sectionId")
_eq(len(by_sid), 4, "group by sectionId → 4 groups")

# invalid key
try:
    group_sections(grp_secs, group_by="nonexistent")
    _assert(False, "invalid group_by should raise ValueError")
except ValueError:
    _assert(True, "invalid group_by raises ValueError")

# empty
_eq(len(group_sections([])), 0, "empty → empty groups")
# determinism
_eq(
    {k: [s.title for s in v] for k, v in group_sections(grp_secs).items()},
    {k: [s.title for s in v] for k, v in group_sections(grp_secs).items()},
    "group_sections deterministic",
)

# ===========================================================================
# §11  find_section()
# ===========================================================================
print("§11  find_section() ...")

search_secs = [
    build_narrative_section("Alpha",   "c", order=1),
    build_narrative_section("Beta",    "c", order=2),
    build_narrative_section("Gamma",   "c", order=3),
]
sec_alpha = search_secs[0]

# By sectionId
found_id = find_section(search_secs, section_id=sec_alpha.sectionId)
_assert(found_id is not None,           "find by sectionId found")
_eq(found_id.title, "Alpha",            "correct section found by id")

# By title
found_title = find_section(search_secs, title="Beta")
_assert(found_title is not None,        "find by title found")
_eq(found_title.order, 2,              "correct section found by title")

# By order
found_order = find_section(search_secs, order=3)
_assert(found_order is not None,        "find by order found")
_eq(found_order.title, "Gamma",         "correct section found by order")

# Not found
_assert(find_section(search_secs, section_id="nonexistent") is None, "not found → None")
_assert(find_section(search_secs, title="Nonexistent")      is None, "not found title → None")
_assert(find_section(search_secs, order=99)                is None, "not found order → None")
_assert(find_section(search_secs)                          is None, "no criterion → None")

# sectionId priority over title
found_prio = find_section(search_secs, section_id=sec_alpha.sectionId, title="Gamma")
_eq(found_prio.title, "Alpha", "sectionId takes priority over title")

# Empty list
_assert(find_section([], section_id="x") is None, "empty list → None")

# Determinism
_eq(find_section(search_secs, title="Beta"), find_section(search_secs, title="Beta"),
    "find_section deterministic")

# ===========================================================================
# §12  build_narrative_document()
# ===========================================================================
print("§12  build_narrative_document() ...")

doc_secs = [
    build_narrative_section("Initial Access",   "DNS query to C2.",          order=1, importance=90.0,
        related_finding_ids=["f-1"], related_evidence_ids=["ev-1","ev-2"]),
    build_narrative_section("Lateral Movement", "Attacker pivoted to host2.", order=2, importance=85.0,
        related_finding_ids=["f-2"], related_alert_ids=["a-1"]),
    build_narrative_section("Data Exfiltration","Exfil over DNS tunnel.",     order=3, importance=80.0,
        related_evidence_ids=["ev-3"]),
    build_narrative_section("Recommendations",  "Isolate and patch.",         order=4, importance=70.0),
]
doc_tl = [
    build_timeline_entry("2026-06-30T10:00:00Z", "Exfil Begins",    "Exfil started.", 80.0),
    build_timeline_entry("2026-06-30T09:30:00Z", "Lateral Move",    "Host pivot.",    70.0),
    build_timeline_entry("2026-06-30T09:00:00Z", "Initial Compromise","C2 contact.", 90.0),
]

doc = build_narrative_document(
    reasoning_id       = "r-abc123",
    context_id         = "ctx-def456",
    investigation_id   = "inv-ghi789",
    summary            = summary,
    created_at         = _TS,
    sections           = doc_secs,
    timeline           = doc_tl,
    finding_count      = 2,
    alert_count        = 1,
    relationship_count = 5,
    evidence_count     = 3,
    processing_time_ms = 77,
)

_assert(isinstance(doc, NarrativeDocument),  "returns NarrativeDocument")
_eq(doc.reasoningId,     "r-abc123",         "reasoningId preserved")
_eq(doc.contextId,       "ctx-def456",       "contextId preserved")
_eq(doc.investigationId, "inv-ghi789",       "investigationId preserved")
_eq(doc.createdAt,       _TS,               "createdAt preserved")
_eq(len(doc.narrativeId),  36,              "narrativeId is UUID (36 chars)")
_eq(len(doc.narrativeKey), 32,              "narrativeKey is 32 chars")
_eq(len(doc.narrativeFingerprint), 32,      "narrativeFingerprint is 32 chars")
_eq(doc.metadata.engineVersion, INVESTIGATION_NARRATIVE_ENGINE_VERSION, "engineVersion correct")
_eq(len(doc.sections),  4,                 "all 4 sections present")
_eq(len(doc.timeline),  3,                 "all 3 timeline entries present")

# Sections sorted by order ASC
_eq(doc.sections[0].order, 1, "sections[0] order=1")
_eq(doc.sections[1].order, 2, "sections[1] order=2")
_eq(doc.sections[2].order, 3, "sections[2] order=3")
_eq(doc.sections[3].order, 4, "sections[3] order=4")

# Timeline sorted by timestamp ASC
_eq(doc.timeline[0].timestamp, "2026-06-30T09:00:00Z", "timeline[0] earliest")
_eq(doc.timeline[1].timestamp, "2026-06-30T09:30:00Z", "timeline[1] middle")
_eq(doc.timeline[2].timestamp, "2026-06-30T10:00:00Z", "timeline[2] latest")

# Immutability
try:
    doc.reasoningId = "changed"  # type: ignore
    _assert(False, "NarrativeDocument should be frozen")
except Exception:
    _assert(True, "NarrativeDocument is immutable")

# ===========================================================================
# §13  Determinism: same input → same output
# ===========================================================================
print("§13  Determinism: same input → same output ...")

def _make_doc(secs, tl) -> NarrativeDocument:
    return build_narrative_document(
        "r-abc123", "ctx-def456", "inv-ghi789",
        summary, _TS, sections=secs, timeline=tl,
    )

d1 = _make_doc(doc_secs, doc_tl)
d2 = _make_doc(doc_secs, doc_tl)
_eq(d1.narrativeId,          d2.narrativeId,          "same input → same narrativeId")
_eq(d1.narrativeKey,         d2.narrativeKey,         "same input → same narrativeKey")
_eq(d1.narrativeFingerprint, d2.narrativeFingerprint, "same input → same fingerprint")
_eq(d1.sections,             d2.sections,             "same input → same sections tuple")
_eq(d1.timeline,             d2.timeline,             "same input → same timeline tuple")

# Reversed sections → same document (sorted internally)
d3 = _make_doc(list(reversed(doc_secs)), list(reversed(doc_tl)))
_eq(d1.narrativeId,          d3.narrativeId,          "reversed input → same narrativeId")
_eq(d1.narrativeKey,         d3.narrativeKey,         "reversed input → same narrativeKey")
_eq(d1.narrativeFingerprint, d3.narrativeFingerprint, "reversed input → same fingerprint")
_eq(d1.sections,             d3.sections,             "reversed input → same sections tuple")
_eq(d1.timeline,             d3.timeline,             "reversed input → same timeline tuple")

# Different reasoningId → different document
d4 = build_narrative_document(
    "r-DIFFERENT", "ctx-def456", "inv-ghi789",
    summary, _TS, sections=doc_secs, timeline=doc_tl,
)
_ne(d1.narrativeId,          d4.narrativeId,          "different reasoningId → different id")
_ne(d1.narrativeKey,         d4.narrativeKey,         "different reasoningId → different key")
_ne(d1.narrativeFingerprint, d4.narrativeFingerprint, "different reasoningId → different fp")

# Changed summary → same key (no section change), different fingerprint
summary2 = build_narrative_summary("Different Title","o","a","r","i","c")
d5 = _make_doc_with_summary = lambda s: build_narrative_document(
    "r-abc123", "ctx-def456", "inv-ghi789", s, _TS, sections=doc_secs, timeline=doc_tl)
doc_s2 = _make_doc_with_summary(summary2)
_eq(d1.narrativeKey,         doc_s2.narrativeKey,         "summary change → same key")
_ne(d1.narrativeFingerprint, doc_s2.narrativeFingerprint, "summary change → different fp")

# No randomness: build 5 times, all identical
ids_5 = [_make_doc(doc_secs, doc_tl).narrativeId for _ in range(5)]
_eq(len(set(ids_5)), 1, "no randomness: 5 builds → identical narrativeId")

# ===========================================================================
# §14  calculate_narrative_statistics()
# ===========================================================================
print("§14  calculate_narrative_statistics() ...")

doc_a = build_narrative_document(
    "r-001","ctx-001","inv-A", summary, _TS,
    sections=[build_narrative_section("S1","c",1)],
    timeline=[build_timeline_entry("2026-06-30T09:00:00Z","E1","d",80.0)],
    finding_count=2, alert_count=1,
)
doc_b = build_narrative_document(
    "r-002","ctx-002","inv-B", summary, _TS,
    sections=[
        build_narrative_section("S2","c",1),
        build_narrative_section("S3","c",2),
        build_narrative_section("S4","c",3),
    ],
    timeline=[
        build_timeline_entry("2026-06-30T09:00:00Z","E2","d",70.0),
        build_timeline_entry("2026-06-30T10:00:00Z","E3","d",90.0),
    ],
    finding_count=4, alert_count=3,
)

stats = calculate_narrative_statistics([doc_a, doc_b])
_assert(isinstance(stats, NarrativeStatistics), "returns NarrativeStatistics")
_eq(stats.totalDocuments,    2,           "totalDocuments = 2")
_eq(stats.minSectionCount,   1,           "minSectionCount = 1")
_eq(stats.maxSectionCount,   3,           "maxSectionCount = 3")
_assert(stats.averageSectionCount > 0,   "averageSectionCount > 0")
_assert(stats.averageTimelineCount > 0,  "averageTimelineCount > 0")
_eq(stats.uniqueInvestigationIds, ("inv-A","inv-B"), "uniqueInvestigationIds sorted")
_eq(stats.totalFindingsReferenced, 6,    "totalFindingsReferenced = 2+4")
_eq(stats.totalAlertsReferenced,   4,    "totalAlertsReferenced = 1+3")

# empty
empty_stats = calculate_narrative_statistics([])
_eq(empty_stats.totalDocuments,       0,   "empty → totalDocuments = 0")
_eq(empty_stats.averageSectionCount,  0.0, "empty → averageSectionCount = 0.0")
_eq(empty_stats.uniqueInvestigationIds, (), "empty → empty tuple")

# immutability
try:
    stats.totalDocuments = 99  # type: ignore
    _assert(False, "NarrativeStatistics should be frozen")
except Exception:
    _assert(True, "NarrativeStatistics is immutable")

# order-independence
_eq(
    calculate_narrative_statistics([doc_a, doc_b]),
    calculate_narrative_statistics([doc_b, doc_a]),
    "calculate_narrative_statistics order-independent",
)

# ===========================================================================
# §15  Empty sections and timeline
# ===========================================================================
print("§15  Empty sections and timeline ...")

doc_empty = build_narrative_document(
    "r-e","ctx-e","inv-e", summary, _TS, sections=[], timeline=[],
)
_eq(len(doc_empty.sections),  0,  "empty sections → 0 sections")
_eq(len(doc_empty.timeline),  0,  "empty timeline → 0 entries")
_eq(len(doc_empty.narrativeId),  36, "empty still produces valid UUID")
_eq(len(doc_empty.narrativeKey), 32, "empty still produces 32-char key")

# ===========================================================================
# §16  NarrativeDocument fields structure
# ===========================================================================
print("§16  NarrativeDocument structure ...")
_assert(hasattr(doc, "narrativeId"),          "has narrativeId")
_assert(hasattr(doc, "narrativeKey"),         "has narrativeKey")
_assert(hasattr(doc, "narrativeFingerprint"), "has narrativeFingerprint")
_assert(hasattr(doc, "summary"),              "has summary")
_assert(hasattr(doc, "sections"),             "has sections")
_assert(hasattr(doc, "timeline"),             "has timeline")
_assert(hasattr(doc, "reasoningId"),          "has reasoningId")
_assert(hasattr(doc, "contextId"),            "has contextId")
_assert(hasattr(doc, "investigationId"),      "has investigationId")
_assert(hasattr(doc, "metadata"),             "has metadata")
_assert(hasattr(doc, "createdAt"),            "has createdAt")
_assert(isinstance(doc.sections, tuple),      "sections is a tuple")
_assert(isinstance(doc.timeline, tuple),      "timeline is a tuple")

# ===========================================================================
# §17  No randomness
# ===========================================================================
print("§17  No randomness ...")
ids_6 = set()
for _ in range(6):
    d = build_narrative_document(
        "r-const","ctx-const","inv-const", summary, _TS,
        sections=[build_narrative_section("S","c",1)],
    )
    ids_6.add(d.narrativeId)
_eq(len(ids_6), 1, "no randomness: 6 builds → identical narrativeId")

# ===========================================================================
# §18  createdAt preserved verbatim
# ===========================================================================
print("§18  createdAt preserved ...")
ts1 = "2026-01-01T00:00:00Z"
ts2 = "2026-12-31T23:59:59Z"
d_ts1 = build_narrative_document("r","c","i", summary, ts1)
d_ts2 = build_narrative_document("r","c","i", summary, ts2)
_eq(d_ts1.createdAt, ts1, "createdAt ts1 preserved")
_eq(d_ts2.createdAt, ts2, "createdAt ts2 preserved")
_eq(d_ts1.narrativeId, d_ts2.narrativeId, "createdAt does not affect narrativeId")

# ===========================================================================
# Final summary
# ===========================================================================
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
    print("  services/investigation_narrative_service.py")
    print("  smoke_test_investigation_narrative_engine.py")
    print()
    print("CONSTANT APPENDED TO core/constants.py")
    print(f"  INVESTIGATION_NARRATIVE_ENGINE_VERSION = "
          f"{repr(INVESTIGATION_NARRATIVE_ENGINE_VERSION)}")
    print()
    print("MODELS  (all frozen=True Pydantic models)")
    print("  NarrativeSection        — one document section with order + importance + linked IDs")
    print("  NarrativeTimelineEntry  — one chronological event with timestamp + evidenceIds")
    print("  NarrativeSummary        — high-level overview with sorted recommendedActions")
    print("  NarrativeMetadata       — provenance, timings, counts, engineVersion")
    print("  NarrativeDocument       — complete provider-agnostic narrative document")
    print("  NarrativeStatistics     — aggregate stats over a list of documents")
    print()
    print("BUILDER FUNCTIONS")
    print("  build_narrative_section()   — build one NarrativeSection with deterministic sectionId")
    print("  build_timeline_entry()      — build one NarrativeTimelineEntry with deterministic eventId")
    print("  build_narrative_summary()   — build NarrativeSummary with sorted actions")
    print("  build_narrative_metadata()  — build NarrativeMetadata from assembly outputs")
    print("  build_narrative_document()  — primary builder: sort → IDs → fingerprint → document")
    print()
    print("UTILITY FUNCTIONS")
    print("  sort_sections()                   — sort by order ASC, sectionId ASC")
    print("  sort_timeline()                   — sort by timestamp ASC, eventId ASC; empty last")
    print("  filter_sections()                 — multi-criterion filter (order/importance/title/IDs)")
    print("  group_sections()                  — group by order / title / sectionId")
    print("  calculate_narrative_statistics()  — aggregate stats over NarrativeDocument list")
    print("  find_section()                    — lookup by sectionId / title / order")
    print()
    print("NARRATIVE GENERATION FLOW")
    print("  Reasoning → Attack Graph → Timeline → Evidence →")
    print("  Findings → Alerts → NarrativeSummary →")
    print("  NarrativeSections → NarrativeTimeline → NarrativeDocument")
    print()
    print("DETERMINISTIC STRATEGY")
    print("  sectionId          = SHA256(title + order + content[:64])[:32]")
    print("  sectionFingerprint = SHA256(sectionId + order + full_content)[:32]")
    print("  eventId            = SHA256(timestamp + title + description[:32])[:32]")
    print("  timelineFingerprint= SHA256(eventId + timestamp + title + description)[:32]")
    print("  summaryFingerprint = SHA256(title+overview+attackSummary+riskSummary+")
    print("                       impactSummary+confidenceSummary+sorted(actions))[:32]")
    print("  narrativeKey       = SHA256(reasoningId + contextId + investigationId +")
    print("                       sorted(sectionIds) + sorted(timelineEventIds))[:32]")
    print("  narrativeId        = UUIDv5(NARRATIVE_NS, narrativeKey)")
    print("  narrativeFingerprint = SHA256(narrativeKey + summaryFingerprint +")
    print("                         sorted(section fingerprints) +")
    print("                         sorted(timeline fingerprints))[:32]")
    print()
    print(f"SMOKE TEST RESULTS: {_PASS} / {total} assertions PASSED — 100%")
    print()
    print("ALL CHECKS PASSED ✓")
else:
    print()
    print(f"SMOKE TEST FAILED: {_FAIL} / {total} assertions failed")
    sys.exit(1)
