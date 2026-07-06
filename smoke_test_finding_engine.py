"""
Smoke test — Findings Engine (Phase A4.0.7)
===========================================
Validates:
  - Deterministic ID generation (findingKey + UUIDv5)
  - build_finding()
  - update_finding()  (status / severity / field / explanation changes)
  - close_finding()
  - confirm_finding()
  - suppress_finding()
  - reopen_finding()
  - clone_finding()
  - sort_findings()
  - filter_findings()
  - group_findings()
  - find_finding()
  - calculate_statistics()
  - findingFingerprint stability (order-independent)
  - FindingExplanation immutability
  - auditTrail accumulation
  - frozen=True enforcement
"""

import sys
from services.finding_service import (
    Finding,
    FindingCategory,
    FindingSeverity,
    FindingStatus,
    FindingStatistics,
    FindingExplanation,
    build_finding,
    update_finding,
    close_finding,
    confirm_finding,
    suppress_finding,
    reopen_finding,
    clone_finding,
    sort_findings,
    filter_findings,
    group_findings,
    find_finding,
    calculate_statistics,
    _compute_finding_key,
    _compute_finding_id,
    _compute_finding_fingerprint,
)
from core.constants import FINDING_ENGINE_VERSION

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
errors: list = []


def check(label: str, condition: bool) -> None:
    status = PASS if condition else FAIL
    print(f"  {status}  {label}")
    if not condition:
        errors.append(label)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

TS1 = "2026-06-30T10:00:00Z"
TS2 = "2026-06-30T11:00:00Z"
TS3 = "2026-06-30T12:00:00Z"

PROJ  = "proj-001"
INV   = "inv-001"

def _make_finding(
    title    = "SMB Lateral Movement Detected",
    category = FindingCategory.ATTACK_GRAPH,
    severity = FindingSeverity.HIGH,
    project_id = PROJ,
    investigation_id = INV,
    **kwargs,
) -> Finding:
    return build_finding(
        project_id                = project_id,
        investigation_id          = investigation_id,
        title                     = title,
        created_by                = "analyst@corp",
        created_at                = TS1,
        category                  = category,
        severity                  = severity,
        description               = "Lateral movement via SMB observed.",
        confidence                = 82.0,
        risk_score                = 74.5,
        asset_ids                 = ["asset-c", "asset-a", "asset-b"],
        relationship_ids          = ["rel-2", "rel-1"],
        evidence_ids              = ["ev-1", "ev-2"],
        timeline_event_ids        = ["te-1"],
        graph_node_ids            = ["node-b", "node-a"],
        mitre_technique_ids       = ["T1021.002", "T1021"],
        graph_fingerprint         = "gfp-abc123",
        timeline_fingerprint      = "tfp-xyz789",
        investigation_fingerprint = "ifp-qrs456",
        reason                    = "SMB traffic observed between internal hosts.",
        evidence_summary          = "3 packets matching SMB lateral movement pattern.",
        affected_assets           = ["asset-a", "asset-b"],
        affected_relationships    = ["rel-1"],
        recommended_action        = "Isolate asset-b and review SMB access controls.",
        tags                      = ["smb", "lateral-movement", "SMB"],
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Section 1: Deterministic IDs
# ---------------------------------------------------------------------------
print("\n── 1. Deterministic IDs ─────────────────────────────────────────────")

k1 = _compute_finding_key(PROJ, "SMB Lateral Movement Detected", FindingCategory.ATTACK_GRAPH, INV)
k2 = _compute_finding_key(PROJ, "SMB Lateral Movement Detected", FindingCategory.ATTACK_GRAPH, INV)
check("findingKey is deterministic",        k1 == k2)
check("findingKey length is 32 hex chars",  len(k1) == 32)

id1 = _compute_finding_id(k1)
id2 = _compute_finding_id(k1)
check("findingId is deterministic (UUIDv5)",            id1 == id2)
check("findingId is valid UUID format (36 chars)",      len(id1) == 36 and id1.count("-") == 4)

k_diff_title = _compute_finding_key(PROJ, "Different Title", FindingCategory.ATTACK_GRAPH, INV)
check("Different title → different key",   k1 != k_diff_title)

k_diff_cat   = _compute_finding_key(PROJ, "SMB Lateral Movement Detected", FindingCategory.NETWORK, INV)
check("Different category → different key", k1 != k_diff_cat)

k_diff_inv   = _compute_finding_key(PROJ, "SMB Lateral Movement Detected", FindingCategory.ATTACK_GRAPH, "inv-002")
check("Different investigationId → different key", k1 != k_diff_inv)


# ---------------------------------------------------------------------------
# Section 2: build_finding()
# ---------------------------------------------------------------------------
print("\n── 2. build_finding() ───────────────────────────────────────────────")

f = _make_finding()
check("status is OPEN",                 f.status   == FindingStatus.OPEN)
check("severity is HIGH",               f.severity == FindingSeverity.HIGH)
check("category is ATTACK_GRAPH",       f.category == FindingCategory.ATTACK_GRAPH)
check("closedAt is None",               f.closedAt is None)
check("engineVersion matches const",    f.engineVersion == FINDING_ENGINE_VERSION)
check("assetIds sorted + deduped",      list(f.assetIds) == sorted(["asset-a","asset-b","asset-c"]))
check("relationshipIds sorted",         list(f.relationshipIds) == sorted(["rel-1","rel-2"]))
check("evidenceIds sorted",             list(f.evidenceIds) == sorted(["ev-1","ev-2"]))
check("graphNodeIds sorted",            list(f.graphNodeIds) == sorted(["node-a","node-b"]))
check("mitreTechniqueIds sorted",       list(f.mitreTechniqueIds) == sorted(["T1021","T1021.002"]))
check("tags deduped + lowercased + sorted", f.tags == ("lateral-movement","smb"))
check("riskScore clamped 0–100",        0.0 <= f.riskScore  <= 100.0)
check("confidence clamped 0–100",       0.0 <= f.confidence <= 100.0)
check("auditTrail starts with Created", f.auditTrail == ("Created",))
check("findingFingerprint is 32 chars", len(f.findingFingerprint) == 32)
check("explanation.reason populated",  f.explanation.reason != "")
check("explanation.recommendedAction populated", f.explanation.recommendedAction != "")
check("explanation.affectedAssets sorted", list(f.explanation.affectedAssets) == sorted(["asset-a","asset-b"]))

# Idempotence — identical inputs → identical outputs
f2 = _make_finding()
check("Identical inputs → same findingId",          f.findingId          == f2.findingId)
check("Identical inputs → same findingKey",         f.findingKey         == f2.findingKey)
check("Identical inputs → same findingFingerprint", f.findingFingerprint == f2.findingFingerprint)


# ---------------------------------------------------------------------------
# Section 3: Immutability
# ---------------------------------------------------------------------------
print("\n── 3. Immutability (frozen=True) ────────────────────────────────────")

try:
    f.status = FindingStatus.CONFIRMED  # type: ignore
    check("frozen=True raises on Finding mutation", False)
except Exception:
    check("frozen=True raises on Finding mutation", True)

try:
    f.explanation.reason = "hacked"  # type: ignore
    check("frozen=True raises on FindingExplanation mutation", False)
except Exception:
    check("frozen=True raises on FindingExplanation mutation", True)


# ---------------------------------------------------------------------------
# Section 4: update_finding()
# ---------------------------------------------------------------------------
print("\n── 4. update_finding() ──────────────────────────────────────────────")

upd = update_finding(
    f,
    updated_at = TS2,
    status     = FindingStatus.CONFIRMED,
    severity   = FindingSeverity.CRITICAL,
    risk_score = 95.0,
)
check("status updated to CONFIRMED",     upd.status   == FindingStatus.CONFIRMED)
check("severity updated to CRITICAL",    upd.severity == FindingSeverity.CRITICAL)
check("riskScore updated",               upd.riskScore == 95.0)
check("updatedAt updated",               upd.updatedAt == TS2)
check("createdAt preserved",             upd.createdAt == TS1)
check("findingId unchanged on update",   upd.findingId == f.findingId)
check("findingKey unchanged on update",  upd.findingKey == f.findingKey)
check("auditTrail has Status changed",   "Status changed to CONFIRMED"  in upd.auditTrail)
check("auditTrail has Severity changed", "Severity changed to CRITICAL" in upd.auditTrail)
check("auditTrail preserves Created",    "Created" in upd.auditTrail)

# Partial update — only reason changed
upd_exp = update_finding(f, updated_at=TS2, reason="Updated reason text")
check("explanation.reason updated",        upd_exp.explanation.reason == "Updated reason text")
check("explanation.evidenceSummary preserved", upd_exp.explanation.evidenceSummary == f.explanation.evidenceSummary)
check("explanation.recommendedAction preserved", upd_exp.explanation.recommendedAction == f.explanation.recommendedAction)

# Partial update — None fields not changed
upd_partial = update_finding(f, updated_at=TS2, confidence=99.0)
check("Partial update: status preserved",     upd_partial.status    == f.status)
check("Partial update: confidence changed",   upd_partial.confidence == 99.0)
check("Partial update: severity preserved",   upd_partial.severity  == f.severity)


# ---------------------------------------------------------------------------
# Section 5: close / confirm / suppress / reopen
# ---------------------------------------------------------------------------
print("\n── 5. close / confirm / suppress / reopen ───────────────────────────")

closed = close_finding(f, closed_at=TS2)
check("close: status is CLOSED",         closed.status   == FindingStatus.CLOSED)
check("close: closedAt is set",          closed.closedAt == TS2)
check("close: updatedAt updated",        closed.updatedAt == TS2)
check("close: auditTrail has Closed",    "Closed" in closed.auditTrail)
check("close: idempotent on CLOSED",     close_finding(closed, TS3) is closed)

confirmed = confirm_finding(f, updated_at=TS2)
check("confirm: status is CONFIRMED",    confirmed.status == FindingStatus.CONFIRMED)
check("confirm: auditTrail has Confirmed","Confirmed" in confirmed.auditTrail)
check("confirm: idempotent on CONFIRMED", confirm_finding(confirmed, TS3) is confirmed)

suppressed = suppress_finding(f, updated_at=TS2, reason="noise")
check("suppress: status is SUPPRESSED",  suppressed.status == FindingStatus.SUPPRESSED)
check("suppress: closedAt stamped",      suppressed.closedAt == TS2)
check("suppress: audit has reason",      "Suppressed: noise" in suppressed.auditTrail)
check("suppress: idempotent",            suppress_finding(suppressed, TS3) is suppressed)

reopened = reopen_finding(closed, updated_at=TS3)
check("reopen: status is OPEN",          reopened.status  == FindingStatus.OPEN)
check("reopen: closedAt cleared",        reopened.closedAt is None)
check("reopen: auditTrail has Reopened", "Reopened" in reopened.auditTrail)
check("reopen: idempotent on OPEN",      reopen_finding(f, TS3) is f)

reopened_suppressed = reopen_finding(suppressed, updated_at=TS3)
check("reopen suppressed: OPEN",         reopened_suppressed.status == FindingStatus.OPEN)


# ---------------------------------------------------------------------------
# Section 6: clone_finding()
# ---------------------------------------------------------------------------
print("\n── 6. clone_finding() ───────────────────────────────────────────────")

cloned = clone_finding(
    closed,
    new_project_id      = "proj-002",
    new_investigation_id= "inv-002",
    new_created_by      = "analyst2@corp",
    new_created_at      = TS3,
    new_title           = "SMB Lateral Movement — Follow-up",
)
check("clone: status is OPEN",           cloned.status    == FindingStatus.OPEN)
check("clone: closedAt is None",         cloned.closedAt  is None)
check("clone: projectId updated",        cloned.projectId == "proj-002")
check("clone: investigationId updated",  cloned.investigationId == "inv-002")
check("clone: createdBy updated",        cloned.createdBy == "analyst2@corp")
check("clone: title updated",            cloned.title     == "SMB Lateral Movement — Follow-up")
check("clone: findingId differs",        cloned.findingId != f.findingId)
check("clone: auditTrail reset",         cloned.auditTrail == ("Created",))
check("clone: assetIds inherited",       cloned.assetIds  == f.assetIds)
check("clone: explanation inherited",    cloned.explanation == f.explanation)
check("clone: engineVersion current",    cloned.engineVersion == FINDING_ENGINE_VERSION)

# Clone with no new title uses original title
cloned_no_title = clone_finding(f, "proj-002", "inv-002", "analyst2@corp", TS3)
check("clone: no title → original title used", cloned_no_title.title == f.title)


# ---------------------------------------------------------------------------
# Section 7: sort_findings()
# ---------------------------------------------------------------------------
print("\n── 7. sort_findings() ───────────────────────────────────────────────")

f_info = _make_finding(title="Info-finding",  severity=FindingSeverity.INFO,     category=FindingCategory.SYSTEM)
f_crit = _make_finding(title="Crit-finding",  severity=FindingSeverity.CRITICAL,  category=FindingCategory.NETWORK)
f_low  = _make_finding(title="Low-finding",   severity=FindingSeverity.LOW,       category=FindingCategory.HOST)
pool   = [f_info, f_crit, f_low]

s_desc = sort_findings(pool, by="severity", ascending=False)
check("severity DESC: CRITICAL first",   s_desc[0].severity == FindingSeverity.CRITICAL)
check("severity DESC: INFO last",        s_desc[-1].severity == FindingSeverity.INFO)

s_asc  = sort_findings(pool, by="severity", ascending=True)
check("severity ASC: INFO first",        s_asc[0].severity == FindingSeverity.INFO)

s_title = sort_findings(pool, by="title", ascending=True)
check("title ASC: alphabetical",         s_title[0].title <= s_title[-1].title)

s_risk  = sort_findings(pool, by="riskScore", ascending=False)
check("riskScore sort returns list",     len(s_risk) == len(pool))

try:
    sort_findings(pool, by="bogus_key")
    check("Invalid sort key raises ValueError", False)
except ValueError:
    check("Invalid sort key raises ValueError", True)


# ---------------------------------------------------------------------------
# Section 8: filter_findings()
# ---------------------------------------------------------------------------
print("\n── 8. filter_findings() ─────────────────────────────────────────────")

f_conf_host = _make_finding(title="Confirmed-host", severity=FindingSeverity.MEDIUM,
                             category=FindingCategory.HOST)
f_conf_host = confirm_finding(f_conf_host, TS2)
mixed = [f, upd, closed, confirmed, suppressed, f_info, f_crit, f_low, f_conf_host]

open_ones  = filter_findings(mixed, status=FindingStatus.OPEN)
check("filter OPEN",                     all(x.status == FindingStatus.OPEN for x in open_ones))

crit_ones  = filter_findings(mixed, severity=FindingSeverity.CRITICAL)
check("filter CRITICAL severity",        all(x.severity == FindingSeverity.CRITICAL for x in crit_ones))

cat_ones   = filter_findings(mixed, category=FindingCategory.ATTACK_GRAPH)
check("filter ATTACK_GRAPH category",    all(x.category == FindingCategory.ATTACK_GRAPH for x in cat_ones))

tagged     = filter_findings(mixed, tags=["smb"])
check("filter by tag 'smb'",             all("smb" in x.tags for x in tagged))

high_risk  = filter_findings(mixed, min_risk_score=70.0)
check("filter min_risk_score=70",        all(x.riskScore >= 70.0 for x in high_risk))

proj_f     = filter_findings(mixed, project_id=PROJ)
check("filter by project_id",            all(x.projectId == PROJ for x in proj_f))

mitre_f    = filter_findings(mixed, mitre_technique="T1021")
check("filter by mitre_technique",       all("T1021" in x.mitreTechniqueIds for x in mitre_f))

conf_f     = filter_findings(mixed, status=FindingStatus.CONFIRMED)
check("filter CONFIRMED",                all(x.status == FindingStatus.CONFIRMED for x in conf_f))


# ---------------------------------------------------------------------------
# Section 9: group_findings()
# ---------------------------------------------------------------------------
print("\n── 9. group_findings() ──────────────────────────────────────────────")

grouped_sev = group_findings(mixed, by="severity")
check("group by severity: HIGH key present",     FindingSeverity.HIGH.value     in grouped_sev)
check("group by severity: CRITICAL key present", FindingSeverity.CRITICAL.value in grouped_sev)

grouped_status = group_findings(mixed, by="status")
check("group by status: OPEN key present",       FindingStatus.OPEN.value       in grouped_status)
check("group by status: CONFIRMED key present",  FindingStatus.CONFIRMED.value  in grouped_status)

grouped_cat = group_findings(mixed, by="category")
check("group by category: ATTACK_GRAPH present", FindingCategory.ATTACK_GRAPH.value in grouped_cat)

try:
    group_findings(mixed, by="invalid_key")
    check("Invalid group key raises ValueError", False)
except ValueError:
    check("Invalid group key raises ValueError", True)


# ---------------------------------------------------------------------------
# Section 10: find_finding()
# ---------------------------------------------------------------------------
print("\n── 10. find_finding() ───────────────────────────────────────────────")

pool2 = [f, upd, closed]

found_id    = find_finding(pool2, finding_id=f.findingId)
found_key   = find_finding(pool2, finding_key=f.findingKey)
found_title = find_finding(pool2, title=f.title)
not_found   = find_finding(pool2, finding_id="nonexistent-uuid")

check("find by findingId",    found_id    is not None and found_id.findingId   == f.findingId)
check("find by findingKey",   found_key   is not None and found_key.findingKey == f.findingKey)
check("find by title",        found_title is not None and found_title.title    == f.title)
check("not found → None",     not_found   is None)


# ---------------------------------------------------------------------------
# Section 11: calculate_statistics()
# ---------------------------------------------------------------------------
print("\n── 11. calculate_statistics() ───────────────────────────────────────")

stats = calculate_statistics(mixed)
check("totalFindings correct",          stats.totalFindings == len(mixed))
check("openFindings >= 0",              stats.openFindings  >= 0)
check("criticalFindings >= 0",          stats.criticalFindings >= 0)
check("resolvedFindings >= 0",          stats.resolvedFindings >= 0)
check("averageRisk in [0, 100]",        0.0 <= stats.averageRisk      <= 100.0)
check("averageConfidence in [0, 100]",  0.0 <= stats.averageConfidence <= 100.0)
check("findingsBySeverity has all keys",
      all(s.value in stats.findingsBySeverity for s in FindingSeverity))
check("findingsByCategory has all keys",
      all(c.value in stats.findingsByCategory for c in FindingCategory))
check("openFindings + resolvedFindings <= total",
      stats.openFindings + stats.resolvedFindings <= stats.totalFindings)

# Order-independence
stats2 = calculate_statistics(list(reversed(mixed)))
check("stats order-independent: averageRisk",  stats.averageRisk  == stats2.averageRisk)
check("stats order-independent: totalFindings",stats.totalFindings == stats2.totalFindings)

# Empty list
empty_stats = calculate_statistics([])
check("empty: totalFindings=0",         empty_stats.totalFindings  == 0)
check("empty: averageRisk=0.0",         empty_stats.averageRisk    == 0.0)
check("empty: averageConfidence=0.0",   empty_stats.averageConfidence == 0.0)
check("empty: all severity counts = 0", all(v == 0 for v in empty_stats.findingsBySeverity.values()))
check("empty: all category counts = 0", all(v == 0 for v in empty_stats.findingsByCategory.values()))


# ---------------------------------------------------------------------------
# Section 12: findingFingerprint stability
# ---------------------------------------------------------------------------
print("\n── 12. findingFingerprint stability ─────────────────────────────────")

fp1 = _compute_finding_fingerprint(
    "gfp-abc", "tfp-xyz", "ifp-qrs",
    ("a-2", "a-1"), ("ev-1",), ("r-1",), ("node-b", "node-a"),
)
fp2 = _compute_finding_fingerprint(
    "gfp-abc", "tfp-xyz", "ifp-qrs",
    ("a-1", "a-2"), ("ev-1",), ("r-1",), ("node-a", "node-b"),  # different order
)
check("fingerprint order-independent (assetIds + nodeIds)", fp1 == fp2)
check("fingerprint is 32 chars", len(fp1) == 32)

fp_diff_gfp = _compute_finding_fingerprint(
    "gfp-CHANGED", "tfp-xyz", "ifp-qrs",
    ("a-1", "a-2"), ("ev-1",), ("r-1",), ("node-a", "node-b"),
)
check("fingerprint changes with different graphFingerprint", fp1 != fp_diff_gfp)

fp_diff_inv = _compute_finding_fingerprint(
    "gfp-abc", "tfp-xyz", "ifp-CHANGED",
    ("a-1", "a-2"), ("ev-1",), ("r-1",), ("node-a", "node-b"),
)
check("fingerprint changes with different investigationFingerprint", fp1 != fp_diff_inv)

fp_diff_ev = _compute_finding_fingerprint(
    "gfp-abc", "tfp-xyz", "ifp-qrs",
    ("a-1", "a-2"), ("ev-1", "ev-2"), ("r-1",), ("node-a", "node-b"),
)
check("fingerprint changes with different evidenceIds", fp1 != fp_diff_ev)


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print("\n" + "─" * 64)
total_checks = sum(1 for line in open(__file__) if "check(" in line)
failed = len(errors)
print(f"  Results: {failed} failed / {total_checks} checks")
if errors:
    print("\n  Failed checks:")
    for e in errors:
        print(f"    {FAIL}  {e}")
    sys.exit(1)
else:
    print(f"\n  {PASS}  All checks passed — Findings Engine (A4.0.7)")
