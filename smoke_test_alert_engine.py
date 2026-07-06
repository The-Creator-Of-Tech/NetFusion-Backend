"""
Smoke test — Alert Engine (Phase A4.0.8)
=========================================
Validates:
  - Deterministic ID generation (alertKey + UUIDv5)
  - build_alert()
  - update_alert()  (status / severity / explanation / correlation)
  - acknowledge_alert()
  - start_alert()
  - resolve_alert()
  - close_alert()
  - suppress_alert()
  - reopen_alert()
  - clone_alert()
  - sort_alerts()
  - filter_alerts()
  - group_alerts()
  - find_alert()
  - calculate_statistics()
  - alertFingerprint stability (order-independent)
  - AlertCorrelation.correlationId determinism
  - AlertExplanation / AlertCorrelation immutability
  - frozen=True enforcement on Alert
  - auditTrail accumulation
"""

import sys
from services.alert_service import (
    Alert,
    AlertCorrelation,
    AlertExplanation,
    AlertSeverity,
    AlertSource,
    AlertStatus,
    AlertStatistics,
    acknowledge_alert,
    build_alert,
    calculate_statistics,
    clone_alert,
    close_alert,
    filter_alerts,
    find_alert,
    group_alerts,
    reopen_alert,
    resolve_alert,
    sort_alerts,
    start_alert,
    suppress_alert,
    update_alert,
    _compute_alert_key,
    _compute_alert_id,
    _compute_alert_fingerprint,
    _compute_correlation_id,
)
from core.constants import ALERT_ENGINE_VERSION

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
errors: list = []


def check(label: str, condition: bool) -> None:
    icon = PASS if condition else FAIL
    print(f"  {icon}  {label}")
    if not condition:
        errors.append(label)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

TS1 = "2026-06-30T10:00:00Z"
TS2 = "2026-06-30T11:00:00Z"
TS3 = "2026-06-30T12:00:00Z"

PROJ = "proj-001"
FIND = "find-001"
INV  = "inv-001"


def _make_alert(
    title            = "SMB Lateral Movement Alert",
    project_id       = PROJ,
    finding_id       = FIND,
    investigation_id = INV,
    severity         = AlertSeverity.HIGH,
    source           = AlertSource.FINDING,
    **kwargs,
) -> Alert:
    return build_alert(
        project_id                = project_id,
        finding_id                = finding_id,
        investigation_id          = investigation_id,
        title                     = title,
        created_by                = "system",
        created_at                = TS1,
        source                    = source,
        severity                  = severity,
        description               = "SMB lateral movement detected between internal hosts.",
        confidence                = 85.0,
        risk_score                = 76.0,
        asset_ids                 = ["asset-c", "asset-a", "asset-b"],
        relationship_ids          = ["rel-2", "rel-1"],
        evidence_ids              = ["ev-2", "ev-1"],
        graph_node_ids            = ["node-b", "node-a"],
        timeline_event_ids        = ["te-1"],
        finding_fingerprint       = "ffp-abc123",
        investigation_fingerprint = "ifp-xyz789",
        graph_fingerprint         = "gfp-qrs456",
        reason                    = "SMB traffic detected between asset-a and asset-b.",
        finding_summary           = "Finding: lateral movement via SMB (HIGH).",
        affected_assets           = ["asset-a", "asset-b"],
        recommended_action        = "Isolate asset-b; review SMB ACLs.",
        escalation_reason         = "",
        related_alert_ids         = ["alert-x", "alert-y"],
        related_finding_ids       = ["find-002"],
        shared_evidence_ids       = ["ev-1"],
        shared_assets             = ["asset-a"],
        correlation_score         = 60.0,
        tags                      = ["smb", "lateral-movement", "SMB"],
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Section 1: Deterministic IDs
# ---------------------------------------------------------------------------
print("\n── 1. Deterministic IDs ─────────────────────────────────────────────")

k1 = _compute_alert_key(PROJ, FIND, "SMB Lateral Movement Alert", AlertSource.FINDING)
k2 = _compute_alert_key(PROJ, FIND, "SMB Lateral Movement Alert", AlertSource.FINDING)
check("alertKey is deterministic",        k1 == k2)
check("alertKey length is 32 hex chars",  len(k1) == 32)

id1 = _compute_alert_id(k1)
id2 = _compute_alert_id(k1)
check("alertId is deterministic (UUIDv5)",          id1 == id2)
check("alertId is valid UUID format (36 chars)",    len(id1) == 36 and id1.count("-") == 4)

k_diff_title  = _compute_alert_key(PROJ, FIND, "Different Title", AlertSource.FINDING)
check("Different title → different key",            k1 != k_diff_title)

k_diff_source = _compute_alert_key(PROJ, FIND, "SMB Lateral Movement Alert", AlertSource.MANUAL)
check("Different source → different key",           k1 != k_diff_source)

k_diff_find   = _compute_alert_key(PROJ, "find-999", "SMB Lateral Movement Alert", AlertSource.FINDING)
check("Different findingId → different key",        k1 != k_diff_find)

cid1 = _compute_correlation_id(("alert-x", "alert-y"))
cid2 = _compute_correlation_id(("alert-y", "alert-x"))   # different order
check("correlationId is order-independent",         cid1 == cid2)
check("correlationId length is 32 hex chars",       len(cid1) == 32)


# ---------------------------------------------------------------------------
# Section 2: build_alert()
# ---------------------------------------------------------------------------
print("\n── 2. build_alert() ─────────────────────────────────────────────────")

a = _make_alert()
check("status is NEW",                    a.status   == AlertStatus.NEW)
check("severity is HIGH",                 a.severity == AlertSeverity.HIGH)
check("source is FINDING",                a.source   == AlertSource.FINDING)
check("closedAt is None",                 a.closedAt       is None)
check("acknowledgedAt is None",           a.acknowledgedAt is None)
check("resolvedAt is None",               a.resolvedAt     is None)
check("engineVersion matches const",      a.engineVersion  == ALERT_ENGINE_VERSION)
check("assetIds sorted + deduped",        list(a.assetIds)  == sorted(["asset-a","asset-b","asset-c"]))
check("evidenceIds sorted",               list(a.evidenceIds) == sorted(["ev-1","ev-2"]))
check("graphNodeIds sorted",              list(a.graphNodeIds) == sorted(["node-a","node-b"]))
check("tags deduped + lowercased",        a.tags == ("lateral-movement","smb"))
check("riskScore clamped 0–100",          0.0 <= a.riskScore  <= 100.0)
check("confidence clamped 0–100",         0.0 <= a.confidence <= 100.0)
check("alertFingerprint is 32 chars",     len(a.alertFingerprint) == 32)
check("auditTrail starts with Created",   a.auditTrail == ("Created",))
check("explanation.reason populated",     a.explanation.reason != "")
check("explanation.affectedAssets sorted",list(a.explanation.affectedAssets) == sorted(["asset-a","asset-b"]))
check("correlation.correlationId 32 chars", len(a.correlation.correlationId) == 32)
check("correlation.relatedAlertIds sorted", list(a.correlation.relatedAlertIds) == sorted(["alert-x","alert-y"]))
check("correlationScore clamped",         0.0 <= a.correlation.correlationScore <= 100.0)

# Idempotence
a2 = _make_alert()
check("Identical inputs → same alertId",          a.alertId          == a2.alertId)
check("Identical inputs → same alertKey",         a.alertKey         == a2.alertKey)
check("Identical inputs → same alertFingerprint", a.alertFingerprint == a2.alertFingerprint)
check("Identical inputs → same correlationId",    a.correlation.correlationId == a2.correlation.correlationId)


# ---------------------------------------------------------------------------
# Section 3: Immutability
# ---------------------------------------------------------------------------
print("\n── 3. Immutability (frozen=True) ────────────────────────────────────")

try:
    a.status = AlertStatus.OPEN  # type: ignore
    check("frozen=True raises on Alert mutation", False)
except Exception:
    check("frozen=True raises on Alert mutation", True)

try:
    a.explanation.reason = "hacked"  # type: ignore
    check("frozen=True raises on AlertExplanation mutation", False)
except Exception:
    check("frozen=True raises on AlertExplanation mutation", True)

try:
    a.correlation.correlationScore = 99.0  # type: ignore
    check("frozen=True raises on AlertCorrelation mutation", False)
except Exception:
    check("frozen=True raises on AlertCorrelation mutation", True)


# ---------------------------------------------------------------------------
# Section 4: update_alert()
# ---------------------------------------------------------------------------
print("\n── 4. update_alert() ────────────────────────────────────────────────")

upd = update_alert(
    a,
    updated_at  = TS2,
    status      = AlertStatus.OPEN,
    severity    = AlertSeverity.CRITICAL,
    assigned_to = "analyst@corp",
    risk_score  = 95.0,
)
check("status updated to OPEN",             upd.status    == AlertStatus.OPEN)
check("severity updated to CRITICAL",       upd.severity  == AlertSeverity.CRITICAL)
check("assignedTo updated",                 upd.assignedTo == "analyst@corp")
check("riskScore updated",                  upd.riskScore  == 95.0)
check("updatedAt updated",                  upd.updatedAt  == TS2)
check("createdAt preserved",                upd.createdAt  == TS1)
check("alertId unchanged",                  upd.alertId    == a.alertId)
check("alertKey unchanged",                 upd.alertKey   == a.alertKey)
check("auditTrail has Status changed",      "Status changed to OPEN"      in upd.auditTrail)
check("auditTrail has Severity changed",    "Severity changed to CRITICAL" in upd.auditTrail)
check("auditTrail has Assigned",            "Assigned"                    in upd.auditTrail)
check("auditTrail preserves Created",       "Created"                     in upd.auditTrail)

# Partial explanation update
upd_exp = update_alert(a, updated_at=TS2, reason="Updated reason")
check("explanation.reason updated",          upd_exp.explanation.reason == "Updated reason")
check("explanation.findingSummary preserved",upd_exp.explanation.findingSummary == a.explanation.findingSummary)
check("explanation.recommendedAction preserved", upd_exp.explanation.recommendedAction == a.explanation.recommendedAction)

# Partial correlation update
upd_cor = update_alert(a, updated_at=TS2, correlation_score=80.0)
check("correlation.correlationScore updated", upd_cor.correlation.correlationScore == 80.0)
check("correlation.relatedAlertIds preserved", upd_cor.correlation.relatedAlertIds == a.correlation.relatedAlertIds)

# None fields not changed
upd_partial = update_alert(a, updated_at=TS2, confidence=99.0)
check("Partial update: status preserved",    upd_partial.status    == a.status)
check("Partial update: confidence changed",  upd_partial.confidence == 99.0)


# ---------------------------------------------------------------------------
# Section 5: Lifecycle builders
# ---------------------------------------------------------------------------
print("\n── 5. Lifecycle builders ────────────────────────────────────────────")

acked = acknowledge_alert(a, acknowledged_at=TS2, assigned_to="analyst@corp")
check("acknowledge: status ACKNOWLEDGED",       acked.status         == AlertStatus.ACKNOWLEDGED)
check("acknowledge: acknowledgedAt stamped",    acked.acknowledgedAt == TS2)
check("acknowledge: assignedTo updated",        acked.assignedTo     == "analyst@corp")
check("acknowledge: auditTrail has Acknowledged","Acknowledged" in acked.auditTrail)
check("acknowledge: idempotent",                acknowledge_alert(acked, TS3) is acked)

started = start_alert(a, updated_at=TS2, assigned_to="analyst@corp")
check("start: status IN_PROGRESS",              started.status   == AlertStatus.IN_PROGRESS)
check("start: auditTrail has Investigation started", "Investigation started" in started.auditTrail)
check("start: idempotent",                      start_alert(started, TS3) is started)

resolved = resolve_alert(a, resolved_at=TS2)
check("resolve: status RESOLVED",               resolved.status    == AlertStatus.RESOLVED)
check("resolve: resolvedAt stamped",            resolved.resolvedAt == TS2)
check("resolve: auditTrail has Resolved",       "Resolved" in resolved.auditTrail)
check("resolve: idempotent on RESOLVED",        resolve_alert(resolved, TS3) is resolved)

closed = close_alert(a, closed_at=TS2)
check("close: status CLOSED",                   closed.status   == AlertStatus.CLOSED)
check("close: closedAt stamped",                closed.closedAt == TS2)
check("close: resolvedAt set when not present", closed.resolvedAt is not None)
check("close: auditTrail has Closed",           "Closed" in closed.auditTrail)
check("close: idempotent on CLOSED",            close_alert(closed, TS3) is closed)

# close preserves existing resolvedAt
resolved_then_closed = close_alert(resolved, closed_at=TS3)
check("close: preserves existing resolvedAt",   resolved_then_closed.resolvedAt == TS2)

suppressed = suppress_alert(a, updated_at=TS2, reason="noise")
check("suppress: status SUPPRESSED",            suppressed.status   == AlertStatus.SUPPRESSED)
check("suppress: closedAt stamped",             suppressed.closedAt == TS2)
check("suppress: audit has reason",             "Suppressed: noise" in suppressed.auditTrail)
check("suppress: idempotent",                   suppress_alert(suppressed, TS3) is suppressed)

reopened_closed = reopen_alert(closed, updated_at=TS3)
check("reopen closed: OPEN",                    reopened_closed.status    == AlertStatus.OPEN)
check("reopen closed: closedAt cleared",        reopened_closed.closedAt  is None)
check("reopen closed: resolvedAt cleared",      reopened_closed.resolvedAt is None)
check("reopen closed: auditTrail has Reopened", "Reopened" in reopened_closed.auditTrail)

reopened_suppressed = reopen_alert(suppressed, updated_at=TS3)
check("reopen suppressed: OPEN",                reopened_suppressed.status == AlertStatus.OPEN)

check("reopen NEW: idempotent",                 reopen_alert(a, TS3) is a)
check("reopen OPEN: idempotent",                reopen_alert(upd, TS3) is upd)


# ---------------------------------------------------------------------------
# Section 6: clone_alert()
# ---------------------------------------------------------------------------
print("\n── 6. clone_alert() ─────────────────────────────────────────────────")

cloned = clone_alert(
    closed,
    new_project_id = "proj-002",
    new_finding_id = "find-002",
    new_created_by = "analyst2@corp",
    new_created_at = TS3,
    new_title      = "SMB Lateral Movement — Follow-up",
)
check("clone: status is NEW",            cloned.status         == AlertStatus.NEW)
check("clone: closedAt is None",         cloned.closedAt       is None)
check("clone: acknowledgedAt is None",   cloned.acknowledgedAt is None)
check("clone: resolvedAt is None",       cloned.resolvedAt     is None)
check("clone: projectId updated",        cloned.projectId      == "proj-002")
check("clone: findingId updated",        cloned.findingId      == "find-002")
check("clone: createdBy updated",        cloned.createdBy      == "analyst2@corp")
check("clone: title updated",            cloned.title          == "SMB Lateral Movement — Follow-up")
check("clone: alertId differs",          cloned.alertId        != a.alertId)
check("clone: auditTrail reset",         cloned.auditTrail     == ("Created",))
check("clone: assetIds inherited",       cloned.assetIds       == a.assetIds)
check("clone: explanation inherited",    cloned.explanation    == a.explanation)
check("clone: correlation inherited",    cloned.correlation    == a.correlation)
check("clone: engineVersion current",    cloned.engineVersion  == ALERT_ENGINE_VERSION)

cloned_no_title = clone_alert(a, "proj-002", "find-002", "analyst2@corp", TS3)
check("clone: no title → original used", cloned_no_title.title == a.title)


# ---------------------------------------------------------------------------
# Section 7: sort_alerts()
# ---------------------------------------------------------------------------
print("\n── 7. sort_alerts() ─────────────────────────────────────────────────")

a_info  = _make_alert(title="Info-alert",  severity=AlertSeverity.INFO,     source=AlertSource.SYSTEM)
a_crit  = _make_alert(title="Crit-alert",  severity=AlertSeverity.CRITICAL, source=AlertSource.RULE)
a_low   = _make_alert(title="Low-alert",   severity=AlertSeverity.LOW,      source=AlertSource.MANUAL)
pool    = [a_info, a_crit, a_low]

s_desc  = sort_alerts(pool, by="severity", ascending=False)
check("severity DESC: CRITICAL first",   s_desc[0].severity  == AlertSeverity.CRITICAL)
check("severity DESC: INFO last",        s_desc[-1].severity == AlertSeverity.INFO)

s_asc   = sort_alerts(pool, by="severity", ascending=True)
check("severity ASC: INFO first",        s_asc[0].severity   == AlertSeverity.INFO)

s_title = sort_alerts(pool, by="title", ascending=True)
check("title ASC: alphabetical",         s_title[0].title <= s_title[-1].title)

s_risk  = sort_alerts(pool, by="riskScore", ascending=False)
check("riskScore sort returns list",     len(s_risk) == len(pool))

try:
    sort_alerts(pool, by="bogus_key")
    check("Invalid sort key raises ValueError", False)
except ValueError:
    check("Invalid sort key raises ValueError", True)


# ---------------------------------------------------------------------------
# Section 8: filter_alerts()
# ---------------------------------------------------------------------------
print("\n── 8. filter_alerts() ───────────────────────────────────────────────")

mixed = [a, upd, acked, started, resolved, closed, suppressed, a_info, a_crit, a_low]

new_ones    = filter_alerts(mixed, status=AlertStatus.NEW)
check("filter NEW",                      all(x.status == AlertStatus.NEW for x in new_ones))

crit_ones   = filter_alerts(mixed, severity=AlertSeverity.CRITICAL)
check("filter CRITICAL severity",        all(x.severity == AlertSeverity.CRITICAL for x in crit_ones))

src_ones    = filter_alerts(mixed, source=AlertSource.FINDING)
check("filter FINDING source",           all(x.source == AlertSource.FINDING for x in src_ones))

tagged      = filter_alerts(mixed, tags=["smb"])
check("filter by tag 'smb'",             all("smb" in x.tags for x in tagged))

high_risk   = filter_alerts(mixed, min_risk_score=70.0)
check("filter min_risk_score=70",        all(x.riskScore >= 70.0 for x in high_risk))

proj_filter = filter_alerts(mixed, project_id=PROJ)
check("filter by project_id",            all(x.projectId == PROJ for x in proj_filter))

find_filter = filter_alerts(mixed, finding_id=FIND)
check("filter by finding_id",            all(x.findingId == FIND for x in find_filter))


# ---------------------------------------------------------------------------
# Section 9: group_alerts()
# ---------------------------------------------------------------------------
print("\n── 9. group_alerts() ────────────────────────────────────────────────")

grouped_sev = group_alerts(mixed, by="severity")
check("group by severity: HIGH present",     AlertSeverity.HIGH.value     in grouped_sev)
check("group by severity: CRITICAL present", AlertSeverity.CRITICAL.value in grouped_sev)

grouped_status = group_alerts(mixed, by="status")
check("group by status: NEW present",        AlertStatus.NEW.value        in grouped_status)
check("group by status: SUPPRESSED present", AlertStatus.SUPPRESSED.value in grouped_status)

grouped_src = group_alerts(mixed, by="source")
check("group by source: FINDING present",    AlertSource.FINDING.value    in grouped_src)

try:
    group_alerts(mixed, by="bad_key")
    check("Invalid group key raises ValueError", False)
except ValueError:
    check("Invalid group key raises ValueError", True)


# ---------------------------------------------------------------------------
# Section 10: find_alert()
# ---------------------------------------------------------------------------
print("\n── 10. find_alert() ─────────────────────────────────────────────────")

pool2        = [a, upd, closed]
found_id     = find_alert(pool2, alert_id=a.alertId)
found_key    = find_alert(pool2, alert_key=a.alertKey)
found_title  = find_alert(pool2, title=a.title)
not_found    = find_alert(pool2, alert_id="nonexistent-id")

check("find by alertId",    found_id    is not None and found_id.alertId   == a.alertId)
check("find by alertKey",   found_key   is not None and found_key.alertKey == a.alertKey)
check("find by title",      found_title is not None and found_title.title  == a.title)
check("not found → None",   not_found   is None)


# ---------------------------------------------------------------------------
# Section 11: calculate_statistics()
# ---------------------------------------------------------------------------
print("\n── 11. calculate_statistics() ───────────────────────────────────────")

stats = calculate_statistics(mixed)
check("totalAlerts correct",            stats.totalAlerts     == len(mixed))
check("newAlerts >= 0",                 stats.newAlerts       >= 0)
check("openAlerts >= 0",                stats.openAlerts      >= 0)
check("criticalAlerts >= 0",            stats.criticalAlerts  >= 0)
check("resolvedAlerts >= 0",            stats.resolvedAlerts  >= 0)
check("suppressedAlerts >= 0",          stats.suppressedAlerts >= 0)
check("averageRisk in [0, 100]",        0.0 <= stats.averageRisk       <= 100.0)
check("averageConfidence in [0, 100]",  0.0 <= stats.averageConfidence <= 100.0)
check("alertsBySeverity has all keys",  all(s.value in stats.alertsBySeverity for s in AlertSeverity))
check("alertsByStatus has all keys",    all(s.value in stats.alertsByStatus   for s in AlertStatus))
check("alertsBySource has all keys",    all(s.value in stats.alertsBySource   for s in AlertSource))
check("newAlerts count correct",        stats.newAlerts == stats.alertsByStatus[AlertStatus.NEW.value])
check("suppressedAlerts matches dict",  stats.suppressedAlerts == stats.alertsByStatus[AlertStatus.SUPPRESSED.value])

# Order-independence
stats2 = calculate_statistics(list(reversed(mixed)))
check("stats order-independent: averageRisk",  stats.averageRisk  == stats2.averageRisk)
check("stats order-independent: totalAlerts",  stats.totalAlerts  == stats2.totalAlerts)

# Empty list
empty_stats = calculate_statistics([])
check("empty: totalAlerts=0",           empty_stats.totalAlerts       == 0)
check("empty: averageRisk=0.0",         empty_stats.averageRisk       == 0.0)
check("empty: averageConfidence=0.0",   empty_stats.averageConfidence == 0.0)
check("empty: all severity counts=0",   all(v == 0 for v in empty_stats.alertsBySeverity.values()))
check("empty: all status counts=0",     all(v == 0 for v in empty_stats.alertsByStatus.values()))
check("empty: all source counts=0",     all(v == 0 for v in empty_stats.alertsBySource.values()))


# ---------------------------------------------------------------------------
# Section 12: alertFingerprint stability
# ---------------------------------------------------------------------------
print("\n── 12. alertFingerprint stability ───────────────────────────────────")

fp1 = _compute_alert_fingerprint(
    "ffp-abc", "ifp-xyz", "gfp-qrs",
    ("a-2", "a-1"), ("ev-2", "ev-1"), ("node-b", "node-a"),
)
fp2 = _compute_alert_fingerprint(
    "ffp-abc", "ifp-xyz", "gfp-qrs",
    ("a-1", "a-2"), ("ev-1", "ev-2"), ("node-a", "node-b"),   # different order
)
check("fingerprint order-independent", fp1 == fp2)
check("fingerprint is 32 chars",       len(fp1) == 32)

fp_diff_ffp = _compute_alert_fingerprint(
    "ffp-CHANGED", "ifp-xyz", "gfp-qrs",
    ("a-1", "a-2"), ("ev-1", "ev-2"), ("node-a", "node-b"),
)
check("fingerprint changes with different findingFingerprint",       fp1 != fp_diff_ffp)

fp_diff_ev = _compute_alert_fingerprint(
    "ffp-abc", "ifp-xyz", "gfp-qrs",
    ("a-1", "a-2"), ("ev-1", "ev-2", "ev-3"), ("node-a", "node-b"),
)
check("fingerprint changes with different evidenceIds",              fp1 != fp_diff_ev)

fp_diff_inv = _compute_alert_fingerprint(
    "ffp-abc", "ifp-CHANGED", "gfp-qrs",
    ("a-1", "a-2"), ("ev-1", "ev-2"), ("node-a", "node-b"),
)
check("fingerprint changes with different investigationFingerprint", fp1 != fp_diff_inv)


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
    print(f"\n  {PASS}  All checks passed — Alert Engine (A4.0.8)")
