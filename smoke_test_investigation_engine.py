"""
Smoke test — Investigation Engine (Phase A4.0.6)
================================================
Validates:
  - Deterministic ID generation (key + UUIDv5)
  - build_investigation()
  - update_investigation()  (status / priority / field changes)
  - close_investigation()
  - archive_investigation()
  - clone_investigation()
  - sort_investigations()
  - filter_investigations()
  - group_investigations()
  - find_investigation()
  - calculate_statistics()
  - investigationFingerprint stability
  - auditTrail accumulation
  - Immutability (frozen=True)
"""

import sys
from services.investigation_service import (
    Investigation,
    InvestigationPriority,
    InvestigationStatus,
    InvestigationStatistics,
    archive_investigation,
    build_investigation,
    calculate_statistics,
    clone_investigation,
    close_investigation,
    filter_investigations,
    find_investigation,
    group_investigations,
    sort_investigations,
    update_investigation,
    _compute_investigation_key,
    _compute_investigation_id,
    _compute_investigation_fingerprint,
)
from core.constants import INVESTIGATION_ENGINE_VERSION

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

def _make_inv(
    title      = "Lateral Movement Campaign",
    project_id = "proj-001",
    created_by = "analyst@corp",
    created_at = TS1,
    priority   = InvestigationPriority.HIGH,
    **kwargs,
) -> Investigation:
    return build_investigation(
        project_id=project_id,
        title=title,
        created_by=created_by,
        created_at=created_at,
        description="Suspected lateral movement via SMB.",
        priority=priority,
        asset_ids=["asset-c", "asset-a", "asset-b"],
        relationship_ids=["rel-2", "rel-1"],
        finding_ids=["find-1"],
        evidence_ids=["ev-1", "ev-2"],
        timeline_event_ids=["te-1"],
        graph_fingerprint="gfp-abc123",
        timeline_fingerprint="tfp-xyz789",
        risk_score=72.5,
        confidence=88.0,
        tags=["smb", "lateral-movement", "SMB"],  # intentional dupe + mixed case
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Section 1: Deterministic IDs
# ---------------------------------------------------------------------------
print("\n── 1. Deterministic IDs ─────────────────────────────────────────────")

key1 = _compute_investigation_key("proj-001", "Lateral Movement Campaign", "analyst@corp")
key2 = _compute_investigation_key("proj-001", "Lateral Movement Campaign", "analyst@corp")
check("investigationKey is deterministic (same call twice)", key1 == key2)
check("investigationKey length is 32 hex chars", len(key1) == 32)

id1 = _compute_investigation_id(key1)
id2 = _compute_investigation_id(key1)
check("investigationId is deterministic (UUIDv5)", id1 == id2)
check("investigationId is valid UUID format (36 chars with dashes)", len(id1) == 36 and id1.count("-") == 4)

key_diff = _compute_investigation_key("proj-001", "Different Title", "analyst@corp")
check("Different title → different key", key1 != key_diff)

key_proj = _compute_investigation_key("proj-002", "Lateral Movement Campaign", "analyst@corp")
check("Different project → different key", key1 != key_proj)


# ---------------------------------------------------------------------------
# Section 2: build_investigation()
# ---------------------------------------------------------------------------
print("\n── 2. build_investigation() ─────────────────────────────────────────")

inv = _make_inv()
check("status is OPEN",            inv.status == InvestigationStatus.OPEN)
check("priority is HIGH",          inv.priority == InvestigationPriority.HIGH)
check("closedAt is None",          inv.closedAt is None)
check("engineVersion matches const", inv.engineVersion == INVESTIGATION_ENGINE_VERSION)
check("assetIds are sorted",       list(inv.assetIds) == sorted(["asset-a", "asset-b", "asset-c"]))
check("relationshipIds are sorted",list(inv.relationshipIds) == sorted(["rel-1", "rel-2"]))
check("tags deduped + sorted",     inv.tags == ("lateral-movement", "smb"))
check("riskScore clamped",         0.0 <= inv.riskScore <= 100.0)
check("confidence clamped",        0.0 <= inv.confidence <= 100.0)
check("auditTrail starts with Created", inv.auditTrail == ("Created",))
check("investigationFingerprint non-empty", len(inv.investigationFingerprint) == 64)

# Build twice — must be identical
inv2 = _make_inv()
check("Identical inputs → identical investigationId",          inv.investigationId  == inv2.investigationId)
check("Identical inputs → identical investigationKey",         inv.investigationKey == inv2.investigationKey)
check("Identical inputs → identical investigationFingerprint", inv.investigationFingerprint == inv2.investigationFingerprint)


# ---------------------------------------------------------------------------
# Section 3: Immutability
# ---------------------------------------------------------------------------
print("\n── 3. Immutability (frozen=True) ────────────────────────────────────")

try:
    inv.status = InvestigationStatus.ACTIVE  # type: ignore
    check("frozen=True raises on mutation", False)
except Exception:
    check("frozen=True raises on mutation", True)


# ---------------------------------------------------------------------------
# Section 4: update_investigation()
# ---------------------------------------------------------------------------
print("\n── 4. update_investigation() ────────────────────────────────────────")

upd = update_investigation(
    inv,
    updated_at = TS2,
    status     = InvestigationStatus.ACTIVE,
    priority   = InvestigationPriority.CRITICAL,
    assigned_to= "lead@corp",
)
check("status updated to ACTIVE",        upd.status   == InvestigationStatus.ACTIVE)
check("priority updated to CRITICAL",    upd.priority == InvestigationPriority.CRITICAL)
check("assignedTo updated",              upd.assignedTo == "lead@corp")
check("updatedAt updated",               upd.updatedAt == TS2)
check("createdAt preserved",             upd.createdAt == TS1)
check("investigationId unchanged",       upd.investigationId == inv.investigationId)
check("auditTrail has Status changed",   "Status changed to ACTIVE" in upd.auditTrail)
check("auditTrail has Priority changed", "Priority changed to CRITICAL" in upd.auditTrail)
check("auditTrail has Assigned",         "Assigned" in upd.auditTrail)
check("auditTrail preserves Created",    "Created" in upd.auditTrail)

# None fields not changed
upd_partial = update_investigation(inv, updated_at=TS2, risk_score=90.0)
check("Partial update: status preserved",  upd_partial.status == inv.status)
check("Partial update: riskScore changed", upd_partial.riskScore == 90.0)


# ---------------------------------------------------------------------------
# Section 5: close_investigation() / archive_investigation()
# ---------------------------------------------------------------------------
print("\n── 5. close_investigation() / archive_investigation() ───────────────")

closed = close_investigation(inv, closed_at=TS2)
check("status is COMPLETED",           closed.status   == InvestigationStatus.COMPLETED)
check("closedAt is set",               closed.closedAt == TS2)
check("updatedAt updated on close",    closed.updatedAt == TS2)
check("auditTrail has Closed",         "Closed" in closed.auditTrail)

# Closing an already-closed investigation is a no-op
closed_again = close_investigation(closed, closed_at=TS3)
check("Double-close returns unchanged", closed_again is closed)

archived = archive_investigation(inv, archived_at=TS3)
check("status is ARCHIVED",            archived.status   == InvestigationStatus.ARCHIVED)
check("closedAt stamped on archive",   archived.closedAt == TS3)
check("auditTrail has Archived",       "Archived" in archived.auditTrail)

# Archive from already-closed preserves original closedAt
archived_from_closed = archive_investigation(closed, archived_at=TS3)
check("closedAt preserved when archiving closed inv", archived_from_closed.closedAt == TS2)


# ---------------------------------------------------------------------------
# Section 6: clone_investigation()
# ---------------------------------------------------------------------------
print("\n── 6. clone_investigation() ─────────────────────────────────────────")

cloned = clone_investigation(
    closed,
    new_project_id = "proj-002",
    new_created_by = "analyst2@corp",
    new_created_at = TS3,
    new_title      = "Lateral Movement — Follow-up",
)
check("clone status is OPEN",            cloned.status    == InvestigationStatus.OPEN)
check("clone closedAt is None",          cloned.closedAt  is None)
check("clone projectId updated",         cloned.projectId == "proj-002")
check("clone createdBy updated",         cloned.createdBy == "analyst2@corp")
check("clone title updated",             cloned.title     == "Lateral Movement — Follow-up")
check("clone investigationId differs",   cloned.investigationId != inv.investigationId)
check("clone auditTrail reset",          cloned.auditTrail == ("Created",))
check("clone inherits assetIds",         cloned.assetIds == inv.assetIds)
check("clone engineVersion current",     cloned.engineVersion == INVESTIGATION_ENGINE_VERSION)


# ---------------------------------------------------------------------------
# Section 7: sort_investigations()
# ---------------------------------------------------------------------------
print("\n── 7. sort_investigations() ─────────────────────────────────────────")

inv_low  = _make_inv(title="Low-pri",      priority=InvestigationPriority.LOW,      created_at=TS1)
inv_crit = _make_inv(title="Critical-pri", priority=InvestigationPriority.CRITICAL, created_at=TS1)
inv_med  = _make_inv(title="Med-pri",      priority=InvestigationPriority.MEDIUM,   created_at=TS1)

pool = [inv_low, inv_crit, inv_med]

sorted_desc = sort_investigations(pool, by="priority", ascending=False)
check("priority DESC: CRITICAL first", sorted_desc[0].priority == InvestigationPriority.CRITICAL)
check("priority DESC: LOW last",       sorted_desc[-1].priority == InvestigationPriority.LOW)

sorted_asc = sort_investigations(pool, by="priority", ascending=True)
check("priority ASC: LOW first",       sorted_asc[0].priority == InvestigationPriority.LOW)

sorted_title = sort_investigations(pool, by="title", ascending=True)
check("title ASC: alphabetical order", sorted_title[0].title <= sorted_title[-1].title)

try:
    sort_investigations(pool, by="invalid_key")
    check("Invalid sort key raises ValueError", False)
except ValueError:
    check("Invalid sort key raises ValueError", True)


# ---------------------------------------------------------------------------
# Section 8: filter_investigations()
# ---------------------------------------------------------------------------
print("\n── 8. filter_investigations() ───────────────────────────────────────")

inv_archived = archive_investigation(inv_low, archived_at=TS2)
mixed = [inv, upd, closed, archived, inv_low, inv_crit, inv_med, inv_archived]

open_ones = filter_investigations(mixed, status=InvestigationStatus.OPEN)
check("filter by OPEN status",         all(i.status == InvestigationStatus.OPEN for i in open_ones))

crit_ones = filter_investigations(mixed, priority=InvestigationPriority.CRITICAL)
check("filter by CRITICAL priority",   all(i.priority == InvestigationPriority.CRITICAL for i in crit_ones))

tagged = filter_investigations(mixed, tags=["smb"])
check("filter by tag 'smb'",           all("smb" in i.tags for i in tagged))

high_risk = filter_investigations(mixed, min_risk_score=70.0)
check("filter min_risk_score=70",      all(i.riskScore >= 70.0 for i in high_risk))

proj_filter = filter_investigations(mixed, project_id="proj-001")
check("filter by project_id",          all(i.projectId == "proj-001" for i in proj_filter))


# ---------------------------------------------------------------------------
# Section 9: group_investigations()
# ---------------------------------------------------------------------------
print("\n── 9. group_investigations() ────────────────────────────────────────")

grouped_status = group_investigations(mixed, by="status")
check("grouped by status: OPEN key present",     InvestigationStatus.OPEN.value     in grouped_status)
check("grouped by status: COMPLETED key present",InvestigationStatus.COMPLETED.value in grouped_status)

grouped_priority = group_investigations(mixed, by="priority")
check("grouped by priority: CRITICAL key present", InvestigationPriority.CRITICAL.value in grouped_priority)
check("grouped by priority: HIGH key present",     InvestigationPriority.HIGH.value     in grouped_priority)

try:
    group_investigations(mixed, by="bad_key")
    check("Invalid group key raises ValueError", False)
except ValueError:
    check("Invalid group key raises ValueError", True)


# ---------------------------------------------------------------------------
# Section 10: find_investigation()
# ---------------------------------------------------------------------------
print("\n── 10. find_investigation() ─────────────────────────────────────────")

pool2 = [inv, upd, closed]
found_by_id  = find_investigation(pool2, investigation_id=inv.investigationId)
found_by_key = find_investigation(pool2, investigation_key=inv.investigationKey)
found_by_title = find_investigation(pool2, title=inv.title)
not_found    = find_investigation(pool2, investigation_id="nonexistent-id")

check("find by investigationId",    found_by_id  is not None and found_by_id.investigationId  == inv.investigationId)
check("find by investigationKey",   found_by_key is not None and found_by_key.investigationKey == inv.investigationKey)
check("find by title",              found_by_title is not None and found_by_title.title == inv.title)
check("not found returns None",     not_found is None)


# ---------------------------------------------------------------------------
# Section 11: calculate_statistics()
# ---------------------------------------------------------------------------
print("\n── 11. calculate_statistics() ───────────────────────────────────────")

stats = calculate_statistics(mixed)
check("totalInvestigations correct",  stats.totalInvestigations == len(mixed))
check("openCount >= 0",               stats.openCount >= 0)
check("closedCount >= 0",             stats.closedCount >= 0)
check("criticalCount >= 0",           stats.criticalCount >= 0)
check("averageRisk in [0, 100]",      0.0 <= stats.averageRisk <= 100.0)
check("averageConfidence in [0, 100]",0.0 <= stats.averageConfidence <= 100.0)
check("openCount + closedCount <= total",
      stats.openCount + stats.closedCount <= stats.totalInvestigations)

# Determinism: same inputs → same stats
stats2 = calculate_statistics(list(reversed(mixed)))
check("statistics are order-independent", stats.averageRisk == stats2.averageRisk)
check("statistics totalInvestigations stable", stats.totalInvestigations == stats2.totalInvestigations)

# Empty list
empty_stats = calculate_statistics([])
check("empty list: totalInvestigations=0", empty_stats.totalInvestigations == 0)
check("empty list: averageRisk=0.0",       empty_stats.averageRisk      == 0.0)
check("empty list: averageConfidence=0.0", empty_stats.averageConfidence == 0.0)


# ---------------------------------------------------------------------------
# Section 12: investigationFingerprint stability
# ---------------------------------------------------------------------------
print("\n── 12. investigationFingerprint stability ───────────────────────────")

fp1 = _compute_investigation_fingerprint(
    "gfp-abc", "tfp-xyz", ("a-2", "a-1"), ("r-1",), ("f-1",)
)
fp2 = _compute_investigation_fingerprint(
    "gfp-abc", "tfp-xyz", ("a-1", "a-2"), ("r-1",), ("f-1",)   # different order
)
check("fingerprint is order-independent across assetIds", fp1 == fp2)

fp_diff = _compute_investigation_fingerprint(
    "gfp-abc", "tfp-xyz", ("a-1",), ("r-1",), ("f-1",)          # fewer assetIds
)
check("fingerprint changes with different assetIds", fp1 != fp_diff)

fp_gfp = _compute_investigation_fingerprint(
    "gfp-CHANGED", "tfp-xyz", ("a-2", "a-1"), ("r-1",), ("f-1",)
)
check("fingerprint changes with different graphFingerprint", fp1 != fp_gfp)


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print("\n" + "─" * 64)
total_checks  = sum(1 for line in open(__file__) if "check(" in line)
failed        = len(errors)
print(f"  Results: {failed} failed / {total_checks} checks")
if errors:
    print("\n  Failed checks:")
    for e in errors:
        print(f"    {FAIL}  {e}")
    sys.exit(1)
else:
    print(f"\n  {PASS}  All checks passed — Investigation Engine (A4.0.6)")
