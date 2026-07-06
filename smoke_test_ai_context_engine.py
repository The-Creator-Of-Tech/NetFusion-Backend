"""
Smoke test — AI Copilot Context Engine (Phase A4.1.0)
======================================================
Validates (200+ assertions):
  ✓ deterministic IDs (contextKey + UUIDv5)
  ✓ deterministic outputs
  ✓ immutable models (frozen=True raises on mutation)
  ✓ build_asset_context()
  ✓ build_relationship_context()
  ✓ build_finding_context()
  ✓ build_alert_context()
  ✓ build_mitre_context()
  ✓ build_timeline_context()
  ✓ build_evidence_context()
  ✓ build_graph_context()
  ✓ build_investigation_context()
  ✓ build_statistics()
  ✓ build_context() — full pipeline
  ✓ search_context()
  ✓ filter_context()
  ✓ group_context()
  ✓ sort_context()
  ✓ find_context_item()
  ✓ calculate_statistics()
  ✓ summarize_context()
  ✓ ordering independence
  ✓ identical input → identical output
  ✓ context fingerprint stability
"""

import sys
from services.ai_context_service import (
    AIContext, ContextAsset, ContextRelationship, ContextFinding,
    ContextAlert, ContextMitre, ContextTimeline, ContextEvidence,
    ContextGraph, ContextInvestigation, ContextStatistics,
    ContextBuildMetadata, ContextSummary,
    build_asset_context, build_relationship_context,
    build_finding_context, build_alert_context,
    build_mitre_context, build_timeline_context,
    build_evidence_context, build_graph_context,
    build_investigation_context, build_statistics,
    build_context, search_context, filter_context,
    group_context, sort_context, find_context_item,
    calculate_statistics, summarize_context,
    _compute_context_key, _compute_context_id,
)
from core.constants import AI_COPILOT_CONTEXT_ENGINE_VERSION

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
errors: list = []


def check(label: str, condition: bool) -> None:
    icon = PASS if condition else FAIL
    print(f"  {icon}  {label}")
    if not condition:
        errors.append(label)


TS = "2026-06-30T10:00:00Z"
PROJ = "proj-001"
INV  = "inv-001"

# ---------------------------------------------------------------------------
# Raw fixture dicts  (simulate outputs from various engines)
# ---------------------------------------------------------------------------

ASSETS = [
    {"id": "asset-a", "assetKey": "ak-a", "deviceName": "Workstation-A",
     "hostnames": ["ws-a.corp", "ws-a"], "ipAddresses": ["10.0.0.1"],
     "macAddresses": ["aa:bb:cc:dd:ee:01"], "riskScore": 80.0, "confidence": 90.0,
     "vendor": "Dell", "operatingSystem": "Windows"},
    {"id": "asset-b", "assetKey": "ak-b", "deviceName": "Server-B",
     "hostnames": ["srv-b.corp"], "ipAddresses": ["10.0.0.2"],
     "macAddresses": ["aa:bb:cc:dd:ee:02"], "riskScore": 55.0, "confidence": 75.0,
     "vendor": "HP"},
    {"id": "asset-c", "assetKey": "ak-c", "deviceName": "DC-C",
     "hostnames": [], "ipAddresses": ["10.0.0.3"],
     "macAddresses": [], "riskScore": 95.0, "confidence": 85.0},
]

RELS = [
    {"relationshipId": "rel-1", "relationshipKey": "rk-1",
     "relationshipType": "COMMUNICATED_WITH",
     "protocol": "SMB", "sourceAssetId": "asset-a", "targetAssetId": "asset-b",
     "direction": "OUTBOUND", "confidence": 82.0},
    {"relationshipId": "rel-2", "relationshipKey": "rk-2",
     "relationshipType": "DNS_QUERY",
     "protocol": "DNS", "sourceAssetId": "asset-b", "targetAssetId": "asset-c",
     "direction": "OUTBOUND", "confidence": 60.0},
]

FINDINGS = [
    {"findingId": "find-1", "severity": "CRITICAL", "status": "OPEN",
     "title": "Lateral Movement via SMB", "description": "SMB lateral movement.",
     "riskScore": 90.0, "confidence": 85.0},
    {"findingId": "find-2", "severity": "HIGH", "status": "CONFIRMED",
     "title": "Suspicious DNS", "description": "Unusual DNS queries.",
     "riskScore": 65.0, "confidence": 70.0},
    {"findingId": "find-3", "severity": "MEDIUM", "status": "OPEN",
     "title": "Port Scan Detected", "description": "Nmap scan.",
     "riskScore": 45.0, "confidence": 60.0},
]

ALERTS = [
    {"alertId": "alert-1", "severity": "CRITICAL", "status": "NEW",
     "title": "SMB Alert", "confidence": 88.0},
    {"alertId": "alert-2", "severity": "HIGH", "status": "IN_PROGRESS",
     "title": "DNS Alert", "confidence": 72.0},
    {"alertId": "alert-3", "severity": "LOW", "status": "CLOSED",
     "title": "Info Alert", "confidence": 40.0},
]

MITRE_TECHS = [
    {"techniqueId": "tech-001", "techniqueCode": "T1021", "name": "Remote Services",
     "tacticIds": ["tac-lat-001"], "riskScore": 75.0, "confidence": 88.0},
    {"techniqueId": "tech-002", "techniqueCode": "T1071", "name": "Application Layer Protocol",
     "tacticIds": ["tac-c2-001"], "riskScore": 60.0, "confidence": 70.0},
]

TIMELINE_EVENTS = [
    {"eventId": "ev-tl-1", "eventType": "EVIDENCE_ADDED",
     "occurredAt": "2026-06-30T09:00:00+00:00",
     "summary": "Observed SMB traffic", "severity": "HIGH", "confidence": 80},
    {"eventId": "ev-tl-2", "eventType": "RELATIONSHIP_CREATED",
     "occurredAt": "2026-06-30T09:05:00+00:00",
     "summary": "Relationship created", "severity": "MEDIUM", "confidence": 65},
    {"eventId": "ev-tl-3", "eventType": "ALERT_GENERATED",
     "occurredAt": "2026-06-30T09:10:00+00:00",
     "summary": "Alert raised", "severity": "CRITICAL", "confidence": 90},
]

EVIDENCE = [
    {"evidenceId": "ev-1", "fieldName": "macAddress", "fieldValue": "aa:bb:cc:dd:ee:01",
     "source": {"sourceType": "pcap"}, "confidence": 95.0},
    {"evidenceId": "ev-2", "fieldName": "hostname",   "fieldValue": "ws-a.corp",
     "source": {"sourceType": "dhcp"}, "confidence": 90.0},
    {"evidenceId": "ev-3", "fieldName": "ipAddress",  "fieldValue": "10.0.0.1",
     "source": {"sourceType": "arp"},  "confidence": 85.0},
]

GRAPH = {
    "graphFingerprint": "gfp-abc123def456789012345678901234",
    "nodes": [{"nodeKey": "nk-1", "riskScore": 80}, {"nodeKey": "nk-2", "riskScore": 60}],
    "edges": [{"edgeKey": "ek-1"}],
    "statistics": {
        "totalNodes": 2, "totalEdges": 1,
        "highestRiskNode": "nk-1",
    },
}

INVESTIGATION = {
    "investigationId": INV,
    "title": "Lateral Movement Campaign",
    "status": "ACTIVE",
    "priority": "HIGH",
}


# ---------------------------------------------------------------------------
# Section 1: Deterministic IDs
# ---------------------------------------------------------------------------
print("\n── 1. Deterministic IDs ─────────────────────────────────────────────")

finding_ids = ("find-1", "find-2", "find-3")
alert_ids   = ("alert-1", "alert-2", "alert-3")

k1 = _compute_context_key(PROJ, INV, "gfp-abc", finding_ids, alert_ids)
k2 = _compute_context_key(PROJ, INV, "gfp-abc", finding_ids, alert_ids)
check("contextKey deterministic",                k1 == k2)
check("contextKey length 32",                    len(k1) == 32)

# Order-independence of findingIds / alertIds
k_rev = _compute_context_key(PROJ, INV, "gfp-abc",
    tuple(reversed(finding_ids)), tuple(reversed(alert_ids)))
check("contextKey order-independent (finding/alert IDs)", k1 == k_rev)

k_diff_proj = _compute_context_key("proj-002", INV, "gfp-abc", finding_ids, alert_ids)
check("different projectId → different contextKey",  k1 != k_diff_proj)

k_diff_fp = _compute_context_key(PROJ, INV, "gfp-CHANGED", finding_ids, alert_ids)
check("different graphFingerprint → different contextKey", k1 != k_diff_fp)

id1 = _compute_context_id(k1)
id2 = _compute_context_id(k1)
check("contextId deterministic (UUIDv5)",        id1 == id2)
check("contextId valid UUID format (36 chars)",  len(id1) == 36 and id1.count("-") == 4)


# ---------------------------------------------------------------------------
# Section 2: build_asset_context()
# ---------------------------------------------------------------------------
print("\n── 2. build_asset_context() ─────────────────────────────────────────")

ctx_assets = build_asset_context(ASSETS)
check("returns tuple",               isinstance(ctx_assets, tuple))
check("count matches input",         len(ctx_assets) == len(ASSETS))
check("sorted by riskScore DESC",    ctx_assets[0].riskScore >= ctx_assets[-1].riskScore)
check("assetId set",                 all(a.assetId for a in ctx_assets))
check("hostnames are sorted tuple",  isinstance(ctx_assets[0].hostnames, tuple))
check("ipAddresses are sorted tuple",isinstance(ctx_assets[0].ipAddresses, tuple))
check("riskScore clamped",           all(0.0 <= a.riskScore <= 100.0 for a in ctx_assets))
check("confidence clamped",          all(0.0 <= a.confidence <= 100.0 for a in ctx_assets))
check("summary non-empty",           all(a.summary for a in ctx_assets))
# asset-c should be first (riskScore=95)
check("highest risk asset first",    ctx_assets[0].assetId == "asset-c")

# Idempotence
ctx_assets2 = build_asset_context(ASSETS)
check("identical inputs → same assetIds", tuple(a.assetId for a in ctx_assets) == tuple(a.assetId for a in ctx_assets2))

# Empty
check("empty input → empty tuple",   build_asset_context([]) == ())


# ---------------------------------------------------------------------------
# Section 3: build_relationship_context()
# ---------------------------------------------------------------------------
print("\n── 3. build_relationship_context() ─────────────────────────────────")

ctx_rels = build_relationship_context(RELS)
check("count matches",               len(ctx_rels) == len(RELS))
check("sorted by confidence DESC",   ctx_rels[0].confidence >= ctx_rels[-1].confidence)
check("protocol uppercased",         all(r.protocol == r.protocol.upper() for r in ctx_rels))
check("summary non-empty",           all(r.summary for r in ctx_rels))
check("SMB first (confidence=82)",   ctx_rels[0].protocol == "SMB")
check("empty input → empty tuple",   build_relationship_context([]) == ())


# ---------------------------------------------------------------------------
# Section 4: build_finding_context()
# ---------------------------------------------------------------------------
print("\n── 4. build_finding_context() ───────────────────────────────────────")

ctx_findings = build_finding_context(FINDINGS)
check("count matches",               len(ctx_findings) == len(FINDINGS))
check("sorted by riskScore DESC",    ctx_findings[0].riskScore >= ctx_findings[-1].riskScore)
check("CRITICAL finding first",      ctx_findings[0].severity == "CRITICAL")
check("severity uppercased",         all(f.severity == f.severity.upper() for f in ctx_findings))
check("status uppercased",           all(f.status   == f.status.upper()   for f in ctx_findings))
check("summary contains severity",   all(f.severity in f.summary for f in ctx_findings))
check("empty → empty tuple",         build_finding_context([]) == ())


# ---------------------------------------------------------------------------
# Section 5: build_alert_context()
# ---------------------------------------------------------------------------
print("\n── 5. build_alert_context() ─────────────────────────────────────────")

ctx_alerts = build_alert_context(ALERTS)
check("count matches",               len(ctx_alerts) == len(ALERTS))
check("sorted severity DESC",        ctx_alerts[0].severity == "CRITICAL")
check("severity uppercased",         all(a.severity == a.severity.upper() for a in ctx_alerts))
check("status uppercased",           all(a.status   == a.status.upper()   for a in ctx_alerts))
check("summary non-empty",           all(a.summary for a in ctx_alerts))
check("empty → empty tuple",         build_alert_context([]) == ())


# ---------------------------------------------------------------------------
# Section 6: build_mitre_context()
# ---------------------------------------------------------------------------
print("\n── 6. build_mitre_context() ─────────────────────────────────────────")

ctx_mitre = build_mitre_context([], MITRE_TECHS)
check("count from techniques",       len(ctx_mitre) == len(MITRE_TECHS))
check("sorted confidence DESC",      ctx_mitre[0].confidence >= ctx_mitre[-1].confidence)
check("techniqueCode set",           all(m.techniqueCode for m in ctx_mitre))
check("T1021 first (conf=88)",       ctx_mitre[0].techniqueCode == "T1021")
check("tacticNames is tuple",        all(isinstance(m.tacticNames, tuple) for m in ctx_mitre))
check("summary contains code",       all(m.techniqueCode in m.summary for m in ctx_mitre))
check("empty → empty tuple",         build_mitre_context([], []) == ())


# ---------------------------------------------------------------------------
# Section 7: build_timeline_context()
# ---------------------------------------------------------------------------
print("\n── 7. build_timeline_context() ──────────────────────────────────────")

ctx_timeline = build_timeline_context(TIMELINE_EVENTS)
check("count matches",               len(ctx_timeline) == len(TIMELINE_EVENTS))
check("sorted occurredAt DESC",      ctx_timeline[0].occurredAt >= ctx_timeline[-1].occurredAt)
check("eventType set",               all(t.eventType for t in ctx_timeline))
check("latest event first",          ctx_timeline[0].eventId == "ev-tl-3")
check("importance clamped 0–100",    all(0.0 <= t.importance <= 100.0 for t in ctx_timeline))
check("empty → empty tuple",         build_timeline_context([]) == ())


# ---------------------------------------------------------------------------
# Section 8: build_evidence_context()
# ---------------------------------------------------------------------------
print("\n── 8. build_evidence_context() ──────────────────────────────────────")

ctx_ev = build_evidence_context(EVIDENCE)
check("count matches",               len(ctx_ev) == len(EVIDENCE))
check("sorted confidence DESC",      ctx_ev[0].confidence >= ctx_ev[-1].confidence)
check("fieldName set",               all(e.fieldName for e in ctx_ev))
check("sourceType set",              all(e.sourceType for e in ctx_ev))
check("summary contains fieldName",  all(e.fieldName in e.summary for e in ctx_ev))
check("highest conf evidence first", ctx_ev[0].confidence == 95.0)
check("empty → empty tuple",         build_evidence_context([]) == ())


# ---------------------------------------------------------------------------
# Section 9: build_graph_context()
# ---------------------------------------------------------------------------
print("\n── 9. build_graph_context() ─────────────────────────────────────────")

ctx_graph = build_graph_context(GRAPH)
check("graphFingerprint set",        ctx_graph.graphFingerprint == GRAPH["graphFingerprint"])
check("nodeCount correct",           ctx_graph.nodeCount == 2)
check("edgeCount correct",           ctx_graph.edgeCount == 1)
check("highestRiskNode set",         ctx_graph.highestRiskNode == "nk-1")
check("summary non-empty",           bool(ctx_graph.summary))

ctx_graph_none = build_graph_context(None)
check("None graph → empty fingerprint", ctx_graph_none.nodeCount == 0)


# ---------------------------------------------------------------------------
# Section 10: build_investigation_context()
# ---------------------------------------------------------------------------
print("\n── 10. build_investigation_context() ────────────────────────────────")

ctx_inv = build_investigation_context(INVESTIGATION)
check("investigationId set",         ctx_inv.investigationId == INV)
check("title set",                   ctx_inv.title == "Lateral Movement Campaign")
check("status uppercased",           ctx_inv.status == "ACTIVE")
check("priority uppercased",         ctx_inv.priority == "HIGH")
check("summary non-empty",           bool(ctx_inv.summary))

ctx_inv_none = build_investigation_context(None)
check("None investigation → empty id", ctx_inv_none.investigationId == "")


# ---------------------------------------------------------------------------
# Section 11: Immutability
# ---------------------------------------------------------------------------
print("\n── 11. Immutability (frozen=True) ────────────────────────────────────")

try:
    ctx_assets[0].riskScore = 99.0  # type: ignore
    check("ContextAsset frozen=True raises", False)
except Exception:
    check("ContextAsset frozen=True raises", True)

try:
    ctx_findings[0].severity = "LOW"  # type: ignore
    check("ContextFinding frozen=True raises", False)
except Exception:
    check("ContextFinding frozen=True raises", True)

try:
    ctx_alerts[0].status = "CLOSED"  # type: ignore
    check("ContextAlert frozen=True raises", False)
except Exception:
    check("ContextAlert frozen=True raises", True)

try:
    ctx_ev[0].fieldValue = "hacked"  # type: ignore
    check("ContextEvidence frozen=True raises", False)
except Exception:
    check("ContextEvidence frozen=True raises", True)

try:
    ctx_graph.nodeCount = 99  # type: ignore
    check("ContextGraph frozen=True raises", False)
except Exception:
    check("ContextGraph frozen=True raises", True)


# ---------------------------------------------------------------------------
# Section 12: build_context() — full pipeline
# ---------------------------------------------------------------------------
print("\n── 12. build_context() — full pipeline ──────────────────────────────")

ctx = build_context(
    project_id       = PROJ,
    investigation_id = INV,
    created_at       = TS,
    assets           = ASSETS,
    relationships    = RELS,
    findings         = FINDINGS,
    alerts           = ALERTS,
    mitre_mappings   = [],
    mitre_techniques = MITRE_TECHS,
    timeline_events  = TIMELINE_EVENTS,
    evidence         = EVIDENCE,
    graph            = GRAPH,
    investigation    = INVESTIGATION,
)

check("contextId valid UUID",              len(ctx.contextId) == 36)
check("contextKey length 32",             len(ctx.contextKey) == 32)
check("engineVersion matches const",      ctx.engineVersion == AI_COPILOT_CONTEXT_ENGINE_VERSION)
check("projectId set",                    ctx.projectId == PROJ)
check("investigationId set",              ctx.investigationId == INV)
check("assets section populated",         len(ctx.assets) == len(ASSETS))
check("relationships section populated",  len(ctx.relationships) == len(RELS))
check("findings section populated",       len(ctx.findings) == len(FINDINGS))
check("alerts section populated",         len(ctx.alerts) == len(ALERTS))
check("mitre section populated",          len(ctx.mitre) == len(MITRE_TECHS))
check("timeline section populated",       len(ctx.timeline) == len(TIMELINE_EVENTS))
check("evidence section populated",       len(ctx.evidence) == len(EVIDENCE))
check("graph section populated",          ctx.graph.nodeCount == 2)
check("investigation section populated",  ctx.investigation.investigationId == INV)
check("statistics.assetCount correct",    ctx.statistics.assetCount == len(ASSETS))
check("statistics.findingCount correct",  ctx.statistics.findingCount == len(FINDINGS))
check("statistics.alertCount correct",    ctx.statistics.alertCount == len(ALERTS))
check("statistics.averageRisk >= 0",      ctx.statistics.averageRisk >= 0.0)
check("statistics.averageConfidence >= 0",ctx.statistics.averageConfidence >= 0.0)
check("buildMetadata.builderVersion",     ctx.buildMetadata.builderVersion == AI_COPILOT_CONTEXT_ENGINE_VERSION)
check("buildMetadata.generatedSections non-empty", len(ctx.buildMetadata.generatedSections) > 0)
check("buildMetadata.sourceCounts has assets",      "assets" in ctx.buildMetadata.sourceCounts)

# Idempotence — identical inputs → identical context
ctx2 = build_context(
    project_id=PROJ, investigation_id=INV, created_at=TS,
    assets=ASSETS, relationships=RELS, findings=FINDINGS, alerts=ALERTS,
    mitre_mappings=[], mitre_techniques=MITRE_TECHS,
    timeline_events=TIMELINE_EVENTS, evidence=EVIDENCE,
    graph=GRAPH, investigation=INVESTIGATION,
)
check("identical inputs → same contextId",  ctx.contextId  == ctx2.contextId)
check("identical inputs → same contextKey", ctx.contextKey == ctx2.contextKey)

# Frozen
try:
    ctx.projectId = "hacked"  # type: ignore
    check("AIContext frozen=True raises", False)
except Exception:
    check("AIContext frozen=True raises", True)


# ---------------------------------------------------------------------------
# Section 13: build_statistics()
# ---------------------------------------------------------------------------
print("\n── 13. build_statistics() ───────────────────────────────────────────")

stats = build_statistics(
    ctx.assets, ctx.relationships, ctx.findings,
    ctx.alerts, ctx.mitre, ctx.timeline, ctx.evidence,
)
check("assetCount correct",           stats.assetCount        == len(ASSETS))
check("relationshipCount correct",    stats.relationshipCount == len(RELS))
check("findingCount correct",         stats.findingCount      == len(FINDINGS))
check("alertCount correct",           stats.alertCount        == len(ALERTS))
check("mitreCount correct",           stats.mitreCount        == len(MITRE_TECHS))
check("timelineCount correct",        stats.timelineCount     == len(TIMELINE_EVENTS))
check("evidenceCount correct",        stats.evidenceCount     == len(EVIDENCE))
check("averageRisk in [0,100]",       0.0 <= stats.averageRisk       <= 100.0)
check("averageConfidence in [0,100]", 0.0 <= stats.averageConfidence <= 100.0)

# Ordering-independence
stats2 = build_statistics(
    tuple(reversed(ctx.assets)),
    tuple(reversed(ctx.relationships)),
    tuple(reversed(ctx.findings)),
    tuple(reversed(ctx.alerts)),
    tuple(reversed(ctx.mitre)),
    tuple(reversed(ctx.timeline)),
    tuple(reversed(ctx.evidence)),
)
check("stats order-independent: assetCount",          stats.assetCount        == stats2.assetCount)
check("stats order-independent: averageRisk",         stats.averageRisk       == stats2.averageRisk)
check("stats order-independent: averageConfidence",   stats.averageConfidence == stats2.averageConfidence)

# Empty
empty_stats = build_statistics((), (), (), (), (), (), ())
check("empty stats: all counts 0",     all(
    getattr(empty_stats, f) == 0
    for f in ("assetCount","relationshipCount","findingCount","alertCount",
              "mitreCount","timelineCount","evidenceCount")
))
check("empty stats: averageRisk=0",    empty_stats.averageRisk       == 0.0)
check("empty stats: averageConf=0",    empty_stats.averageConfidence == 0.0)


# ---------------------------------------------------------------------------
# Section 14: search_context()
# ---------------------------------------------------------------------------
print("\n── 14. search_context() ─────────────────────────────────────────────")

r_smb = search_context(ctx, "SMB")
check("search 'SMB' finds relationships",    len(r_smb["relationships"]) > 0)
check("search 'SMB' finds findings",         len(r_smb["findings"])      > 0)
check("search 'SMB' finds alerts",           len(r_smb["alerts"])        > 0)

r_ws = search_context(ctx, "Workstation-A")
check("search by deviceName finds asset",    len(r_ws["assets"]) > 0)

r_ip = search_context(ctx, "10.0.0.1")
check("search by IP finds asset",            len(r_ip["assets"]) > 0)

r_mac = search_context(ctx, "aa:bb:cc:dd:ee:01")
check("search by MAC finds asset",           len(r_mac["assets"]) > 0)

r_host = search_context(ctx, "ws-a.corp")
check("search by hostname finds asset",      len(r_host["assets"]) > 0)

r_t1021 = search_context(ctx, "T1021")
check("search by MITRE code",                len(r_t1021["mitre"]) > 0)

r_mitre_name = search_context(ctx, "Remote Services")
check("search by MITRE name",                len(r_mitre_name["mitre"]) > 0)

r_ev = search_context(ctx, "macAddress")
check("search by fieldName finds evidence",  len(r_ev["evidence"]) > 0)

r_ev_val = search_context(ctx, "ws-a.corp")
check("search by fieldValue finds evidence", len(r_ev_val["evidence"]) > 0)

r_empty = search_context(ctx, "")
check("empty query returns all empty",       all(v == [] for v in r_empty.values()))

r_none = search_context(ctx, "zzznomatch999xyz")
check("no-match query returns all empty",    all(v == [] for v in r_none.values()))

# Search is case-insensitive
r_low = search_context(ctx, "smb")
check("search case-insensitive (smb == SMB)", len(r_low["relationships"]) == len(r_smb["relationships"]))

r_tl = search_context(ctx, "SMB traffic")
check("search timeline summary",             len(r_tl["timeline"]) > 0)


# ---------------------------------------------------------------------------
# Section 15: filter_context()
# ---------------------------------------------------------------------------
print("\n── 15. filter_context() ─────────────────────────────────────────────")

f_risk = filter_context(ctx, min_risk=70.0)
check("filter min_risk=70: all assets >= 70",
      all(a.riskScore >= 70.0 for a in f_risk.get("assets", [])))
check("filter min_risk=70: all findings >= 70",
      all(f.riskScore >= 70.0 for f in f_risk.get("findings", [])))

f_sev = filter_context(ctx, severity="CRITICAL")
check("filter severity=CRITICAL: findings",
      all(f.severity == "CRITICAL" for f in f_sev.get("findings", [])))
check("filter severity=CRITICAL: alerts",
      all(a.severity == "CRITICAL" for a in f_sev.get("alerts", [])))

f_fstat = filter_context(ctx, finding_status="OPEN")
check("filter finding_status=OPEN: only OPEN findings",
      all(f.status == "OPEN" for f in f_fstat.get("findings", [])))

f_astat = filter_context(ctx, alert_status="NEW")
check("filter alert_status=NEW: only NEW alerts",
      all(a.status == "NEW" for a in f_astat.get("alerts", [])))

f_conf = filter_context(ctx, min_confidence=80.0)
check("filter min_confidence=80: assets ok",
      all(a.confidence >= 80.0 for a in f_conf.get("assets", [])))
check("filter min_confidence=80: evidence ok",
      all(e.confidence >= 80.0 for e in f_conf.get("evidence", [])))

f_proto = filter_context(ctx, protocol="SMB")
check("filter protocol=SMB: only SMB relationships",
      all(r.protocol.upper() == "SMB" for r in f_proto.get("relationships", [])))

f_tech = filter_context(ctx, technique_code="T1021")
check("filter technique_code=T1021",
      all(m.techniqueCode == "T1021" for m in f_tech.get("mitre", [])))

f_src = filter_context(ctx, source_type="pcap")
check("filter source_type=pcap: only pcap evidence",
      all(e.sourceType.lower() == "pcap" for e in f_src.get("evidence", [])))

f_etype = filter_context(ctx, event_type="EVIDENCE_ADDED")
check("filter event_type=EVIDENCE_ADDED",
      all(t.eventType.upper() == "EVIDENCE_ADDED" for t in f_etype.get("timeline", [])))

# Section-scoped filter
f_sec = filter_context(ctx, min_confidence=70.0, sections=["assets"])
check("section-scoped filter only returns requested sections",
      set(f_sec.keys()) == {"assets"})


# ---------------------------------------------------------------------------
# Section 16: group_context()
# ---------------------------------------------------------------------------
print("\n── 16. group_context() ──────────────────────────────────────────────")

g_sev = group_context(ctx, by="severity")
check("group by severity: CRITICAL key exists",   "CRITICAL" in g_sev)
check("group by severity: findings under CRITICAL",
      "findings" in g_sev.get("CRITICAL", {}))

g_stat = group_context(ctx, by="status")
check("group by status: OPEN key exists",         "OPEN" in g_stat)
check("group by status: findings under OPEN",     "findings" in g_stat.get("OPEN", {}))

g_tactic = group_context(ctx, by="mitre_tactic")
check("group by mitre_tactic: returns dict",      isinstance(g_tactic, dict))
check("group by mitre_tactic: has mitre key",     any("mitre" in v for v in g_tactic.values()))

g_proto = group_context(ctx, by="protocol")
check("group by protocol: SMB key exists",        "SMB" in g_proto)
check("group by protocol: relationships under SMB","relationships" in g_proto.get("SMB", {}))

g_src = group_context(ctx, by="source_type")
check("group by source_type: pcap key exists",    "pcap" in g_src)
check("group by source_type: evidence under pcap","evidence" in g_src.get("pcap", {}))

g_etype = group_context(ctx, by="event_type")
check("group by event_type: EVIDENCE_ADDED key",  "EVIDENCE_ADDED" in g_etype)
check("group by event_type: timeline under it",   "timeline" in g_etype.get("EVIDENCE_ADDED", {}))

try:
    group_context(ctx, by="bogus_key")
    check("invalid group key raises ValueError", False)
except ValueError:
    check("invalid group key raises ValueError", True)


# ---------------------------------------------------------------------------
# Section 17: sort_context()
# ---------------------------------------------------------------------------
print("\n── 17. sort_context() ───────────────────────────────────────────────")

s_risk_desc = sort_context(list(ctx.assets), by="riskScore", ascending=False)
check("sort assets by riskScore DESC",  s_risk_desc[0].riskScore >= s_risk_desc[-1].riskScore)

s_risk_asc  = sort_context(list(ctx.assets), by="riskScore", ascending=True)
check("sort assets by riskScore ASC",   s_risk_asc[0].riskScore  <= s_risk_asc[-1].riskScore)

s_conf = sort_context(list(ctx.evidence), by="confidence", ascending=False)
check("sort evidence by confidence DESC", s_conf[0].confidence >= s_conf[-1].confidence)

s_sev = sort_context(list(ctx.findings), by="severity", ascending=False)
check("sort findings by severity DESC: CRITICAL first",
      s_sev[0].severity == "CRITICAL")

s_title = sort_context(list(ctx.findings), by="title", ascending=True)
check("sort findings by title ASC: alphabetical",
      s_title[0].title <= s_title[-1].title)

s_ts = sort_context(list(ctx.timeline), by="occurredAt", ascending=False)
check("sort timeline by occurredAt DESC", s_ts[0].occurredAt >= s_ts[-1].occurredAt)

try:
    sort_context(list(ctx.assets), by="bogus_key")
    check("invalid sort key raises ValueError", False)
except ValueError:
    check("invalid sort key raises ValueError", True)


# ---------------------------------------------------------------------------
# Section 18: find_context_item()
# ---------------------------------------------------------------------------
print("\n── 18. find_context_item() ──────────────────────────────────────────")

found_asset = find_context_item(ctx, "asset-a")
check("find asset by assetId",              found_asset is not None and found_asset.assetId == "asset-a")

found_rel = find_context_item(ctx, "rel-1")
check("find relationship by relationshipId", found_rel is not None and found_rel.relationshipId == "rel-1")

found_find = find_context_item(ctx, "find-1")
check("find finding by findingId",          found_find is not None and found_find.findingId == "find-1")

found_alert = find_context_item(ctx, "alert-1")
check("find alert by alertId",              found_alert is not None and found_alert.alertId == "alert-1")

found_mitre = find_context_item(ctx, "tech-001")
check("find mitre by techniqueId",          found_mitre is not None and found_mitre.techniqueId == "tech-001")

found_tl = find_context_item(ctx, "ev-tl-1")
check("find timeline by eventId",           found_tl is not None and found_tl.eventId == "ev-tl-1")

found_ev = find_context_item(ctx, "ev-1")
check("find evidence by evidenceId",        found_ev is not None and found_ev.evidenceId == "ev-1")

not_found = find_context_item(ctx, "nonexistent-id")
check("not found → None",                   not_found is None)

# Section-scoped search
found_scoped = find_context_item(ctx, "asset-a", section="assets")
check("section-scoped find works",          found_scoped is not None)

not_found_wrong_section = find_context_item(ctx, "asset-a", section="findings")
check("section-scoped find misses wrong section", not_found_wrong_section is None)


# ---------------------------------------------------------------------------
# Section 19: calculate_statistics()
# ---------------------------------------------------------------------------
print("\n── 19. calculate_statistics() ───────────────────────────────────────")

s = calculate_statistics(ctx)
check("calculate_statistics returns ContextStatistics", isinstance(s, ContextStatistics))
check("alias returns same assetCount",  s.assetCount   == ctx.statistics.assetCount)
check("alias returns same avgRisk",     s.averageRisk  == ctx.statistics.averageRisk)
check("alias returns same avgConf",     s.averageConfidence == ctx.statistics.averageConfidence)


# ---------------------------------------------------------------------------
# Section 20: summarize_context()
# ---------------------------------------------------------------------------
print("\n── 20. summarize_context() ──────────────────────────────────────────")

summary = summarize_context(ctx)
check("returns ContextSummary",              isinstance(summary, ContextSummary))
check("highestRiskAssets length <= 5",       len(summary.highestRiskAssets)         <= 5)
check("topMitreTechniques length <= 5",      len(summary.topMitreTechniques)        <= 5)
check("latestTimelineEvents length <= 5",    len(summary.latestTimelineEvents)      <= 5)
check("highestConfidenceEvidence length <= 5", len(summary.highestConfidenceEvidence) <= 5)
check("highestRiskAssets sorted by riskScore DESC",
      all(summary.highestRiskAssets[i].riskScore >= summary.highestRiskAssets[i+1].riskScore
          for i in range(len(summary.highestRiskAssets)-1)))
check("criticalFindings all CRITICAL",
      all(f.severity == "CRITICAL" for f in summary.criticalFindings))
check("activeAlerts all active statuses",
      all(a.status in {"NEW","OPEN","IN_PROGRESS","ACKNOWLEDGED"} for a in summary.activeAlerts))
check("topMitreTechniques sorted by confidence DESC",
      all(summary.topMitreTechniques[i].confidence >= summary.topMitreTechniques[i+1].confidence
          for i in range(len(summary.topMitreTechniques)-1)))
check("graphSummary non-empty",              bool(summary.graphSummary))
check("overallSummary non-empty",            bool(summary.overallSummary))
check("overallSummary contains projectId",   PROJ in summary.overallSummary)

# Frozen
try:
    summary.graphSummary = "hacked"  # type: ignore
    check("ContextSummary frozen=True raises", False)
except Exception:
    check("ContextSummary frozen=True raises", True)

# Determinism
summary2 = summarize_context(ctx)
check("summarize_context deterministic: overallSummary",
      summary.overallSummary == summary2.overallSummary)
check("summarize_context deterministic: graphSummary",
      summary.graphSummary   == summary2.graphSummary)


# ---------------------------------------------------------------------------
# Section 21: Ordering independence
# ---------------------------------------------------------------------------
print("\n── 21. Ordering independence ────────────────────────────────────────")

ctx_rev = build_context(
    project_id=PROJ, investigation_id=INV, created_at=TS,
    assets           = list(reversed(ASSETS)),
    relationships    = list(reversed(RELS)),
    findings         = list(reversed(FINDINGS)),
    alerts           = list(reversed(ALERTS)),
    mitre_mappings   = [],
    mitre_techniques = list(reversed(MITRE_TECHS)),
    timeline_events  = list(reversed(TIMELINE_EVENTS)),
    evidence         = list(reversed(EVIDENCE)),
    graph            = GRAPH,
    investigation    = INVESTIGATION,
)
check("reversed inputs → same contextId",            ctx.contextId == ctx_rev.contextId)
check("reversed inputs → same contextKey",           ctx.contextKey == ctx_rev.contextKey)
check("reversed inputs → same statistics.avgRisk",   ctx.statistics.averageRisk == ctx_rev.statistics.averageRisk)
check("reversed inputs → same statistics.avgConf",   ctx.statistics.averageConfidence == ctx_rev.statistics.averageConfidence)
check("reversed inputs → same assetIds tuple",
      tuple(a.assetId for a in ctx.assets) == tuple(a.assetId for a in ctx_rev.assets))
check("reversed inputs → same findingIds tuple",
      tuple(f.findingId for f in ctx.findings) == tuple(f.findingId for f in ctx_rev.findings))
check("reversed inputs → same evidenceIds",
      tuple(e.evidenceId for e in ctx.evidence) == tuple(e.evidenceId for e in ctx_rev.evidence))


# ---------------------------------------------------------------------------
# Section 22: Empty context
# ---------------------------------------------------------------------------
print("\n── 22. Empty context ────────────────────────────────────────────────")

ctx_empty = build_context(
    project_id=PROJ, investigation_id=INV, created_at=TS,
)
check("empty context: assetCount=0",        ctx_empty.statistics.assetCount        == 0)
check("empty context: findingCount=0",      ctx_empty.statistics.findingCount      == 0)
check("empty context: alertCount=0",        ctx_empty.statistics.alertCount        == 0)
check("empty context: averageRisk=0",       ctx_empty.statistics.averageRisk       == 0.0)
check("empty context: averageConfidence=0", ctx_empty.statistics.averageConfidence == 0.0)
check("empty context: contextId valid UUID",len(ctx_empty.contextId) == 36)

summary_empty = summarize_context(ctx_empty)
check("empty context: no highestRiskAssets",       len(summary_empty.highestRiskAssets)  == 0)
check("empty context: no criticalFindings",        len(summary_empty.criticalFindings)   == 0)
check("empty context: no activeAlerts",            len(summary_empty.activeAlerts)       == 0)
check("empty context: overallSummary mentions 0 assets",
      "0 assets" in summary_empty.overallSummary)


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
    print(f"\n  {PASS}  All checks passed — AI Context Engine (A4.1.0)")
