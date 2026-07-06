"""
AI Copilot Context Engine
==========================
Phase A4.1.0 — Deterministic, immutable context assembly for the AI Copilot.

Responsibilities
----------------
- Project every forensic engine's output (assets, relationships, findings,
  alerts, MITRE mappings, timeline events, evidence, attack graph, investigation)
  into compact, AI-ready context objects.
- Build a single AIContext that contains every section needed for AI reasoning.
- Provide global search, filter, group, sort, and summarise utilities so the
  Copilot never has to re-derive structure from raw data.
- Produce a deterministic contextKey + contextId (SHA-256 + UUIDv5).
- Compute a context fingerprint stable across identical inputs.

Design principles
-----------------
- All models are immutable (frozen=True dataclasses).
- All builder/utility functions return NEW objects; nothing is mutated.
- Fully deterministic: same inputs → same outputs across every run.
- No database, no repository, no API, no HTTP, no AI, no randomness.
- No uuid4(). No random module. No datetime.now() inside ID computation.
- Canonical sorting before every hash and every statistic accumulation.
- Pure business logic only.
- Engine version from core/constants.py — never hardcoded.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from core.constants import AI_COPILOT_CONTEXT_ENGINE_VERSION

# ── UUIDv5 namespace — fixed; changing it invalidates all stored IDs ────────
_CONTEXT_NS = uuid.UUID("6ba7b813-9dad-11d1-80b4-00c04fd430c8")


# ===========================================================================
# Immutable context section models  (frozen=True dataclasses)
# ===========================================================================

@dataclass(frozen=True)
class ContextAsset:
    """Compact AI-ready projection of one asset."""
    assetId     : str
    assetKey    : str
    deviceName  : str
    hostnames   : Tuple[str, ...]
    ipAddresses : Tuple[str, ...]
    macAddresses: Tuple[str, ...]
    riskScore   : float
    confidence  : float
    summary     : str


@dataclass(frozen=True)
class ContextRelationship:
    """Compact AI-ready projection of one relationship."""
    relationshipId  : str
    relationshipKey : str
    relationshipType: str
    protocol        : str
    direction       : str
    confidence      : float
    summary         : str


@dataclass(frozen=True)
class ContextFinding:
    """Compact AI-ready projection of one finding."""
    findingId  : str
    severity   : str
    status     : str
    title      : str
    summary    : str
    riskScore  : float
    confidence : float


@dataclass(frozen=True)
class ContextAlert:
    """Compact AI-ready projection of one alert."""
    alertId    : str
    severity   : str
    status     : str
    title      : str
    summary    : str
    confidence : float


@dataclass(frozen=True)
class ContextMitre:
    """Compact AI-ready projection of one MITRE ATT&CK mapping."""
    techniqueId  : str
    techniqueCode: str
    techniqueName: str
    tacticNames  : Tuple[str, ...]
    confidence   : float
    summary      : str


@dataclass(frozen=True)
class ContextTimeline:
    """Compact AI-ready projection of one timeline event."""
    eventId    : str
    occurredAt : str          # ISO-8601 or ""
    eventType  : str
    summary    : str
    importance : float        # 0–100 mapped from confidence/severity


@dataclass(frozen=True)
class ContextEvidence:
    """Compact AI-ready projection of one evidence record."""
    evidenceId : str
    fieldName  : str
    fieldValue : str
    sourceType : str
    confidence : float
    summary    : str


@dataclass(frozen=True)
class ContextGraph:
    """Compact AI-ready summary of the attack graph."""
    graphFingerprint : str
    nodeCount        : int
    edgeCount        : int
    highestRiskNode  : str    # nodeKey or "" if empty
    summary          : str


@dataclass(frozen=True)
class ContextInvestigation:
    """Compact AI-ready projection of the investigation."""
    investigationId : str
    title           : str
    status          : str
    priority        : str
    summary         : str


@dataclass(frozen=True)
class ContextStatistics:
    """Aggregate counts and averages across all context sections."""
    assetCount        : int
    relationshipCount : int
    findingCount      : int
    alertCount        : int
    mitreCount        : int
    timelineCount     : int
    evidenceCount     : int
    averageRisk       : float
    averageConfidence : float


@dataclass(frozen=True)
class ContextBuildMetadata:
    """Provenance and performance metadata for one context build."""
    buildDurationMs    : int
    builderVersion     : str
    generatedSections  : Tuple[str, ...]    # section names built
    sourceCounts       : Dict[str, int]     # section → raw item count
    warnings           : Tuple[str, ...]


@dataclass(frozen=True)
class AIContext:
    """
    The complete, immutable AI Copilot context for one investigation scope.

    Identity
    --------
    contextId  : UUIDv5(CONTEXT_NS, contextKey) — deterministic
    contextKey : SHA256(projectId + investigationId + graphFingerprint +
                        sorted(findingIds) + sorted(alertIds))[:32]

    Sections (all are sorted tuples for determinism)
    ------------------------------------------------
    assets, relationships, findings, alerts, mitre,
    timeline, evidence, graph, investigation

    Statistics / Metadata
    ---------------------
    statistics    : ContextStatistics — aggregate counts and averages
    buildMetadata : ContextBuildMetadata — provenance + timings
    """
    # ── Identity ─────────────────────────────────────────────────────────
    contextId       : str
    contextKey      : str

    # ── Scope ────────────────────────────────────────────────────────────
    projectId       : str
    investigationId : str

    # ── Sections (tuples for immutability + deterministic order) ─────────
    assets          : Tuple[ContextAsset, ...]
    relationships   : Tuple[ContextRelationship, ...]
    findings        : Tuple[ContextFinding, ...]
    alerts          : Tuple[ContextAlert, ...]
    mitre           : Tuple[ContextMitre, ...]
    timeline        : Tuple[ContextTimeline, ...]
    evidence        : Tuple[ContextEvidence, ...]
    graph           : ContextGraph
    investigation   : ContextInvestigation

    # ── Aggregates ───────────────────────────────────────────────────────
    statistics      : ContextStatistics
    buildMetadata   : ContextBuildMetadata

    # ── Versioning ───────────────────────────────────────────────────────
    engineVersion   : str
    createdAt       : str     # ISO-8601 (caller-supplied)


@dataclass(frozen=True)
class ContextSummary:
    """
    Deterministic high-level summary sent directly to the AI Copilot.

    All fields are derived from the AIContext without any AI inference.
    """
    highestRiskAssets        : Tuple[ContextAsset, ...]        # top 5 by riskScore
    criticalFindings         : Tuple[ContextFinding, ...]      # severity == CRITICAL
    activeAlerts             : Tuple[ContextAlert, ...]        # status in NEW/OPEN/IN_PROGRESS
    topMitreTechniques       : Tuple[ContextMitre, ...]        # top 5 by confidence
    latestTimelineEvents     : Tuple[ContextTimeline, ...]     # 5 most recent
    highestConfidenceEvidence: Tuple[ContextEvidence, ...]     # top 5 by confidence
    graphSummary             : str
    overallSummary           : str


# ===========================================================================
# Deterministic ID helpers
# ===========================================================================

def _compute_context_key(
    project_id       : str,
    investigation_id : str,
    graph_fingerprint: str,
    finding_ids      : Tuple[str, ...],
    alert_ids        : Tuple[str, ...],
) -> str:
    """
    contextKey = SHA256(projectId + investigationId + graphFingerprint +
                        sorted(findingIds) + sorted(alertIds))[:32]

    Components are null-byte-separated; ID lists use \\x01 separator.
    """
    parts = [
        project_id,
        investigation_id,
        graph_fingerprint,
        "\x01".join(sorted(finding_ids)),
        "\x01".join(sorted(alert_ids)),
    ]
    return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()[:32]


def _compute_context_id(context_key: str) -> str:
    """contextId = UUIDv5(CONTEXT_NS, contextKey)."""
    return str(uuid.uuid5(_CONTEXT_NS, context_key))


# ===========================================================================
# Internal normalisation helpers
# ===========================================================================

def _clamp(v: float) -> float:
    return float(max(0.0, min(100.0, v)))


def _norm_strs(items: Optional[List[str]]) -> Tuple[str, ...]:
    if not items:
        return ()
    return tuple(sorted({s.strip() for s in items if s and s.strip()}))


def _get(obj: Any, *keys: str, default: Any = None) -> Any:
    """Duck-typed accessor: works on both Pydantic models and plain dicts."""
    for k in keys:
        v = obj.get(k) if isinstance(obj, dict) else getattr(obj, k, None)
        if v is not None:
            return v
    return default


def _str(val: Any) -> str:
    if val is None:
        return ""
    if hasattr(val, "value"):    # Enum
        return val.value
    return str(val)


def _float(val: Any, default: float = 0.0) -> float:
    try:
        return _clamp(float(val))
    except (TypeError, ValueError):
        return default


def _int(val: Any, default: int = 0) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def _iso(val: Any) -> str:
    if val is None:
        return ""
    if hasattr(val, "isoformat"):
        return val.isoformat()
    return str(val)


# ===========================================================================
# Section builders
# ===========================================================================

def build_asset_context(assets: List[Any]) -> Tuple[ContextAsset, ...]:
    """
    Project asset objects/dicts into ContextAsset items.

    Accepts AssetRecord Pydantic objects or plain dicts.
    Sorted by riskScore DESC, then assetId ASC for determinism.
    """
    result: List[ContextAsset] = []
    for a in assets:
        asset_id = _str(_get(a, "id", "assetId", "asset_id"))
        if not asset_id:
            continue

        hostnames    = _get(a, "hostnames", default=[]) or []
        ips          = _get(a, "ipAddresses", "ip_addresses", "currentIp", default=[]) or []
        macs         = _get(a, "macAddresses", "macAddress", "mac_address", default=[]) or []

        # Accept both list and scalar for IP/MAC
        if isinstance(ips, str):
            ips = [ips]
        if isinstance(macs, str):
            macs = [macs]
        if isinstance(hostnames, str):
            hostnames = [hostnames]

        risk     = _float(_get(a, "riskScore", "risk_score", "currentRiskScore", default=0))
        conf     = _float(_get(a, "confidence", default=0))
        devname  = _str(_get(a, "deviceName", "device_name", "hostname", "deviceType", default=""))
        vendor   = _str(_get(a, "vendor", default=""))
        os_      = _str(_get(a, "os", "operatingSystem", default=""))

        summary = (
            f"Asset {asset_id}: {devname or 'unknown'}"
            + (f" ({vendor})" if vendor else "")
            + (f" — risk={risk:.0f}, conf={conf:.0f}" )
        )

        result.append(ContextAsset(
            assetId      = asset_id,
            assetKey     = _str(_get(a, "assetKey", "asset_key", default=asset_id)),
            deviceName   = devname,
            hostnames    = _norm_strs(list(hostnames)),
            ipAddresses  = _norm_strs(list(ips)),
            macAddresses = _norm_strs(list(macs)),
            riskScore    = risk,
            confidence   = conf,
            summary      = summary,
        ))

    return tuple(sorted(result, key=lambda x: (-x.riskScore, x.assetId)))


def build_relationship_context(relationships: List[Any]) -> Tuple[ContextRelationship, ...]:
    """
    Project relationship objects/dicts into ContextRelationship items.

    Sorted by confidence DESC, then relationshipId ASC.
    """
    result: List[ContextRelationship] = []
    for r in relationships:
        rid   = _str(_get(r, "relationshipId", "id", default=""))
        if not rid:
            continue
        rtype = _str(_get(r, "relationshipType", "relationship_type", default="UNKNOWN"))
        proto = _str(_get(r, "protocol", default="UNKNOWN"))
        src   = _str(_get(r, "sourceAssetId", "source_asset_id", default=""))
        tgt   = _str(_get(r, "targetAssetId", "target_asset_id", default=""))
        direc = _str(_get(r, "direction", default="UNKNOWN"))
        conf  = _float(_get(r, "confidence", default=0))

        summary = f"{src[:16]}→{tgt[:16]} [{proto}] dir={direc} conf={conf:.0f}"

        result.append(ContextRelationship(
            relationshipId   = rid,
            relationshipKey  = _str(_get(r, "relationshipKey", "relationship_key", default=rid)),
            relationshipType = rtype,
            protocol         = proto,
            direction        = direc,
            confidence       = conf,
            summary          = summary,
        ))

    return tuple(sorted(result, key=lambda x: (-x.confidence, x.relationshipId)))


def build_finding_context(findings: List[Any]) -> Tuple[ContextFinding, ...]:
    """
    Project finding objects/dicts into ContextFinding items.

    Sorted by riskScore DESC, then severity DESC, then findingId ASC.
    """
    _SEV_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

    result: List[ContextFinding] = []
    for f in findings:
        fid    = _str(_get(f, "findingId", "finding_id", "id", default=""))
        if not fid:
            continue
        sev    = _str(_get(f, "severity", default="MEDIUM")).upper()
        status = _str(_get(f, "status",   default="OPEN")).upper()
        title  = _str(_get(f, "title",    default=""))
        risk   = _float(_get(f, "riskScore", "risk_score", default=0))
        conf   = _float(_get(f, "confidence", default=0))
        desc   = _str(_get(f, "description", default=""))

        summary = f"[{sev}] {title} — risk={risk:.0f}, status={status}"

        result.append(ContextFinding(
            findingId  = fid,
            severity   = sev,
            status     = status,
            title      = title,
            summary    = summary,
            riskScore  = risk,
            confidence = conf,
        ))

    return tuple(sorted(
        result,
        key=lambda x: (-x.riskScore, -_SEV_ORDER.get(x.severity, 0), x.findingId),
    ))


def build_alert_context(alerts: List[Any]) -> Tuple[ContextAlert, ...]:
    """
    Project alert objects/dicts into ContextAlert items.

    Sorted by severity DESC, confidence DESC, alertId ASC.
    """
    _SEV_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

    result: List[ContextAlert] = []
    for a in alerts:
        aid    = _str(_get(a, "alertId", "alert_id", "id", default=""))
        if not aid:
            continue
        sev    = _str(_get(a, "severity", default="MEDIUM")).upper()
        status = _str(_get(a, "status",   default="NEW")).upper()
        title  = _str(_get(a, "title",    default=""))
        conf   = _float(_get(a, "confidence", default=0))

        summary = f"[{sev}] {title} — status={status}, conf={conf:.0f}"

        result.append(ContextAlert(
            alertId    = aid,
            severity   = sev,
            status     = status,
            title      = title,
            summary    = summary,
            confidence = conf,
        ))

    return tuple(sorted(
        result,
        key=lambda x: (-_SEV_ORDER.get(x.severity, 0), -x.confidence, x.alertId),
    ))


def build_mitre_context(
    mappings   : List[Any],
    techniques : Optional[List[Any]] = None,
) -> Tuple[ContextMitre, ...]:
    """
    Project MITRE mapping/technique objects/dicts into ContextMitre items.

    Accepts two modes:
    1. mappings list populated → each mapping's techniqueIds are expanded
       using the techniques lookup table for names.
    2. mappings empty, techniques provided → techniques are projected directly
       (useful when building context from a technique catalogue only).

    Sorted by confidence DESC, techniqueCode ASC.
    """
    # Build technique lookup index
    tech_index: Dict[str, Any] = {}
    if techniques:
        for t in techniques:
            tid   = _str(_get(t, "techniqueId", "technique_id", "id", default=""))
            tcode = _str(_get(t, "techniqueCode", "technique_code", "code", default=""))
            if tid:
                tech_index[tid] = t
            if tcode:
                tech_index[tcode] = t

    # If no mappings provided, project techniques directly
    if not mappings and techniques:
        result: List[ContextMitre] = []
        for t in techniques:
            tid   = _str(_get(t, "techniqueId", "technique_id", "id", default=""))
            tcode = _str(_get(t, "techniqueCode", "technique_code", "code", default=""))
            tname = _str(_get(t, "name", "techniqueName", default=tcode))
            conf  = _float(_get(t, "confidence", default=0))
            tactic_ids   = _get(t, "tacticIds", "tactic_ids", default=[]) or []
            tactic_names = tuple(sorted(str(x) for x in tactic_ids if x))
            summary = f"{tcode} — {tname} (conf={conf:.0f})"
            if tcode or tid:
                result.append(ContextMitre(
                    techniqueId   = tid or tcode,
                    techniqueCode = tcode,
                    techniqueName = tname,
                    tacticNames   = tactic_names,
                    confidence    = conf,
                    summary       = summary,
                ))
        deduped: Dict[str, ContextMitre] = {}
        for item in result:
            existing = deduped.get(item.techniqueId)
            if existing is None or item.confidence > existing.confidence:
                deduped[item.techniqueId] = item
        return tuple(sorted(deduped.values(), key=lambda x: (-x.confidence, x.techniqueCode)))

    result2: List[ContextMitre] = []
    for m in mappings:
        tech_ids = _get(m, "techniqueIds", "technique_ids", default=[]) or []
        conf     = _float(_get(m, "confidence", default=0))

        # If the object itself looks like a technique (has techniqueCode)
        tech_code = _str(_get(m, "techniqueCode", "technique_code", "code", default=""))
        if tech_code:
            tech_id      = _str(_get(m, "techniqueId", "technique_id", "id", default=""))
            tech_name    = _str(_get(m, "name", "techniqueName", default=tech_code))
            tactic_ids   = _get(m, "tacticIds", "tactic_ids", default=[]) or []
            tactic_names = tuple(sorted(str(x) for x in tactic_ids if x))
            summary = f"{tech_code} — {tech_name} (conf={conf:.0f})"
            result2.append(ContextMitre(
                techniqueId   = tech_id or tech_code,
                techniqueCode = tech_code,
                techniqueName = tech_name,
                tacticNames   = tactic_names,
                confidence    = conf,
                summary       = summary,
            ))
            continue

        for tid in tech_ids:
            tid_str      = _str(tid)
            tech         = tech_index.get(tid_str)
            tcode        = _str(_get(tech, "techniqueCode", "technique_code", default=tid_str)) if tech else tid_str
            tname        = _str(_get(tech, "name", "techniqueName", default=tcode)) if tech else tcode
            tactic_ids   = _get(tech, "tacticIds", "tactic_ids", default=[]) or [] if tech else []
            tactic_names = tuple(sorted(str(x) for x in tactic_ids if x))
            summary = f"{tcode} — {tname} (conf={conf:.0f})"
            result2.append(ContextMitre(
                techniqueId   = tid_str,
                techniqueCode = tcode,
                techniqueName = tname,
                tacticNames   = tactic_names,
                confidence    = conf,
                summary       = summary,
            ))

    # Deduplicate by techniqueId, keep highest confidence
    deduped2: Dict[str, ContextMitre] = {}
    for item in result2:
        existing = deduped2.get(item.techniqueId)
        if existing is None or item.confidence > existing.confidence:
            deduped2[item.techniqueId] = item

    return tuple(sorted(deduped2.values(), key=lambda x: (-x.confidence, x.techniqueCode)))


def build_timeline_context(events: List[Any]) -> Tuple[ContextTimeline, ...]:
    """
    Project timeline event objects/dicts into ContextTimeline items.

    Sorted by occurredAt DESC (most recent first), then eventId ASC.
    """
    _SEV_IMPORTANCE = {"CRITICAL": 100, "HIGH": 80, "MEDIUM": 60, "LOW": 40, "INFO": 20}

    result: List[ContextTimeline] = []
    for ev in events:
        eid       = _str(_get(ev, "eventId", "event_id", "id", default=""))
        if not eid:
            continue
        etype     = _str(_get(ev, "eventType", "event_type", default="UNKNOWN"))
        occurred  = _get(ev, "occurredAt", "occurred_at")
        summary   = _str(_get(ev, "summary", default=""))
        sev       = _str(_get(ev, "severity", default="INFO")).upper()
        conf      = _float(_get(ev, "confidence", default=0))
        importance = _SEV_IMPORTANCE.get(sev, 20) * (conf / 100.0) if conf > 0 else _SEV_IMPORTANCE.get(sev, 20)

        result.append(ContextTimeline(
            eventId    = eid,
            occurredAt = _iso(occurred),
            eventType  = etype,
            summary    = summary,
            importance = _clamp(importance),
        ))

    # Sort: occurredAt DESC (empty last), then eventId ASC
    def _sort_key(x: ContextTimeline) -> tuple:
        ts = x.occurredAt if x.occurredAt else ""
        return (ts, x.eventId)

    return tuple(sorted(result, key=_sort_key, reverse=True))


def build_evidence_context(evidence: List[Any]) -> Tuple[ContextEvidence, ...]:
    """
    Project evidence record objects/dicts into ContextEvidence items.

    Sorted by confidence DESC, then evidenceId ASC.
    """
    result: List[ContextEvidence] = []
    for ev in evidence:
        eid    = _str(_get(ev, "evidenceId", "evidence_id", "id", default=""))
        if not eid:
            continue
        field  = _str(_get(ev, "fieldName",  "field_name",  default=""))
        value  = _str(_get(ev, "fieldValue", "field_value", default=""))
        conf   = _float(_get(ev, "confidence", default=0))

        # Navigate nested source object
        src_obj    = _get(ev, "source")
        if src_obj is not None:
            src_type = _str(_get(src_obj, "sourceType", "source_type", default="unknown"))
        else:
            src_type = _str(_get(ev, "sourceType", "source_type", default="unknown"))

        summary = f"{field}={value!r} [{src_type}] conf={conf:.0f}"

        result.append(ContextEvidence(
            evidenceId = eid,
            fieldName  = field,
            fieldValue = value,
            sourceType = src_type,
            confidence = conf,
            summary    = summary,
        ))

    return tuple(sorted(result, key=lambda x: (-x.confidence, x.evidenceId)))


def build_graph_context(graph: Any) -> ContextGraph:
    """
    Project an attack graph object/dict into a ContextGraph.

    Accepts AttackGraph Pydantic objects or plain dicts.
    """
    if graph is None:
        return ContextGraph(
            graphFingerprint = "0" * 32,
            nodeCount        = 0,
            edgeCount        = 0,
            highestRiskNode  = "",
            summary          = "No attack graph available.",
        )

    fp         = _str(_get(graph, "graphFingerprint", "graph_fingerprint", default="0" * 32))
    nodes      = _get(graph, "nodes", default=[]) or []
    edges      = _get(graph, "edges", default=[]) or []
    node_count = _int(_get(graph, "statistics.totalNodes", default=0)) or len(nodes)
    edge_count = _int(_get(graph, "statistics.totalEdges", default=0)) or len(edges)

    # Highest risk node from statistics or by scanning nodes
    stats = _get(graph, "statistics")
    hrn   = ""
    if stats is not None:
        hrn = _str(_get(stats, "highestRiskNode", "highest_risk_node", default=""))
    if not hrn and nodes:
        best = max(nodes, key=lambda n: _float(_get(n, "riskScore", "risk_score", default=0)), default=None)
        if best is not None:
            hrn = _str(_get(best, "nodeKey", "node_key", "nodeId", "id", default=""))

    summary = (
        f"Attack graph: {node_count} nodes, {edge_count} edges"
        + (f", highest-risk node: {hrn}" if hrn else "")
        + f" [fp={fp[:8]}…]"
    )

    return ContextGraph(
        graphFingerprint = fp,
        nodeCount        = node_count,
        edgeCount        = edge_count,
        highestRiskNode  = hrn,
        summary          = summary,
    )


def build_investigation_context(investigation: Any) -> ContextInvestigation:
    """
    Project an investigation object/dict into a ContextInvestigation.
    """
    if investigation is None:
        return ContextInvestigation(
            investigationId = "",
            title           = "",
            status          = "",
            priority        = "",
            summary         = "No investigation context available.",
        )

    iid      = _str(_get(investigation, "investigationId", "investigation_id", "id", default=""))
    title    = _str(_get(investigation, "title", default=""))
    status   = _str(_get(investigation, "status", default="")).upper()
    priority = _str(_get(investigation, "priority", default="")).upper()

    summary = f"Investigation '{title}' [{status}] priority={priority}"

    return ContextInvestigation(
        investigationId = iid,
        title           = title,
        status          = status,
        priority        = priority,
        summary         = summary,
    )


# ===========================================================================
# Statistics builder
# ===========================================================================

def build_statistics(
    assets        : Tuple[ContextAsset, ...],
    relationships : Tuple[ContextRelationship, ...],
    findings      : Tuple[ContextFinding, ...],
    alerts        : Tuple[ContextAlert, ...],
    mitre         : Tuple[ContextMitre, ...],
    timeline      : Tuple[ContextTimeline, ...],
    evidence      : Tuple[ContextEvidence, ...],
) -> ContextStatistics:
    """
    Compute ContextStatistics over all context sections.

    Deterministic: canonical sort applied before numeric accumulation so
    floating-point sums are identical across all runs.
    """
    # Canonical sort order for accumulation
    ordered_assets    = sorted(assets,        key=lambda x: x.assetId)
    ordered_findings  = sorted(findings,      key=lambda x: x.findingId)
    ordered_evidence  = sorted(evidence,      key=lambda x: x.evidenceId)
    ordered_rels      = sorted(relationships, key=lambda x: x.relationshipId)

    # Average risk from assets + findings (both carry riskScore)
    risk_values  = [a.riskScore  for a in ordered_assets]   \
                 + [f.riskScore  for f in ordered_findings]
    conf_values  = [a.confidence for a in ordered_assets]   \
                 + [f.confidence for f in ordered_findings]  \
                 + [e.confidence for e in ordered_evidence]  \
                 + [r.confidence for r in ordered_rels]

    avg_risk = round(sum(risk_values) / len(risk_values), 4) if risk_values else 0.0
    avg_conf = round(sum(conf_values) / len(conf_values), 4) if conf_values else 0.0

    return ContextStatistics(
        assetCount        = len(assets),
        relationshipCount = len(relationships),
        findingCount      = len(findings),
        alertCount        = len(alerts),
        mitreCount        = len(mitre),
        timelineCount     = len(timeline),
        evidenceCount     = len(evidence),
        averageRisk       = avg_risk,
        averageConfidence = avg_conf,
    )


# ===========================================================================
# Primary builder: build_context()
# ===========================================================================

def build_context(
    project_id       : str,
    investigation_id : str,
    created_at       : str,
    assets           : Optional[List[Any]] = None,
    relationships    : Optional[List[Any]] = None,
    findings         : Optional[List[Any]] = None,
    alerts           : Optional[List[Any]] = None,
    mitre_mappings   : Optional[List[Any]] = None,
    mitre_techniques : Optional[List[Any]] = None,
    timeline_events  : Optional[List[Any]] = None,
    evidence         : Optional[List[Any]] = None,
    graph            : Optional[Any]       = None,
    investigation    : Optional[Any]       = None,
) -> AIContext:
    """
    Build a complete AIContext from raw forensic data collections.

    All inputs are optional — missing collections behave as empty lists.
    Every section is deterministically sorted and deduplicated.
    contextKey and contextId are derived deterministically from the scope
    and content — no randomness.

    Parameters
    ----------
    project_id       : owning project identifier
    investigation_id : parent investigation identifier
    created_at       : ISO-8601 timestamp (caller-supplied for determinism)
    assets           : AssetRecord objects or asset dicts
    relationships    : Relationship objects or relationship dicts
    findings         : Finding objects or finding dicts
    alerts           : Alert objects or alert dicts
    mitre_mappings   : MitreMapping objects or mapping dicts
    mitre_techniques : MitreTechnique objects or technique dicts
    timeline_events  : TimelineEvent objects or event dicts
    evidence         : EvidenceRecord objects or evidence dicts
    graph            : AttackGraph object or graph dict
    investigation    : Investigation object or investigation dict

    Returns
    -------
    AIContext (frozen)
    """
    t_start = time.monotonic_ns()
    warnings: List[str] = []

    _assets    = list(assets           or [])
    _rels      = list(relationships    or [])
    _findings  = list(findings         or [])
    _alerts    = list(alerts           or [])
    _mappings  = list(mitre_mappings   or [])
    _techs     = list(mitre_techniques or [])
    _timeline  = list(timeline_events  or [])
    _evidence  = list(evidence         or [])

    # Build all sections
    ctx_assets    = build_asset_context(_assets)
    ctx_rels      = build_relationship_context(_rels)
    ctx_findings  = build_finding_context(_findings)
    ctx_alerts    = build_alert_context(_alerts)
    ctx_mitre     = build_mitre_context(_mappings, _techs)
    ctx_timeline  = build_timeline_context(_timeline)
    ctx_evidence  = build_evidence_context(_evidence)
    ctx_graph     = build_graph_context(graph)
    ctx_inv       = build_investigation_context(investigation)

    # Deterministic context key
    finding_ids = tuple(sorted(f.findingId for f in ctx_findings))
    alert_ids   = tuple(sorted(a.alertId   for a in ctx_alerts))
    ctx_key     = _compute_context_key(
        project_id, investigation_id,
        ctx_graph.graphFingerprint,
        finding_ids, alert_ids,
    )
    ctx_id = _compute_context_id(ctx_key)

    stats = build_statistics(
        ctx_assets, ctx_rels, ctx_findings, ctx_alerts,
        ctx_mitre, ctx_timeline, ctx_evidence,
    )

    t_end = time.monotonic_ns()
    build_ms = max(0, round((t_end - t_start) / 1_000_000))

    sections = [
        s for s, items in [
            ("assets",        ctx_assets),
            ("relationships", ctx_rels),
            ("findings",      ctx_findings),
            ("alerts",        ctx_alerts),
            ("mitre",         ctx_mitre),
            ("timeline",      ctx_timeline),
            ("evidence",      ctx_evidence),
        ]
        if items
    ] + (["graph"] if ctx_graph.nodeCount > 0 else []) \
      + (["investigation"] if ctx_inv.investigationId else [])

    metadata = ContextBuildMetadata(
        buildDurationMs   = build_ms,
        builderVersion    = AI_COPILOT_CONTEXT_ENGINE_VERSION,
        generatedSections = tuple(sorted(sections)),
        sourceCounts      = {
            "assets"        : len(_assets),
            "relationships" : len(_rels),
            "findings"      : len(_findings),
            "alerts"        : len(_alerts),
            "mitre_mappings": len(_mappings),
            "timeline"      : len(_timeline),
            "evidence"      : len(_evidence),
        },
        warnings = tuple(warnings),
    )

    return AIContext(
        contextId       = ctx_id,
        contextKey      = ctx_key,
        projectId       = project_id,
        investigationId = investigation_id,
        assets          = ctx_assets,
        relationships   = ctx_rels,
        findings        = ctx_findings,
        alerts          = ctx_alerts,
        mitre           = ctx_mitre,
        timeline        = ctx_timeline,
        evidence        = ctx_evidence,
        graph           = ctx_graph,
        investigation   = ctx_inv,
        statistics      = stats,
        buildMetadata   = metadata,
        engineVersion   = AI_COPILOT_CONTEXT_ENGINE_VERSION,
        createdAt       = created_at,
    )


# ===========================================================================
# Utility: sort_context()
# ===========================================================================

_SORT_VALID = frozenset({
    "riskScore", "confidence", "severity", "occurredAt", "title",
})

_SEVERITY_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


def sort_context(
    items    : List[Any],
    by       : str  = "riskScore",
    ascending: bool = False,
) -> List[Any]:
    """
    Sort a homogeneous list of context items by a named field.

    Works on any context dataclass that has the requested field.
    Tie-breaking is always by the item's primary ID field ASC.

    Parameters
    ----------
    items     : list of ContextAsset / ContextFinding / ContextAlert / etc.
    by        : "riskScore" | "confidence" | "severity" | "occurredAt" | "title"
    ascending : False = highest first (default)

    Raises ValueError for unknown sort key.
    """
    if by not in _SORT_VALID:
        raise ValueError(
            f"sort_context: unknown key '{by}'. Valid: {sorted(_SORT_VALID)}"
        )

    def _id(item: Any) -> str:
        for attr in ("assetId", "findingId", "alertId", "eventId",
                     "evidenceId", "relationshipId", "techniqueId", "investigationId"):
            v = getattr(item, attr, None)
            if v is not None:
                return v
        return ""

    def _key(item: Any) -> tuple:
        raw = getattr(item, by, None)
        if by == "severity":
            primary = _SEVERITY_ORDER.get(str(raw).upper() if raw else "", 0)
        elif raw is None:
            primary = ""
        else:
            primary = raw
        return (primary, _id(item))

    return sorted(items, key=_key, reverse=not ascending)


# ===========================================================================
# Utility: filter_context()
# ===========================================================================

def filter_context(
    context          : AIContext,
    min_risk         : Optional[float] = None,
    max_risk         : Optional[float] = None,
    min_confidence   : Optional[float] = None,
    severity         : Optional[str]   = None,
    status           : Optional[str]   = None,
    finding_status   : Optional[str]   = None,
    alert_status     : Optional[str]   = None,
    technique_code   : Optional[str]   = None,
    protocol         : Optional[str]   = None,
    source_type      : Optional[str]   = None,
    event_type       : Optional[str]   = None,
    sections         : Optional[List[str]] = None,
) -> Dict[str, List[Any]]:
    """
    Filter context sections and return a dict of matching items per section.

    Parameters
    ----------
    context        : source AIContext
    min_risk       : minimum riskScore (applies to assets + findings)
    max_risk       : maximum riskScore
    min_confidence : minimum confidence (all sections)
    severity       : exact severity string (findings + alerts)
    status         : generic status filter (findings + alerts)
    finding_status : status filter applied only to findings
    alert_status   : status filter applied only to alerts
    technique_code : filter mitre items by techniqueCode (exact, uppercase)
    protocol       : filter relationships by protocol (uppercase)
    source_type    : filter evidence by sourceType
    event_type     : filter timeline by eventType
    sections       : limit to these section names (default: all)

    Returns
    -------
    Dict[str, List[Any]] — section name → matching items list
    """
    all_sections = {"assets", "relationships", "findings", "alerts",
                    "mitre", "timeline", "evidence"}
    target = set(sections) & all_sections if sections else all_sections

    norm_sev  = severity.upper()       if severity       else None
    norm_tech = technique_code.upper() if technique_code else None
    norm_proto= protocol.upper()       if protocol       else None
    norm_src  = source_type.lower()    if source_type    else None
    norm_etype= event_type.upper()     if event_type     else None
    norm_fstat= finding_status.upper() if finding_status else (status.upper() if status else None)
    norm_astat= alert_status.upper()   if alert_status   else (status.upper() if status else None)

    result: Dict[str, List[Any]] = {}

    if "assets" in target:
        out = list(context.assets)
        if min_risk        is not None: out = [x for x in out if x.riskScore  >= min_risk]
        if max_risk        is not None: out = [x for x in out if x.riskScore  <= max_risk]
        if min_confidence  is not None: out = [x for x in out if x.confidence >= min_confidence]
        result["assets"] = out

    if "relationships" in target:
        out = list(context.relationships)
        if min_confidence  is not None: out = [x for x in out if x.confidence >= min_confidence]
        if norm_proto      is not None: out = [x for x in out if x.protocol.upper() == norm_proto]
        result["relationships"] = out

    if "findings" in target:
        out = list(context.findings)
        if min_risk        is not None: out = [x for x in out if x.riskScore  >= min_risk]
        if max_risk        is not None: out = [x for x in out if x.riskScore  <= max_risk]
        if min_confidence  is not None: out = [x for x in out if x.confidence >= min_confidence]
        if norm_sev        is not None: out = [x for x in out if x.severity   == norm_sev]
        if norm_fstat      is not None: out = [x for x in out if x.status     == norm_fstat]
        result["findings"] = out

    if "alerts" in target:
        out = list(context.alerts)
        if min_confidence  is not None: out = [x for x in out if x.confidence >= min_confidence]
        if norm_sev        is not None: out = [x for x in out if x.severity   == norm_sev]
        if norm_astat      is not None: out = [x for x in out if x.status     == norm_astat]
        result["alerts"] = out

    if "mitre" in target:
        out = list(context.mitre)
        if min_confidence  is not None: out = [x for x in out if x.confidence >= min_confidence]
        if norm_tech       is not None: out = [x for x in out if x.techniqueCode.upper() == norm_tech]
        result["mitre"] = out

    if "timeline" in target:
        out = list(context.timeline)
        if norm_etype      is not None: out = [x for x in out if x.eventType.upper() == norm_etype]
        result["timeline"] = out

    if "evidence" in target:
        out = list(context.evidence)
        if min_confidence  is not None: out = [x for x in out if x.confidence >= min_confidence]
        if norm_src        is not None: out = [x for x in out if x.sourceType.lower() == norm_src]
        result["evidence"] = out

    return result


# ===========================================================================
# Utility: search_context()
# ===========================================================================

def search_context(context: AIContext, query: str) -> Dict[str, List[Any]]:
    """
    Global case-insensitive substring search across ALL context sections.

    Searched fields per section
    ----------------------------
    assets        : deviceName, hostnames, ipAddresses, macAddresses, summary
    relationships : summary, protocol, relationshipType
    findings      : title, summary
    alerts        : title, summary
    mitre         : techniqueCode, techniqueName, tacticNames, summary
    timeline      : summary, eventType
    evidence      : fieldName, fieldValue, summary

    Parameters
    ----------
    query : search string (stripped + lowercased internally)

    Returns
    -------
    Dict[str, List[Any]] — section name → matching items list (order preserved)
    Empty list for empty query.
    """
    q = query.strip().lower()
    if not q:
        return {s: [] for s in ("assets", "relationships", "findings",
                                 "alerts", "mitre", "timeline", "evidence")}

    def _match(*fields: str) -> bool:
        return any(q in f.lower() for f in fields if f)

    def _join(items: Tuple[str, ...]) -> str:
        return " ".join(items)

    return {
        "assets": [
            a for a in context.assets
            if _match(a.deviceName, a.summary,
                      _join(a.hostnames), _join(a.ipAddresses), _join(a.macAddresses))
        ],
        "relationships": [
            r for r in context.relationships
            if _match(r.summary, r.protocol, r.relationshipType)
        ],
        "findings": [
            f for f in context.findings
            if _match(f.title, f.summary)
        ],
        "alerts": [
            a for a in context.alerts
            if _match(a.title, a.summary)
        ],
        "mitre": [
            m for m in context.mitre
            if _match(m.techniqueCode, m.techniqueName, m.summary, _join(m.tacticNames))
        ],
        "timeline": [
            t for t in context.timeline
            if _match(t.summary, t.eventType)
        ],
        "evidence": [
            e for e in context.evidence
            if _match(e.fieldName, e.fieldValue, e.summary)
        ],
    }


# ===========================================================================
# Utility: group_context()
# ===========================================================================

def group_context(
    context : AIContext,
    by      : str = "severity",
) -> Dict[str, Dict[str, List[Any]]]:
    """
    Group context sections by a named dimension.

    Parameters
    ----------
    by : "severity"          — group findings + alerts by severity
         "status"            — group findings + alerts by status
         "mitre_tactic"      — group mitre items by first tacticName
         "protocol"          — group relationships by protocol
         "source_type"       — group evidence by sourceType
         "event_type"        — group timeline events by eventType

    Returns
    -------
    Dict[str, Dict[str, List[Any]]] — dimension value → section → items
    Raises ValueError for unknown *by* values.
    """
    valid = {"severity", "status", "mitre_tactic", "protocol", "source_type", "event_type"}
    if by not in valid:
        raise ValueError(f"group_context: unknown key '{by}'. Valid: {sorted(valid)}")

    groups: Dict[str, Dict[str, List[Any]]] = {}

    def _add(group_key: str, section: str, item: Any) -> None:
        groups.setdefault(group_key, {}).setdefault(section, []).append(item)

    if by == "severity":
        for f in context.findings:
            _add(f.severity, "findings", f)
        for a in context.alerts:
            _add(a.severity, "alerts", a)

    elif by == "status":
        for f in context.findings:
            _add(f.status, "findings", f)
        for a in context.alerts:
            _add(a.status, "alerts", a)

    elif by == "mitre_tactic":
        for m in context.mitre:
            key = m.tacticNames[0] if m.tacticNames else "unassigned"
            _add(key, "mitre", m)

    elif by == "protocol":
        for r in context.relationships:
            _add(r.protocol.upper(), "relationships", r)

    elif by == "source_type":
        for e in context.evidence:
            _add(e.sourceType.lower(), "evidence", e)

    elif by == "event_type":
        for t in context.timeline:
            _add(t.eventType.upper(), "timeline", t)

    return groups


# ===========================================================================
# Utility: find_context_item()
# ===========================================================================

def find_context_item(
    context : AIContext,
    item_id : str,
    section : Optional[str] = None,
) -> Optional[Any]:
    """
    Find a single context item by its primary ID across all (or one) section.

    Searches by the primary ID field of each section:
    assets → assetId, relationships → relationshipId, findings → findingId,
    alerts → alertId, mitre → techniqueId, timeline → eventId,
    evidence → evidenceId.

    Parameters
    ----------
    context : source AIContext
    item_id : the ID string to match
    section : optional section name to limit search scope

    Returns
    -------
    The first matching context item, or None if not found.
    """
    needle = item_id.strip()
    sections_to_search = {
        "assets"        : (context.assets,        "assetId"),
        "relationships" : (context.relationships,  "relationshipId"),
        "findings"      : (context.findings,       "findingId"),
        "alerts"        : (context.alerts,         "alertId"),
        "mitre"         : (context.mitre,          "techniqueId"),
        "timeline"      : (context.timeline,       "eventId"),
        "evidence"      : (context.evidence,       "evidenceId"),
    }

    for sec_name, (items, id_field) in sections_to_search.items():
        if section is not None and sec_name != section:
            continue
        for item in items:
            if getattr(item, id_field, None) == needle:
                return item
    return None


# ===========================================================================
# Utility: calculate_statistics() — public alias
# ===========================================================================

def calculate_statistics(context: AIContext) -> ContextStatistics:
    """
    Return the pre-computed statistics from an existing AIContext.

    If you need to recompute from scratch (e.g. after filtering), call
    build_statistics() directly with the filtered section tuples.
    """
    return context.statistics


# ===========================================================================
# Utility: summarize_context()
# ===========================================================================

_ACTIVE_ALERT_STATUSES = frozenset({"NEW", "OPEN", "IN_PROGRESS", "ACKNOWLEDGED"})


def summarize_context(context: AIContext) -> ContextSummary:
    """
    Produce a deterministic ContextSummary from an AIContext.

    All selections are deterministic:
    - highestRiskAssets        : top 5 by riskScore DESC, assetId ASC
    - criticalFindings         : severity == CRITICAL, sorted riskScore DESC
    - activeAlerts             : status in NEW/OPEN/IN_PROGRESS/ACKNOWLEDGED,
                                 sorted severity DESC, confidence DESC
    - topMitreTechniques       : top 5 by confidence DESC, techniqueCode ASC
    - latestTimelineEvents     : top 5 by occurredAt DESC, eventId ASC
    - highestConfidenceEvidence: top 5 by confidence DESC, evidenceId ASC
    - graphSummary             : context.graph.summary
    - overallSummary           : one-sentence deterministic summary

    Returns
    -------
    ContextSummary (frozen)
    """
    top_assets = tuple(
        sorted(context.assets, key=lambda a: (-a.riskScore, a.assetId))[:5]
    )

    critical_findings = tuple(
        sorted(
            [f for f in context.findings if f.severity == "CRITICAL"],
            key=lambda f: (-f.riskScore, f.findingId),
        )
    )

    active_alerts = tuple(
        sorted(
            [a for a in context.alerts if a.status in _ACTIVE_ALERT_STATUSES],
            key=lambda a: (-_SEVERITY_ORDER.get(a.severity, 0), -a.confidence, a.alertId),
        )
    )

    top_mitre = tuple(
        sorted(context.mitre, key=lambda m: (-m.confidence, m.techniqueCode))[:5]
    )

    latest_timeline = tuple(
        sorted(context.timeline, key=lambda t: (t.occurredAt, t.eventId), reverse=True)[:5]
    )

    top_evidence = tuple(
        sorted(context.evidence, key=lambda e: (-e.confidence, e.evidenceId))[:5]
    )

    stats = context.statistics
    overall = (
        f"Project {context.projectId} investigation context: "
        f"{stats.assetCount} assets, "
        f"{stats.findingCount} findings ({len(critical_findings)} critical), "
        f"{stats.alertCount} alerts ({len(active_alerts)} active), "
        f"{stats.mitreCount} MITRE techniques, "
        f"avg risk={stats.averageRisk:.1f}, "
        f"avg confidence={stats.averageConfidence:.1f}."
    )

    return ContextSummary(
        highestRiskAssets         = top_assets,
        criticalFindings          = critical_findings,
        activeAlerts              = active_alerts,
        topMitreTechniques        = top_mitre,
        latestTimelineEvents      = latest_timeline,
        highestConfidenceEvidence = top_evidence,
        graphSummary              = context.graph.summary,
        overallSummary            = overall,
    )


# ===========================================================================
# Extension points
# ===========================================================================

def _hook_on_context_built(context: AIContext) -> None:
    """
    Extension point → AI Copilot / SOC Dashboard.
    Called after build_context() produces a new AIContext.
    May trigger: AI triage pass, dashboard push, alert routing.
    """
    # TODO (future phase): AI Copilot integration


def _hook_on_context_summarized(summary: ContextSummary) -> None:
    """
    Extension point → Report Engine.
    Called after summarize_context().
    May trigger: executive summary generation, auto-report section.
    """
    # TODO (future phase): Report Engine integration
