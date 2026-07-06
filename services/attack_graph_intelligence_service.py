"""
Attack Graph Intelligence Engine
==================================
Phase A4.0.4 — Pure reasoning layer over an existing AttackGraph.

Responsibilities
----------------
- Detect attack patterns (beaconing, C2, lateral movement, etc.).
- Build attack chains from related node clusters.
- Calculate blast radius from any source node.
- Identify critical assets by centrality, risk, and degree.
- Detect lateral movement, pivot nodes, and choke points.
- Correlate MITRE ATT&CK techniques to graph evidence.
- Rank attack paths by risk, confidence, and evidence.
- Generate deterministic, rule-based recommendations.
- Produce reasoning traces for every finding.
- Compute deterministic chain fingerprints (SHA-256, 32-char hex).

Design constraints (FREEZE BOUNDARY — A4.0.4)
----------------------------------------------
- PURE: no Prisma, no repository, no FastAPI, no database, no HTTP, no filesystem.
- Immutable output: every model uses frozen=True.
- Deterministic: same graph → same result always.
- No side effects. No global mutable state. No circular imports.
- Never mutate AttackGraph, AttackGraphNode, or AttackGraphEdge.
- No LLM calls — all recommendations are rule-based.

Dependency graph
----------------
  core.constants                               (ATTACK_GRAPH_INTELLIGENCE_ENGINE_VERSION)
  services.attack_graph_service                (AttackGraph, node/edge models, enums)
  services.attack_graph_query_service          (breadth_first_search, connected_components)
  pydantic, typing, hashlib, collections, time
  ← services.attack_graph_intelligence_service  (this file)
"""

from __future__ import annotations

import hashlib
import time
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, Sequence, Tuple

from pydantic import BaseModel, Field

from core.constants import ATTACK_GRAPH_INTELLIGENCE_ENGINE_VERSION
from services.attack_graph_service import (
    AttackGraph,
    AttackGraphEdge,
    AttackGraphNode,
    GraphEdgeTypeEnum,
    GraphNodeTypeEnum,
)
from services.attack_graph_query_service import (
    breadth_first_search,
    connected_components,
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _now_ms() -> int:
    """Current monotonic time in milliseconds."""
    return round(time.monotonic_ns() / 1_000_000)


def _sha256_32(*parts: str) -> str:
    """Return first 32 hex chars of SHA-256 over '|'-joined parts."""
    raw = "|".join(str(p) for p in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _chain_fingerprint(ordered_node_keys: List[str], ordered_edge_keys: List[str]) -> str:
    """
    Compute a deterministic 32-char chain fingerprint.

    Algorithm: ordered nodeKeys joined by '>' + '|' + ordered edgeKeys joined by '>'.
    SHA-256 hash, first 32 hex chars.

    Same ordered sequence always → same fingerprint.
    Enables caching, comparison, forensic replay, and chain diff detection.
    """
    if not ordered_node_keys and not ordered_edge_keys:
        return "0" * 32
    raw = ">".join(ordered_node_keys) + "|" + ">".join(ordered_edge_keys)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _build_adjacency_maps(
    graph: AttackGraph,
) -> Tuple[
    Dict[str, AttackGraphNode],
    Dict[str, List[AttackGraphEdge]],
    Dict[str, List[AttackGraphEdge]],
    Dict[str, AttackGraphEdge],
]:
    """
    Build O(n+m) lookup structures.

    Returns: node_index, out_edges, in_edges, edge_index
    """
    node_index: Dict[str, AttackGraphNode] = {}
    out_edges: Dict[str, List[AttackGraphEdge]] = defaultdict(list)
    in_edges: Dict[str, List[AttackGraphEdge]] = defaultdict(list)
    edge_index: Dict[str, AttackGraphEdge] = {}

    for node in graph.nodes:
        node_index[node.nodeKey] = node
    for edge in graph.edges:
        edge_index[edge.edgeKey] = edge
        out_edges[edge.sourceNodeId].append(edge)
        in_edges[edge.targetNodeId].append(edge)

    return node_index, out_edges, in_edges, edge_index


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

from enum import Enum


class PatternTypeEnum(str, Enum):
    BEACONING             = "BEACONING"
    COMMAND_AND_CONTROL   = "COMMAND_AND_CONTROL"
    MALWARE_DOWNLOAD      = "MALWARE_DOWNLOAD"
    CREDENTIAL_ACCESS     = "CREDENTIAL_ACCESS"
    LATERAL_MOVEMENT      = "LATERAL_MOVEMENT"
    DATA_EXFILTRATION     = "DATA_EXFILTRATION"
    INTERNAL_RECON        = "INTERNAL_RECON"
    UNKNOWN               = "UNKNOWN"


class SeverityEnum(str, Enum):
    CRITICAL  = "CRITICAL"
    HIGH      = "HIGH"
    MEDIUM    = "MEDIUM"
    LOW       = "LOW"
    INFO      = "INFO"


class AttackStageEnum(str, Enum):
    RECONNAISSANCE    = "RECONNAISSANCE"
    INITIAL_ACCESS    = "INITIAL_ACCESS"
    EXECUTION         = "EXECUTION"
    PERSISTENCE       = "PERSISTENCE"
    PRIVILEGE_ESC     = "PRIVILEGE_ESCALATION"
    DEFENSE_EVASION   = "DEFENSE_EVASION"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    DISCOVERY         = "DISCOVERY"
    LATERAL_MOVEMENT  = "LATERAL_MOVEMENT"
    COLLECTION        = "COLLECTION"
    EXFILTRATION      = "EXFILTRATION"
    COMMAND_CONTROL   = "COMMAND_AND_CONTROL"
    IMPACT            = "IMPACT"
    UNKNOWN           = "UNKNOWN"


# ---------------------------------------------------------------------------
# Output Models — all frozen Pydantic models
# ---------------------------------------------------------------------------

class AttackPattern(BaseModel):
    """A detected attack pattern in the graph."""
    patternId       : str
    patternType     : PatternTypeEnum
    title           : str
    description     : str
    involvedNodes   : List[str]           = Field(default_factory=list)  # nodeKeys
    involvedEdges   : List[str]           = Field(default_factory=list)  # edgeKeys
    confidence      : int                 = Field(ge=0, le=100, default=0)
    severity        : SeverityEnum        = SeverityEnum.MEDIUM
    mitreTechniques : List[str]           = Field(default_factory=list)
    evidenceIds     : List[str]           = Field(default_factory=list)
    metadata        : Dict[str, Any]      = Field(default_factory=dict)

    class Config:
        frozen = True


class AttackChain(BaseModel):
    """An ordered sequence of attack stages grouped from related nodes."""
    chainId          : str
    name             : str
    nodes            : List[str]           = Field(default_factory=list)  # ordered nodeKeys
    edges            : List[str]           = Field(default_factory=list)  # ordered edgeKeys
    totalRisk        : int                 = 0
    confidence       : int                 = Field(ge=0, le=100, default=0)
    attackStages     : List[AttackStageEnum] = Field(default_factory=list)
    evidenceIds      : List[str]           = Field(default_factory=list)
    findings         : List[str]           = Field(default_factory=list)
    chainFingerprint : str                 = "0" * 32
    metadata         : Dict[str, Any]      = Field(default_factory=dict)

    class Config:
        frozen = True


class BlastRadius(BaseModel):
    """Reachability impact from a source node."""
    sourceNode         : str               # nodeKey
    reachableNodes     : List[str]         = Field(default_factory=list)  # nodeKeys
    affectedAssets     : List[str]         = Field(default_factory=list)  # nodeKeys of ASSET type
    maximumDepth       : int               = 0
    estimatedImpact    : str               = "NONE"   # NONE / LOW / MEDIUM / HIGH / CRITICAL
    riskScore          : int               = 0

    class Config:
        frozen = True


class CriticalAsset(BaseModel):
    """A high-importance asset ranked by centrality and risk."""
    assetNode            : str    # nodeKey
    degree               : int    = 0
    incomingConnections  : int    = 0
    outgoingConnections  : int    = 0
    riskScore            : int    = 0
    confidence           : int    = Field(ge=0, le=100, default=0)
    importanceScore      : int    = 0   # 0–100 composite score

    class Config:
        frozen = True


class IntelligenceFinding(BaseModel):
    """A high-level intelligence finding with reasoning trace."""
    findingId       : str
    title           : str
    description     : str
    severity        : SeverityEnum        = SeverityEnum.MEDIUM
    confidence      : int                 = Field(ge=0, le=100, default=0)
    relatedNodes    : List[str]           = Field(default_factory=list)  # nodeKeys
    relatedEdges    : List[str]           = Field(default_factory=list)  # edgeKeys
    evidenceIds     : List[str]           = Field(default_factory=list)
    mitreTechniques : List[str]           = Field(default_factory=list)
    recommendation  : str                 = ""
    reasoningTrace  : List[str]           = Field(default_factory=list)
    metadata        : Dict[str, Any]      = Field(default_factory=dict)

    class Config:
        frozen = True


class IntelligenceStatistics(BaseModel):
    """Summary counts of all intelligence outputs."""
    attackChains              : int = 0
    findings                  : int = 0
    criticalAssets            : int = 0
    blastRadiusCalculations   : int = 0
    suspiciousPatterns        : int = 0
    lateralMovements          : int = 0
    pivotsDetected            : int = 0

    class Config:
        frozen = True


class IntelligenceExplanation(BaseModel):
    """Machine-readable explanation of the intelligence pass."""
    reasoningSteps   : List[str]  = Field(default_factory=list)
    algorithmsUsed   : List[str]  = Field(default_factory=list)
    patternsDetected : List[str]  = Field(default_factory=list)
    processingStages : List[str]  = Field(default_factory=list)
    executionTimeMs  : int        = 0

    class Config:
        frozen = True


class AttackGraphIntelligenceResult(BaseModel):
    """Top-level result returned by analyse_graph()."""
    attackChains     : List[AttackChain]         = Field(default_factory=list)
    findings         : List[IntelligenceFinding] = Field(default_factory=list)
    criticalAssets   : List[CriticalAsset]       = Field(default_factory=list)
    blastRadius      : List[BlastRadius]         = Field(default_factory=list)
    statistics       : IntelligenceStatistics    = Field(default_factory=IntelligenceStatistics)
    explanation      : IntelligenceExplanation   = Field(default_factory=IntelligenceExplanation)
    processingTimeMs : int                       = 0
    engineVersion    : str                       = ATTACK_GRAPH_INTELLIGENCE_ENGINE_VERSION

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# MITRE Technique mappings — rule-based, deterministic
# ---------------------------------------------------------------------------

# Pattern type → MITRE ATT&CK techniques
_PATTERN_MITRE: Dict[str, List[str]] = {
    PatternTypeEnum.BEACONING           : ["T1071", "T1071.001", "T1071.004"],
    PatternTypeEnum.COMMAND_AND_CONTROL : ["T1071", "T1095", "T1105", "T1571"],
    PatternTypeEnum.MALWARE_DOWNLOAD    : ["T1105", "T1203", "T1566"],
    PatternTypeEnum.CREDENTIAL_ACCESS   : ["T1078", "T1110", "T1555", "T1003"],
    PatternTypeEnum.LATERAL_MOVEMENT    : ["T1021", "T1550", "T1210", "T1563"],
    PatternTypeEnum.DATA_EXFILTRATION   : ["T1041", "T1048", "T1052", "T1567"],
    PatternTypeEnum.INTERNAL_RECON      : ["T1046", "T1018", "T1083", "T1135"],
}

# Edge types → likely attack stage
_EDGE_STAGE: Dict[str, AttackStageEnum] = {
    GraphEdgeTypeEnum.SCANNED.value           : AttackStageEnum.RECONNAISSANCE,
    GraphEdgeTypeEnum.CONNECTS_TO.value       : AttackStageEnum.INITIAL_ACCESS,
    GraphEdgeTypeEnum.EXPLOITS.value          : AttackStageEnum.EXECUTION,
    GraphEdgeTypeEnum.AUTHENTICATES_TO.value  : AttackStageEnum.CREDENTIAL_ACCESS,
    GraphEdgeTypeEnum.COMMUNICATES_WITH.value : AttackStageEnum.COMMAND_CONTROL,
    GraphEdgeTypeEnum.DOWNLOADS.value         : AttackStageEnum.EXECUTION,
    GraphEdgeTypeEnum.USES.value              : AttackStageEnum.EXECUTION,
    GraphEdgeTypeEnum.HOSTS.value             : AttackStageEnum.PERSISTENCE,
    GraphEdgeTypeEnum.INDICATES.value         : AttackStageEnum.DISCOVERY,
    GraphEdgeTypeEnum.TRIGGERED.value         : AttackStageEnum.IMPACT,
    GraphEdgeTypeEnum.GENERATED.value         : AttackStageEnum.COLLECTION,
    GraphEdgeTypeEnum.OBSERVED_IN.value       : AttackStageEnum.COLLECTION,
    GraphEdgeTypeEnum.RELATED_TO.value        : AttackStageEnum.UNKNOWN,
    GraphEdgeTypeEnum.RESOLVES_TO.value       : AttackStageEnum.COMMAND_CONTROL,
}

# Node type → whether it is an "asset-class" node for blast radius
_ASSET_NODE_TYPES = {
    GraphNodeTypeEnum.ASSET,
    GraphNodeTypeEnum.IP,
    GraphNodeTypeEnum.DOMAIN,
    GraphNodeTypeEnum.SERVICE,
    GraphNodeTypeEnum.EXTERNAL_HOST,
    GraphNodeTypeEnum.USER,
    GraphNodeTypeEnum.PROCESS,
}

# Severity thresholds
_RISK_SEVERITY: List[Tuple[int, SeverityEnum]] = [
    (85, SeverityEnum.CRITICAL),
    (65, SeverityEnum.HIGH),
    (40, SeverityEnum.MEDIUM),
    (15, SeverityEnum.LOW),
    (0,  SeverityEnum.INFO),
]


def _risk_to_severity(risk: int) -> SeverityEnum:
    for threshold, sev in _RISK_SEVERITY:
        if risk >= threshold:
            return sev
    return SeverityEnum.INFO


def _impact_label(reachable_count: int, risk_score: int) -> str:
    if reachable_count == 0:
        return "NONE"
    if risk_score >= 80 or reachable_count >= 10:
        return "CRITICAL"
    if risk_score >= 60 or reachable_count >= 6:
        return "HIGH"
    if risk_score >= 40 or reachable_count >= 3:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# Pattern Detection
# ---------------------------------------------------------------------------

def detect_attack_patterns(graph: AttackGraph) -> List[AttackPattern]:
    """
    Detect well-known attack patterns from the graph topology and node types.

    Patterns detected
    -----------------
    BEACONING           : Asset → COMMUNICATES_WITH → EXTERNAL_HOST/DOMAIN repeatedly
    COMMAND_AND_CONTROL : FINDING/ALERT nodes with C2-related labels + MITRE T1071 nodes
    MALWARE_DOWNLOAD    : DOWNLOADS or CONNECTS_TO edges from ASSET to EXTERNAL_HOST
    CREDENTIAL_ACCESS   : AUTHENTICATES_TO edges + FINDING nodes labelled with cred keywords
    LATERAL_MOVEMENT    : ASSET → COMMUNICATES_WITH → ASSET (internal-to-internal)
    DATA_EXFILTRATION   : High-risk ASSET → outgoing edges to EXTERNAL_HOST
    INTERNAL_RECON      : SCANNED edges between internal ASSET nodes

    Complexity: O(n + m) per pattern; O(7 * (n+m)) overall = O(n+m).

    Parameters
    ----------
    graph : frozen AttackGraph (never mutated).

    Returns
    -------
    List[AttackPattern] — zero or more detected patterns; deterministic order.
    """
    node_index, out_edges, in_edges, _ = _build_adjacency_maps(graph)
    patterns: List[AttackPattern] = []

    # Pre-group nodes by type for O(1) access per group
    by_type: Dict[str, List[AttackGraphNode]] = defaultdict(list)
    for n in graph.nodes:
        by_type[n.nodeType.value].append(n)

    def _collect_evidence_ids(nodes: List[AttackGraphNode]) -> List[str]:
        ids: List[str] = []
        for n in nodes:
            eid = n.metadata.get("evidenceId") or n.metadata.get("assetId")
            if eid:
                ids.append(str(eid))
        return list(dict.fromkeys(ids))  # deduplicate preserving order

    # ── 1. BEACONING ────────────────────────────────────────────────────────
    # Asset nodes with ≥1 COMMUNICATES_WITH edge to an EXTERNAL_HOST/DOMAIN
    beaconing_nodes: List[str] = []
    beaconing_edges: List[str] = []
    for n in by_type.get(GraphNodeTypeEnum.ASSET.value, []):
        for e in out_edges.get(n.nodeKey, []):
            if e.edgeType != GraphEdgeTypeEnum.COMMUNICATES_WITH:
                continue
            tgt = node_index.get(e.targetNodeId)
            if tgt and tgt.nodeType in (
                GraphNodeTypeEnum.EXTERNAL_HOST, GraphNodeTypeEnum.DOMAIN,
                GraphNodeTypeEnum.IP, GraphNodeTypeEnum.URL,
            ):
                beaconing_nodes.append(n.nodeKey)
                beaconing_edges.append(e.edgeKey)

    if beaconing_nodes:
        pid = _sha256_32("pattern", "BEACONING", *sorted(set(beaconing_nodes)))
        patterns.append(AttackPattern(
            patternId=pid,
            patternType=PatternTypeEnum.BEACONING,
            title="Periodic Beacon Detected",
            description=(
                f"{len(set(beaconing_nodes))} internal asset(s) communicating with "
                "external hosts — consistent with beaconing behaviour."
            ),
            involvedNodes=list(dict.fromkeys(beaconing_nodes)),
            involvedEdges=list(dict.fromkeys(beaconing_edges)),
            confidence=min(100, 50 + len(set(beaconing_nodes)) * 5),
            severity=_risk_to_severity(
                max((node_index[k].riskScore for k in set(beaconing_nodes) if k in node_index), default=0)
            ),
            mitreTechniques=_PATTERN_MITRE[PatternTypeEnum.BEACONING],
            evidenceIds=_collect_evidence_ids(
                [node_index[k] for k in list(dict.fromkeys(beaconing_nodes)) if k in node_index]
            ),
            metadata={"uniqueAssets": len(set(beaconing_nodes))},
        ))

    # ── 2. COMMAND AND CONTROL ───────────────────────────────────────────────
    c2_keywords = {"c2", "beacon", "command", "control", "rat", "backdoor", "malware", "trojan"}
    c2_nodes: List[str] = []
    c2_edges: List[str] = []
    for n in graph.nodes:
        label_lc = n.label.lower()
        dn_lc = n.displayName.lower()
        if any(kw in label_lc or kw in dn_lc for kw in c2_keywords):
            c2_nodes.append(n.nodeKey)
    for n in by_type.get(GraphNodeTypeEnum.MITRE.value, []):
        tech = n.metadata.get("techniqueId", "")
        if str(tech).startswith("T1071") or str(tech).startswith("T1095"):
            c2_nodes.append(n.nodeKey)
    for ek in list(dict.fromkeys(c2_nodes)):   # ordered-unique; no set iteration
        for e in out_edges.get(ek, []) + in_edges.get(ek, []):
            c2_edges.append(e.edgeKey)

    if c2_nodes:
        pid = _sha256_32("pattern", "C2", *sorted(set(c2_nodes)))
        patterns.append(AttackPattern(
            patternId=pid,
            patternType=PatternTypeEnum.COMMAND_AND_CONTROL,
            title="Command and Control Activity",
            description=(
                f"{len(set(c2_nodes))} node(s) exhibit C2 indicators "
                "(label keywords, MITRE T1071/T1095)."
            ),
            involvedNodes=list(dict.fromkeys(c2_nodes)),
            involvedEdges=list(dict.fromkeys(c2_edges)),
            confidence=min(100, 55 + len(set(c2_nodes)) * 5),
            severity=SeverityEnum.HIGH,
            mitreTechniques=_PATTERN_MITRE[PatternTypeEnum.COMMAND_AND_CONTROL],
            evidenceIds=_collect_evidence_ids(
                [node_index[k] for k in list(dict.fromkeys(c2_nodes)) if k in node_index]
            ),
            metadata={"c2NodeCount": len(set(c2_nodes))},
        ))

    # ── 3. MALWARE DOWNLOAD ──────────────────────────────────────────────────
    dl_nodes: List[str] = []
    dl_edges: List[str] = []
    for e in graph.edges:
        if e.edgeType in (GraphEdgeTypeEnum.DOWNLOADS, GraphEdgeTypeEnum.CONNECTS_TO):
            src = node_index.get(e.sourceNodeId)
            tgt = node_index.get(e.targetNodeId)
            if src and tgt and src.nodeType == GraphNodeTypeEnum.ASSET and tgt.nodeType in (
                GraphNodeTypeEnum.EXTERNAL_HOST, GraphNodeTypeEnum.URL, GraphNodeTypeEnum.HASH,
            ):
                dl_nodes.extend([src.nodeKey, tgt.nodeKey])
                dl_edges.append(e.edgeKey)

    if dl_nodes:
        pid = _sha256_32("pattern", "DOWNLOAD", *sorted(set(dl_nodes)))
        patterns.append(AttackPattern(
            patternId=pid,
            patternType=PatternTypeEnum.MALWARE_DOWNLOAD,
            title="Malware Download Behaviour",
            description=(
                f"{len(dl_edges)} download/connect edge(s) observed between "
                "internal assets and external hosts or hashes."
            ),
            involvedNodes=list(dict.fromkeys(dl_nodes)),
            involvedEdges=list(dict.fromkeys(dl_edges)),
            confidence=min(100, 60 + len(dl_edges) * 5),
            severity=SeverityEnum.HIGH,
            mitreTechniques=_PATTERN_MITRE[PatternTypeEnum.MALWARE_DOWNLOAD],
            evidenceIds=[
                str(node_index[k].metadata.get("evidenceId", ""))
                for k in list(dict.fromkeys(dl_nodes)) if k in node_index
                and node_index[k].metadata.get("evidenceId")
            ],
            metadata={"downloadEdges": len(dl_edges)},
        ))

    # ── 4. CREDENTIAL ACCESS ─────────────────────────────────────────────────
    cred_keywords = {"credential", "password", "login", "auth", "kerberos", "ntlm", "hash", "lsass"}
    cred_nodes: List[str] = []
    cred_edges: List[str] = []
    for e in graph.edges:
        if e.edgeType == GraphEdgeTypeEnum.AUTHENTICATES_TO:
            cred_edges.append(e.edgeKey)
            cred_nodes.extend([e.sourceNodeId, e.targetNodeId])
    for n in graph.nodes:
        lbl = n.label.lower() + " " + n.displayName.lower()
        if any(kw in lbl for kw in cred_keywords):
            cred_nodes.append(n.nodeKey)

    if cred_nodes:
        pid = _sha256_32("pattern", "CRED", *sorted(set(cred_nodes)))
        patterns.append(AttackPattern(
            patternId=pid,
            patternType=PatternTypeEnum.CREDENTIAL_ACCESS,
            title="Credential Access Detected",
            description=(
                f"{len(set(cred_nodes))} node(s) involved in credential-related activity "
                f"({len(cred_edges)} authentication edge(s))."
            ),
            involvedNodes=list(dict.fromkeys(cred_nodes)),
            involvedEdges=list(dict.fromkeys(cred_edges)),
            confidence=min(100, 50 + len(cred_edges) * 8),
            severity=SeverityEnum.HIGH,
            mitreTechniques=_PATTERN_MITRE[PatternTypeEnum.CREDENTIAL_ACCESS],
            evidenceIds=[],
            metadata={"authEdges": len(cred_edges)},
        ))

    # ── 5. LATERAL MOVEMENT ───────────────────────────────────────────────────
    lat_nodes: List[str] = []
    lat_edges: List[str] = []
    for e in graph.edges:
        if e.edgeType == GraphEdgeTypeEnum.COMMUNICATES_WITH:
            src = node_index.get(e.sourceNodeId)
            tgt = node_index.get(e.targetNodeId)
            if (src and tgt and
                src.nodeType == GraphNodeTypeEnum.ASSET and
                tgt.nodeType == GraphNodeTypeEnum.ASSET):
                lat_nodes.extend([src.nodeKey, tgt.nodeKey])
                lat_edges.append(e.edgeKey)

    if lat_nodes:
        pid = _sha256_32("pattern", "LATERAL", *sorted(set(lat_nodes)))
        patterns.append(AttackPattern(
            patternId=pid,
            patternType=PatternTypeEnum.LATERAL_MOVEMENT,
            title="Lateral Movement Pattern",
            description=(
                f"{len(set(lat_nodes))} asset(s) communicating directly "
                f"with other assets via {len(lat_edges)} internal edge(s)."
            ),
            involvedNodes=list(dict.fromkeys(lat_nodes)),
            involvedEdges=list(dict.fromkeys(lat_edges)),
            confidence=min(100, 45 + len(lat_edges) * 6),
            severity=SeverityEnum.HIGH,
            mitreTechniques=_PATTERN_MITRE[PatternTypeEnum.LATERAL_MOVEMENT],
            evidenceIds=[],
            metadata={"internalEdges": len(lat_edges)},
        ))

    # ── 6. DATA EXFILTRATION ──────────────────────────────────────────────────
    exfil_keywords = {"exfil", "upload", "transfer", "leak", "steal", "dump"}
    exfil_nodes: List[str] = []
    exfil_edges: List[str] = []
    for n in graph.nodes:
        lbl = n.label.lower()
        if any(kw in lbl for kw in exfil_keywords) or (
            n.nodeType == GraphNodeTypeEnum.ASSET and n.riskScore >= 70
        ):
            for e in out_edges.get(n.nodeKey, []):
                tgt = node_index.get(e.targetNodeId)
                if tgt and tgt.nodeType in (
                    GraphNodeTypeEnum.EXTERNAL_HOST, GraphNodeTypeEnum.IP,
                    GraphNodeTypeEnum.DOMAIN, GraphNodeTypeEnum.URL,
                ):
                    exfil_nodes.extend([n.nodeKey, tgt.nodeKey])
                    exfil_edges.append(e.edgeKey)

    if exfil_nodes:
        pid = _sha256_32("pattern", "EXFIL", *sorted(set(exfil_nodes)))
        patterns.append(AttackPattern(
            patternId=pid,
            patternType=PatternTypeEnum.DATA_EXFILTRATION,
            title="Potential Data Exfiltration",
            description=(
                f"{len(set(exfil_nodes))} node(s) showing outbound activity "
                "consistent with data exfiltration."
            ),
            involvedNodes=list(dict.fromkeys(exfil_nodes)),
            involvedEdges=list(dict.fromkeys(exfil_edges)),
            confidence=min(100, 45 + len(exfil_edges) * 7),
            severity=SeverityEnum.CRITICAL,
            mitreTechniques=_PATTERN_MITRE[PatternTypeEnum.DATA_EXFILTRATION],
            evidenceIds=[],
            metadata={"outboundEdges": len(exfil_edges)},
        ))

    # ── 7. INTERNAL RECONNAISSANCE ────────────────────────────────────────────
    recon_nodes: List[str] = []
    recon_edges: List[str] = []
    for e in graph.edges:
        if e.edgeType == GraphEdgeTypeEnum.SCANNED:
            src = node_index.get(e.sourceNodeId)
            tgt = node_index.get(e.targetNodeId)
            if src and tgt:
                recon_nodes.extend([src.nodeKey, tgt.nodeKey])
                recon_edges.append(e.edgeKey)

    # Also flag ASSET nodes with very high out-degree (mass scanning behaviour)
    for n in by_type.get(GraphNodeTypeEnum.ASSET.value, []):
        if len(out_edges.get(n.nodeKey, [])) >= 5:
            recon_nodes.append(n.nodeKey)

    if recon_nodes:
        pid = _sha256_32("pattern", "RECON", *sorted(set(recon_nodes)))
        patterns.append(AttackPattern(
            patternId=pid,
            patternType=PatternTypeEnum.INTERNAL_RECON,
            title="Internal Reconnaissance Activity",
            description=(
                f"{len(set(recon_nodes))} node(s) involved in scanning or "
                "high-fanout behaviour consistent with internal reconnaissance."
            ),
            involvedNodes=list(dict.fromkeys(recon_nodes)),
            involvedEdges=list(dict.fromkeys(recon_edges)),
            confidence=min(100, 40 + len(set(recon_nodes)) * 5),
            severity=SeverityEnum.MEDIUM,
            mitreTechniques=_PATTERN_MITRE[PatternTypeEnum.INTERNAL_RECON],
            evidenceIds=[],
            metadata={"reconNodes": len(set(recon_nodes))},
        ))

    return patterns


# ---------------------------------------------------------------------------
# Attack Chain Detection
# ---------------------------------------------------------------------------

def build_attack_chains(graph: AttackGraph) -> List[AttackChain]:
    """
    Automatically group related nodes into ordered attack chains.

    Algorithm (O(n + m))
    --------------------
    1. Build weakly connected components — each component is a candidate chain.
    2. Within each component, topologically sort nodes using Kahn's algorithm
       (directed BFS) to produce an ordered stage sequence.
    3. If the directed graph has cycles, fall back to risk-score ordering.
    4. Compute totalRisk (sum of node riskScores), confidence (mean edge
       confidence), evidenceIds, attackStages, and chainFingerprint.
    5. Skip trivial single-node isolated chains.

    Parameters
    ----------
    graph : frozen AttackGraph (never mutated).

    Returns
    -------
    List[AttackChain] — sorted by totalRisk DESC.
    """
    node_index, out_edges, in_edges, _ = _build_adjacency_maps(graph)
    components = connected_components(graph)
    chains: List[AttackChain] = []

    for comp_idx, component in enumerate(components):
        if len(component) < 2:
            continue  # skip trivial single-node components

        comp_keys = {n.nodeKey for n in component}

        # ── Topological sort (Kahn's) within this component ──────────────
        in_degree: Dict[str, int] = {k: 0 for k in comp_keys}
        for n in component:
            for e in out_edges.get(n.nodeKey, []):
                if e.targetNodeId in comp_keys:
                    in_degree[e.targetNodeId] = in_degree.get(e.targetNodeId, 0) + 1

        # Sort initial zero-in-degree nodes for deterministic Kahn's traversal
        queue: deque = deque(sorted(k for k in comp_keys if in_degree.get(k, 0) == 0))
        ordered_keys: List[str] = []
        while queue:
            k = queue.popleft()
            ordered_keys.append(k)
            for e in out_edges.get(k, []):
                if e.targetNodeId in comp_keys:
                    in_degree[e.targetNodeId] -= 1
                    if in_degree[e.targetNodeId] == 0:
                        queue.append(e.targetNodeId)

        # Cycle fallback: sort remaining by risk DESC, then key ASC for determinism
        ordered_set = set(ordered_keys)
        remaining = sorted(
            (k for k in comp_keys if k not in ordered_set),
            key=lambda k: (-(node_index[k].riskScore if k in node_index else 0), k),
        )
        ordered_keys.extend(remaining)

        # ── Collect ordered edges ─────────────────────────────────────────
        ordered_edge_keys: List[str] = []
        for k in ordered_keys:
            for e in out_edges.get(k, []):
                if e.targetNodeId in comp_keys:
                    ordered_edge_keys.append(e.edgeKey)

        # ── Metrics ──────────────────────────────────────────────────────
        total_risk = sum(
            node_index[k].riskScore for k in ordered_keys if k in node_index
        )
        edge_confidences = [
            e.confidence
            for e in graph.edges
            if e.edgeKey in set(ordered_edge_keys)
        ]
        avg_confidence = (
            round(sum(edge_confidences) / len(edge_confidences))
            if edge_confidences else 0
        )

        # ── Attack stages from edge types ────────────────────────────────
        stages_seen: List[AttackStageEnum] = []
        stages_set: set = set()
        for k in ordered_keys:
            for e in out_edges.get(k, []):
                if e.targetNodeId in comp_keys:
                    stage = _EDGE_STAGE.get(e.edgeType.value, AttackStageEnum.UNKNOWN)
                    if stage not in stages_set:
                        stages_set.add(stage)
                        stages_seen.append(stage)

        if not stages_seen:
            stages_seen = [AttackStageEnum.UNKNOWN]

        # ── Evidence IDs ──────────────────────────────────────────────────
        evidence_ids: List[str] = []
        for k in ordered_keys:
            n = node_index.get(k)
            if n:
                eid = n.metadata.get("evidenceId")
                if eid:
                    evidence_ids.append(str(eid))
        evidence_ids = list(dict.fromkeys(evidence_ids))

        # ── Findings (FINDING node labels in the chain) ───────────────────
        finding_labels: List[str] = []
        for k in ordered_keys:
            n = node_index.get(k)
            if n and n.nodeType == GraphNodeTypeEnum.FINDING:
                finding_labels.append(n.displayName)

        # ── Fingerprint ───────────────────────────────────────────────────
        fp = _chain_fingerprint(ordered_keys, ordered_edge_keys)

        # ── Chain name (label of highest-risk node) ───────────────────────
        highest_risk_node = max(
            component, key=lambda n: n.riskScore, default=component[0]
        )
        chain_name = f"Chain-{comp_idx+1}: {highest_risk_node.displayName}"

        chains.append(AttackChain(
            chainId=_sha256_32("chain", str(comp_idx), fp),
            name=chain_name,
            nodes=ordered_keys,
            edges=ordered_edge_keys,
            totalRisk=total_risk,
            confidence=avg_confidence,
            attackStages=stages_seen,
            evidenceIds=evidence_ids,
            findings=finding_labels,
            chainFingerprint=fp,
            metadata={
                "componentSize": len(component),
                "cycleDetected": len(remaining) > 0,
            },
        ))

    # Sort by totalRisk DESC, then confidence DESC
    return sorted(chains, key=lambda c: (-c.totalRisk, -c.confidence))


# ---------------------------------------------------------------------------
# Blast Radius
# ---------------------------------------------------------------------------

def calculate_blast_radius(
    graph       : AttackGraph,
    source_key  : str,
    *,
    max_depth   : int = 8,
) -> BlastRadius:
    """
    Calculate the blast radius from a source node.

    Algorithm: directed BFS from source_key (outgoing edges only),
    bounded by max_depth.  O(n + m).

    Parameters
    ----------
    graph      : frozen AttackGraph.
    source_key : nodeKey of the starting node.
    max_depth  : maximum traversal depth (default 8).

    Returns
    -------
    BlastRadius (frozen / immutable).
    """
    traversal = breadth_first_search(
        graph,
        source_key,
        max_depth=max_depth,
        include_incoming=False,
        include_outgoing=True,
    )

    reachable_keys = [
        n.nodeKey for n in traversal.visitedNodes if n.nodeKey != source_key
    ]

    # Affected assets: reachable nodes that are "asset-class"
    node_index, _, _, _ = _build_adjacency_maps(graph)
    affected_asset_keys = [
        k for k in reachable_keys
        if k in node_index and node_index[k].nodeType in _ASSET_NODE_TYPES
    ]

    # Risk score = max risk across reachable nodes
    max_risk = max(
        (node_index[k].riskScore for k in reachable_keys if k in node_index),
        default=0,
    )

    impact = _impact_label(len(affected_asset_keys), max_risk)

    return BlastRadius(
        sourceNode=source_key,
        reachableNodes=reachable_keys,
        affectedAssets=affected_asset_keys,
        maximumDepth=traversal.maxDepthReached,
        estimatedImpact=impact,
        riskScore=max_risk,
    )


# ---------------------------------------------------------------------------
# Critical Asset Detection
# ---------------------------------------------------------------------------

def find_critical_assets(graph: AttackGraph) -> List[CriticalAsset]:
    """
    Rank assets by degree, risk, confidence, and centrality approximation.

    Centrality approximation (O(n + m))
    ------------------------------------
    importanceScore = clamp(
        0.30 * degree_norm +
        0.35 * risk_norm +
        0.20 * conf_norm +
        0.15 * betweenness_approx,   # fraction of shortest 2-hop paths through node
        0, 100
    ) * 100

    Only ASSET, IP, DOMAIN, SERVICE, EXTERNAL_HOST, USER, PROCESS nodes
    are considered.

    Parameters
    ----------
    graph : frozen AttackGraph.

    Returns
    -------
    List[CriticalAsset] sorted by importanceScore DESC.
    """
    node_index, out_edges, in_edges, _ = _build_adjacency_maps(graph)

    candidate_keys = [
        k for k, n in node_index.items()
        if n.nodeType in _ASSET_NODE_TYPES
    ]

    if not candidate_keys:
        return []

    # Build degree maps
    degree_map: Dict[str, int] = {}
    out_deg_map: Dict[str, int] = {}
    in_deg_map: Dict[str, int] = {}
    for k in candidate_keys:
        od = len(out_edges.get(k, []))
        id_ = len(in_edges.get(k, []))
        degree_map[k] = od + id_
        out_deg_map[k] = od
        in_deg_map[k] = id_

    max_degree = max(degree_map.values(), default=1) or 1
    max_risk = max(
        (node_index[k].riskScore for k in candidate_keys), default=1
    ) or 1
    max_conf = max(
        (node_index[k].confidence for k in candidate_keys), default=1
    ) or 1

    # Betweenness approximation: for each node count how many pairs of
    # immediate neighbors are connected THROUGH this node (ratio-based).
    def _betweenness_approx(key: str) -> float:
        """Approximate betweenness as fraction of 1-hop pairs passing through key."""
        neighbors = set()
        for e in out_edges.get(key, []):
            neighbors.add(e.targetNodeId)
        for e in in_edges.get(key, []):
            neighbors.add(e.sourceNodeId)
        if len(neighbors) < 2:
            return 0.0
        # Check how many neighbor pairs are NOT directly connected (must go via key)
        indirect = 0
        nb_list = list(neighbors)
        for i in range(len(nb_list)):
            for j in range(i + 1, len(nb_list)):
                a, b = nb_list[i], nb_list[j]
                # Check if a direct edge exists between a and b
                direct = any(
                    e.targetNodeId == b for e in out_edges.get(a, [])
                ) or any(
                    e.targetNodeId == a for e in out_edges.get(b, [])
                )
                if not direct:
                    indirect += 1
        total_pairs = len(nb_list) * (len(nb_list) - 1) / 2
        return indirect / total_pairs if total_pairs > 0 else 0.0

    assets: List[CriticalAsset] = []
    for k in candidate_keys:
        n = node_index[k]
        deg = degree_map[k]
        deg_norm = deg / max_degree
        risk_norm = n.riskScore / max_risk
        conf_norm = n.confidence / max_conf
        btw = _betweenness_approx(k)

        importance = int(min(100, (
            0.30 * deg_norm +
            0.35 * risk_norm +
            0.20 * conf_norm +
            0.15 * btw
        ) * 100))

        assets.append(CriticalAsset(
            assetNode=k,
            degree=deg,
            incomingConnections=in_deg_map[k],
            outgoingConnections=out_deg_map[k],
            riskScore=n.riskScore,
            confidence=n.confidence,
            importanceScore=importance,
        ))

    return sorted(assets, key=lambda a: (-a.importanceScore, -a.riskScore))


# ---------------------------------------------------------------------------
# Lateral Movement Detection
# ---------------------------------------------------------------------------

def detect_lateral_movement(graph: AttackGraph) -> List[IntelligenceFinding]:
    """
    Identify paths where compromise spreads between internal assets.

    Algorithm (O(n + m))
    --------------------
    Find ASSET → COMMUNICATES_WITH → ASSET chains where the source node
    has riskScore >= 30 (possibly compromised).  Multi-hop chains where each
    hop is an ASSET-to-ASSET edge are grouped into a single finding per
    originating source.

    Parameters
    ----------
    graph : frozen AttackGraph.

    Returns
    -------
    List[IntelligenceFinding] — one finding per lateral movement origin.
    """
    node_index, out_edges, _, _ = _build_adjacency_maps(graph)
    findings: List[IntelligenceFinding] = []

    visited_pairs: set = set()

    for n in graph.nodes:
        if n.nodeType != GraphNodeTypeEnum.ASSET or n.riskScore < 30:
            continue

        # BFS from this asset, following COMMUNICATES_WITH to other assets only
        chain_nodes = [n.nodeKey]
        chain_edges: List[str] = []
        queue: deque = deque([(n.nodeKey, 0)])
        visited_local: set = {n.nodeKey}
        hops_found = 0

        while queue:
            cur_key, depth = queue.popleft()
            if depth >= 6:
                continue
            for e in out_edges.get(cur_key, []):
                if e.edgeType != GraphEdgeTypeEnum.COMMUNICATES_WITH:
                    continue
                tgt = node_index.get(e.targetNodeId)
                if tgt and tgt.nodeType == GraphNodeTypeEnum.ASSET and e.targetNodeId not in visited_local:
                    visited_local.add(e.targetNodeId)
                    chain_nodes.append(e.targetNodeId)
                    chain_edges.append(e.edgeKey)
                    queue.append((e.targetNodeId, depth + 1))
                    hops_found += 1

        if hops_found == 0:
            continue

        pair_key = tuple(sorted(chain_nodes))
        if pair_key in visited_pairs:
            continue
        visited_pairs.add(pair_key)

        confidence = min(100, 50 + hops_found * 10)
        severity = _risk_to_severity(n.riskScore + hops_found * 5)

        trace = [
            f"Source asset '{n.displayName}' has riskScore={n.riskScore} (>= 30).",
            f"Found {hops_found} COMMUNICATES_WITH hop(s) to other internal assets.",
            f"Chain: {' → '.join(node_index[k].displayName for k in chain_nodes if k in node_index)}",
            "Pattern matches lateral movement: ASSET → ASSET propagation.",
            f"Confidence: {confidence}%.",
        ]

        fid = _sha256_32("finding", "lateral", n.nodeKey, *sorted(chain_nodes))
        findings.append(IntelligenceFinding(
            findingId=fid,
            title=f"Lateral Movement from {n.displayName}",
            description=(
                f"Asset '{n.displayName}' (risk={n.riskScore}) has "
                f"{hops_found} internal lateral movement hop(s) detected."
            ),
            severity=severity,
            confidence=confidence,
            relatedNodes=chain_nodes,
            relatedEdges=chain_edges,
            evidenceIds=[],
            mitreTechniques=_PATTERN_MITRE[PatternTypeEnum.LATERAL_MOVEMENT],
            recommendation=(
                f"Isolate '{n.displayName}'. Inspect traffic to connected assets. "
                "Check for credential reuse across the chain."
            ),
            reasoningTrace=trace,
            metadata={"hops": hops_found, "originRisk": n.riskScore},
        ))

    return sorted(findings, key=lambda f: (-f.confidence, f.title))


# ---------------------------------------------------------------------------
# Pivot Detection
# ---------------------------------------------------------------------------

def detect_pivots(graph: AttackGraph) -> List[IntelligenceFinding]:
    """
    Detect nodes that connect multiple attack paths (pivot nodes).

    Algorithm (O(n + m))
    --------------------
    A node is a pivot if it has both incoming edges from ≥1 source AND
    outgoing edges to ≥1 destination that are NOT the same source.
    Scored by in-degree × out-degree (connectivity product).

    Parameters
    ----------
    graph : frozen AttackGraph.

    Returns
    -------
    List[IntelligenceFinding] — one finding per pivot node.
    """
    node_index, out_edges, in_edges, _ = _build_adjacency_maps(graph)
    findings: List[IntelligenceFinding] = []

    for n in graph.nodes:
        od = len(out_edges.get(n.nodeKey, []))
        id_ = len(in_edges.get(n.nodeKey, []))
        if od < 1 or id_ < 1:
            continue

        connectivity = od * id_
        if connectivity < 2:
            continue

        in_sources = {e.sourceNodeId for e in in_edges.get(n.nodeKey, [])}
        out_targets = {e.targetNodeId for e in out_edges.get(n.nodeKey, [])}
        if not (in_sources - out_targets):
            continue  # all in-sources are also out-targets — not a true pivot

        confidence = min(100, 40 + connectivity * 5)
        severity = _risk_to_severity(n.riskScore + connectivity * 3)

        in_names = [
            node_index[k].displayName for k in in_sources if k in node_index
        ][:5]
        out_names = [
            node_index[k].displayName for k in out_targets if k in node_index
        ][:5]

        trace = [
            f"Node '{n.displayName}' (type={n.nodeType.value}) has {id_} incoming and {od} outgoing edges.",
            f"Connectivity product = {connectivity} (in × out).",
            f"Incoming sources: {in_names}.",
            f"Outgoing targets: {out_names}.",
            "Pattern matches pivot node: multiple independent paths converge and diverge here.",
            f"Confidence: {confidence}%.",
        ]

        related_edges = (
            [e.edgeKey for e in in_edges.get(n.nodeKey, [])] +
            [e.edgeKey for e in out_edges.get(n.nodeKey, [])]
        )

        fid = _sha256_32("finding", "pivot", n.nodeKey)
        findings.append(IntelligenceFinding(
            findingId=fid,
            title=f"Pivot Node: {n.displayName}",
            description=(
                f"'{n.displayName}' bridges {id_} incoming and {od} outgoing "
                f"paths (connectivity={connectivity}). Acts as a pivot."
            ),
            severity=severity,
            confidence=confidence,
            relatedNodes=[n.nodeKey] + list(in_sources) + list(out_targets),
            relatedEdges=related_edges,
            evidenceIds=[],
            mitreTechniques=["T1021", "T1563"],
            recommendation=(
                f"Monitor '{n.displayName}' closely. Consider network segmentation. "
                "Inspect all connections through this node."
            ),
            reasoningTrace=trace,
            metadata={"inDegree": id_, "outDegree": od, "connectivityProduct": connectivity},
        ))

    return sorted(findings, key=lambda f: (-f.confidence, f.title))


# ---------------------------------------------------------------------------
# Choke Point Detection
# ---------------------------------------------------------------------------

def detect_choke_points(graph: AttackGraph) -> List[IntelligenceFinding]:
    """
    Detect nodes whose removal would disconnect large sections of the graph.

    Algorithm: Approximation via articulation-point-like scoring O(n + m).
    For each candidate node, we measure whether removing it increases the
    number of connected components.  We use a lightweight heuristic:
    a node is a choke point if its neighbors form ≥2 separate groups that
    are only connected THROUGH the candidate node.

    Full articulation-point algorithm is O(n + m) Tarjan DFS.
    We use it here with an undirected adjacency view.

    Parameters
    ----------
    graph : frozen AttackGraph.

    Returns
    -------
    List[IntelligenceFinding] — one finding per choke point detected.
    """
    node_index, out_edges, in_edges, _ = _build_adjacency_maps(graph)
    all_keys = list(node_index.keys())

    if len(all_keys) < 3:
        return []

    # Build undirected adjacency for Tarjan's AP algorithm
    undirected: Dict[str, set] = defaultdict(set)
    for e in graph.edges:
        undirected[e.sourceNodeId].add(e.targetNodeId)
        undirected[e.targetNodeId].add(e.sourceNodeId)

    # Tarjan's articulation point algorithm (iterative)
    disc: Dict[str, int] = {}
    low: Dict[str, int] = {}
    parent: Dict[str, Optional[str]] = {}
    ap_set: set = set()
    timer = [0]

    def _dfs_ap(start: str) -> None:
        stack = [(start, iter(undirected[start]), False)]
        disc[start] = low[start] = timer[0]; timer[0] += 1
        parent[start] = None
        child_count = [0]

        while stack:
            u, children, is_return = stack[-1]
            if is_return:
                stack.pop()
                if stack:
                    p = stack[-1][0]
                    low[p] = min(low[p], low[u])
                    if parent[p] is None:
                        pass  # root handled separately
                    elif low[u] >= disc[p]:
                        ap_set.add(p)
                continue

            try:
                v = next(children)
            except StopIteration:
                stack[-1] = (u, children, True)
                continue

            if v not in disc:
                disc[v] = low[v] = timer[0]; timer[0] += 1
                parent[v] = u
                stack.append((v, iter(undirected[v]), False))
            elif v != parent.get(u):
                low[u] = min(low[u], disc[v])

    for k in all_keys:
        if k not in disc:
            _dfs_ap(k)

    # Root nodes with ≥2 children are also APs (Tarjan's root condition)
    for k in all_keys:
        if parent.get(k) is None:
            children_count = sum(1 for v in undirected[k] if parent.get(v) == k)
            if children_count >= 2:
                ap_set.add(k)

    findings: List[IntelligenceFinding] = []
    for k in ap_set:
        n = node_index.get(k)
        if n is None:
            continue

        degree = len(undirected.get(k, set()))
        confidence = min(100, 55 + degree * 3)
        severity = _risk_to_severity(n.riskScore + degree * 2)

        trace = [
            f"Node '{n.displayName}' (type={n.nodeType.value}) identified as articulation point.",
            f"Degree = {degree} (undirected).",
            "Removing this node increases the number of connected components.",
            "Classic choke point: controls connectivity between graph sections.",
            f"Confidence: {confidence}%.",
        ]

        related_edges = [
            e.edgeKey for e in (out_edges.get(k, []) + in_edges.get(k, []))
        ]

        fid = _sha256_32("finding", "chokepoint", k)
        findings.append(IntelligenceFinding(
            findingId=fid,
            title=f"Choke Point: {n.displayName}",
            description=(
                f"'{n.displayName}' is a graph articulation point. "
                f"Its removal disconnects the network (degree={degree})."
            ),
            severity=severity,
            confidence=confidence,
            relatedNodes=[k] + list(undirected.get(k, set())),
            relatedEdges=related_edges,
            evidenceIds=[],
            mitreTechniques=["T1018", "T1046"],
            recommendation=(
                f"Harden '{n.displayName}'. Apply strict ACLs. "
                "Monitor for unusual traffic volume or new connections through this node."
            ),
            reasoningTrace=trace,
            metadata={"degree": degree, "isArticulationPoint": True},
        ))

    return sorted(findings, key=lambda f: (-f.confidence, f.title))


# ---------------------------------------------------------------------------
# MITRE Correlation
# ---------------------------------------------------------------------------

def correlate_mitre(graph: AttackGraph) -> List[IntelligenceFinding]:
    """
    Group nodes by ATT&CK techniques found in the graph.

    Algorithm (O(n))
    ----------------
    Scan MITRE nodes and any node whose metadata contains 'techniqueId' or
    label matches a T-number pattern.  Group attached evidence and
    produce one IntelligenceFinding per unique technique.

    Parameters
    ----------
    graph : frozen AttackGraph.

    Returns
    -------
    List[IntelligenceFinding] — one per unique MITRE technique, sorted
    by confidence DESC.
    """
    import re
    t_pattern = re.compile(r"T\d{4}(?:\.\d{3})?")

    node_index, out_edges, in_edges, _ = _build_adjacency_maps(graph)

    # technique_id → {nodes, evidence, confidence_samples}
    tech_nodes: Dict[str, List[str]] = defaultdict(list)
    tech_evidence: Dict[str, List[str]] = defaultdict(list)
    tech_conf: Dict[str, List[int]] = defaultdict(list)
    tech_name: Dict[str, str] = {}

    for n in graph.nodes:
        # Explicit MITRE node
        if n.nodeType == GraphNodeTypeEnum.MITRE:
            tid = str(n.metadata.get("techniqueId", "") or n.label)
            if tid:
                tech_nodes[tid].append(n.nodeKey)
                tech_conf[tid].append(n.confidence)
                tech_name[tid] = str(n.metadata.get("name", tid))
                sources = n.metadata.get("sources", []) or []
                for s in sources:
                    tech_evidence[tid].append(str(s))

        # Any node whose label matches a T-number
        matches = t_pattern.findall(n.label + " " + n.displayName)
        for tid in matches:
            if n.nodeKey not in tech_nodes[tid]:
                tech_nodes[tid].append(n.nodeKey)
                tech_conf[tid].append(n.confidence)

        # Metadata techniqueId
        tid_meta = str(n.metadata.get("techniqueId", "") or "")
        if tid_meta and n.nodeKey not in tech_nodes[tid_meta]:
            tech_nodes[tid_meta].append(n.nodeKey)
            tech_conf[tid_meta].append(n.confidence)

    findings: List[IntelligenceFinding] = []
    for tid, nkeys in tech_nodes.items():
        if not tid:
            continue
        confs = tech_conf[tid]
        avg_conf = round(sum(confs) / len(confs)) if confs else 50
        severity = _risk_to_severity(avg_conf)

        related_edges: List[str] = []
        for k in nkeys:
            for e in (out_edges.get(k, []) + in_edges.get(k, [])):
                related_edges.append(e.edgeKey)

        name = tech_name.get(tid, tid)
        trace = [
            f"MITRE technique {tid} ({name}) detected in the graph.",
            f"{len(nkeys)} node(s) associated with this technique.",
            f"Average confidence: {avg_conf}%.",
            f"Evidence sources: {list(dict.fromkeys(tech_evidence[tid]))[:5]}",
        ]

        fid = _sha256_32("finding", "mitre", tid)
        findings.append(IntelligenceFinding(
            findingId=fid,
            title=f"MITRE {tid}: {name}",
            description=(
                f"Technique {tid} ({name}) is evidenced by "
                f"{len(nkeys)} node(s) in the attack graph."
            ),
            severity=severity,
            confidence=avg_conf,
            relatedNodes=list(dict.fromkeys(nkeys)),
            relatedEdges=list(dict.fromkeys(related_edges)),
            evidenceIds=list(dict.fromkeys(tech_evidence[tid]))[:10],
            mitreTechniques=[tid],
            recommendation=f"Investigate activity mapped to {tid}. Refer to MITRE ATT&CK for {name}.",
            reasoningTrace=trace,
            metadata={"techniqueId": tid, "techniqueName": name},
        ))

    return sorted(findings, key=lambda f: (-f.confidence, f.title))


# ---------------------------------------------------------------------------
# Risk Ranking
# ---------------------------------------------------------------------------

def rank_attack_paths(chains: List[AttackChain]) -> List[AttackChain]:
    """
    Sort attack chains by: totalRisk DESC, confidence DESC, evidence count DESC.

    O(k log k) where k = len(chains).

    Parameters
    ----------
    chains : list of AttackChain objects.

    Returns
    -------
    New sorted list; input not mutated.
    """
    return sorted(
        chains,
        key=lambda c: (-c.totalRisk, -c.confidence, -len(c.evidenceIds)),
    )


# ---------------------------------------------------------------------------
# AI Recommendation Engine (rule-based, deterministic)
# ---------------------------------------------------------------------------

_RECOMMENDATION_RULES: List[Tuple[Any, Any, str]] = [
    # (node_type_set_or_None, min_risk, recommendation_template)
    (
        {GraphNodeTypeEnum.ASSET},
        80,
        "Isolate host immediately. Capture volatile memory and network state."
        " Block all outbound connections pending investigation.",
    ),
    (
        {GraphNodeTypeEnum.ASSET},
        50,
        "Investigate host for signs of compromise. Review process list, "
        "network connections, and recent authentication events.",
    ),
    (
        {GraphNodeTypeEnum.USER},
        40,
        "Reset user credentials immediately. Audit recent login activity "
        "across all systems for this account.",
    ),
    (
        {GraphNodeTypeEnum.PROCESS},
        50,
        "Inspect process for malicious behaviour. Collect memory dump "
        "and volatile artifacts. Terminate if confirmed malicious.",
    ),
    (
        {GraphNodeTypeEnum.DOMAIN, GraphNodeTypeEnum.EXTERNAL_HOST},
        30,
        "Block domain/IP at perimeter firewall and DNS resolver. "
        "Investigate all hosts that communicated with this endpoint.",
    ),
    (
        {GraphNodeTypeEnum.HASH},
        0,
        "Quarantine and submit file hash to threat intelligence platform. "
        "Scan all endpoints for this hash.",
    ),
    (
        {GraphNodeTypeEnum.EMAIL},
        0,
        "Quarantine phishing email. Block sender domain. "
        "Notify affected recipients.",
    ),
    (
        {GraphNodeTypeEnum.FINDING},
        70,
        "Escalate finding to incident response team. "
        "Preserve all associated evidence for forensic review.",
    ),
    (
        {GraphNodeTypeEnum.ALERT},
        60,
        "Triage alert. Correlate with other findings. "
        "Determine if escalation to incident response is warranted.",
    ),
    (
        {GraphNodeTypeEnum.SERVICE, GraphNodeTypeEnum.PORT},
        50,
        "Review service configuration. Apply patching if vulnerable. "
        "Restrict access via firewall rules.",
    ),
    (
        None,
        85,
        "Capture volatile artifacts immediately. Preserve memory, "
        "process list, and network state before rebooting.",
    ),
]


def generate_recommendations(
    nodes    : List[AttackGraphNode],
    findings : List[IntelligenceFinding],
) -> Dict[str, str]:
    """
    Generate deterministic rule-based recommendations.

    For each node, applies the FIRST matching rule in _RECOMMENDATION_RULES
    (type match AND risk threshold).  For each IntelligenceFinding, if no
    recommendation is already set, derives one from the severity.

    Parameters
    ----------
    nodes    : list of AttackGraphNode to evaluate.
    findings : list of IntelligenceFinding to evaluate.

    Returns
    -------
    Dict[nodeKey_or_findingId → recommendation_str]

    Complexity: O(n * R) where R = len(_RECOMMENDATION_RULES) — effectively O(n).
    """
    result: Dict[str, str] = {}

    for n in nodes:
        for type_set, min_risk, rec in _RECOMMENDATION_RULES:
            if type_set is not None and n.nodeType not in type_set:
                continue
            if n.riskScore < min_risk:
                continue
            result[n.nodeKey] = rec
            break

    # Fallback severity-based recommendations for findings without explicit ones
    _sev_rec: Dict[SeverityEnum, str] = {
        SeverityEnum.CRITICAL : "Immediate escalation required. Contain and eradicate.",
        SeverityEnum.HIGH     : "Prioritise for investigation within 24 hours.",
        SeverityEnum.MEDIUM   : "Schedule investigation. Monitor for escalation.",
        SeverityEnum.LOW      : "Log and monitor. Review during next regular cycle.",
        SeverityEnum.INFO     : "Record for awareness. No immediate action required.",
    }

    for f in findings:
        if f.recommendation:
            result[f.findingId] = f.recommendation
        else:
            result[f.findingId] = _sev_rec.get(f.severity, "Review and investigate.")

    return result


# ---------------------------------------------------------------------------
# Main entry point: analyse_graph()
# ---------------------------------------------------------------------------

def analyse_graph(graph: AttackGraph) -> AttackGraphIntelligenceResult:
    """
    Run the full intelligence pass over an existing AttackGraph.

    Pipeline
    --------
    1. detect_attack_patterns()       — pattern recognition
    2. build_attack_chains()          — chain grouping + fingerprinting
    3. rank_attack_paths()            — sort by risk/confidence/evidence
    4. find_critical_assets()         — centrality + risk ranking
    5. calculate_blast_radius()       — per critical asset (top 10)
    6. detect_lateral_movement()      — lateral movement findings
    7. detect_pivots()                — pivot node findings
    8. detect_choke_points()          — articulation point findings
    9. correlate_mitre()              — MITRE ATT&CK correlation
    10. generate_recommendations()    — deterministic rule-based output
    11. Assemble IntelligenceStatistics, IntelligenceExplanation, result

    Complexity
    ----------
    O(P * (n + m)) where P ≈ 10 passes, each O(n + m).
    Effectively O(n + m) — linear in graph size.

    Parameters
    ----------
    graph : frozen AttackGraph (never mutated).

    Returns
    -------
    AttackGraphIntelligenceResult (frozen / immutable).
    """
    t_start = _now_ms()
    stages: List[str] = []
    algorithms_used: List[str] = []
    reasoning_steps: List[str] = []
    patterns_detected: List[str] = []

    # ── Stage 1: Pattern detection ──────────────────────────────────────────
    stages.append("Pattern detection")
    algorithms_used.append("detect_attack_patterns")
    patterns = detect_attack_patterns(graph)
    for p in patterns:
        patterns_detected.append(f"{p.patternType.value}: {p.title}")
    reasoning_steps.append(
        f"Detected {len(patterns)} attack pattern(s): "
        f"{[p.patternType.value for p in patterns]}."
    )

    # ── Stage 2: Attack chain detection ─────────────────────────────────────
    stages.append("Attack chain detection (Kahn topological sort)")
    algorithms_used.append("build_attack_chains")
    chains = build_attack_chains(graph)
    reasoning_steps.append(
        f"Built {len(chains)} attack chain(s) from connected components."
    )

    # ── Stage 3: Risk ranking ────────────────────────────────────────────────
    stages.append("Attack path ranking")
    algorithms_used.append("rank_attack_paths")
    chains = rank_attack_paths(chains)
    reasoning_steps.append("Ranked chains by totalRisk → confidence → evidence count.")

    # ── Stage 4: Critical asset detection ───────────────────────────────────
    stages.append("Critical asset detection (betweenness approximation)")
    algorithms_used.append("find_critical_assets")
    critical = find_critical_assets(graph)
    reasoning_steps.append(
        f"Identified {len(critical)} critical asset(s) by degree, risk, and centrality."
    )

    # ── Stage 5: Blast radius (top-10 critical assets) ─────────────────────
    stages.append("Blast radius calculation (BFS directed reachability)")
    algorithms_used.append("calculate_blast_radius")
    blast_radii: List[BlastRadius] = []
    for ca in critical[:10]:
        br = calculate_blast_radius(graph, ca.assetNode, max_depth=8)
        blast_radii.append(br)
    reasoning_steps.append(
        f"Calculated blast radius for {len(blast_radii)} critical asset(s)."
    )

    # ── Stage 6: Lateral movement detection ─────────────────────────────────
    stages.append("Lateral movement detection (directed BFS per asset)")
    algorithms_used.append("detect_lateral_movement")
    lat_findings = detect_lateral_movement(graph)
    reasoning_steps.append(
        f"Found {len(lat_findings)} lateral movement path(s)."
    )

    # ── Stage 7: Pivot detection ─────────────────────────────────────────────
    stages.append("Pivot node detection (in/out degree product)")
    algorithms_used.append("detect_pivots")
    pivot_findings = detect_pivots(graph)
    reasoning_steps.append(
        f"Detected {len(pivot_findings)} pivot node(s)."
    )

    # ── Stage 8: Choke point detection ──────────────────────────────────────
    stages.append("Choke point detection (Tarjan articulation points)")
    algorithms_used.append("detect_choke_points")
    choke_findings = detect_choke_points(graph)
    reasoning_steps.append(
        f"Identified {len(choke_findings)} choke point(s) (articulation points)."
    )

    # ── Stage 9: MITRE correlation ───────────────────────────────────────────
    stages.append("MITRE ATT&CK correlation (technique grouping)")
    algorithms_used.append("correlate_mitre")
    mitre_findings = correlate_mitre(graph)
    reasoning_steps.append(
        f"Correlated {len(mitre_findings)} MITRE technique(s) from graph nodes."
    )

    # ── Merge all findings ───────────────────────────────────────────────────
    all_findings = lat_findings + pivot_findings + choke_findings + mitre_findings
    # Sort by severity (CRITICAL first), then confidence DESC
    _sev_order = {
        SeverityEnum.CRITICAL: 0,
        SeverityEnum.HIGH:     1,
        SeverityEnum.MEDIUM:   2,
        SeverityEnum.LOW:      3,
        SeverityEnum.INFO:     4,
    }
    all_findings = sorted(
        all_findings,
        key=lambda f: (_sev_order.get(f.severity, 99), -f.confidence),
    )

    # ── Stage 10: Recommendations ────────────────────────────────────────────
    stages.append("Recommendation generation (rule-based)")
    algorithms_used.append("generate_recommendations")
    recs = generate_recommendations(list(graph.nodes), all_findings)
    reasoning_steps.append(
        f"Generated {len(recs)} deterministic recommendation(s)."
    )

    # Patch findings with recommendations where missing
    patched_findings: List[IntelligenceFinding] = []
    for f in all_findings:
        if f.recommendation:
            patched_findings.append(f)
        else:
            rec = recs.get(f.findingId, "Review and investigate.")
            patched_findings.append(IntelligenceFinding(
                findingId=f.findingId,
                title=f.title,
                description=f.description,
                severity=f.severity,
                confidence=f.confidence,
                relatedNodes=f.relatedNodes,
                relatedEdges=f.relatedEdges,
                evidenceIds=f.evidenceIds,
                mitreTechniques=f.mitreTechniques,
                recommendation=rec,
                reasoningTrace=f.reasoningTrace,
                metadata=f.metadata,
            ))

    t_end = _now_ms()
    exec_ms = t_end - t_start

    # ── Statistics ────────────────────────────────────────────────────────────
    stats = IntelligenceStatistics(
        attackChains=len(chains),
        findings=len(patched_findings),
        criticalAssets=len(critical),
        blastRadiusCalculations=len(blast_radii),
        suspiciousPatterns=len(patterns),
        lateralMovements=len(lat_findings),
        pivotsDetected=len(pivot_findings),
    )

    # ── Explanation ───────────────────────────────────────────────────────────
    explanation = IntelligenceExplanation(
        reasoningSteps=reasoning_steps,
        algorithmsUsed=list(dict.fromkeys(algorithms_used)),
        patternsDetected=patterns_detected,
        processingStages=stages,
        executionTimeMs=exec_ms,
    )

    return AttackGraphIntelligenceResult(
        attackChains=chains,
        findings=patched_findings,
        criticalAssets=critical,
        blastRadius=blast_radii,
        statistics=stats,
        explanation=explanation,
        processingTimeMs=exec_ms,
        engineVersion=ATTACK_GRAPH_INTELLIGENCE_ENGINE_VERSION,
    )
