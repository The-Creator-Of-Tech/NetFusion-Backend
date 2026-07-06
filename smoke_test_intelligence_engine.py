"""
Smoke Test — Attack Graph Intelligence Engine (Phase A4.0.4)
=============================================================
Builds a synthetic attack graph, runs the full intelligence pass,
and asserts every required output is present and correct.

Run with:
    python smoke_test_intelligence_engine.py

All assertions must pass.  Exit code 0 = success.
"""

from __future__ import annotations

import sys
import time

# ── Import graph builders ──────────────────────────────────────────────────
from services.attack_graph_service import (
    GraphEdgeTypeEnum,
    GraphNodeTypeEnum,
    build_attack_graph,
    build_edge,
    build_node,
    build_graph,
)

# ── Import intelligence engine ─────────────────────────────────────────────
from services.attack_graph_intelligence_service import (
    ATTACK_GRAPH_INTELLIGENCE_ENGINE_VERSION,  # noqa: F401 — existence check
    AttackChain,
    AttackGraphIntelligenceResult,
    AttackPattern,
    BlastRadius,
    CriticalAsset,
    IntelligenceFinding,
    IntelligenceExplanation,
    IntelligenceStatistics,
    PatternTypeEnum,
    SeverityEnum,
    analyse_graph,
    build_attack_chains,
    calculate_blast_radius,
    correlate_mitre,
    detect_attack_patterns,
    detect_choke_points,
    detect_lateral_movement,
    detect_pivots,
    find_critical_assets,
    generate_recommendations,
    rank_attack_paths,
    _chain_fingerprint,
)

from core.constants import ATTACK_GRAPH_INTELLIGENCE_ENGINE_VERSION as _VER_CONST

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"

_failures: list = []


def _assert(condition: bool, msg: str) -> None:
    status = PASS if condition else FAIL
    print(f"  {status} {msg}")
    if not condition:
        _failures.append(msg)


# ===========================================================================
# Build synthetic attack graph
# ===========================================================================

def _build_synthetic_graph():
    """
    Synthetic topology:

        asset_workstation ──COMMUNICATES_WITH──► asset_server
        asset_server      ──COMMUNICATES_WITH──► external_c2
        asset_workstation ──COMMUNICATES_WITH──► external_c2
        external_c2       ──RESOLVES_TO──────────► domain_evil
        asset_server      ──AUTHENTICATES_TO──── asset_dc
        asset_dc          ──SCANNED──────────────► asset_workstation
        finding_malware   ──INDICATES──────────── asset_workstation
        mitre_t1071       ──(USES via finding)─── finding_malware
        process_cmd       ──GENERATED──────────── finding_malware
        email_phish       ──RELATED_TO──────────── asset_workstation
        asset_db          ──COMMUNICATES_WITH──── asset_server
        asset_db          ──COMMUNICATES_WITH──── external_c2   (exfil)
    """
    ns = "smoke-intel"

    # Nodes
    n_ws  = build_node(GraphNodeTypeEnum.ASSET, "workstation-01",
                       display_name="Workstation 01", risk_score=70, confidence=80, namespace=ns)
    n_srv = build_node(GraphNodeTypeEnum.ASSET, "server-02",
                       display_name="Server 02", risk_score=60, confidence=75, namespace=ns)
    n_dc  = build_node(GraphNodeTypeEnum.ASSET, "dc-01",
                       display_name="Domain Controller", risk_score=85, confidence=90, namespace=ns)
    n_db  = build_node(GraphNodeTypeEnum.ASSET, "db-server",
                       display_name="Database Server", risk_score=75, confidence=80, namespace=ns)
    n_c2  = build_node(GraphNodeTypeEnum.EXTERNAL_HOST, "203.0.113.99",
                       display_name="C2 Server 203.0.113.99", risk_score=90, confidence=85, namespace=ns)
    n_dom = build_node(GraphNodeTypeEnum.DOMAIN, "evil-beacon.com",
                       display_name="evil-beacon.com (C2 Domain)", risk_score=88, confidence=88, namespace=ns)
    n_fnd = build_node(GraphNodeTypeEnum.FINDING, "malware-beacon",
                       display_name="[HIGH] Malware Beacon Finding", risk_score=80, confidence=75, namespace=ns)
    n_mit = build_node(GraphNodeTypeEnum.MITRE, "T1071.001",
                       display_name="T1071.001 — Web Protocols",
                       risk_score=70, confidence=90, namespace=ns,
                       metadata={"techniqueId": "T1071.001", "name": "Web Protocols", "tactic": "command-and-control"})
    n_proc= build_node(GraphNodeTypeEnum.PROCESS, "cmd.exe",
                       display_name="cmd.exe", risk_score=55, confidence=70, namespace=ns)
    n_email=build_node(GraphNodeTypeEnum.EMAIL, "phish@evil-beacon.com",
                       display_name="Phishing Email", risk_score=65, confidence=70, namespace=ns)
    n_alert=build_node(GraphNodeTypeEnum.ALERT, "beacon-alert",
                       display_name="[HIGH] Beacon Alert", risk_score=80, confidence=80, namespace=ns)

    nodes = [n_ws, n_srv, n_dc, n_db, n_c2, n_dom, n_fnd, n_mit, n_proc, n_email, n_alert]

    # Edges
    e1  = build_edge(n_ws.nodeKey,   n_srv.nodeKey,  GraphEdgeTypeEnum.COMMUNICATES_WITH, confidence=80)
    e2  = build_edge(n_srv.nodeKey,  n_c2.nodeKey,   GraphEdgeTypeEnum.COMMUNICATES_WITH, confidence=75)
    e3  = build_edge(n_ws.nodeKey,   n_c2.nodeKey,   GraphEdgeTypeEnum.COMMUNICATES_WITH, confidence=85)
    e4  = build_edge(n_c2.nodeKey,   n_dom.nodeKey,  GraphEdgeTypeEnum.RESOLVES_TO,       confidence=90)
    e5  = build_edge(n_srv.nodeKey,  n_dc.nodeKey,   GraphEdgeTypeEnum.AUTHENTICATES_TO,  confidence=70)
    e6  = build_edge(n_dc.nodeKey,   n_ws.nodeKey,   GraphEdgeTypeEnum.SCANNED,           confidence=65)
    e7  = build_edge(n_fnd.nodeKey,  n_ws.nodeKey,   GraphEdgeTypeEnum.INDICATES,         confidence=75)
    e8  = build_edge(n_fnd.nodeKey,  n_mit.nodeKey,  GraphEdgeTypeEnum.USES,              confidence=70)
    e9  = build_edge(n_proc.nodeKey, n_fnd.nodeKey,  GraphEdgeTypeEnum.GENERATED,         confidence=65)
    e10 = build_edge(n_email.nodeKey,n_ws.nodeKey,   GraphEdgeTypeEnum.RELATED_TO,        confidence=60)
    e11 = build_edge(n_db.nodeKey,   n_srv.nodeKey,  GraphEdgeTypeEnum.COMMUNICATES_WITH, confidence=70)
    e12 = build_edge(n_db.nodeKey,   n_c2.nodeKey,   GraphEdgeTypeEnum.COMMUNICATES_WITH, confidence=80)
    e13 = build_edge(n_fnd.nodeKey,  n_alert.nodeKey,GraphEdgeTypeEnum.TRIGGERED,         confidence=75)

    edges = [e1, e2, e3, e4, e5, e6, e7, e8, e9, e10, e11, e12, e13]
    return build_graph(nodes, edges)


# ===========================================================================
# Run tests
# ===========================================================================

def run_smoke_test() -> None:
    print("\n" + "=" * 64)
    print("  Phase A4.0.4 — Attack Graph Intelligence Engine Smoke Test")
    print("=" * 64)

    graph = _build_synthetic_graph()
    print(f"\n  Graph: {graph.statistics.totalNodes} nodes, {graph.statistics.totalEdges} edges")

    # ── 1. Engine version constant ──────────────────────────────────────────
    print("\n[1] Engine Version")
    _assert(
        bool(ATTACK_GRAPH_INTELLIGENCE_ENGINE_VERSION),
        "ATTACK_GRAPH_INTELLIGENCE_ENGINE_VERSION is defined",
    )
    _assert(
        _VER_CONST == ATTACK_GRAPH_INTELLIGENCE_ENGINE_VERSION,
        "Constant exported correctly from core.constants",
    )

    # ── 2. Pattern detection ────────────────────────────────────────────────
    print("\n[2] Pattern Detection")
    patterns = detect_attack_patterns(graph)
    _assert(isinstance(patterns, list), "detect_attack_patterns() returns list")
    _assert(len(patterns) > 0, f"At least 1 pattern detected (got {len(patterns)})")
    pattern_types = {p.patternType for p in patterns}
    _assert(
        PatternTypeEnum.BEACONING in pattern_types,
        "BEACONING pattern detected",
    )
    _assert(
        PatternTypeEnum.LATERAL_MOVEMENT in pattern_types,
        "LATERAL_MOVEMENT pattern detected",
    )
    for p in patterns:
        _assert(isinstance(p, AttackPattern), f"Pattern '{p.patternType.value}' is AttackPattern instance")
        _assert(bool(p.patternId), f"Pattern '{p.patternType.value}' has patternId")
        _assert(len(p.involvedNodes) > 0, f"Pattern '{p.patternType.value}' has involvedNodes")
        _assert(p.confidence >= 0 and p.confidence <= 100, f"Pattern confidence in [0,100]: {p.confidence}")
        _assert(len(p.mitreTechniques) > 0, f"Pattern '{p.patternType.value}' has mitreTechniques")

    # ── 3. Attack chain detection ───────────────────────────────────────────
    print("\n[3] Attack Chain Detection")
    chains = build_attack_chains(graph)
    _assert(isinstance(chains, list), "build_attack_chains() returns list")
    _assert(len(chains) > 0, f"At least 1 attack chain built (got {len(chains)})")
    for c in chains:
        _assert(isinstance(c, AttackChain), f"Chain '{c.name}' is AttackChain instance")
        _assert(len(c.nodes) >= 2, f"Chain has ≥2 nodes: {len(c.nodes)}")
        _assert(bool(c.chainFingerprint), f"Chain '{c.name}' has chainFingerprint")
        _assert(len(c.chainFingerprint) == 32, f"chainFingerprint is 32 chars")
        _assert(c.totalRisk >= 0, f"Chain totalRisk ≥ 0: {c.totalRisk}")
        _assert(len(c.attackStages) > 0, f"Chain has attackStages")

    # ── 4. Chain fingerprint determinism ────────────────────────────────────
    print("\n[4] Deterministic Chain Fingerprint")
    fp1 = _chain_fingerprint(["a", "b", "c"], ["e1", "e2"])
    fp2 = _chain_fingerprint(["a", "b", "c"], ["e1", "e2"])
    _assert(fp1 == fp2, "Same inputs → same chainFingerprint (deterministic)")
    _assert(len(fp1) == 32, "chainFingerprint is 32 hex chars")
    fp3 = _chain_fingerprint(["a", "b", "c"], ["e1", "e3"])
    _assert(fp1 != fp3, "Different edges → different fingerprint")
    # Rebuild chains twice — fingerprints must be identical
    chains_a = build_attack_chains(graph)
    chains_b = build_attack_chains(graph)
    for ca, cb in zip(chains_a, chains_b):
        _assert(
            ca.chainFingerprint == cb.chainFingerprint,
            f"Chain '{ca.name}' fingerprint is deterministic across runs",
        )

    # ── 5. Blast radius ─────────────────────────────────────────────────────
    print("\n[5] Blast Radius")
    critical = find_critical_assets(graph)
    if critical:
        br = calculate_blast_radius(graph, critical[0].assetNode, max_depth=6)
        _assert(isinstance(br, BlastRadius), "calculate_blast_radius() returns BlastRadius")
        _assert(br.sourceNode == critical[0].assetNode, "sourceNode matches input")
        _assert(isinstance(br.reachableNodes, list), "reachableNodes is a list")
        _assert(isinstance(br.affectedAssets, list), "affectedAssets is a list")
        _assert(br.maximumDepth >= 0, f"maximumDepth ≥ 0: {br.maximumDepth}")
        _assert(br.estimatedImpact in ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"),
                f"estimatedImpact is valid: {br.estimatedImpact}")
    else:
        _assert(False, "find_critical_assets() found no assets — check graph")

    # ── 6. Critical assets ──────────────────────────────────────────────────
    print("\n[6] Critical Asset Detection")
    _assert(len(critical) > 0, f"At least 1 critical asset found (got {len(critical)})")
    for ca in critical:
        _assert(isinstance(ca, CriticalAsset), "Result is CriticalAsset instance")
        _assert(ca.importanceScore >= 0 and ca.importanceScore <= 100,
                f"importanceScore in [0,100]: {ca.importanceScore}")
        _assert(ca.degree == ca.incomingConnections + ca.outgoingConnections,
                f"degree = in + out: {ca.degree}")
    # Sorted by importanceScore DESC
    scores = [ca.importanceScore for ca in critical]
    _assert(scores == sorted(scores, reverse=True), "Critical assets sorted by importanceScore DESC")

    # ── 7. Lateral movement ─────────────────────────────────────────────────
    print("\n[7] Lateral Movement Detection")
    lat = detect_lateral_movement(graph)
    _assert(isinstance(lat, list), "detect_lateral_movement() returns list")
    _assert(len(lat) > 0, f"At least 1 lateral movement finding (got {len(lat)})")
    for f in lat:
        _assert(isinstance(f, IntelligenceFinding), "Finding is IntelligenceFinding")
        _assert(len(f.reasoningTrace) > 0, "Finding has reasoningTrace")
        _assert(bool(f.recommendation), "Finding has recommendation")
        _assert(bool(f.findingId), "Finding has findingId")

    # ── 8. Pivots ───────────────────────────────────────────────────────────
    print("\n[8] Pivot Detection")
    pivots = detect_pivots(graph)
    _assert(isinstance(pivots, list), "detect_pivots() returns list")
    _assert(len(pivots) > 0, f"At least 1 pivot detected (got {len(pivots)})")
    for f in pivots:
        _assert(isinstance(f, IntelligenceFinding), "Pivot finding is IntelligenceFinding")
        _assert(len(f.reasoningTrace) > 0, "Pivot has reasoningTrace")

    # ── 9. Choke points ─────────────────────────────────────────────────────
    print("\n[9] Choke Point Detection")
    chokes = detect_choke_points(graph)
    _assert(isinstance(chokes, list), "detect_choke_points() returns list")
    _assert(len(chokes) > 0, f"At least 1 choke point detected (got {len(chokes)})")
    for f in chokes:
        _assert(isinstance(f, IntelligenceFinding), "Choke finding is IntelligenceFinding")
        _assert(len(f.reasoningTrace) > 0, "Choke point has reasoningTrace")

    # ── 10. MITRE correlation ───────────────────────────────────────────────
    print("\n[10] MITRE Correlation")
    mitre_findings = correlate_mitre(graph)
    _assert(isinstance(mitre_findings, list), "correlate_mitre() returns list")
    _assert(len(mitre_findings) > 0, f"At least 1 MITRE finding (got {len(mitre_findings)})")
    tech_ids = [f.metadata.get("techniqueId") for f in mitre_findings]
    _assert("T1071.001" in tech_ids, "T1071.001 correlated from MITRE node")
    for f in mitre_findings:
        _assert(len(f.mitreTechniques) > 0, f"MITRE finding has mitreTechniques: {f.title}")

    # ── 11. Risk ranking ────────────────────────────────────────────────────
    print("\n[11] Risk Ranking (rank_attack_paths)")
    ranked = rank_attack_paths(chains)
    risks = [c.totalRisk for c in ranked]
    _assert(risks == sorted(risks, reverse=True), "Chains sorted by totalRisk DESC")

    # ── 12. Recommendations ─────────────────────────────────────────────────
    print("\n[12] Recommendation Engine")
    all_fnd_for_rec = lat + pivots + chokes + mitre_findings
    recs = generate_recommendations(list(graph.nodes), all_fnd_for_rec)
    _assert(isinstance(recs, dict), "generate_recommendations() returns dict")
    _assert(len(recs) > 0, f"At least 1 recommendation generated (got {len(recs)})")
    for key, rec in recs.items():
        _assert(isinstance(rec, str) and len(rec) > 0, f"Recommendation for '{key[:8]}…' is non-empty string")

    # ── 13. Reasoning trace present on ALL findings ──────────────────────────
    print("\n[13] Reasoning Traces on All Findings")
    all_findings = lat + pivots + chokes + mitre_findings
    for f in all_findings:
        _assert(
            len(f.reasoningTrace) >= 1,
            f"Finding '{f.title[:40]}' has ≥1 reasoning step",
        )

    # ── 14. Full analyse_graph() pipeline ────────────────────────────────────
    print("\n[14] Full analyse_graph() Pipeline")
    t0 = time.monotonic()
    result = analyse_graph(graph)
    elapsed = time.monotonic() - t0

    _assert(isinstance(result, AttackGraphIntelligenceResult),
            "analyse_graph() returns AttackGraphIntelligenceResult")
    _assert(result.engineVersion == ATTACK_GRAPH_INTELLIGENCE_ENGINE_VERSION,
            f"engineVersion matches constant: {result.engineVersion}")
    _assert(result.processingTimeMs >= 0, f"processingTimeMs ≥ 0: {result.processingTimeMs}")
    _assert(isinstance(result.statistics, IntelligenceStatistics),
            "result.statistics is IntelligenceStatistics")
    _assert(isinstance(result.explanation, IntelligenceExplanation),
            "result.explanation is IntelligenceExplanation")
    _assert(len(result.explanation.reasoningSteps) > 0, "explanation has reasoningSteps")
    _assert(len(result.explanation.algorithmsUsed) > 0, "explanation has algorithmsUsed")
    _assert(len(result.explanation.processingStages) > 0, "explanation has processingStages")
    _assert(len(result.attackChains) > 0, f"result has attackChains: {len(result.attackChains)}")
    _assert(len(result.findings) > 0, f"result has findings: {len(result.findings)}")
    _assert(len(result.criticalAssets) > 0, f"result has criticalAssets: {len(result.criticalAssets)}")
    _assert(len(result.blastRadius) > 0, f"result has blastRadius: {len(result.blastRadius)}")
    _assert(result.statistics.attackChains == len(result.attackChains),
            "statistics.attackChains matches len(result.attackChains)")
    _assert(result.statistics.findings == len(result.findings),
            "statistics.findings matches len(result.findings)")
    _assert(result.statistics.criticalAssets == len(result.criticalAssets),
            "statistics.criticalAssets matches len(result.criticalAssets)")

    # Every finding must have recommendation and reasoningTrace
    for f in result.findings:
        _assert(bool(f.recommendation), f"Finding '{f.title[:30]}' has recommendation")
        _assert(len(f.reasoningTrace) > 0, f"Finding '{f.title[:30]}' has reasoningTrace")

    # ── 15. Determinism — same graph → same result ─────────────────────────
    print("\n[15] Determinism (same graph → same output)")
    result_b = analyse_graph(graph)
    _assert(
        len(result.attackChains) == len(result_b.attackChains),
        "Same chain count on repeated run",
    )
    _assert(
        len(result.findings) == len(result_b.findings),
        "Same finding count on repeated run",
    )
    for ca, cb in zip(result.attackChains, result_b.attackChains):
        _assert(
            ca.chainFingerprint == cb.chainFingerprint,
            f"Chain fingerprint stable: {ca.chainFingerprint[:8]}…",
        )

    # ── 16. Frozen models (immutability) ────────────────────────────────────
    print("\n[16] Frozen Models (immutability)")
    try:
        result.findings[0].title = "mutated"  # type: ignore[misc]
        _assert(False, "IntelligenceFinding should be immutable (frozen=True)")
    except Exception:
        _assert(True, "IntelligenceFinding is immutable (frozen=True)")
    try:
        result.statistics.attackChains = 99  # type: ignore[misc]
        _assert(False, "IntelligenceStatistics should be immutable (frozen=True)")
    except Exception:
        _assert(True, "IntelligenceStatistics is immutable (frozen=True)")

    # ── Summary ────────────────────────────────────────────────────────────
    print("\n" + "=" * 64)
    total = 0
    passed = 0
    # Count from _failures length vs expected assertions (approximate)
    if _failures:
        print(f"\n  {FAIL}  {len(_failures)} assertion(s) FAILED:\n")
        for msg in _failures:
            print(f"    • {msg}")
        print()
        sys.exit(1)
    else:
        print(f"\n  {PASS}  ALL ASSERTIONS PASSED\n")
        print(f"  Engine : {ATTACK_GRAPH_INTELLIGENCE_ENGINE_VERSION}")
        print(f"  Time   : {elapsed * 1000:.1f} ms\n")
        sys.exit(0)


if __name__ == "__main__":
    run_smoke_test()
