"""
NETFUSION IL-10: Enterprise Investigation Lifecycle Manager - Trace Difference Engine

Deterministic comparison engine between two investigations or reasoning sessions to show
new evidence, removed evidence, graph changes, confidence deltas, hypothesis changes,
recommendation changes, timeline changes, risk changes, and report differences.
"""

from datetime import datetime, timezone
import threading
from typing import Any, Dict, List, Optional

from netfusion_investigation.lifecycle.models import Investigation, ReasoningSession, TraceDifference


class ComparisonEngine:
    """Computes deterministic diffs between investigations or reasoning sessions."""

    def __init__(self):
        self._lock = threading.RLock()

    def compare_investigations(
        self,
        inv1: Investigation,
        inv2: Investigation,
        inv1_context: Optional[Dict[str, Any]] = None,
        inv2_context: Optional[Dict[str, Any]] = None,
    ) -> TraceDifference:
        with self._lock:
            ctx1 = inv1_context or {}
            ctx2 = inv2_context or {}

            # 1. Evidence Diff
            ev1 = ctx1.get("evidence", [])
            ev2 = ctx2.get("evidence", [])

            ev1_map = {e.get("id", idx): e for idx, e in enumerate(ev1)}
            ev2_map = {e.get("id", idx): e for idx, e in enumerate(ev2)}

            new_ev_keys = set(ev2_map.keys()) - set(ev1_map.keys())
            rem_ev_keys = set(ev1_map.keys()) - set(ev2_map.keys())

            new_evidence = sorted([ev2_map[k] for k in new_ev_keys], key=lambda x: str(x.get("id")))
            removed_evidence = sorted([ev1_map[k] for k in rem_ev_keys], key=lambda x: str(x.get("id")))

            # 2. Graph Diff
            nodes1 = set(ctx1.get("graph_nodes", []))
            nodes2 = set(ctx2.get("graph_nodes", []))
            edges1 = set(ctx1.get("graph_edges", []))
            edges2 = set(ctx2.get("graph_edges", []))

            changed_graph = {
                "added_nodes": sorted(list(nodes2 - nodes1)),
                "removed_nodes": sorted(list(nodes1 - nodes2)),
                "added_edges": sorted(list(edges2 - edges1)),
                "removed_edges": sorted(list(edges1 - edges2)),
            }

            # 3. Confidence Delta
            conf1 = float(ctx1.get("confidence", 0.0))
            conf2 = float(ctx2.get("confidence", 0.0))
            confidence_delta = round(conf2 - conf1, 4)

            # 4. Hypotheses
            hyp1 = ctx1.get("hypotheses", [])
            hyp2 = ctx2.get("hypotheses", [])
            hypothesis_changes = {
                "inv1_count": len(hyp1),
                "inv2_count": len(hyp2),
                "added_hypotheses": [h for h in hyp2 if h not in hyp1],
                "removed_hypotheses": [h for h in hyp1 if h not in hyp2],
            }

            # 5. Recommendations
            rec1 = ctx1.get("recommendations", [])
            rec2 = ctx2.get("recommendations", [])
            recommendation_changes = {
                "inv1_count": len(rec1),
                "inv2_count": len(rec2),
                "added_recommendations": [r for r in rec2 if r not in rec1],
                "removed_recommendations": [r for r in rec1 if r not in rec2],
            }

            # 6. Timeline
            tl1 = ctx1.get("timeline", [])
            tl2 = ctx2.get("timeline", [])
            timeline_changes = {
                "inv1_events_count": len(tl1),
                "inv2_events_count": len(tl2),
                "added_timeline_events": [t for t in tl2 if t not in tl1],
                "removed_timeline_events": [t for t in tl1 if t not in tl2],
            }

            # 7. Risk
            risk1 = float(ctx1.get("risk_score", 0.0))
            risk2 = float(ctx2.get("risk_score", 0.0))
            risk_changes = {
                "inv1_risk": risk1,
                "inv2_risk": risk2,
                "risk_delta": round(risk2 - risk1, 4),
            }

            # 8. Reports
            rep1 = ctx1.get("reports", [])
            rep2 = ctx2.get("reports", [])
            report_differences = {
                "inv1_report_count": len(rep1),
                "inv2_report_count": len(rep2),
                "added_reports": [r for r in rep2 if r not in rep1],
            }

            return TraceDifference(
                investigation_id_1=inv1.id,
                investigation_id_2=inv2.id,
                new_evidence=new_evidence,
                removed_evidence=removed_evidence,
                changed_graph=changed_graph,
                confidence_delta=confidence_delta,
                hypothesis_changes=hypothesis_changes,
                recommendation_changes=recommendation_changes,
                timeline_changes=timeline_changes,
                risk_changes=risk_changes,
                report_differences=report_differences,
                timestamp=datetime.now(timezone.utc).isoformat(),
            )

    def compare_sessions(
        self,
        sess1: ReasoningSession,
        sess2: ReasoningSession,
    ) -> TraceDifference:
        with self._lock:
            s1_state = sess1.state or {}
            s2_state = sess2.state or {}

            # Create dummy investigation wrappers for session comparative diff
            dummy_inv1 = Investigation(id=sess1.id, case_id="SESS-1", title=sess1.title, description="")
            dummy_inv2 = Investigation(id=sess2.id, case_id="SESS-2", title=sess2.title, description="")

            return self.compare_investigations(
                dummy_inv1, dummy_inv2, inv1_context=s1_state, inv2_context=s2_state
            )
