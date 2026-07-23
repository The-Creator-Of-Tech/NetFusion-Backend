"""
NETFUSION IL-10: Enterprise Investigation Lifecycle Manager - Replay Engine

Non-destructive step-by-step investigation replay engine for timeline, graph expansions,
evidence collection, reasoning steps, confidence calculations, recommendations, and reports.
"""

from datetime import datetime, timezone
import copy
import threading
from typing import Any, Dict, List, Optional
import uuid

from netfusion_investigation.lifecycle.models import Investigation, ReplaySession, ReplayStep


class ReplayEngine:
    """Step-by-step non-destructive replay engine."""

    def __init__(self):
        self._replays: Dict[str, ReplaySession] = {}
        self._lock = threading.RLock()

    def initialize_replay(
        self,
        investigation: Investigation,
        timeline_events: Optional[List[Dict[str, Any]]] = None,
        graph_events: Optional[List[Dict[str, Any]]] = None,
        evidence_events: Optional[List[Dict[str, Any]]] = None,
        reasoning_events: Optional[List[Dict[str, Any]]] = None,
        recommendation_events: Optional[List[Dict[str, Any]]] = None,
        report_events: Optional[List[Dict[str, Any]]] = None,
    ) -> ReplaySession:
        with self._lock:
            steps: List[ReplayStep] = []
            step_counter = 1

            # 1. Timeline steps
            for item in timeline_events or []:
                steps.append(ReplayStep(
                    step_id=f"step-{step_counter}",
                    step_number=step_counter,
                    timestamp=item.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    step_type="TIMELINE",
                    description=item.get("title", f"Timeline Event #{step_counter}"),
                    state_delta={"timeline_event": copy.deepcopy(item)},
                ))
                step_counter += 1

            # 2. Graph expansion steps
            for item in graph_events or []:
                steps.append(ReplayStep(
                    step_id=f"step-{step_counter}",
                    step_number=step_counter,
                    timestamp=item.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    step_type="GRAPH_EXPANSION",
                    description=item.get("description", f"Graph Expansion #{step_counter}"),
                    state_delta={"graph_change": copy.deepcopy(item)},
                ))
                step_counter += 1

            # 3. Evidence collection steps
            for item in evidence_events or []:
                steps.append(ReplayStep(
                    step_id=f"step-{step_counter}",
                    step_number=step_counter,
                    timestamp=item.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    step_type="EVIDENCE_COLLECTION",
                    description=item.get("name", f"Evidence Item #{step_counter}"),
                    state_delta={"evidence_item": copy.deepcopy(item)},
                ))
                step_counter += 1

            # 4. Reasoning & Confidence steps
            for item in reasoning_events or []:
                steps.append(ReplayStep(
                    step_id=f"step-{step_counter}",
                    step_number=step_counter,
                    timestamp=item.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    step_type="REASONING",
                    description=item.get("hypothesis", f"Reasoning Step #{step_counter}"),
                    state_delta={
                        "reasoning_trace": copy.deepcopy(item),
                        "confidence": item.get("confidence", 0.0),
                    },
                ))
                step_counter += 1

            # 5. Recommendation steps
            for item in recommendation_events or []:
                steps.append(ReplayStep(
                    step_id=f"step-{step_counter}",
                    step_number=step_counter,
                    timestamp=item.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    step_type="RECOMMENDATION",
                    description=item.get("action", f"Recommendation #{step_counter}"),
                    state_delta={"recommendation": copy.deepcopy(item)},
                ))
                step_counter += 1

            # 6. Report steps
            for item in report_events or []:
                steps.append(ReplayStep(
                    step_id=f"step-{step_counter}",
                    step_number=step_counter,
                    timestamp=item.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    step_type="REPORT",
                    description=item.get("title", f"Report Event #{step_counter}"),
                    state_delta={"report": copy.deepcopy(item)},
                ))
                step_counter += 1

            # Sort steps by timestamp
            steps.sort(key=lambda s: s.timestamp)
            for idx, s in enumerate(steps, start=1):
                s.step_number = idx

            replay_id = f"rpl-{uuid.uuid4().hex[:12]}"
            session = ReplaySession(
                replay_id=replay_id,
                investigation_id=investigation.id,
                current_step_index=0,
                total_steps=len(steps),
                status="PAUSED",
                steps=steps,
            )
            self._replays[replay_id] = session
            return session

    def get_replay(self, replay_id: str) -> Optional[ReplaySession]:
        with self._lock:
            return self._replays.get(replay_id)

    def play(self, replay_id: str) -> ReplaySession:
        with self._lock:
            session = self.get_replay(replay_id)
            if not session:
                raise ValueError(f"Replay {replay_id} not found")
            session.status = "PLAYING"
            return session

    def pause(self, replay_id: str) -> ReplaySession:
        with self._lock:
            session = self.get_replay(replay_id)
            if not session:
                raise ValueError(f"Replay {replay_id} not found")
            session.status = "PAUSED"
            return session

    def resume(self, replay_id: str) -> ReplaySession:
        return self.play(replay_id)

    def jump_to_step(self, replay_id: str, step_index: int) -> ReplayStep:
        with self._lock:
            session = self.get_replay(replay_id)
            if not session:
                raise ValueError(f"Replay {replay_id} not found")
            if not session.steps:
                raise ValueError("Replay session has no steps")
            if step_index < 0 or step_index >= len(session.steps):
                raise ValueError(f"Step index {step_index} out of bounds (0-{len(session.steps)-1})")

            session.current_step_index = step_index
            return session.steps[step_index]

    def forward(self, replay_id: str) -> ReplayStep:
        with self._lock:
            session = self.get_replay(replay_id)
            if not session:
                raise ValueError(f"Replay {replay_id} not found")
            if not session.steps:
                raise ValueError("Replay session has no steps")

            if session.current_step_index < len(session.steps) - 1:
                session.current_step_index += 1
            else:
                session.status = "COMPLETED"

            return session.steps[session.current_step_index]

    def backward(self, replay_id: str) -> ReplayStep:
        with self._lock:
            session = self.get_replay(replay_id)
            if not session:
                raise ValueError(f"Replay {replay_id} not found")
            if not session.steps:
                raise ValueError("Replay session has no steps")

            if session.current_step_index > 0:
                session.current_step_index -= 1

            return session.steps[session.current_step_index]

    def get_current_state(self, replay_id: str) -> Dict[str, Any]:
        """Constructs and returns reconstructed state up to current_step_index without mutating raw data."""
        with self._lock:
            session = self.get_replay(replay_id)
            if not session or not session.steps:
                return {}

            reconstructed = {
                "investigation_id": session.investigation_id,
                "current_step_index": session.current_step_index,
                "timeline": [],
                "graph_nodes": [],
                "graph_edges": [],
                "evidence": [],
                "reasoning_traces": [],
                "latest_confidence": 0.0,
                "recommendations": [],
                "reports": [],
            }

            active_steps = session.steps[: session.current_step_index + 1]
            for step in active_steps:
                delta = step.state_delta
                if "timeline_event" in delta:
                    reconstructed["timeline"].append(delta["timeline_event"])
                if "graph_change" in delta:
                    gc = delta["graph_change"]
                    if "nodes" in gc:
                        reconstructed["graph_nodes"].extend(gc["nodes"])
                    if "edges" in gc:
                        reconstructed["graph_edges"].extend(gc["edges"])
                if "evidence_item" in delta:
                    reconstructed["evidence"].append(delta["evidence_item"])
                if "reasoning_trace" in delta:
                    reconstructed["reasoning_traces"].append(delta["reasoning_trace"])
                if "confidence" in delta:
                    reconstructed["latest_confidence"] = delta["confidence"]
                if "recommendation" in delta:
                    reconstructed["recommendations"].append(delta["recommendation"])
                if "report" in delta:
                    reconstructed["reports"].append(delta["report"])

            return reconstructed

    def clear(self) -> None:
        with self._lock:
            self._replays.clear()
