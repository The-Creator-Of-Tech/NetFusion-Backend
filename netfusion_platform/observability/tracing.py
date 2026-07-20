"""
NetFusion Distributed Tracing Module
OpenTelemetry-compatible trace contexts and span propagation.
"""

import time
import uuid
from typing import Optional, Dict, Any, List
from contextlib import contextmanager


class Span:
    """Represents a single trace span in execution pipeline."""

    def __init__(self, name: str, trace_id: str, parent_span_id: Optional[str] = None):
        self.name = name
        self.trace_id = trace_id
        self.span_id = str(uuid.uuid4())[:8]
        self.parent_span_id = parent_span_id
        self.start_time = time.time()
        self.end_time: Optional[float] = None
        self.attributes: Dict[str, Any] = {}
        self.status: str = "OK"

    def set_attribute(self, key: str, value: Any) -> None:
        self.attributes[key] = value

    def set_error(self, err: Exception) -> None:
        self.status = "ERROR"
        self.attributes["error.type"] = type(err).__name__
        self.attributes["error.message"] = str(err)

    def finish(self) -> None:
        self.end_time = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_ms": int(((self.end_time or time.time()) - self.start_time) * 1000),
            "status": self.status,
            "attributes": self.attributes,
        }


class TraceTracer:
    """Manages active trace spans and trace context lifecycle."""

    def __init__(self):
        self._spans: List[Span] = []

    def start_span(self, name: str, trace_id: Optional[str] = None, parent_span_id: Optional[str] = None) -> Span:
        t_id = trace_id or str(uuid.uuid4())
        span = Span(name=name, trace_id=t_id, parent_span_id=parent_span_id)
        self._spans.append(span)
        return span

    @contextmanager
    def trace_context(self, name: str, trace_id: Optional[str] = None):
        span = self.start_span(name=name, trace_id=trace_id)
        try:
            yield span
        except Exception as e:
            span.set_error(e)
            raise
        finally:
            span.finish()

    def get_completed_spans(self) -> List[Dict[str, Any]]:
        return [s.to_dict() for s in self._spans]
