"""
NetFusion Metrics Collection Module
Counters, Gauges, and Histograms for platform-wide observability.
"""

import time
import threading
from typing import Dict, Any, List, Optional


class PlatformMetricsManager:
    """Thread-safe Prometheus-compatible metrics registry and collector."""

    def __init__(self):
        self._lock = threading.Lock()
        self._counters: Dict[str, float] = {}
        self._gauges: Dict[str, float] = {}
        self._histograms: Dict[str, List[float]] = {}

    def increment_counter(self, name: str, value: float = 1.0, labels: Optional[Dict[str, str]] = None) -> None:
        key = self._format_key(name, labels)
        with self._lock:
            self._counters[key] = self._counters.get(key, 0.0) + value

    def set_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        key = self._format_key(name, labels)
        with self._lock:
            self._gauges[key] = value

    def record_histogram(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        key = self._format_key(name, labels)
        with self._lock:
            if key not in self._histograms:
                self._histograms[key] = []
            self._histograms[key].append(value)

    def get_all_metrics(self) -> Dict[str, Any]:
        with self._lock:
            histogram_summary = {}
            for k, vals in self._histograms.items():
                if vals:
                    histogram_summary[k] = {
                        "count": len(vals),
                        "sum": sum(vals),
                        "avg": sum(vals) / len(vals),
                        "min": min(vals),
                        "max": max(vals),
                    }
                else:
                    histogram_summary[k] = {"count": 0, "sum": 0.0, "avg": 0.0, "min": 0.0, "max": 0.0}

            return {
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
                "histograms": histogram_summary,
            }

    @staticmethod
    def _format_key(name: str, labels: Optional[Dict[str, str]] = None) -> str:
        if not labels:
            return name
        label_str = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"
