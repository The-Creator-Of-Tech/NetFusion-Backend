import os
import time
from typing import Dict, Any

try:
    import psutil
except ImportError:
    psutil = None


class MetricsManager:
    """Metrics Manager tracking collector performance, CPU, memory, and telemetry."""

    def __init__(self, collector_id: str, execution_id: str):
        self.collector_id = collector_id
        self.execution_id = execution_id
        self.start_time = time.time()
        self.packets_captured = 0
        self.packets_processed = 0
        self.flows_generated = 0
        self.objects_generated = 0
        self.dropped_packets = 0
        self._process = psutil.Process(os.getpid()) if psutil else None

    def increment_packets_captured(self, count: int = 1) -> None:
        self.packets_captured += count

    def increment_packets_processed(self, count: int = 1) -> None:
        self.packets_processed += count

    def increment_flows_generated(self, count: int = 1) -> None:
        self.flows_generated += count

    def increment_objects_generated(self, count: int = 1) -> None:
        self.objects_generated += count

    def increment_dropped_packets(self, count: int = 1) -> None:
        self.dropped_packets += count

    def get_cpu_percent(self) -> float:
        if not self._process:
            return 0.0
        try:
            return self._process.cpu_percent(interval=None)
        except Exception:
            return 0.0

    def get_memory_bytes(self) -> int:
        if not self._process:
            return 0
        try:
            return self._process.memory_info().rss
        except Exception:
            return 0

    def get_summary(self) -> Dict[str, Any]:
        duration = time.time() - self.start_time
        return {
            "collector_id": self.collector_id,
            "execution_id": self.execution_id,
            "packets_captured": self.packets_captured,
            "packets_processed": self.packets_processed,
            "flows_generated": self.flows_generated,
            "objects_generated": self.objects_generated,
            "dropped_packets": self.dropped_packets,
            "duration_seconds": round(duration, 4),
            "cpu_percent": self.get_cpu_percent(),
            "memory_peak_bytes": self.get_memory_bytes(),
        }
