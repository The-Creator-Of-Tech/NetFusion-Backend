import os
import time

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

from typing import Any, Dict


class ThreatIntelMetrics:
    """
    Performance and Telemetry Metrics Manager for Threat Intelligence Collector.
    Tracks IOC lookups, cache ratios, provider latencies, CPU, Memory, and emitted objects.
    """

    def __init__(self):
        self.start_time: float = time.time()
        self.ioc_lookups: int = 0
        self.cache_hits: int = 0
        self.cache_misses: int = 0
        self.provider_failures: int = 0
        self.rate_limit_events: int = 0
        self.threat_matches: int = 0
        self.objects_emitted: int = 0
        self.provider_latencies: Dict[str, float] = {}
        self.provider_counts: Dict[str, int] = {}

    def record_lookup(self, count: int = 1) -> None:
        self.ioc_lookups += count

    def record_cache_hit(self) -> None:
        self.cache_hits += 1

    def record_cache_miss(self) -> None:
        self.cache_misses += 1

    def record_provider_latency(self, provider_name: str, latency_ms: float) -> None:
        current = self.provider_latencies.get(provider_name, 0.0)
        cnt = self.provider_counts.get(provider_name, 0)
        self.provider_latencies[provider_name] = current + latency_ms
        self.provider_counts[provider_name] = cnt + 1

    def record_failure(self) -> None:
        self.provider_failures += 1

    def record_rate_limit(self) -> None:
        self.rate_limit_events += 1

    def record_threat_match(self) -> None:
        self.threat_matches += 1

    def record_object_emitted(self) -> None:
        self.objects_emitted += 1

    def get_cache_hit_ratio(self) -> float:
        total = self.cache_hits + self.cache_misses
        return (self.cache_hits / total) if total > 0 else 0.0

    def get_avg_provider_latency(self, provider_name: str) -> float:
        cnt = self.provider_counts.get(provider_name, 0)
        if cnt == 0:
            return 0.0
        return round(self.provider_latencies.get(provider_name, 0.0) / cnt, 2)

    def get_resource_usage(self) -> Dict[str, float]:
        if not HAS_PSUTIL:
            return {"cpu_percent": 0.0, "memory_mb": 0.0}
        try:
            process = psutil.Process(os.getpid())
            cpu_percent = process.cpu_percent(interval=None)
            mem_info = process.memory_info()
            mem_mb = mem_info.rss / (1024 * 1024)
            return {"cpu_percent": cpu_percent, "memory_mb": round(mem_mb, 2)}
        except Exception:
            return {"cpu_percent": 0.0, "memory_mb": 0.0}

    def get_summary(self) -> Dict[str, Any]:
        duration = time.time() - self.start_time
        res_usage = self.get_resource_usage()
        avg_latencies = {
            prov: self.get_avg_provider_latency(prov) for prov in self.provider_counts
        }

        return {
            "execution_duration_seconds": round(duration, 4),
            "total_ioc_lookups": self.ioc_lookups,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "cache_hit_ratio": round(self.get_cache_hit_ratio(), 4),
            "provider_failures": self.provider_failures,
            "rate_limit_events": self.rate_limit_events,
            "threat_matches": self.threat_matches,
            "objects_emitted": self.objects_emitted,
            "avg_provider_latencies_ms": avg_latencies,
            "cpu_percent": res_usage["cpu_percent"],
            "memory_mb": res_usage["memory_mb"],
        }
