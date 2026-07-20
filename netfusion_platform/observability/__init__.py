"""
NetFusion Observability Package
Structured JSON logging, Prometheus-compatible metrics, tracing context, and health aggregation.
"""

from netfusion_platform.observability.logger import (
    StructuredJsonFormatter,
    setup_platform_logger,
)
from netfusion_platform.observability.metrics import (
    PlatformMetricsManager,
)
from netfusion_platform.observability.tracing import (
    Span,
    TraceTracer,
)
from netfusion_platform.observability.health import (
    HealthAggregator,
    PlatformHealthReport,
)

__all__ = [
    "StructuredJsonFormatter",
    "setup_platform_logger",
    "PlatformMetricsManager",
    "Span",
    "TraceTracer",
    "HealthAggregator",
    "PlatformHealthReport",
]
