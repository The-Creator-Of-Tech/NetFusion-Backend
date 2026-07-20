"""
NetFusion REST API Server & Health Endpoints Module
Exposes Health probes (/health, /liveness, /readiness), Investigation APIs, Metrics, and Collector endpoints.
"""

from typing import Dict, Any, Optional, List
from netfusion_platform.orchestrator import PlatformOrchestrator
from netfusion_platform.reporting.generator import ProductionReportGenerator, InvestigationProductionReport

try:
    from fastapi import FastAPI, HTTPException, Depends, Header, status
    from fastapi.responses import JSONResponse, PlainTextResponse
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False


def create_app(orchestrator: Optional[PlatformOrchestrator] = None) -> Any:
    """Create and configure FastAPI application if FastAPI is installed."""
    orch = orchestrator or PlatformOrchestrator()
    if not orch._is_started:
        orch.startup()

    if not HAS_FASTAPI:
        # Lightweight fallback client if FastAPI is not installed
        class DummyApp:
            def __init__(self, orchestrator):
                self.orchestrator = orchestrator

            def get_health(self):
                return self.orchestrator.get_health().__dict__

            def get_liveness(self):
                return {"status": "UP"}

            def get_readiness(self):
                return {"status": "READY" if self.orchestrator._is_started else "NOT_READY"}

        return DummyApp(orch)

    app = FastAPI(
        title="NetFusion Investigation Platform API",
        version=orch.config.version,
        description="Production API exposing investigation pipelines, health probes, and reporting.",
    )

    @app.get("/health", tags=["Health"])
    def get_health():
        """Aggregated platform health status report."""
        report = orch.get_health()
        status_code = status.HTTP_200_OK if report.status in ("HEALTHY", "DEGRADED") else status.HTTP_503_SERVICE_UNAVAILABLE
        return JSONResponse(content=report.__dict__, status_code=status_code)

    @app.get("/health/liveness", tags=["Health Probes"])
    def liveness_probe():
        """Kubernetes/Container liveness probe."""
        return {"status": "UP"}

    @app.get("/health/readiness", tags=["Health Probes"])
    def readiness_probe():
        """Kubernetes/Container readiness probe."""
        if orch._is_started:
            return {"status": "READY"}
        raise HTTPException(status_code=503, detail="Platform initializing")

    @app.get("/api/v1/metrics", tags=["Observability"])
    def get_metrics():
        """Prometheus metrics endpoint."""
        return orch.metrics_manager.get_all_metrics()

    @app.post("/api/v1/investigations/run", tags=["Pipeline"])
    def run_investigation(payload: Dict[str, Any]):
        """Execute an end-to-end investigation pipeline run."""
        title = payload.get("title", "API Triggered Investigation")
        events = payload.get("events", [])
        result = orch.pipeline_orchestrator.run_investigation_pipeline(
            case_title=title,
            raw_events=events,
        )
        return {
            "case_id": result["case"].id,
            "investigation_id": result["investigation"].id,
            "timeline_count": result["timeline_count"],
            "evidence_count": result["evidence_count"],
            "status": result["status"],
        }

    @app.get("/api/v1/collectors", tags=["Collectors"])
    def list_collectors():
        """List registered collectors and health."""
        return orch._registered_collectors

    return app
