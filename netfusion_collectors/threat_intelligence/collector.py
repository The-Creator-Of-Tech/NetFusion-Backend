import os
import shutil
import time
import traceback
from typing import Any, Dict, List, Optional
from netfusion_collector_sdk import (
    BaseCollector,
    CollectorContext,
    CollectionResult,
    ExecutionState,
)
from .config import ThreatIntelConfig, IOCType
from .cache import ThreatIntelCache
from .metrics import ThreatIntelMetrics
from .health import ThreatIntelHealthChecker
from .correlator import ThreatCorrelator
from .runner import ThreatIntelRunner
from .providers import IOCInput, ProviderResponse
from .events import ThreatIntelMatchedEvent


class ThreatIntelCollector(BaseCollector):
    """
    Production-ready Threat Intelligence Collector extending BaseCollector.
    Integrates Collector SDK, Runtime Engine, Canonical Data Model, Validation Pipeline,
    Event Bus, and InvestigationContext.
    """

    def __init__(self, context: Optional[CollectorContext] = None):
        super().__init__(context=context)
        self.context.collector_type = "ThreatIntelCollector"
        self.threat_config: ThreatIntelConfig = ThreatIntelConfig()
        self.cache: Optional[ThreatIntelCache] = None
        self.collector_metrics: ThreatIntelMetrics = ThreatIntelMetrics()
        self.health_checker: Optional[ThreatIntelHealthChecker] = None
        self.correlator: ThreatCorrelator = ThreatCorrelator()
        self.runner: Optional[ThreatIntelRunner] = None
        self.temp_scratch_dir: Optional[str] = None

    def validate_configuration(self, config: Dict[str, Any]) -> bool:
        ThreatIntelConfig(**config)
        return True

    def on_configure(self, config: Dict[str, Any]) -> None:
        self.threat_config = ThreatIntelConfig(**config)

        # Initialize Two-Tier Cache
        cache_db_path = os.path.join(self.threat_config.cache_dir, "cache.db")
        self.cache = ThreatIntelCache(
            db_path=cache_db_path,
            default_ttl=self.threat_config.cache_ttl,
        )

        # Initialize Metrics & Health Checker
        self.collector_metrics = ThreatIntelMetrics()
        self.health_checker = ThreatIntelHealthChecker(self.threat_config)

        # Initialize Async Runner
        self.runner = ThreatIntelRunner(
            config=self.threat_config,
            cache=self.cache,
            metrics=self.collector_metrics,
        )

    def on_pre_execute(self) -> None:
        if self.logger:
            self.logger.info(
                "Executing Threat Intelligence pre-execution health probes.",
                {"collector_id": self.context.collector_id},
            )

        if self.health_checker:
            report = self.health_checker.run_all()
            if report.status == "DEGRADED" and self.logger:
                self.logger.warning(
                    "Threat Intelligence Collector health probe reported warnings/degradation.",
                    {"warnings": report.warnings, "errors": report.errors},
                )

        # Create temporary working directory
        self.temp_scratch_dir = os.path.join(
            self.context.temp_dir,
            f"threat_intel_{self.context.execution_id}",
        )
        os.makedirs(self.temp_scratch_dir, exist_ok=True)

    def execute_collection(self) -> CollectionResult:
        if not self.runner or not self.cache:
            raise RuntimeError("Collector runner not initialized. Ensure on_configure() is executed.")

        start_time = time.time()
        emitted_objects: List[Any] = []

        if self.event_publisher:
            self.event_publisher.publish_started(
                execution_id=self.context.execution_id,
                collector_id=self.context.collector_id,
                config_summary={"batch_size": self.threat_config.batch_size},
            )

        if self.logger:
            self.logger.info(
                f"Starting Threat Intelligence Enrichment [BatchSize: {self.threat_config.batch_size}]",
                {"execution_id": self.context.execution_id},
            )

        try:
            # 1. Gather input IOCs from Config & InvestigationContext
            iocs_to_enrich: List[IOCInput] = self._extract_iocs()

            total_iocs = len(iocs_to_enrich)
            if self.logger:
                self.logger.info(
                    f"Extracted {total_iocs} IOCs for threat intelligence lookup.",
                    {"total_iocs": total_iocs},
                )

            # 2. Execute Async Enrichment via Runner
            provider_responses: List[ProviderResponse] = self.runner.execute_sync(iocs_to_enrich)

            # 3. Correlate Responses into Canonical Objects & Emit
            for idx, resp in enumerate(provider_responses, 1):
                canonical_objs = self.correlator.correlate_provider_response(resp, self.context)

                for c_obj in canonical_objs:
                    success = self.emit_canonical_object(c_obj)
                    if success:
                        emitted_objects.append(c_obj)
                        self.collector_metrics.record_object_emitted()

                        # Emit custom ThreatIntelMatchedEvent if threat matched
                        if c_obj.canonical_type.endswith("ThreatIntelMatched") and self.event_publisher:
                            try:
                                matched_event = ThreatIntelMatchedEvent(
                                    execution_id=self.context.execution_id,
                                    collector_id=self.context.collector_id,
                                    ioc_value=getattr(c_obj, "ioc_value", ""),
                                    ioc_type=getattr(c_obj, "ioc_type", ""),
                                    provider=getattr(c_obj, "provider", ""),
                                    threat_name=getattr(c_obj, "threat_name", ""),
                                    severity=getattr(c_obj, "match_severity", "MEDIUM"),
                                    confidence=getattr(c_obj, "confidence", 0.0),
                                )
                                self.event_publisher._publish(matched_event)
                            except Exception:
                                pass

                if total_iocs > 0 and (idx % 5 == 0 or idx == len(provider_responses)):
                    self.emit_progress(
                        current=idx,
                        total=len(provider_responses),
                        message=f"Enriched {idx}/{len(provider_responses)} provider responses",
                    )

            end_time = time.time()
            duration = end_time - start_time

            metrics_summary = self.collector_metrics.get_summary()

            if self.event_publisher:
                self.event_publisher.publish_completed(
                    execution_id=self.context.execution_id,
                    collector_id=self.context.collector_id,
                    metrics_summary=metrics_summary,
                    duration_seconds=duration,
                )

            result = CollectionResult(
                execution_id=self.context.execution_id,
                collector_id=self.context.collector_id,
                status=ExecutionState.COMPLETED,
                packets_captured=total_iocs,
                packets_processed=total_iocs,
                objects_generated=len(emitted_objects),
                start_time=start_time,
                end_time=end_time,
                duration_seconds=duration,
                emitted_objects=emitted_objects,
                metadata=metrics_summary,
            )
            return result

        except Exception as e:
            if self.event_publisher:
                self.event_publisher.publish_failure(
                    execution_id=self.context.execution_id,
                    collector_id=self.context.collector_id,
                    error_type=type(e).__name__,
                    error_message=str(e),
                    stack_trace=traceback.format_exc(),
                )
            raise

    def _extract_iocs(self) -> List[IOCInput]:
        """Extracts and normalizes IOCs from config and InvestigationContext metadata."""
        iocs: List[IOCInput] = []

        # Config IOCs
        for raw_ioc in self.threat_config.iocs:
            if isinstance(raw_ioc, dict) and "value" in raw_ioc:
                iocs.append(
                    IOCInput(
                        value=str(raw_ioc["value"]).strip(),
                        type=str(raw_ioc.get("type", "IPv4")).strip(),
                        context_metadata=raw_ioc.get("metadata", {}),
                    )
                )

        # InvestigationContext metadata IOCs
        if self.threat_config.enrich_investigation_context and self.context.metadata:
            ctx_iocs = self.context.metadata.get("iocs", [])
            for raw_ioc in ctx_iocs:
                if isinstance(raw_ioc, dict) and "value" in raw_ioc:
                    iocs.append(
                        IOCInput(
                            value=str(raw_ioc["value"]).strip(),
                            type=str(raw_ioc.get("type", "IPv4")).strip(),
                            context_metadata=raw_ioc.get("metadata", {}),
                        )
                    )

        # Remove duplicates preserving order
        seen = set()
        unique_iocs = []
        for ioc in iocs:
            key = (ioc.value.lower(), ioc.type.lower())
            if key not in seen and ioc.value:
                seen.add(key)
                unique_iocs.append(ioc)

        return unique_iocs

    def on_post_execute(self, result: CollectionResult) -> None:
        if self.logger:
            self.logger.info(
                "Threat Intelligence collection execution completed successfully.",
                {
                    "iocs_processed": result.packets_captured,
                    "objects_generated": result.objects_generated,
                    "duration_seconds": result.duration_seconds,
                },
            )

    def on_cleanup(self) -> None:
        if self.temp_scratch_dir and os.path.exists(self.temp_scratch_dir):
            try:
                shutil.rmtree(self.temp_scratch_dir, ignore_errors=True)
            except Exception:
                pass
