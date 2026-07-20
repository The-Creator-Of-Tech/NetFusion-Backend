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
from .config import NmapConfig
from .runner import NmapProcessRunner
from .parsers import NmapParserFactory
from .mapper import NmapCanonicalMapper
from .health import NmapHealthChecker


class NmapCollector(BaseCollector):
    """
    Production-ready Nmap Collector extending BaseCollector.
    Integrates Collector SDK, Runtime Engine, Canonical Data Model, Canonical Validation Pipeline,
    Event Bus, and InvestigationContext.
    """

    def __init__(self, context: Optional[CollectorContext] = None):
        super().__init__(context=context)
        self.context.collector_type = "NmapCollector"
        self.nmap_config: NmapConfig = NmapConfig()
        self.runner: Optional[NmapProcessRunner] = None
        self.mapper: NmapCanonicalMapper = NmapCanonicalMapper()
        self.health_checker: Optional[NmapHealthChecker] = None
        self.temp_scratch_dir: Optional[str] = None

    def validate_configuration(self, config: Dict[str, Any]) -> bool:
        NmapConfig(**config)
        return True

    def on_configure(self, config: Dict[str, Any]) -> None:
        self.nmap_config = NmapConfig(**config)
        self.runner = NmapProcessRunner(self.nmap_config)
        self.health_checker = NmapHealthChecker(
            binary_path=self.nmap_config.binary_path
        )

    def on_pre_execute(self) -> None:
        if self.logger:
            self.logger.info(
                "Executing Nmap pre-execution health probes.",
                {"config": self.nmap_config.model_dump()},
            )

        if self.health_checker:
            report = self.health_checker.run_all(collector_id=self.context.collector_id)
            if report.status == "UNHEALTHY" and self.logger:
                self.logger.warning("Nmap pre-execution health probe returned warnings.", {"errors": report.errors})

        # Set up temporary workspace
        self.temp_scratch_dir = os.path.join(
            self.nmap_config.temporary_workspace,
            f"nmap_{self.context.execution_id}",
        )
        os.makedirs(self.temp_scratch_dir, exist_ok=True)

    def execute_collection(self) -> CollectionResult:
        if not self.runner:
            raise RuntimeError("Collector runner not initialized. Ensure on_configure() is executed.")

        start_time = time.time()
        emitted_objects: List[Any] = []

        if self.event_publisher:
            self.event_publisher.publish_started(
                execution_id=self.context.execution_id,
                collector_id=self.context.collector_id,
                config_summary=self.nmap_config.model_dump(),
            )

        if self.logger:
            self.logger.info(
                f"Starting Nmap execution [ScanType: {self.nmap_config.scan_type.value}, Format: {self.nmap_config.output_format.value}]",
                {"execution_id": self.context.execution_id},
            )

        try:
            # Execute Nmap subprocess via Runtime SDK subprocess manager
            exit_code, stdout_data, stderr_data = self.runner.execute()

            if exit_code != 0 and not stdout_data.strip():
                err_msg = f"Nmap subprocess execution failed with exit code {exit_code}: {stderr_data}"
                if self.logger:
                    self.logger.error(err_msg, {"execution_id": self.context.execution_id})
                if self.event_publisher:
                    self.event_publisher.publish_failure(
                        execution_id=self.context.execution_id,
                        collector_id=self.context.collector_id,
                        error_type="SubprocessError",
                        error_message=err_msg,
                        stack_trace=traceback.format_exc(),
                    )
                raise RuntimeError(err_msg)

            # Parse output using parser strategy factory
            parser = NmapParserFactory.get_parser(self.nmap_config.output_format)
            parsed_hosts = parser.parse(stdout_data)

            total_hosts = len(parsed_hosts)
            if self.logger:
                self.logger.info(
                    f"Nmap output parsed successfully. Discovered {total_hosts} hosts.",
                    {"total_hosts": total_hosts, "execution_id": self.context.execution_id},
                )

            # Map host dictionary records to Canonical Domain Objects
            for idx, host_dict in enumerate(parsed_hosts, 1):
                canonical_objs = self.mapper.map_host_to_canonical(host_dict, self.context)
                for c_obj in canonical_objs:
                    success = self.emit_canonical_object(c_obj)
                    if success:
                        emitted_objects.append(c_obj)

                if total_hosts > 0:
                    self.emit_progress(
                        current=idx,
                        total=total_hosts,
                        message=f"Processed host {idx}/{total_hosts} ({host_dict.get('ip_address', 'unknown')})",
                    )

            end_time = time.time()
            duration = end_time - start_time

            metrics_summary = self.metrics.get_summary() if self.metrics else {"duration_seconds": round(duration, 4)}

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
                packets_captured=total_hosts,
                packets_processed=total_hosts,
                objects_generated=len(emitted_objects),
                start_time=start_time,
                end_time=end_time,
                duration_seconds=duration,
                emitted_objects=emitted_objects,
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

    def on_post_execute(self, result: CollectionResult) -> None:
        if self.logger:
            self.logger.info(
                "Nmap collection execution completed successfully.",
                {
                    "hosts_discovered": result.packets_captured,
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
