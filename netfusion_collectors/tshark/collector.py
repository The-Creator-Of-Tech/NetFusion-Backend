import os
import shutil
import time
from typing import Any, Dict, List, Optional
from netfusion_collector_sdk import BaseCollector, CollectorContext, CollectionResult, ExecutionState
from netfusion_canonical import NormalizationPipeline, DeadLetterQueue
from .config import TSharkConfig, TSharkOutputFormat
from .runner import TSharkProcessRunner
from .parsers import TSharkParserFactory
from .mapper import TSharkCanonicalMapper
from .health import TSharkHealthChecker


class TSharkCollector(BaseCollector):
    """
    Production-ready TShark Collector extending BaseCollector.
    Integrates Collector SDK, Runtime Engine, Canonical Data Model, Normalization Pipeline,
    Event Bus, and InvestigationContext.
    """

    def __init__(self, context: Optional[CollectorContext] = None):
        super().__init__(context=context)
        self.context.collector_type = "TSharkCollector"
        self.tshark_config: TSharkConfig = TSharkConfig()
        self.runner: Optional[TSharkProcessRunner] = None
        self.mapper: TSharkCanonicalMapper = TSharkCanonicalMapper()
        self.health_checker: Optional[TSharkHealthChecker] = None
        self.temp_scratch_dir: Optional[str] = None

    def validate_configuration(self, config: Dict[str, Any]) -> bool:
        TSharkConfig(**config)
        return True

    def on_configure(self, config: Dict[str, Any]) -> None:
        self.tshark_config = TSharkConfig(**config)
        self.runner = TSharkProcessRunner(self.tshark_config)
        self.health_checker = TSharkHealthChecker(
            tshark_path=self.tshark_config.tshark_path,
            capture_interface=self.tshark_config.capture_interface,
        )

    def on_pre_execute(self) -> None:
        if self.logger:
            self.logger.info("Executing TShark pre-execution health probes.", {"config": self.tshark_config.model_dump()})

        # Run health check
        if self.health_checker:
            health_report = self.health_checker.run_all(collector_id=self.context.collector_id)
            if health_report.status == "UNHEALTHY" and self.tshark_config.capture_mode == "live":
                if self.logger:
                    self.logger.warning("Health check failed before live capture execution.", {"errors": health_report.errors})

        # Setup temporary workspace
        self.temp_scratch_dir = os.path.join(
            self.tshark_config.temporary_storage,
            f"tshark_{self.context.execution_id}",
        )
        os.makedirs(self.temp_scratch_dir, exist_ok=True)

    def execute_collection(self) -> CollectionResult:
        if not self.runner:
            raise RuntimeError("Collector runner not initialized. Ensure on_configure() is executed.")

        if self.logger:
            self.logger.info(
                f"Starting TShark packet collection [Mode: {self.tshark_config.capture_mode.value}, Format: {self.tshark_config.output_format.value}]",
                {"execution_id": self.context.execution_id},
            )

        start_time = time.time()
        emitted_objects: List[Any] = []

        # Execute TShark subprocess
        exit_code, stdout_data, stderr_data = self.runner.execute()

        if exit_code != 0 and not stdout_data.strip():
            err_msg = f"TShark subprocess execution failed with exit code {exit_code}: {stderr_data}"
            if self.logger:
                self.logger.error(err_msg)
            raise RuntimeError(err_msg)

        # Parse TShark output
        parser = TSharkParserFactory.get_parser(self.tshark_config.output_format)
        parsed_packets = parser.parse(stdout_data)

        total_packets = len(parsed_packets)
        if self.metrics:
            self.metrics.increment_packets_captured(total_packets)

        if self.logger:
            self.logger.info(f"TShark output parsed successfully. Found {total_packets} packets.", {"total_packets": total_packets})

        # Map to Canonical Domain Objects and Normalization Pipeline
        for idx, packet_dict in enumerate(parsed_packets, 1):
            if self.metrics:
                self.metrics.increment_packets_processed(1)

            canonical_objs = self.mapper.map_packet_to_canonical(packet_dict, self.context)
            for c_obj in canonical_objs:
                success = self.emit_canonical_object(c_obj)
                if success:
                    emitted_objects.append(c_obj)
                    if c_obj.canonical_type.endswith("NetworkFlowObserved") and self.metrics:
                        self.metrics.increment_flows_generated(1)

            if total_packets > 0 and (idx % 100 == 0 or idx == total_packets):
                self.emit_progress(current=idx, total=total_packets, message=f"Processed {idx}/{total_packets} packets")

        end_time = time.time()
        duration = end_time - start_time

        result = CollectionResult(
            execution_id=self.context.execution_id,
            collector_id=self.context.collector_id,
            status=ExecutionState.COMPLETED,
            packets_captured=total_packets,
            packets_processed=total_packets,
            flows_generated=self.metrics.flows_generated if self.metrics else 0,
            objects_generated=len(emitted_objects),
            start_time=start_time,
            end_time=end_time,
            duration_seconds=duration,
            emitted_objects=emitted_objects,
        )
        return result

    def on_post_execute(self, result: CollectionResult) -> None:
        if self.logger:
            self.logger.info(
                "TShark collection execution completed.",
                {
                    "packets_captured": result.packets_captured,
                    "packets_processed": result.packets_processed,
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
