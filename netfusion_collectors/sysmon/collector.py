import time
import traceback
from typing import Any, Dict, List, Optional, Union
from netfusion_collector_sdk import (
    BaseCollector,
    CollectorContext,
    CollectionResult,
    ExecutionState,
)
from .config import SysmonConfig
from .runner import SysmonEventRunner
from .mapper import SysmonCanonicalMapper
from .health import SysmonHealthChecker
from .bookmark import BookmarkManager


class SysmonCollector(BaseCollector):
    """
    Enterprise Microsoft Sysmon Collector extending BaseCollector.
    Ingests Sysmon telemetry from Windows System Event Log or offline EVTX log files,
    converting them into normalized Canonical Endpoint Observations.
    """

    def __init__(self, context: Optional[CollectorContext] = None):
        super().__init__(context=context)
        self.context.collector_type = "SysmonCollector"
        self.sysmon_config: SysmonConfig = SysmonConfig()
        self.runner: Optional[SysmonEventRunner] = None
        self.mapper: SysmonCanonicalMapper = SysmonCanonicalMapper()
        self.health_checker: Optional[SysmonHealthChecker] = None
        self.bookmark_manager: Optional[BookmarkManager] = None
        self._mock_input_events: Optional[List[Any]] = None

    def set_mock_input_events(self, mock_events: List[Any]) -> None:
        """Sets input events for unit testing and offline mock runs."""
        self._mock_input_events = mock_events

    def validate_configuration(self, config: Dict[str, Any]) -> bool:
        SysmonConfig(**config)
        return True

    def on_configure(self, config: Dict[str, Any]) -> None:
        self.sysmon_config = SysmonConfig(**config)
        if self.sysmon_config.persist_bookmark:
            self.bookmark_manager = BookmarkManager(self.sysmon_config.bookmark_path)
        else:
            self.bookmark_manager = BookmarkManager(None)

        self.runner = SysmonEventRunner(self.sysmon_config, bookmark_manager=self.bookmark_manager)
        self.health_checker = SysmonHealthChecker(
            channel=self.sysmon_config.channel,
            bookmark_path=self.sysmon_config.bookmark_path,
            evtx_path=self.sysmon_config.evtx_file_path,
        )

    def on_pre_execute(self) -> None:
        if self.logger:
            self.logger.info(
                "Executing Sysmon pre-execution health probes.",
                {"config": self.sysmon_config.model_dump()},
            )

        if self.health_checker:
            report = self.health_checker.run_all(collector_id=self.context.collector_id)
            if report.status == "UNHEALTHY" and self.logger:
                self.logger.warning(
                    "Sysmon pre-execution health probe returned warnings.",
                    {"errors": report.errors},
                )

    def execute_collection(self) -> CollectionResult:
        if not self.runner:
            raise RuntimeError("Collector runner not initialized. Ensure on_configure() is executed.")

        start_time = time.time()
        emitted_objects: List[Any] = []
        dropped_events = 0
        parser_failures = 0

        if self.event_publisher:
            self.event_publisher.publish_started(
                execution_id=self.context.execution_id,
                collector_id=self.context.collector_id,
                config_summary=self.sysmon_config.model_dump(),
            )

        if self.logger:
            self.logger.info(
                f"Starting Sysmon Ingestion [Source: {self.sysmon_config.event_source.value}, Mode: {self.sysmon_config.collection_mode.value}]",
                {"execution_id": self.context.execution_id},
            )

        try:
            # Fetch events via runner strategy
            raw_events = self.runner.fetch_events(mock_events=self._mock_input_events)
            total_events = len(raw_events)

            if self.logger:
                self.logger.info(
                    f"Fetched {total_events} Sysmon events for processing.",
                    {"total_events": total_events, "execution_id": self.context.execution_id},
                )

            for idx, event_dict in enumerate(raw_events, 1):
                if self.metrics:
                    self.metrics.increment_packets_captured()

                try:
                    canonical_objs = self.mapper.map_event(event_dict, self.sysmon_config, self.context)
                    if not canonical_objs and event_dict:
                        dropped_events += 1
                        if self.metrics:
                            self.metrics.increment_dropped_packets()

                    for c_obj in canonical_objs:
                        success = self.emit_canonical_object(c_obj)
                        if success:
                            emitted_objects.append(c_obj)
                        else:
                            dropped_events += 1
                            if self.metrics:
                                self.metrics.increment_dropped_packets()

                    if self.metrics:
                        self.metrics.increment_packets_processed()

                except Exception as ex:
                    parser_failures += 1
                    dropped_events += 1
                    if self.metrics:
                        self.metrics.increment_dropped_packets()
                    if self.logger:
                        self.logger.warning(
                            f"Parser/mapping error on event index {idx}: {str(ex)}",
                            {"event": event_dict},
                        )

                if total_events > 0 and (idx % self.sysmon_config.batch_size == 0 or idx == total_events):
                    self.emit_progress(
                        current=idx,
                        total=total_events,
                        message=f"Processed event batch {idx}/{total_events}",
                    )

            end_time = time.time()
            duration = end_time - start_time
            events_per_sec = (total_events / duration) if duration > 0 else 0.0

            metrics_summary = self.metrics.get_summary() if self.metrics else {
                "events_processed": total_events,
                "events_per_sec": round(events_per_sec, 2),
                "objects_emitted": len(emitted_objects),
                "dropped_events": dropped_events,
                "parser_failures": parser_failures,
                "duration_seconds": round(duration, 4),
            }

            metrics_summary["events_per_sec"] = round(events_per_sec, 2)
            metrics_summary["dropped_events"] = dropped_events
            metrics_summary["parser_failures"] = parser_failures

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
                packets_captured=total_events,
                packets_processed=total_events - parser_failures,
                objects_generated=len(emitted_objects),
                dropped_packets=dropped_events,
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

    def on_post_execute(self, result: CollectionResult) -> None:
        if self.logger:
            self.logger.info(
                "Sysmon collection execution finished.",
                {
                    "total_events": result.packets_captured,
                    "objects_generated": result.objects_generated,
                    "duration_seconds": result.duration_seconds,
                },
            )

    def on_cleanup(self) -> None:
        if self.bookmark_manager and self.sysmon_config.persist_bookmark:
            self.bookmark_manager.save()
