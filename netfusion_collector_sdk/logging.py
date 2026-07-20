import json
import logging
import sys
import time
from typing import Any, Dict, Optional


class StructuredJSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt) or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "correlation_id": getattr(record, "correlation_id", "N/A"),
            "trace_id": getattr(record, "trace_id", "N/A"),
            "collector_id": getattr(record, "collector_id", "N/A"),
            "execution_id": getattr(record, "execution_id", "N/A"),
            "investigation_id": getattr(record, "investigation_id", "N/A"),
        }
        if hasattr(record, "extra_payload"):
            log_entry["payload"] = getattr(record, "extra_payload")
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)


class LoggingManager:
    """Runtime Logging Manager providing contextual structured JSON logging."""

    def __init__(
        self,
        name: str = "netfusion.collector",
        collector_id: Optional[str] = None,
        execution_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        investigation_id: Optional[str] = None,
        level: int = logging.INFO,
    ):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        self.collector_id = collector_id
        self.execution_id = execution_id
        self.correlation_id = correlation_id
        self.trace_id = trace_id
        self.investigation_id = investigation_id

        if not self.logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(StructuredJSONFormatter())
            self.logger.addHandler(handler)

    def _get_extra(self, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        base_extra = {
            "collector_id": self.collector_id,
            "execution_id": self.execution_id,
            "correlation_id": self.correlation_id,
            "trace_id": self.trace_id,
            "investigation_id": self.investigation_id,
        }
        if extra:
            base_extra["extra_payload"] = extra
        return base_extra

    def info(self, msg: str, payload: Optional[Dict[str, Any]] = None) -> None:
        self.logger.info(msg, extra=self._get_extra(payload))

    def debug(self, msg: str, payload: Optional[Dict[str, Any]] = None) -> None:
        self.logger.debug(msg, extra=self._get_extra(payload))

    def warning(self, msg: str, payload: Optional[Dict[str, Any]] = None) -> None:
        self.logger.warning(msg, extra=self._get_extra(payload))

    def error(self, msg: str, payload: Optional[Dict[str, Any]] = None, exc_info: bool = False) -> None:
        self.logger.error(msg, extra=self._get_extra(payload), exc_info=exc_info)

    def critical(self, msg: str, payload: Optional[Dict[str, Any]] = None, exc_info: bool = False) -> None:
        self.logger.critical(msg, extra=self._get_extra(payload), exc_info=exc_info)
