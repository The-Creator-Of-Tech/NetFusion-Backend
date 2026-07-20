"""
Structured logging module for netfusion_intelligence.
Ensures every synchronization produces structured log metrics.
"""

from datetime import datetime, timezone
import json
import logging
import sys
from typing import Any, Dict, Optional


class StructuredJsonFormatter(logging.Formatter):
    """
    JSON Formatter for structured logging.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_obj: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "sync_details") and isinstance(record.sync_details, dict): # type: ignore
            log_obj.update(record.sync_details) # type: ignore

        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_obj)


def get_structured_logger(name: str = "netfusion_intelligence") -> logging.Logger:
    """
    Returns a configured structured logger.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(StructuredJsonFormatter())
        logger.addHandler(handler)
    return logger


def log_sync_summary(
    logger: logging.Logger,
    feed_id: str,
    start_time: str,
    finish_time: str,
    duration: float,
    records_processed: int,
    records_inserted: int,
    records_updated: int,
    validation_result: Dict[str, Any],
    errors: Optional[list] = None,
) -> None:
    """
    Helper to emit structured synchronization execution summary log.
    """
    summary = {
        "event": "intelligence_sync_summary",
        "feed_id": feed_id,
        "start_time": start_time,
        "finish_time": finish_time,
        "duration_seconds": duration,
        "records_processed": records_processed,
        "records_inserted": records_inserted,
        "records_updated": records_updated,
        "validation_result": validation_result,
        "errors": errors or [],
    }
    extra = {"sync_details": summary}
    if errors:
        logger.error(f"Synchronization finished with errors for feed '{feed_id}'", extra=extra)
    else:
        logger.info(f"Synchronization completed successfully for feed '{feed_id}'", extra=extra)
