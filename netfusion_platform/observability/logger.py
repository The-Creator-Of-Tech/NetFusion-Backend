"""
NetFusion Structured Logging & Correlation Module
JSON-formatted structured logging with correlation/trace IDs and secret masking filter.
"""

import json
import logging
import time
import uuid
from typing import Optional, Dict, Any
from netfusion_platform.security.secrets import SecretLogMasker


class StructuredJsonFormatter(logging.Formatter):
    """JSON formatter for enterprise structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
        }

        # Correlation and Trace IDs
        if hasattr(record, "correlation_id"):
            log_entry["correlation_id"] = record.correlation_id
        if hasattr(record, "trace_id"):
            log_entry["trace_id"] = record.trace_id

        # Exception details
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry)


def setup_platform_logger(
    name: str = "netfusion",
    level: str = "INFO",
    secret_masker: Optional[SecretLogMasker] = None
) -> logging.Logger:
    """Configure platform-wide structured logger with optional secret log masking."""
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()

    handler = logging.StreamHandler()
    handler.setFormatter(StructuredJsonFormatter())

    if secret_masker:
        handler.addFilter(secret_masker)

    logger.addHandler(handler)
    logger.propagate = False
    return logger
