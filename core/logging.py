"""Centralized logging configuration for NetFusion."""

import logging
import sys

_LOGGER_NAME = "netfusion"
_configured = False


def get_logger(name: str = None) -> logging.Logger:
    """Return a configured logger instance."""
    global _configured
    logger_name = f"{_LOGGER_NAME}.{name}" if name else _LOGGER_NAME
    logger = logging.getLogger(logger_name)
    if not _configured:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(message)s"))
        root = logging.getLogger(_LOGGER_NAME)
        root.addHandler(handler)
        root.setLevel(logging.INFO)
        _configured = True
    return logger
