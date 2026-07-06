"""Date and time formatting utilities."""

from datetime import datetime


def utc_iso_timestamp() -> str:
    return datetime.utcnow().isoformat() + "Z"


def report_display_timestamp() -> str:
    return datetime.now().strftime("%d %b %Y %H:%M")


def local_iso_timestamp() -> str:
    return datetime.now().isoformat()
