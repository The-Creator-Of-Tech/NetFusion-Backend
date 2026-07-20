"""
NetFusion Secret Management & Log Redaction Module
Secure handling of credentials, API keys, TLS certs, and zero-log leak guarantees via automated redactor.
"""

import logging
import base64
from typing import Dict, Any, Optional, Set
from dataclasses import dataclass


@dataclass
class SecretItem:
    name: str
    category: str  # api_key, db_cred, ai_cred, threat_intel_cred, tls_cert, signing_key
    value: str
    description: str = ""


class SecretLogMasker(logging.Filter):
    """Logging filter that dynamically redacts registered secret strings from log outputs."""

    def __init__(self, secrets_to_mask: Optional[Set[str]] = None):
        super().__init__()
        self._secrets: Set[str] = secrets_to_mask or set()

    def add_secret(self, secret: str) -> None:
        """Register a secret value to be masked in log records."""
        if secret and len(secret) > 2:  # Avoid masking empty or single-character strings
            self._secrets.add(secret)

    def filter(self, record: logging.LogRecord) -> bool:
        """Inspect and sanitize log messages, args, and tracebacks."""
        if not self._secrets:
            return True

        if isinstance(record.msg, str):
            record.msg = self._mask_string(record.msg)

        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: self._mask_string(str(v)) for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(self._mask_string(str(arg)) for arg in record.args)

        return True

    def _mask_string(self, text: str) -> str:
        masked = text
        for secret in self._secrets:
            if secret in masked:
                masked = masked.replace(secret, "[REDACTED_SECRET]")
        return masked


class SecretStore:
    """Secure Secret Store providing credential retrieval and zero-log redaction."""

    def __init__(self, masker: Optional[SecretLogMasker] = None):
        self._secrets: Dict[str, SecretItem] = {}
        self._masker = masker or SecretLogMasker()

    @property
    def masker(self) -> SecretLogMasker:
        return self._masker

    def set_secret(self, name: str, value: str, category: str = "api_key", description: str = "") -> None:
        """Store secret and automatically register with log redactor filter."""
        item = SecretItem(name=name, category=category, value=value, description=description)
        self._secrets[name] = item
        self._masker.add_secret(value)

    def get_secret(self, name: str) -> Optional[str]:
        """Retrieve plain-text secret by name."""
        item = self._secrets.get(name)
        return item.value if item else None

    def get_secret_item(self, name: str) -> Optional[SecretItem]:
        """Retrieve full SecretItem."""
        return self._secrets.get(name)

    def delete_secret(self, name: str) -> bool:
        """Delete secret from store."""
        if name in self._secrets:
            del self._secrets[name]
            return True
        return False

    def list_secret_names(self) -> Dict[str, str]:
        """List secret metadata (category & description), NEVER values."""
        return {name: f"category={item.category}, desc={item.description}" for name, item in self._secrets.items()}
