"""
NetFusion Security Hardening Module
Input validation, output encoding, command injection protection, and path traversal guardrails.
"""

import os
import re
import html
import json
from pathlib import Path
from typing import Any, Union, Dict, List


class SecurityHardeningError(ValueError):
    """Raised when a security validation check fails."""
    pass


def validate_safe_path(base_dir: Union[str, Path], user_path: Union[str, Path]) -> Path:
    """
    Prevents Path Traversal attacks by ensuring target path resides strictly inside base_dir.
    Raises SecurityHardeningError if path escapes base_dir.
    """
    base_resolved = Path(base_dir).resolve()
    target_resolved = Path(user_path).resolve()

    try:
        target_resolved.relative_to(base_resolved)
    except ValueError:
        raise SecurityHardeningError(
            f"Path Traversal Violation: '{user_path}' escapes base directory '{base_dir}'"
        )

    return target_resolved


def sanitize_input_string(val: str, max_length: int = 10000) -> str:
    """Sanitize user input string against null bytes and excessive length."""
    if not isinstance(val, str):
        return str(val)

    if len(val) > max_length:
        raise SecurityHardeningError(f"Input string length ({len(val)}) exceeds maximum allowed ({max_length})")

    # Remove null bytes
    sanitized = val.replace("\x00", "")
    return sanitized


def sanitize_command_arg(arg: str) -> str:
    """
    Guardrail checking CLI arguments for dangerous shell injection operators
    (e.g., ;, &&, ||, |, `, $, >, <).
    """
    dangerous_patterns = [r";", r"&&", r"\|\|", r"\|", r"`", r"\$(?!\()", r">", r"<"]
    for pattern in dangerous_patterns:
        if re.search(pattern, arg):
            raise SecurityHardeningError(f"Command Injection Guardrail: argument '{arg}' contains dangerous shell token")
    return arg


def encode_output_html(text: str) -> str:
    """HTML entity encode string to prevent XSS."""
    return html.escape(text)


def safe_json_dumps(obj: Any, **kwargs) -> str:
    """Safely dump JSON object while handling non-serializable elements."""
    def default_encoder(o):
        if hasattr(o, "to_dict"):
            return o.to_dict()
        if hasattr(o, "__dict__"):
            return o.__dict__
        return str(o)

    return json.dumps(obj, default=default_encoder, **kwargs)
