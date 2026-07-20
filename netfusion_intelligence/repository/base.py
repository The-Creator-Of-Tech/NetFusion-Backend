"""
Base repository helpers.
"""

from typing import Any, Dict
import json


def serialize_json(data: Any) -> str:
    if data is None:
        return "{}"
    if isinstance(data, str):
        return data
    try:
        return json.dumps(data)
    except Exception:
        return "{}"


def deserialize_json(data: str) -> Dict[str, Any]:
    if not data:
        return {}
    try:
        return json.loads(data)
    except Exception:
        return {}
