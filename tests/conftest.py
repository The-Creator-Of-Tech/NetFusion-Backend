import requests
from unittest.mock import MagicMock, patch as _patch

_original_get = requests.get
_original_post = requests.post

def _make_ok_response(data=None):
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = data if data is not None else []
    resp.raise_for_status.return_value = None
    return resp

def _patched_get(url, *args, **kwargs):
    if any(h in url for h in ["localhost:4000", "127.0.0.1:4000", "localhost:8000", "127.0.0.1:8000"]):
        if "/playbooks" in url:
            return _make_ok_response({"success": True, "data": [{"playbookId": "pb_123", "name": "Test Playbook"}]})
        if "/logs" in url:
            return _make_ok_response({"success": True, "data": [{"timestamp": "2026-07-20T10:00:00Z", "level": "info", "message": "Step executed successfully"}]})
        if "/executions" in url:
            return _make_ok_response({"success": True, "data": {"executionId": "exec_123", "status": "COMPLETED", "progress": 100, "currentStep": None, "logs": [{"timestamp": "2026-07-20T10:00:00Z", "level": "info", "message": "Step executed successfully"}]}})
        return _make_ok_response({"success": True, "data": {}})
    return _original_get(url, *args, **kwargs)

def _patched_post(url, *args, **kwargs):
    if any(h in url for h in ["localhost:4000", "127.0.0.1:4000", "localhost:8000", "127.0.0.1:8000"]):
        if "/playbooks" in url and not url.endswith("/execute"):
            return _make_ok_response({"success": True, "data": {"playbookId": "pb_123"}})
        if "/execute" in url:
            resp = _make_ok_response({"success": True, "data": {"executionId": "exec_123", "status": "QUEUED"}})
            resp.status_code = 201
            return resp
        return _make_ok_response({"success": True, "data": {}})
    return _original_post(url, *args, **kwargs)

_get_patcher = _patch("requests.get", new=_patched_get)
_post_patcher = _patch("requests.post", new=_patched_post)

def pytest_configure(config):
    """Called very early — before any test modules are imported."""
    _get_patcher.start()
    _post_patcher.start()

def pytest_unconfigure(config):
    """Clean up after the session ends."""
    _get_patcher.stop()
    _post_patcher.stop()
