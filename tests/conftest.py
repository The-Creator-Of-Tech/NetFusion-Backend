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
    if "localhost:4000" in url or "127.0.0.1:4000" in url:
        return _make_ok_response()
    return _original_get(url, *args, **kwargs)

def _patched_post(url, *args, **kwargs):
    if "localhost:4000" in url or "127.0.0.1:4000" in url:
        return _make_ok_response()
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
