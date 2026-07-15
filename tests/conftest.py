"""
conftest.py — patch outbound HTTP before any test module is collected.

api.persistence calls requests.post to localhost:4000 at import time
(via call_repository).  We must intercept this before pytest's collection
phase imports the test file, so we use a pytest plugin hook (pytest_configure)
which runs before collection.
"""
from unittest.mock import MagicMock, patch as _patch


def _make_ok_response(data=None):
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = data if data is not None else []
    resp.raise_for_status.return_value = None
    return resp


# Start patches at plugin-registration time (before collection).
_post_patcher = _patch("requests.post", return_value=_make_ok_response())
_get_patcher  = _patch("requests.get",  return_value=_make_ok_response())


def pytest_configure(config):
    """Called very early — before any test modules are imported."""
    _post_patcher.start()
    _get_patcher.start()


def pytest_unconfigure(config):
    """Clean up after the session ends."""
    _post_patcher.stop()
    _get_patcher.stop()
