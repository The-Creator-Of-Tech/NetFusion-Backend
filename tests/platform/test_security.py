"""
Integration tests for NetFusion Security, Auth, RBAC, Secret Store & Log Redactor.
"""

import pytest
import logging
from netfusion_platform.security import (
    AuthManager,
    AuthenticationError,
    RBACEngine,
    Role,
    Permission,
    AuthorizationError,
    SecretStore,
    SecretLogMasker,
    validate_safe_path,
    SecurityHardeningError,
)


def test_auth_jwt_and_api_keys():
    auth = AuthManager(jwt_secret="test-secret-key-123")
    
    # API key test
    auth.register_api_key("secret_api_key_val", "user_1", {Role.ANALYST})
    ctx = auth.validate_api_key("secret_api_key_val")
    assert ctx is not None
    assert ctx["user_id"] == "user_1"

    # JWT test
    token = auth.create_jwt("user_1", "analyst_bob", {Role.ANALYST})
    payload = auth.verify_jwt(token)
    assert payload["sub"] == "user_1"
    assert "analyst" in payload["roles"]

    # Revocation test
    auth.revoke_token(token)
    with pytest.raises(AuthenticationError):
        auth.verify_jwt(token)


def test_rbac_engine():
    rbac = RBACEngine()
    
    # Analyst permissions
    assert rbac.has_permission({Role.ANALYST}, Permission.INVESTIGATION_READ)
    assert rbac.has_permission({Role.ANALYST}, Permission.AI_ANALYZE)
    assert not rbac.has_permission({Role.ANALYST}, Permission.SYSTEM_ADMIN)

    with pytest.raises(AuthorizationError):
        rbac.check_permission({Role.ANALYST}, Permission.SYSTEM_ADMIN)


def test_secret_log_masker():
    masker = SecretLogMasker()
    masker.add_secret("super_secret_password_999")

    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=1,
        msg="Logged password: super_secret_password_999 in text",
        args=(),
        exc_info=None
    )

    masker.filter(record)
    assert "super_secret_password_999" not in record.msg
    assert "[REDACTED_SECRET]" in record.msg


def test_path_traversal_hardening():
    base = "c:\\Netfusion\\NetFusion-Agent" if False else "/tmp/base"
    import tempfile, os
    with tempfile.TemporaryDirectory() as tmpdir:
        sub = os.path.join(tmpdir, "valid.txt")
        open(sub, "w").write("test")
        
        valid_p = validate_safe_path(tmpdir, sub)
        assert valid_p.exists()

        with pytest.raises(SecurityHardeningError):
            validate_safe_path(tmpdir, os.path.join(tmpdir, "..", "escaped.txt"))
