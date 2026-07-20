"""
NetFusion Platform Security Package
Authentication, Authorization, RBAC, Secret Store, Log Redactor, and Hardening.
"""

from netfusion_platform.security.auth import (
    AuthManager,
    UserSession,
    AuthenticationError,
)
from netfusion_platform.security.rbac import (
    Role,
    Permission,
    ROLE_PERMISSIONS,
    RBACEngine,
    AuthorizationError,
)
from netfusion_platform.security.secrets import (
    SecretStore,
    SecretItem,
    SecretLogMasker,
)
from netfusion_platform.security.hardening import (
    validate_safe_path,
    sanitize_input_string,
    sanitize_command_arg,
    encode_output_html,
    safe_json_dumps,
    SecurityHardeningError,
)

__all__ = [
    "AuthManager",
    "UserSession",
    "AuthenticationError",
    "Role",
    "Permission",
    "ROLE_PERMISSIONS",
    "RBACEngine",
    "AuthorizationError",
    "SecretStore",
    "SecretItem",
    "SecretLogMasker",
    "validate_safe_path",
    "sanitize_input_string",
    "sanitize_command_arg",
    "encode_output_html",
    "safe_json_dumps",
    "SecurityHardeningError",
]
