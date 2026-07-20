"""
NetFusion Role-Based Access Control (RBAC) Module
Enforces least-privilege permission checks across administrative, analyst, auditor, and service roles.
"""

from enum import Enum
from typing import Set, Dict, List, Union


class Role(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    AUDITOR = "auditor"
    COLLECTOR_SERVICE = "collector_service"
    READ_ONLY = "read_only"


class Permission(str, Enum):
    # Investigation permissions
    INVESTIGATION_READ = "investigation:read"
    INVESTIGATION_CREATE = "investigation:create"
    INVESTIGATION_UPDATE = "investigation:update"
    INVESTIGATION_DELETE = "investigation:delete"
    INVESTIGATION_CLOSE = "investigation:close"

    # Collector permissions
    COLLECTOR_READ = "collector:read"
    COLLECTOR_EXECUTE = "collector:execute"
    COLLECTOR_MANAGE = "collector:manage"

    # AI permissions
    AI_ANALYZE = "ai:analyze"
    AI_CONFIGURE = "ai:configure"

    # Reporting permissions
    REPORT_GENERATE = "report:generate"
    REPORT_EXPORT = "report:export"

    # System permissions
    SYSTEM_ADMIN = "system:admin"
    AUDIT_READ = "audit:read"
    SECRET_READ = "secret:read"


# Mapping from Role to granted Permission set
ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
    Role.ADMIN: set(Permission),  # All permissions
    
    Role.ANALYST: {
        Permission.INVESTIGATION_READ,
        Permission.INVESTIGATION_CREATE,
        Permission.INVESTIGATION_UPDATE,
        Permission.INVESTIGATION_CLOSE,
        Permission.COLLECTOR_READ,
        Permission.COLLECTOR_EXECUTE,
        Permission.AI_ANALYZE,
        Permission.REPORT_GENERATE,
        Permission.REPORT_EXPORT,
        Permission.AUDIT_READ,
    },
    
    Role.AUDITOR: {
        Permission.INVESTIGATION_READ,
        Permission.COLLECTOR_READ,
        Permission.REPORT_GENERATE,
        Permission.REPORT_EXPORT,
        Permission.AUDIT_READ,
    },
    
    Role.COLLECTOR_SERVICE: {
        Permission.COLLECTOR_READ,
        Permission.COLLECTOR_EXECUTE,
        Permission.INVESTIGATION_READ,
        Permission.INVESTIGATION_UPDATE,
    },
    
    Role.READ_ONLY: {
        Permission.INVESTIGATION_READ,
        Permission.COLLECTOR_READ,
    },
}


class AuthorizationError(ValueError):
    """Raised when access is denied due to insufficient permissions."""
    pass


class RBACEngine:
    """Evaluates roles and permissions for access control enforcement."""

    def __init__(self, role_mappings: Optional[Dict[Role, Set[Permission]]] = None):
        self._mappings = role_mappings or ROLE_PERMISSIONS

    def get_permissions_for_roles(self, roles: Set[Union[Role, str]]) -> Set[Permission]:
        """Aggregate all permissions granted across user's assigned roles."""
        permissions: Set[Permission] = set()
        for r in roles:
            try:
                role_enum = Role(r)
                permissions.update(self._mappings.get(role_enum, set()))
            except ValueError:
                pass
        return permissions

    def has_permission(self, user_roles: Set[Union[Role, str]], required_permission: Permission) -> bool:
        """Check if any assigned role grants the required permission."""
        user_perms = self.get_permissions_for_roles(user_roles)
        return required_permission in user_perms

    def check_permission(self, user_roles: Set[Union[Role, str]], required_permission: Permission) -> None:
        """Enforce permission requirement; raises AuthorizationError if not granted."""
        if not self.has_permission(user_roles, required_permission):
            raise AuthorizationError(
                f"Access Denied: Roles {list(user_roles)} lack required permission '{required_permission.value}'"
            )
