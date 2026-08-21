"""Role-Based Access Control (RBAC) and Least Privilege enforcement."""

from enum import Enum
from typing import Dict, List, Set


class Role(str, Enum):
    """User roles with increasing hierarchical privileges."""
    USER = "user"
    MODERATOR = "moderator"
    ADMIN = "admin"
    SUPERADMIN = "superadmin"


class Permission(str, Enum):
    """Granular permissions adhering to the Principle of Least Privilege."""
    # User Profile Permissions
    USER_READ_SELF = "user:read_self"
    USER_UPDATE_SELF = "user:update_self"
    MFA_MANAGE_SELF = "mfa:manage_self"

    # User Management Permissions
    USER_READ_ALL = "user:read_all"
    USER_WRITE_ALL = "user:write_all"
    USER_DELETE = "user:delete"
    USER_CHANGE_ROLE = "user:change_role"

    # Audit & Security
    AUDIT_READ = "audit:read"

    # System Operations
    SYSTEM_ADMIN = "system:admin"


# Role hierarchy weights (higher means more privileged)
ROLE_HIERARCHY: Dict[Role, int] = {
    Role.USER: 10,
    Role.MODERATOR: 20,
    Role.ADMIN: 30,
    Role.SUPERADMIN: 40,
}

# Role-to-Permissions Policy Matrix
ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
    Role.USER: {
        Permission.USER_READ_SELF,
        Permission.USER_UPDATE_SELF,
        Permission.MFA_MANAGE_SELF,
    },
    Role.MODERATOR: {
        Permission.USER_READ_SELF,
        Permission.USER_UPDATE_SELF,
        Permission.MFA_MANAGE_SELF,
        Permission.USER_READ_ALL,
    },
    Role.ADMIN: {
        Permission.USER_READ_SELF,
        Permission.USER_UPDATE_SELF,
        Permission.MFA_MANAGE_SELF,
        Permission.USER_READ_ALL,
        Permission.USER_WRITE_ALL,
        Permission.USER_CHANGE_ROLE,
        Permission.AUDIT_READ,
    },
    Role.SUPERADMIN: {
        Permission.USER_READ_SELF,
        Permission.USER_UPDATE_SELF,
        Permission.MFA_MANAGE_SELF,
        Permission.USER_READ_ALL,
        Permission.USER_WRITE_ALL,
        Permission.USER_DELETE,
        Permission.USER_CHANGE_ROLE,
        Permission.AUDIT_READ,
        Permission.SYSTEM_ADMIN,
    },
}


def get_role_permissions(role: str) -> List[str]:
    """Retrieve all permission string keys granted to a specific role."""
    try:
        role_enum = Role(role)
        permissions = ROLE_PERMISSIONS.get(role_enum, set())
        return sorted([p.value for p in permissions])
    except ValueError:
        return []


def has_permission(role: str, required_permission: Permission) -> bool:
    """Check whether a given role holds the required permission."""
    try:
        role_enum = Role(role)
        allowed = ROLE_PERMISSIONS.get(role_enum, set())
        return required_permission in allowed
    except ValueError:
        return False


def is_role_at_least(user_role: str, minimum_required_role: Role) -> bool:
    """Check whether a user's role meets or exceeds a given role hierarchy tier."""
    try:
        user_role_enum = Role(user_role)
        user_weight = ROLE_HIERARCHY.get(user_role_enum, 0)
        required_weight = ROLE_HIERARCHY.get(minimum_required_role, 0)
        return user_weight >= required_weight
    except ValueError:
        return False
