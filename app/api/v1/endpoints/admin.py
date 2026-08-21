"""Administrative and security auditing endpoints."""

from typing import Any, Dict, List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import RequirePermission
from app.config import settings
from app.core.rbac import ROLE_PERMISSIONS, Permission
from app.db.session import get_db
from app.schemas.audit import AuditLogRead
from app.schemas.common import PaginatedResponse
from app.services import audit_service

router = APIRouter(prefix="/admin", tags=["Administration & Security"])


@router.get(
    "/audit-logs",
    response_model=PaginatedResponse[AuditLogRead],
    summary="Query security audit trail",
    description="Inspect immutable security audit logs. Requires 'audit:read' permission.",
    dependencies=[Depends(RequirePermission(Permission.AUDIT_READ))],
)
async def get_audit_logs(
    event_type: str = Query(None, description="Filter by event type"),
    user_email: str = Query(None, description="Filter by user email"),
    status: str = Query(None, description="Filter by status (SUCCESS, FAILURE, WARNING)"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
) -> PaginatedResponse[AuditLogRead]:
    logs, total = await audit_service.query_audit_logs(
        db=db,
        event_type=event_type,
        user_email=user_email,
        status=status,
        skip=skip,
        limit=limit,
    )
    return PaginatedResponse[AuditLogRead](
        items=[AuditLogRead.model_validate(log) for log in logs],
        total=total,
        skip=skip,
        limit=limit,
    )


@router.get(
    "/roles-permissions",
    summary="List RBAC roles and permissions matrix",
    description="Inspect the active Least Privilege Role-to-Permissions matrix.",
    dependencies=[Depends(RequirePermission(Permission.AUDIT_READ))],
)
async def get_roles_permissions() -> Dict[str, List[str]]:
    return {
        role.value: sorted([perm.value for perm in perms])
        for role, perms in ROLE_PERMISSIONS.items()
    }


@router.get(
    "/system-status",
    summary="Security and system configuration overview",
    description="Returns high-level system parameters and security controls.",
    dependencies=[Depends(RequirePermission(Permission.SYSTEM_ADMIN))],
)
async def get_system_status() -> Dict[str, Any]:
    return {
        "project": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "cryptography": {
            "jwt_algorithm": settings.ALGORITHM,
            "access_token_expire_minutes": settings.ACCESS_TOKEN_EXPIRE_MINUTES,
            "refresh_token_expire_days": settings.REFRESH_TOKEN_EXPIRE_DAYS,
            "mfa_token_expire_minutes": settings.MFA_TOKEN_EXPIRE_MINUTES,
        },
        "mfa": {
            "issuer": settings.MFA_ISSUER_NAME,
            "backup_code_count": settings.MFA_BACKUP_CODE_COUNT,
            "totp_standard": "RFC 6238",
        },
        "rate_limiting": {
            "default": settings.RATE_LIMIT_DEFAULT,
            "login": settings.RATE_LIMIT_LOGIN,
            "register": settings.RATE_LIMIT_REGISTER,
            "mfa": settings.RATE_LIMIT_MFA,
        },
    }
