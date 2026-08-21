"""FastAPI authentication, authorization, and client dependencies."""

from typing import Tuple
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.rate_limit import get_client_ip
from app.core.rbac import Permission, Role, has_permission, is_role_at_least
from app.core.security import TOKEN_TYPE_ACCESS, decode_token
from app.db.session import get_db
from app.models.user import User

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_STR}/auth/login",
    auto_error=True,
)


def get_client_info(request: Request) -> Tuple[str, str]:
    """Extract client IP and User-Agent header for security audit logging."""
    ip_address = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "Unknown")[:255]
    return ip_address, user_agent


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Validate bearer access token and retrieve current authenticated user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_token(token, expected_type=TOKEN_TYPE_ACCESS)
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """Ensure authenticated user account is active."""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user account.",
        )
    return current_user


class RequirePermission:
    """
    Dependency checking that the authenticated user possesses a specific granular permission.
    Adheres to the Principle of Least Privilege.
    """
    def __init__(self, permission: Permission):
        self.permission = permission

    async def __call__(
        self,
        current_user: User = Depends(get_current_active_user),
    ) -> User:
        if not has_permission(current_user.role, self.permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Missing required permission '{self.permission.value}'.",
            )
        return current_user


class RequireRole:
    """
    Dependency checking that the authenticated user meets or exceeds a minimum role hierarchy tier.
    """
    def __init__(self, minimum_role: Role):
        self.minimum_role = minimum_role

    async def __call__(
        self,
        current_user: User = Depends(get_current_active_user),
    ) -> User:
        if not is_role_at_least(current_user.role, self.minimum_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Requires minimum role '{self.minimum_role.value}'.",
            )
        return current_user
