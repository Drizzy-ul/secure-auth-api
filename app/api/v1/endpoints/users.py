"""User profile, password management, and user administration endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    RequirePermission,
    get_client_info,
    get_current_active_user,
)
from app.core.rbac import Permission, has_permission
from app.db.session import get_db
from app.models.user import User
from app.schemas.auth import PasswordChangeRequest
from app.schemas.common import MessageResponse, PaginatedResponse
from app.schemas.user import UserRead, UserRoleUpdate, UserUpdate
from app.services import user_service

router = APIRouter(prefix="/users", tags=["Users"])


@router.get(
    "/me",
    response_model=UserRead,
    summary="Get current user profile",
    description="Retrieves profile information for the authenticated user.",
)
async def get_me(
    current_user: User = Depends(get_current_active_user),
) -> UserRead:
    return current_user


@router.patch(
    "/me",
    response_model=UserRead,
    summary="Update current user profile",
    description="Updates editable profile details (e.g. full name) for the authenticated user.",
)
async def update_me(
    payload: UserUpdate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> UserRead:
    return await user_service.update_user_profile(
        db=db,
        user=current_user,
        full_name=payload.full_name,
    )


@router.post(
    "/me/change-password",
    response_model=MessageResponse,
    summary="Change password",
    description="Updates user password and terminates all existing refresh token sessions.",
)
async def change_password(
    request: Request,
    payload: PasswordChangeRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    ip_address, user_agent = get_client_info(request)
    await user_service.change_user_password(
        db=db,
        user=current_user,
        current_password=payload.current_password,
        new_password=payload.new_password,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    return MessageResponse(message="Password successfully updated. All other active sessions have been signed out.")


@router.get(
    "/",
    response_model=PaginatedResponse[UserRead],
    summary="List all users",
    description="Lists all users in the system. Requires 'user:read_all' permission.",
    dependencies=[Depends(RequirePermission(Permission.USER_READ_ALL))],
)
async def list_users(
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
) -> PaginatedResponse[UserRead]:
    users, total = await user_service.list_users(db=db, skip=skip, limit=limit)
    return PaginatedResponse[UserRead](
        items=[UserRead.model_validate(u) for u in users],
        total=total,
        skip=skip,
        limit=limit,
    )


@router.get(
    "/{user_id}",
    response_model=UserRead,
    summary="Get user by ID",
    description="Fetches a user profile. Allowed if viewing own profile or if caller holds 'user:read_all' permission.",
)
async def get_user_by_id(
    user_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> UserRead:
    # Check ownership or elevated privilege (OWASP Broken Object Level Authorization mitigation)
    if current_user.id != user_id and not has_permission(current_user.role, Permission.USER_READ_ALL):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: You can only view your own user account.",
        )

    user = await user_service.get_user_by_id(db=db, user_id=user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )
    return user


@router.patch(
    "/{user_id}/role",
    response_model=UserRead,
    summary="Update user role",
    description="Modifies a user's role adhering strictly to hierarchical Least Privilege controls.",
    dependencies=[Depends(RequirePermission(Permission.USER_CHANGE_ROLE))],
)
async def update_user_role(
    user_id: str,
    payload: UserRoleUpdate,
    request: Request,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> UserRead:
    ip_address, user_agent = get_client_info(request)
    target_user = await user_service.get_user_by_id(db=db, user_id=user_id)
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target user not found.",
        )

    updated = await user_service.update_user_role(
        db=db,
        target_user=target_user,
        new_role=payload.role,
        actor_user=current_user,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    return updated
