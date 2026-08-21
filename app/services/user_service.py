"""User management service."""

from datetime import datetime, timezone
from typing import List, Optional, Tuple
from fastapi import HTTPException, status
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.rbac import Role, ROLE_HIERARCHY
from app.core.security import hash_password, verify_password
from app.models.token import RefreshToken
from app.models.user import User
from app.services.audit_service import log_security_event


async def get_user_by_id(db: AsyncSession, user_id: str) -> Optional[User]:
    """Fetch user by primary key ID."""
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


async def get_user_by_email(db: AsyncSession, email: str) -> Optional[User]:
    """Fetch user by lowercase email."""
    result = await db.execute(select(User).where(User.email == email.lower().strip()))
    return result.scalar_one_or_none()


async def list_users(
    db: AsyncSession,
    skip: int = 0,
    limit: int = 50,
) -> Tuple[List[User], int]:
    """Retrieve users list with total count."""
    count_query = select(func.count(User.id))
    total_count = await db.scalar(count_query) or 0

    query = select(User).order_by(User.created_at.desc()).offset(skip).limit(limit)
    result = await db.execute(query)
    users = result.scalars().all()

    return list(users), total_count


async def update_user_profile(
    db: AsyncSession,
    user: User,
    full_name: Optional[str] = None,
) -> User:
    """Update profile information for the current user."""
    if full_name is not None:
        user.full_name = full_name
    await db.commit()
    await db.refresh(user)
    return user


async def update_user_role(
    db: AsyncSession,
    target_user: User,
    new_role: Role,
    actor_user: User,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> User:
    """
    Update a user's role while enforcing Least Privilege rules:
    - Actor cannot promote anyone to a rank higher than their own.
    - Actor cannot modify the role of someone with equal or higher rank unless they are SUPERADMIN.
    """
    actor_role = Role(actor_user.role)
    target_current_role = Role(target_user.role)

    actor_rank = ROLE_HIERARCHY.get(actor_role, 0)
    target_rank = ROLE_HIERARCHY.get(target_current_role, 0)
    new_role_rank = ROLE_HIERARCHY.get(new_role, 0)

    if actor_role != Role.SUPERADMIN:
        if new_role_rank >= actor_rank:
            await log_security_event(
                db,
                event_type="UNAUTHORIZED_ROLE_ESCALATION_ATTEMPT",
                user_id=actor_user.id,
                user_email=actor_user.email,
                ip_address=ip_address,
                user_agent=user_agent,
                status="WARNING",
                details={
                    "target_user_id": target_user.id,
                    "attempted_role": new_role.value,
                },
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You cannot grant a role equal to or higher than your own tier.",
            )

        if target_rank >= actor_rank and target_user.id != actor_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You cannot modify the role of an equal or higher-ranked user.",
            )

    old_role_str = target_user.role
    target_user.role = new_role.value
    await db.commit()
    await db.refresh(target_user)

    await log_security_event(
        db,
        event_type="ROLE_CHANGED",
        user_id=actor_user.id,
        user_email=actor_user.email,
        ip_address=ip_address,
        user_agent=user_agent,
        status="SUCCESS",
        details={
            "target_user_id": target_user.id,
            "target_user_email": target_user.email,
            "old_role": old_role_str,
            "new_role": new_role.value,
        },
    )
    return target_user


async def change_user_password(
    db: AsyncSession,
    user: User,
    current_password: str,
    new_password: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> None:
    """
    Safely update user password, invalidate all existing sessions/refresh tokens.
    """
    if not verify_password(current_password, user.hashed_password):
        await log_security_event(
            db,
            event_type="PASSWORD_CHANGE_FAILED",
            user_id=user.id,
            user_email=user.email,
            ip_address=ip_address,
            user_agent=user_agent,
            status="FAILURE",
            details={"reason": "Incorrect current password"},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect.",
        )

    user.hashed_password = hash_password(new_password)

    # Invalidate all active refresh tokens for this user upon password change (OWASP Session Invalidation)
    await db.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user.id, RefreshToken.is_revoked == False)
        .values(is_revoked=True)
    )

    await db.commit()

    await log_security_event(
        db,
        event_type="PASSWORD_CHANGED",
        user_id=user.id,
        user_email=user.email,
        ip_address=ip_address,
        user_agent=user_agent,
        status="SUCCESS",
        details={"sessions_revoked": True},
    )
