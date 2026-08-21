"""Authentication service managing registration, login, token issuance, and rotation."""

from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, Union
import uuid
from fastapi import HTTPException, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.rbac import get_role_permissions
from app.core.security import (
    TOKEN_TYPE_MFA_PENDING,
    TOKEN_TYPE_REFRESH,
    create_access_token,
    create_mfa_pending_token,
    create_refresh_token,
    decode_token,
    hash_password,
    hash_token,
    verify_password,
    verify_token_hash,
)
from app.models.token import RefreshToken
from app.models.user import User
from app.schemas.auth import (
    MFAPendingResponse,
    TokenResponse,
    UserRegisterRequest,
)
from app.services.audit_service import log_security_event
from app.services.mfa_service import verify_user_mfa


async def register_user(
    db: AsyncSession,
    register_data: UserRegisterRequest,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> User:
    """Register a new user account with validated credentials."""
    email_clean = register_data.email.lower().strip()
    
    # Check duplicate email
    existing = await db.execute(select(User).where(User.email == email_clean))
    if existing.scalar_one_or_none():
        await log_security_event(
            db,
            event_type="REGISTER_FAILED_DUPLICATE_EMAIL",
            user_email=email_clean,
            ip_address=ip_address,
            user_agent=user_agent,
            status="WARNING",
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email address already exists.",
        )

    user = User(
        email=email_clean,
        hashed_password=hash_password(register_data.password),
        full_name=register_data.full_name,
        role="user",
        is_active=True,
        is_verified=False,
        mfa_enabled=False,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    await log_security_event(
        db,
        event_type="USER_REGISTERED",
        user_id=user.id,
        user_email=user.email,
        ip_address=ip_address,
        user_agent=user_agent,
        status="SUCCESS",
    )
    return user


async def create_user_tokens(
    db: AsyncSession,
    user: User,
    family_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> TokenResponse:
    """
    Issue a new Access Token and single-use Refresh Token.
    Stores the hashed refresh token with family tracking.
    """
    permissions = get_role_permissions(user.role)
    access_token = create_access_token(
        subject=user.id,
        role=user.role,
        permissions=permissions,
    )

    token_family = family_id or str(uuid.uuid4())
    raw_refresh_token, jti = create_refresh_token(subject=user.id)
    
    # Calculate expiry datetime for refresh token
    expires_at = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    token_entity = RefreshToken(
        user_id=user.id,
        token_hash=hash_token(raw_refresh_token),
        jti=jti,
        family_id=token_family,
        is_revoked=False,
        expires_at=expires_at,
    )
    db.add(token_entity)
    await db.commit()

    return TokenResponse(
        access_token=access_token,
        refresh_token=raw_refresh_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        role=user.role,
        permissions=permissions,
    )


async def authenticate_user(
    db: AsyncSession,
    email: str,
    password: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Tuple[User, bool, Union[TokenResponse, MFAPendingResponse]]:
    """
    Authenticate primary credentials.
    If MFA is enabled, returns (user, True, MFAPendingResponse).
    Otherwise returns (user, False, TokenResponse).
    """
    email_clean = email.lower().strip()
    result = await db.execute(select(User).where(User.email == email_clean))
    user = result.scalar_one_or_none()

    if not user or not verify_password(password, user.hashed_password):
        await log_security_event(
            db,
            event_type="LOGIN_FAILED_BAD_CREDENTIALS",
            user_email=email_clean,
            ip_address=ip_address,
            user_agent=user_agent,
            status="FAILURE",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        await log_security_event(
            db,
            event_type="LOGIN_FAILED_INACTIVE_ACCOUNT",
            user_id=user.id,
            user_email=user.email,
            ip_address=ip_address,
            user_agent=user_agent,
            status="WARNING",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This user account has been deactivated.",
        )

    # Check Multi-Factor Authentication requirement
    if user.mfa_enabled:
        mfa_token = create_mfa_pending_token(subject=user.id)
        await log_security_event(
            db,
            event_type="MFA_CHALLENGE_ISSUED",
            user_id=user.id,
            user_email=user.email,
            ip_address=ip_address,
            user_agent=user_agent,
            status="SUCCESS",
        )
        return user, True, MFAPendingResponse(mfa_token=mfa_token)

    # Standard Login Success
    tokens = await create_user_tokens(db, user, ip_address=ip_address, user_agent=user_agent)
    user.last_login = datetime.now(timezone.utc)
    await db.commit()

    await log_security_event(
        db,
        event_type="LOGIN_SUCCESS",
        user_id=user.id,
        user_email=user.email,
        ip_address=ip_address,
        user_agent=user_agent,
        status="SUCCESS",
        details={"mfa_used": False},
    )
    return user, False, tokens


async def verify_mfa_login(
    db: AsyncSession,
    mfa_token: str,
    code: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> TokenResponse:
    """
    Validate the second factor (TOTP code or backup code) using the intermediate MFA challenge token.
    Issues full session tokens upon success.
    """
    try:
        payload = decode_token(mfa_token, expected_type=TOKEN_TYPE_MFA_PENDING)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or account is deactivated.",
        )

    is_valid, method = await verify_user_mfa(db, user, code)
    if not is_valid:
        await log_security_event(
            db,
            event_type="MFA_LOGIN_FAILED",
            user_id=user.id,
            user_email=user.email,
            ip_address=ip_address,
            user_agent=user_agent,
            status="FAILURE",
            details={"reason": "Invalid TOTP or backup code"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid two-factor authentication code.",
        )

    tokens = await create_user_tokens(db, user, ip_address=ip_address, user_agent=user_agent)
    user.last_login = datetime.now(timezone.utc)
    await db.commit()

    await log_security_event(
        db,
        event_type="MFA_LOGIN_SUCCESS",
        user_id=user.id,
        user_email=user.email,
        ip_address=ip_address,
        user_agent=user_agent,
        status="SUCCESS",
        details={"verification_method": method},
    )
    return tokens


async def refresh_token_pair(
    db: AsyncSession,
    refresh_token_str: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> TokenResponse:
    """
    Perform Refresh Token Rotation:
    - Decodes token and verifies signature.
    - Checks database hash.
    - If a revoked token is used, trigger Family Revocation (indicates token theft / replay attack).
    - If valid, revokes old token and issues fresh token pair preserving family chain.
    """
    try:
        payload = decode_token(refresh_token_str, expected_type=TOKEN_TYPE_REFRESH)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_jti = payload.get("jti")
    user_id = payload.get("sub")

    # Fetch token entity from DB
    result = await db.execute(select(RefreshToken).where(RefreshToken.jti == token_jti))
    token_record = result.scalar_one_or_none()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token.",
        )

    # REPLAY ATTACK DETECTION
    if token_record.is_revoked:
        # Revoke ALL tokens in this family immediately!
        await db.execute(
            update(RefreshToken)
            .where(RefreshToken.family_id == token_record.family_id)
            .values(is_revoked=True)
        )
        await db.commit()

        await log_security_event(
            db,
            event_type="SUSPICIOUS_TOKEN_REPLAY_DETECTED",
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            status="WARNING",
            details={
                "jti": token_jti,
                "family_id": token_record.family_id,
                "action": "All sessions in family revoked",
            },
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Security alert: Token reuse detected. All active sessions in this sequence have been revoked.",
        )

    # Verify expiration against database stored timestamp
    now = datetime.now(timezone.utc)
    expires_at = token_record.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < now:
        token_record.is_revoked = True
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired. Please log in again.",
        )

    # Fetch user
    user_res = await db.execute(select(User).where(User.id == user_id))
    user = user_res.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account inactive or not found.",
        )

    # Invalidate the consumed refresh token
    token_record.is_revoked = True

    # Rotate into a new token pair maintaining the same family_id
    new_tokens = await create_user_tokens(
        db,
        user=user,
        family_id=token_record.family_id,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    await log_security_event(
        db,
        event_type="TOKEN_ROTATED",
        user_id=user.id,
        user_email=user.email,
        ip_address=ip_address,
        user_agent=user_agent,
        status="SUCCESS",
        details={"family_id": token_record.family_id},
    )

    return new_tokens


async def revoke_refresh_token(
    db: AsyncSession,
    refresh_token_str: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> None:
    """Logout / revoke an active refresh token."""
    try:
        payload = decode_token(refresh_token_str, expected_type=TOKEN_TYPE_REFRESH)
        token_jti = payload.get("jti")
        user_id = payload.get("sub")
        
        result = await db.execute(select(RefreshToken).where(RefreshToken.jti == token_jti))
        token_record = result.scalar_one_or_none()
        if token_record:
            token_record.is_revoked = True
            await db.commit()

            await log_security_event(
                db,
                event_type="USER_LOGOUT",
                user_id=user_id,
                ip_address=ip_address,
                user_agent=user_agent,
                status="SUCCESS",
                details={"jti": token_jti},
            )
    except Exception:
        # Avoid leaking token errors during logout
        pass
