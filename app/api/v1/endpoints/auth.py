"""Authentication endpoints for registration, login, MFA challenge, refresh, and logout."""

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_client_info
from app.config import settings
from app.core.rate_limit import limiter
from app.db.session import get_db
from app.schemas.auth import (
    LoginResponse,
    MFALoginRequest,
    RefreshTokenRequest,
    TokenResponse,
    UserLoginRequest,
    UserRegisterRequest,
)
from app.schemas.common import MessageResponse
from app.schemas.user import UserRead
from app.services import auth_service

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/register",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    description="Registers a new user account with strict password complexity validation.",
)
@limiter.limit(settings.RATE_LIMIT_REGISTER)
async def register(
    request: Request,
    response: Response,
    payload: UserRegisterRequest,
    db: AsyncSession = Depends(get_db),
) -> UserRead:
    ip_address, user_agent = get_client_info(request)
    user = await auth_service.register_user(
        db=db,
        register_data=payload,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    return user


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="User login",
    description="Authenticates credentials. Returns access & refresh tokens or an MFA pending challenge token.",
)
@limiter.limit(settings.RATE_LIMIT_LOGIN)
async def login(
    request: Request,
    response: Response,
    payload: UserLoginRequest,
    db: AsyncSession = Depends(get_db),
) -> LoginResponse:
    ip_address, user_agent = get_client_info(request)
    _, _, response_payload = await auth_service.authenticate_user(
        db=db,
        email=payload.email,
        password=payload.password,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    return response_payload


@router.post(
    "/login/mfa",
    response_model=TokenResponse,
    summary="Complete MFA login challenge",
    description="Submits TOTP code or single-use emergency backup recovery code with the intermediate MFA challenge token.",
)
@limiter.limit(settings.RATE_LIMIT_MFA)
async def login_mfa(
    request: Request,
    response: Response,
    payload: MFALoginRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    ip_address, user_agent = get_client_info(request)
    tokens = await auth_service.verify_mfa_login(
        db=db,
        mfa_token=payload.mfa_token,
        code=payload.code,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    return tokens


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Rotate refresh token",
    description="Exchanges an unrevoked single-use refresh token for a brand new token pair. Triggers family revocation upon token reuse.",
)
@limiter.limit(settings.RATE_LIMIT_DEFAULT)
async def refresh_tokens(
    request: Request,
    response: Response,
    payload: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    ip_address, user_agent = get_client_info(request)
    tokens = await auth_service.refresh_token_pair(
        db=db,
        refresh_token_str=payload.refresh_token,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    return tokens


@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Revoke refresh token session",
    description="Revokes the provided refresh token session.",
)
async def logout(
    request: Request,
    payload: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    ip_address, user_agent = get_client_info(request)
    await auth_service.revoke_refresh_token(
        db=db,
        refresh_token_str=payload.refresh_token,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    return MessageResponse(message="Successfully logged out and session revoked.")
