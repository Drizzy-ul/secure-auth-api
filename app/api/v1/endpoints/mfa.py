"""Multi-Factor Authentication (MFA) management endpoints."""

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import RequirePermission, get_client_info, get_current_active_user
from app.config import settings
from app.core.rate_limit import limiter
from app.core.rbac import Permission
from app.db.session import get_db
from app.models.user import User
from app.schemas.common import MessageResponse
from app.schemas.mfa import (
    MFABackupCodesResponse,
    MFADisableRequest,
    MFAEnableRequest,
    MFASetupResponse,
)
from app.services import mfa_service

router = APIRouter(prefix="/mfa", tags=["Multi-Factor Authentication"])


@router.post(
    "/setup",
    response_model=MFASetupResponse,
    summary="Initiate MFA setup",
    description="Generates a new TOTP secret, provisioning URI, and QR codes for authenticator app enrollment.",
    dependencies=[Depends(RequirePermission(Permission.MFA_MANAGE_SELF))],
)
@limiter.limit(settings.RATE_LIMIT_MFA)
async def mfa_setup(
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> MFASetupResponse:
    return await mfa_service.initiate_mfa_setup(db=db, user=current_user)


@router.post(
    "/enable",
    response_model=MFABackupCodesResponse,
    summary="Verify & enable MFA",
    description="Validates the initial TOTP code to confirm authenticator setup, enables MFA, and returns 10 emergency recovery codes.",
    dependencies=[Depends(RequirePermission(Permission.MFA_MANAGE_SELF))],
)
@limiter.limit(settings.RATE_LIMIT_MFA)
async def mfa_enable(
    request: Request,
    response: Response,
    payload: MFAEnableRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> MFABackupCodesResponse:
    ip_address, user_agent = get_client_info(request)
    backup_codes = await mfa_service.confirm_and_enable_mfa(
        db=db,
        user=current_user,
        totp_code=payload.code,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    return MFABackupCodesResponse(backup_codes=backup_codes)


@router.post(
    "/disable",
    response_model=MessageResponse,
    summary="Disable MFA",
    description="Deactivates MFA on the account after authenticating with a valid TOTP code or backup code.",
    dependencies=[Depends(RequirePermission(Permission.MFA_MANAGE_SELF))],
)
@limiter.limit(settings.RATE_LIMIT_MFA)
async def mfa_disable(
    request: Request,
    response: Response,
    payload: MFADisableRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    ip_address, user_agent = get_client_info(request)
    await mfa_service.disable_mfa(
        db=db,
        user=current_user,
        code=payload.code,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    return MessageResponse(message="Multi-factor authentication has been successfully disabled.")


@router.post(
    "/backup-codes/regenerate",
    response_model=MFABackupCodesResponse,
    summary="Regenerate backup recovery codes",
    description="Invalidates existing backup codes and generates a fresh set of 10 emergency recovery codes.",
    dependencies=[Depends(RequirePermission(Permission.MFA_MANAGE_SELF))],
)
@limiter.limit(settings.RATE_LIMIT_MFA)
async def mfa_regenerate_backup_codes(
    request: Request,
    response: Response,
    payload: MFAEnableRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> MFABackupCodesResponse:
    ip_address, user_agent = get_client_info(request)
    backup_codes = await mfa_service.regenerate_backup_codes(
        db=db,
        user=current_user,
        totp_code=payload.code,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    return MFABackupCodesResponse(backup_codes=backup_codes)
