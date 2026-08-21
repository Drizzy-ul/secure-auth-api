"""MFA business logic: TOTP generation, validation, activation, and recovery codes."""

from typing import List, Optional, Tuple
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from app.core.mfa import (
    generate_backup_codes,
    generate_qr_code_png_base64,
    generate_qr_code_svg,
    generate_totp_secret,
    get_totp_uri,
    hash_backup_code,
    verify_backup_code,
    verify_totp_code,
)
from app.models.user import User
from app.schemas.mfa import MFASetupResponse
from app.services.audit_service import log_security_event


async def initiate_mfa_setup(db: AsyncSession, user: User) -> MFASetupResponse:
    """
    Begin the MFA onboarding flow.
    Generates a new TOTP secret and QR codes without activating MFA until confirmed.
    """
    secret = generate_totp_secret()
    user.mfa_secret = secret
    await db.commit()
    await db.refresh(user)

    uri = get_totp_uri(secret, user.email)
    qr_png = generate_qr_code_png_base64(uri)
    qr_svg = generate_qr_code_svg(uri)

    return MFASetupResponse(
        secret=secret,
        provisioning_uri=uri,
        qr_code_png_base64=qr_png,
        qr_code_svg=qr_svg,
    )


async def confirm_and_enable_mfa(
    db: AsyncSession,
    user: User,
    totp_code: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> List[str]:
    """
    Verify the initial TOTP code to ensure the user has successfully synced their authenticator.
    Activates MFA and generates 10 single-use emergency recovery backup codes.
    """
    if not user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA setup has not been initiated. Call /mfa/setup first.",
        )

    if not verify_totp_code(user.mfa_secret, totp_code):
        await log_security_event(
            db,
            event_type="MFA_ENABLE_FAILED",
            user_id=user.id,
            user_email=user.email,
            ip_address=ip_address,
            user_agent=user_agent,
            status="FAILURE",
            details={"reason": "Invalid verification code during setup"},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid authentication code. Please check the time on your device and try again.",
        )

    # Generate and securely hash backup codes
    raw_backup_codes = generate_backup_codes()
    hashed_codes = [hash_backup_code(code) for code in raw_backup_codes]

    user.mfa_enabled = True
    user.backup_codes = hashed_codes
    await db.commit()
    await db.refresh(user)

    await log_security_event(
        db,
        event_type="MFA_ENABLED",
        user_id=user.id,
        user_email=user.email,
        ip_address=ip_address,
        user_agent=user_agent,
        status="SUCCESS",
        details={"backup_codes_generated": len(raw_backup_codes)},
    )

    return raw_backup_codes


async def disable_mfa(
    db: AsyncSession,
    user: User,
    code: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> None:
    """Deactivate MFA on account after verifying TOTP or a backup code."""
    if not user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is not currently enabled for this account.",
        )

    is_valid, method = await verify_user_mfa(db, user, code)
    if not is_valid:
        await log_security_event(
            db,
            event_type="MFA_DISABLE_FAILED",
            user_id=user.id,
            user_email=user.email,
            ip_address=ip_address,
            user_agent=user_agent,
            status="FAILURE",
            details={"reason": "Invalid verification code during disable request"},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid authentication code.",
        )

    user.mfa_enabled = False
    user.mfa_secret = None
    user.backup_codes = []
    await db.commit()
    await db.refresh(user)

    await log_security_event(
        db,
        event_type="MFA_DISABLED",
        user_id=user.id,
        user_email=user.email,
        ip_address=ip_address,
        user_agent=user_agent,
        status="WARNING",
        details={"verified_via": method},
    )


async def regenerate_backup_codes(
    db: AsyncSession,
    user: User,
    totp_code: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> List[str]:
    """Regenerate a new set of 10 backup codes after validating active TOTP."""
    if not user.mfa_enabled or not user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is not enabled on this account.",
        )

    if not verify_totp_code(user.mfa_secret, totp_code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid TOTP authentication code.",
        )

    raw_backup_codes = generate_backup_codes()
    hashed_codes = [hash_backup_code(code) for code in raw_backup_codes]

    user.backup_codes = hashed_codes
    flag_modified(user, "backup_codes")
    await db.commit()
    await db.refresh(user)

    await log_security_event(
        db,
        event_type="MFA_BACKUP_CODES_REGENERATED",
        user_id=user.id,
        user_email=user.email,
        ip_address=ip_address,
        user_agent=user_agent,
        status="SUCCESS",
    )

    return raw_backup_codes


async def verify_user_mfa(
    db: AsyncSession,
    user: User,
    code: str,
) -> Tuple[bool, str]:
    """
    Verify an MFA code against user's TOTP secret or backup recovery codes.
    If a backup code is matched, it is immediately invalidated and removed (single-use).
    Returns (is_valid, method) where method is 'totp', 'backup_code', or 'none'.
    """
    cleaned_code = code.strip()

    # 1. Test TOTP verification
    if user.mfa_secret and verify_totp_code(user.mfa_secret, cleaned_code):
        return True, "totp"

    # 2. Test Backup Codes
    if user.backup_codes:
        for idx, hashed_code in enumerate(user.backup_codes):
            if verify_backup_code(cleaned_code, hashed_code):
                # Consume and remove the used backup code
                updated_backup_codes = list(user.backup_codes)
                updated_backup_codes.pop(idx)
                user.backup_codes = updated_backup_codes
                flag_modified(user, "backup_codes")
                await db.commit()
                return True, "backup_code"

    return False, "none"
