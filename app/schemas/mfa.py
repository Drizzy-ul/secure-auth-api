"""Multi-Factor Authentication (MFA) schemas."""

from typing import List, Optional
from pydantic import BaseModel


class MFASetupResponse(BaseModel):
    """Response containing TOTP secret, provisioning URI, and QR codes."""
    secret: str
    provisioning_uri: str
    qr_code_png_base64: str
    qr_code_svg: str


class MFAEnableRequest(BaseModel):
    """Request to verify initial TOTP and formally activate MFA on account."""
    code: str


class MFADisableRequest(BaseModel):
    """Request to deactivate MFA with TOTP verification code or backup code."""
    code: str


class MFAVerifyRequest(BaseModel):
    """Generic TOTP or backup code verification request."""
    code: str


class MFABackupCodesResponse(BaseModel):
    """Response returning freshly generated emergency backup recovery codes."""
    backup_codes: List[str]
    message: str = (
        "Store these recovery codes in a secure location. "
        "Each code can only be used once to access your account if your authenticator device is lost."
    )
