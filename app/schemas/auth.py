"""Authentication request and response schemas."""

from typing import List, Optional, Union
from pydantic import BaseModel, ConfigDict, EmailStr, field_validator

from app.core.security import validate_password_strength


class UserRegisterRequest(BaseModel):
    """Registration request payload with password complexity enforcement."""
    email: EmailStr
    password: str
    full_name: Optional[str] = None

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        is_valid, error_msg = validate_password_strength(v)
        if not is_valid:
            raise ValueError(error_msg)
        return v


class UserLoginRequest(BaseModel):
    """Primary credential login request."""
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    """Successful authentication token response."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    role: str
    permissions: List[str]

    model_config = ConfigDict(from_attributes=True)


class MFAPendingResponse(BaseModel):
    """Response returned when password is valid but MFA code is required."""
    mfa_required: bool = True
    mfa_token: str
    message: str = "Two-factor authentication required. Please verify TOTP or backup code."


class MFALoginRequest(BaseModel):
    """MFA challenge submission request."""
    mfa_token: str
    code: str  # 6-digit TOTP code or XXXX-XXXX backup code


class RefreshTokenRequest(BaseModel):
    """Token refresh request."""
    refresh_token: str


class PasswordChangeRequest(BaseModel):
    """Password update request."""
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        is_valid, error_msg = validate_password_strength(v)
        if not is_valid:
            raise ValueError(error_msg)
        return v


LoginResponse = Union[TokenResponse, MFAPendingResponse]
