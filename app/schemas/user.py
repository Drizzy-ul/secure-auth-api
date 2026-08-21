"""User profile and role update schemas."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, EmailStr

from app.core.rbac import Role


class UserRead(BaseModel):
    """User account details returned to authenticated clients."""
    id: str
    email: EmailStr
    full_name: Optional[str] = None
    role: str
    is_active: bool
    is_verified: bool
    mfa_enabled: bool
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class UserUpdate(BaseModel):
    """User profile self-modification request."""
    full_name: Optional[str] = None


class UserRoleUpdate(BaseModel):
    """Administrative user role modification request."""
    role: Role
