"""Audit log schemas."""

from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict


class AuditLogRead(BaseModel):
    """Audit log entry representation."""
    id: str
    event_type: str
    user_id: Optional[str] = None
    user_email: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    status: str
    details: Optional[Dict[str, Any]] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AuditLogFilter(BaseModel):
    """Query filters for searching audit logs."""
    event_type: Optional[str] = None
    user_email: Optional[str] = None
    status: Optional[str] = None
    skip: int = 0
    limit: int = 50
