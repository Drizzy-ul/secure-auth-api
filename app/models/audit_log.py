"""Security Audit Log database model."""

from typing import Any, Dict, Optional
from sqlalchemy import JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class AuditLog(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    Immutable audit trail recording security-critical events, authentication attempts,
    MFA modifications, role escalations, and detected anomalies.
    """
    __tablename__ = "audit_logs"

    event_type: Mapped[str] = mapped_column(
        String(100),
        index=True,
        nullable=False,
    )
    user_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        index=True,
        nullable=True,
    )
    user_email: Mapped[Optional[str]] = mapped_column(
        String(255),
        index=True,
        nullable=True,
    )
    ip_address: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True,
    )
    user_agent: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    status: Mapped[str] = mapped_column(
        String(20),
        default="SUCCESS",
        nullable=False,
    )
    details: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
    )

    def __repr__(self) -> str:
        return f"<AuditLog id={self.id} event={self.event_type} user={self.user_email} status={self.status}>"
