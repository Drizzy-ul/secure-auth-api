"""Audit service for recording and retrieving security events."""

from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog


async def log_security_event(
    db: AsyncSession,
    event_type: str,
    user_id: Optional[str] = None,
    user_email: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    status: str = "SUCCESS",
    details: Optional[Dict[str, Any]] = None,
) -> AuditLog:
    """Record an immutable security event log entry in the database."""
    log_entry = AuditLog(
        event_type=event_type,
        user_id=user_id,
        user_email=user_email,
        ip_address=ip_address,
        user_agent=user_agent,
        status=status,
        details=details or {},
    )
    db.add(log_entry)
    await db.commit()
    await db.refresh(log_entry)
    return log_entry


async def query_audit_logs(
    db: AsyncSession,
    event_type: Optional[str] = None,
    user_email: Optional[str] = None,
    status: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
) -> Tuple[List[AuditLog], int]:
    """Retrieve filtered audit logs with pagination."""
    query = select(AuditLog)
    count_query = select(func.count(AuditLog.id))

    if event_type:
        query = query.where(AuditLog.event_type == event_type)
        count_query = count_query.where(AuditLog.event_type == event_type)
    if user_email:
        query = query.where(AuditLog.user_email == user_email)
        count_query = count_query.where(AuditLog.user_email == user_email)
    if status:
        query = query.where(AuditLog.status == status)
        count_query = count_query.where(AuditLog.status == status)

    # Order by newest first
    query = query.order_by(AuditLog.created_at.desc()).offset(skip).limit(limit)

    total_count = await db.scalar(count_query) or 0
    result = await db.execute(query)
    items = result.scalars().all()

    return list(items), total_count
