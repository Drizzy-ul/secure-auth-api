"""Rate limiting infrastructure using SlowAPI."""

from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import settings


def get_client_ip(request: Request) -> str:
    """
    Extract client IP address, respecting X-Forwarded-For if configured behind a reverse proxy.
    Falls back to request.client.host.
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # First IP in list is the original client
        return forwarded.split(",")[0].strip()
    return get_remote_address(request) or "127.0.0.1"


# Global rate limiter instance
limiter = Limiter(
    key_func=get_client_ip,
    default_limits=[settings.RATE_LIMIT_DEFAULT],
    headers_enabled=True,
)
