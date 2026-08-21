"""Cryptographic utilities, password hashing, and JWT token management."""

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import re
import uuid
from typing import Any, Dict, List, Optional, Tuple

import bcrypt
import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

from app.config import settings


# Token Type Constants
TOKEN_TYPE_ACCESS = "access"
TOKEN_TYPE_REFRESH = "refresh"
TOKEN_TYPE_MFA_PENDING = "mfa_pending"


def hash_password(password: str) -> str:
    """Securely hash a password with bcrypt and work factor 12."""
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against its bcrypt hash in constant time."""
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8")
        )
    except Exception:
        return False


def validate_password_strength(password: str) -> Tuple[bool, Optional[str]]:
    """
    Validate password strength according to Security+ and NIST guidelines.
    Requirements:
    - Minimum 8 characters
    - At least 1 uppercase letter
    - At least 1 lowercase letter
    - At least 1 digit
    - At least 1 special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if len(password) > 128:
        return False, "Password cannot exceed 128 characters."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>\-_+=\[\]\\/`~]", password):
        return False, "Password must contain at least one special character."
    return True, None


def hash_token(token: str) -> str:
    """Generate a SHA-256 hash of a token for secure database storage."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_token_hash(token: str, expected_hash: str) -> bool:
    """Perform a timing-attack resistant comparison of a token against a stored hash."""
    computed_hash = hash_token(token)
    return hmac.compare_digest(computed_hash, expected_hash)


def create_token(
    subject: str,
    token_type: str,
    expires_delta: timedelta,
    extra_claims: Optional[Dict[str, Any]] = None,
) -> str:
    """Create a signed JWT token with standard claims and expiration."""
    now = datetime.now(timezone.utc)
    expire = now + expires_delta
    
    payload: Dict[str, Any] = {
        "sub": str(subject),
        "type": token_type,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": str(uuid.uuid4()),
        "iss": settings.PROJECT_NAME,
    }
    
    if extra_claims:
        payload.update(extra_claims)
        
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_access_token(
    subject: str,
    role: str,
    permissions: List[str],
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Generate a short-lived access token with role and permission claims."""
    delta = expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    extra_claims = {
        "role": role,
        "permissions": permissions,
    }
    return create_token(
        subject=subject,
        token_type=TOKEN_TYPE_ACCESS,
        expires_delta=delta,
        extra_claims=extra_claims,
    )


def create_refresh_token(
    subject: str,
    jti: Optional[str] = None,
    expires_delta: Optional[timedelta] = None,
) -> Tuple[str, str]:
    """
    Generate a long-lived refresh token.
    Returns a tuple of (raw_token, jti).
    """
    delta = expires_delta or timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    token_jti = jti or str(uuid.uuid4())
    extra_claims = {
        "jti": token_jti,
    }
    token = create_token(
        subject=subject,
        token_type=TOKEN_TYPE_REFRESH,
        expires_delta=delta,
        extra_claims=extra_claims,
    )
    return token, token_jti


def create_mfa_pending_token(
    subject: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Generate a short-lived MFA challenge token.
    Used when primary credentials succeed, but MFA verification is pending.
    """
    delta = expires_delta or timedelta(minutes=settings.MFA_TOKEN_EXPIRE_MINUTES)
    return create_token(
        subject=subject,
        token_type=TOKEN_TYPE_MFA_PENDING,
        expires_delta=delta,
    )


def decode_token(token: str, expected_type: Optional[str] = None) -> Dict[str, Any]:
    """
    Decode and validate a JWT token.
    Checks signature, expiration, issuer, and token type.
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            issuer=settings.PROJECT_NAME,
            options={"require": ["sub", "exp", "iat", "type", "jti"]},
        )
    except ExpiredSignatureError:
        raise ValueError("Token has expired.")
    except InvalidTokenError as e:
        raise ValueError(f"Invalid token: {str(e)}")
        
    if expected_type and payload.get("type") != expected_type:
        raise ValueError(f"Invalid token type. Expected '{expected_type}', got '{payload.get('type')}'.")
        
    return payload
