"""Tests for token tampering, security headers, token type validation, and cryptographic safety."""

import pytest
from httpx import AsyncClient

from app.core.security import create_refresh_token, hash_password, verify_password


@pytest.mark.asyncio
async def test_tampered_jwt_token_rejection(client: AsyncClient, regular_user):
    """Test that forged or tampered JWT tokens are strictly rejected."""
    # Tampered signature
    fake_token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    headers = {"Authorization": f"Bearer {fake_token}"}
    res = await client.get("/api/v1/users/me", headers=headers)
    assert res.status_code == 401
    assert "Invalid token" in res.json()["detail"] or "Could not validate credentials" in res.json()["detail"]


@pytest.mark.asyncio
async def test_wrong_token_type_misuse(client: AsyncClient, regular_user):
    """Test that presenting a refresh token as an access token in the Authorization header is rejected."""
    # Obtain tokens
    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": "regular.user@example.com", "password": "Secur3P@ssw0rd!"},
    )
    refresh_token = login_res.json()["refresh_token"]

    # Try using refresh token as access token
    headers = {"Authorization": f"Bearer {refresh_token}"}
    res = await client.get("/api/v1/users/me", headers=headers)
    assert res.status_code == 401
    assert "Invalid token type" in res.json()["detail"]


@pytest.mark.asyncio
async def test_security_response_headers(client: AsyncClient):
    """Verify presence of OWASP security headers on HTTP responses."""
    response = await client.get("/health")
    assert response.status_code == 200
    headers = response.headers

    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("X-XSS-Protection") == "1; mode=block"
    assert "Strict-Transport-Security" in headers
    assert "Content-Security-Policy" in headers
    assert "Cache-Control" in headers


def test_password_hashing_and_verification():
    """Verify bcrypt hashing generates unique salts and validates timing-safely."""
    pwd = "Secur3P@ssw0rd!"
    hash1 = hash_password(pwd)
    hash2 = hash_password(pwd)

    assert hash1 != hash2  # Different salts
    assert verify_password(pwd, hash1) is True
    assert verify_password(pwd, hash2) is True
    assert verify_password("WrongPassword!", hash1) is False
