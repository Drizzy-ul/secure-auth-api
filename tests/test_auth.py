"""Tests for user registration, authentication, token rotation, and replay detection."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_register_success(client: AsyncClient):
    """Test successful user registration with compliant password."""
    response = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "newuser@example.com",
            "password": "StrongPassword123!",
            "full_name": "New User",
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "newuser@example.com"
    assert data["full_name"] == "New User"
    assert data["role"] == "user"
    assert "password" not in data
    assert "hashed_password" not in data


@pytest.mark.asyncio
async def test_register_duplicate_email(client: AsyncClient):
    """Test rejection of duplicate email registration."""
    payload = {
        "email": "duplicate@example.com",
        "password": "StrongPassword123!",
        "full_name": "First Instance",
    }
    res1 = await client.post("/api/v1/auth/register", json=payload)
    assert res1.status_code == 201

    res2 = await client.post("/api/v1/auth/register", json=payload)
    assert res2.status_code == 409
    assert "already exists" in res2.json()["detail"]


@pytest.mark.asyncio
async def test_register_weak_passwords(client: AsyncClient):
    """Test validation errors for passwords not meeting NIST/Security+ standards."""
    weak_passwords = [
        ("short1!", "at least 8 characters"),
        ("nouppercase123!", "uppercase letter"),
        ("NOLOWERCASE123!", "lowercase letter"),
        ("NoNumbersHere!", "digit"),
        ("NoSpecialCharacters123", "special character"),
    ]

    for pwd, _ in weak_passwords:
        res = await client.post(
            "/api/v1/auth/register",
            json={
                "email": f"test_{pwd[:4]}@example.com",
                "password": pwd,
            },
        )
        assert res.status_code == 422


@pytest.mark.asyncio
async def test_login_success(client: AsyncClient, regular_user):
    """Test successful standard login without MFA."""
    response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": "regular.user@example.com",
            "password": "Secur3P@ssw0rd!",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert data["role"] == "user"


@pytest.mark.asyncio
async def test_login_bad_credentials(client: AsyncClient, regular_user):
    """Test login failure with invalid password or non-existent user."""
    # Bad password
    res1 = await client.post(
        "/api/v1/auth/login",
        json={
            "email": "regular.user@example.com",
            "password": "WrongPassword123!",
        },
    )
    assert res1.status_code == 401

    # Nonexistent user
    res2 = await client.post(
        "/api/v1/auth/login",
        json={
            "email": "ghost@example.com",
            "password": "Secur3P@ssw0rd!",
        },
    )
    assert res2.status_code == 401


@pytest.mark.asyncio
async def test_refresh_token_rotation_and_replay_defense(client: AsyncClient, regular_user):
    """
    Test refresh token rotation and replay attack mitigation:
    1. Login to obtain Refresh Token R1.
    2. Use R1 to rotate and obtain R2 (R1 is now invalidated).
    3. Reusing R1 must be detected as a replay attack and revoke the token family!
    """
    # 1. Login
    login_res = await client.post(
        "/api/v1/auth/login",
        json={
            "email": "regular.user@example.com",
            "password": "Secur3P@ssw0rd!",
        },
    )
    r1 = login_res.json()["refresh_token"]

    # 2. Legitimate rotation
    rotate_res = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": r1},
    )
    assert rotate_res.status_code == 200
    r2 = rotate_res.json()["refresh_token"]
    assert r1 != r2

    # 3. Malicious/Replay reuse of R1
    replay_res = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": r1},
    )
    assert replay_res.status_code == 401
    assert "Token reuse detected" in replay_res.json()["detail"]

    # 4. As a consequence of family revocation, R2 must also now be revoked
    r2_res = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": r2},
    )
    assert r2_res.status_code == 401


@pytest.mark.asyncio
async def test_logout(client: AsyncClient, regular_user):
    """Test user logout and session invalidation."""
    login_res = await client.post(
        "/api/v1/auth/login",
        json={
            "email": "regular.user@example.com",
            "password": "Secur3P@ssw0rd!",
        },
    )
    refresh_token = login_res.json()["refresh_token"]

    logout_res = await client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": refresh_token},
    )
    assert logout_res.status_code == 200

    # Token should now be unusable
    post_logout_refresh = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert post_logout_refresh.status_code == 401
