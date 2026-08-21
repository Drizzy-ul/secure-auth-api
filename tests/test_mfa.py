"""Tests for Multi-Factor Authentication (TOTP and emergency recovery codes)."""

import pyotp
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_mfa_lifecycle(client: AsyncClient, regular_user):
    """
    Complete end-to-end MFA lifecycle:
    1. Authenticate to obtain access token.
    2. Initiate MFA setup -> receive secret + QR codes.
    3. Try enabling MFA with invalid code -> rejected.
    4. Enable MFA with valid TOTP -> receive backup codes.
    5. Log in -> receives MFA challenge response instead of direct access token.
    6. Complete MFA challenge with TOTP code -> receive access & refresh tokens.
    7. Log in again and use single-use backup recovery code.
    8. Verify used backup code cannot be used again.
    9. Disable MFA.
    """
    # 1. Login to get session
    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": "regular.user@example.com", "password": "Secur3P@ssw0rd!"},
    )
    access_token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}

    # 2. Setup MFA
    setup_res = await client.post("/api/v1/mfa/setup", headers=headers)
    assert setup_res.status_code == 200
    setup_data = setup_res.json()
    secret = setup_data["secret"]
    assert "otpauth://" in setup_data["provisioning_uri"]
    assert "data:image/png;base64," in setup_data["qr_code_png_base64"]
    assert "<svg" in setup_data["qr_code_svg"]

    # 3. Invalid code rejection
    bad_enable = await client.post(
        "/api/v1/mfa/enable",
        json={"code": "000000"},
        headers=headers,
    )
    assert bad_enable.status_code == 400

    # 4. Valid enable
    totp = pyotp.TOTP(secret)
    valid_code = totp.now()
    enable_res = await client.post(
        "/api/v1/mfa/enable",
        json={"code": valid_code},
        headers=headers,
    )
    assert enable_res.status_code == 200
    backup_codes = enable_res.json()["backup_codes"]
    assert len(backup_codes) == 10
    assert "-" in backup_codes[0]

    # 5. Subsequent Login gives MFA Challenge
    mfa_login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": "regular.user@example.com", "password": "Secur3P@ssw0rd!"},
    )
    assert mfa_login_res.status_code == 200
    challenge = mfa_login_res.json()
    assert challenge.get("mfa_required") is True
    mfa_token = challenge["mfa_token"]

    # 6. Verify MFA Challenge with TOTP
    totp_verify = await client.post(
        "/api/v1/auth/login/mfa",
        json={"mfa_token": mfa_token, "code": totp.now()},
    )
    assert totp_verify.status_code == 200
    session_tokens = totp_verify.json()
    assert "access_token" in session_tokens

    # 7. Login with Backup Code
    login_for_backup = await client.post(
        "/api/v1/auth/login",
        json={"email": "regular.user@example.com", "password": "Secur3P@ssw0rd!"},
    )
    mfa_token_2 = login_for_backup.json()["mfa_token"]

    test_backup_code = backup_codes[0]
    backup_verify = await client.post(
        "/api/v1/auth/login/mfa",
        json={"mfa_token": mfa_token_2, "code": test_backup_code},
    )
    assert backup_verify.status_code == 200

    # 8. Verify consumed backup code cannot be reused
    login_for_backup_reuse = await client.post(
        "/api/v1/auth/login",
        json={"email": "regular.user@example.com", "password": "Secur3P@ssw0rd!"},
    )
    mfa_token_3 = login_for_backup_reuse.json()["mfa_token"]

    backup_reuse_verify = await client.post(
        "/api/v1/auth/login/mfa",
        json={"mfa_token": mfa_token_3, "code": test_backup_code},
    )
    assert backup_reuse_verify.status_code == 401

    # 9. Disable MFA
    current_session = backup_verify.json()["access_token"]
    current_headers = {"Authorization": f"Bearer {current_session}"}

    disable_res = await client.post(
        "/api/v1/mfa/disable",
        json={"code": totp.now()},
        headers=current_headers,
    )
    assert disable_res.status_code == 200

    # Next login should be direct without MFA
    direct_login = await client.post(
        "/api/v1/auth/login",
        json={"email": "regular.user@example.com", "password": "Secur3P@ssw0rd!"},
    )
    assert direct_login.status_code == 200
    assert "access_token" in direct_login.json()
    assert direct_login.json().get("mfa_required") is None
