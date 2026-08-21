"""Tests for Role-Based Access Control (RBAC) and Least Privilege enforcement."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_user_permission_boundaries(client: AsyncClient, regular_user, admin_user):
    """Test standard user vs admin permission boundaries."""
    # Obtain access token for regular user
    res_user = await client.post(
        "/api/v1/auth/login",
        json={"email": "regular.user@example.com", "password": "Secur3P@ssw0rd!"},
    )
    user_token = res_user.json()["access_token"]
    user_headers = {"Authorization": f"Bearer {user_token}"}

    # Regular user attempting to list all users -> Forbidden (403)
    list_res_user = await client.get("/api/v1/users/", headers=user_headers)
    assert list_res_user.status_code == 403
    assert "user:read_all" in list_res_user.json()["detail"]

    # Regular user attempting to access audit logs -> Forbidden (403)
    audit_res_user = await client.get("/api/v1/admin/audit-logs", headers=user_headers)
    assert audit_res_user.status_code == 403
    assert "audit:read" in audit_res_user.json()["detail"]

    # Obtain access token for admin user
    res_admin = await client.post(
        "/api/v1/auth/login",
        json={"email": "admin.user@example.com", "password": "AdminP@ssw0rd!"},
    )
    admin_token = res_admin.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Admin user listing all users -> Allowed (200)
    list_res_admin = await client.get("/api/v1/users/", headers=admin_headers)
    assert list_res_admin.status_code == 200
    assert "items" in list_res_admin.json()

    # Admin user accessing audit logs -> Allowed (200)
    audit_res_admin = await client.get("/api/v1/admin/audit-logs", headers=admin_headers)
    assert audit_res_admin.status_code == 200
    assert "items" in audit_res_admin.json()


@pytest.mark.asyncio
async def test_least_privilege_role_escalation_prevention(client: AsyncClient, regular_user, admin_user):
    """
    Test that an Admin cannot promote a user to Superadmin (a rank higher than Admin),
    preventing unauthorized privilege escalation.
    """
    res_admin = await client.post(
        "/api/v1/auth/login",
        json={"email": "admin.user@example.com", "password": "AdminP@ssw0rd!"},
    )
    admin_token = res_admin.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Admin attempting to promote regular_user to superadmin
    promote_res = await client.patch(
        f"/api/v1/users/{regular_user.id}/role",
        json={"role": "superadmin"},
        headers=admin_headers,
    )
    assert promote_res.status_code == 403
    assert "equal to or higher than your own tier" in promote_res.json()["detail"]
