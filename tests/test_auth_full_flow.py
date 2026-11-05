import pytest
from httpx import AsyncClient, ASGITransport
from backend.main import app
from backend.database.database import DatabaseManager
from backend.database.in_memory_db import InMemoryDatabase
from backend.auth.auth_service import AuthService

@pytest.mark.asyncio
async def test_admin_and_analyst_login_flow():
    DatabaseManager.db = InMemoryDatabase()
    await AuthService().seed_initial_users()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Admin login
        admin_resp = await client.post(
            "/api/v1/auth/login",
            json={"username": "admin@netriq.local", "email": "admin@netriq.local", "password": "AdminPassword123!"}
        )
        assert admin_resp.status_code == 200, f"Admin login failed: {admin_resp.text}"
        admin_data = admin_resp.json()
        assert "access_token" in admin_data
        assert admin_data["role"] == "admin"
        admin_token = admin_data["access_token"]

        # 2. Verify /api/v1/auth/me for Admin
        me_resp = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert me_resp.status_code == 200, f"GET /me failed: {me_resp.text}"
        me_data = me_resp.json()
        assert me_data["email"] == "admin@netriq.local"
        assert me_data["role"] == "admin"
        assert "CREATE_ORGANIZATION" in me_data["capabilities"]

        # 3. Analyst login
        analyst_resp = await client.post(
            "/api/v1/auth/login",
            json={"username": "analyst@netriq.local", "email": "analyst@netriq.local", "password": "AnalystPassword123!"}
        )
        assert analyst_resp.status_code == 200, f"Analyst login failed: {analyst_resp.text}"
        analyst_data = analyst_resp.json()
        assert "access_token" in analyst_data
        assert analyst_data["role"] == "analyst"

        # 4. Invalid credentials rejected
        bad_resp = await client.post(
            "/api/v1/auth/login",
            json={"username": "admin@netriq.local", "password": "WrongPassword123!"}
        )
        assert bad_resp.status_code == 401
