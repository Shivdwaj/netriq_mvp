import pytest
from httpx import AsyncClient, ASGITransport
from backend.main import app
from backend.database.database import DatabaseManager
from backend.database.in_memory_db import InMemoryDatabase
from backend.auth.jwt_handler import create_access_token
from backend.auth.roles import Role

@pytest.mark.asyncio
async def test_rules_api_endpoints():
    DatabaseManager.db = InMemoryDatabase()
    token = create_access_token(user_id="admin_user_rules_test", role=Role.ADMIN.value, tenant_id="default")
    admin_headers = {"Authorization": f"Bearer {token}"}

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Negative test: Anonymous request to modify rule is rejected with 401
        anon_resp = await client.put("/api/v1/rules/ET-2010935", json={"enabled": False})
        assert anon_resp.status_code == 401, "Anonymous rule modification must be rejected with 401"

        # 1. Fetch rules as authenticated admin
        resp = await client.get("/api/v1/rules", headers=admin_headers)
        assert resp.status_code == 200, f"GET /rules failed: {resp.text}"
        data = resp.json()
        assert "suricata_signatures" in data
        assert "netriq_heuristics" in data
        assert "behaviour_baselines" in data
        assert data["total_rules"] > 0
        assert data["active_rules"] > 0

        # 2. Update a rule as authenticated admin
        rule_id = data["suricata_signatures"][0]["id"]
        update_resp = await client.put(f"/api/v1/rules/{rule_id}", json={"enabled": False}, headers=admin_headers)
        assert update_resp.status_code == 200
        assert update_resp.json()["rule"]["enabled"] is False

        # Re-enable
        await client.put(f"/api/v1/rules/{rule_id}", json={"enabled": True}, headers=admin_headers)

        # 3. Trigger rule distribution as authenticated admin
        dist_resp = await client.post("/api/v1/rules/distribute", headers=admin_headers)
        assert dist_resp.status_code == 200
        dist_data = dist_resp.json()
        assert dist_data["status"] == "success"
        assert "version" in dist_data
