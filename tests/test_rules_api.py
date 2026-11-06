import pytest
from httpx import AsyncClient, ASGITransport
from backend.main import app
from backend.database.database import DatabaseManager
from backend.database.in_memory_db import InMemoryDatabase

@pytest.mark.asyncio
async def test_rules_api_endpoints():
    DatabaseManager.db = InMemoryDatabase()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Fetch rules
        resp = await client.get("/api/v1/rules")
        assert resp.status_code == 200, f"GET /rules failed: {resp.text}"
        data = resp.json()
        assert "suricata_signatures" in data
        assert "netriq_heuristics" in data
        assert "behaviour_baselines" in data
        assert data["total_rules"] > 0
        assert data["active_rules"] > 0

        # 2. Update a rule
        rule_id = data["suricata_signatures"][0]["id"]
        update_resp = await client.put(f"/api/v1/rules/{rule_id}", json={"enabled": False})
        assert update_resp.status_code == 200
        assert update_resp.json()["rule"]["enabled"] is False

        # Re-enable
        await client.put(f"/api/v1/rules/{rule_id}", json={"enabled": True})

        # 3. Trigger rule distribution
        dist_resp = await client.post("/api/v1/rules/distribute")
        assert dist_resp.status_code == 200
        dist_data = dist_resp.json()
        assert dist_data["status"] == "success"
        assert "version" in dist_data
