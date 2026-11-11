"""
tests/test_tenant_and_sensor_isolation.py

Regression suite for Stage 1 Security Hardening:
1. WebSocket multi-tenant broadcast isolation.
2. Analytics tenant-scoped KPIs, trends, and cache isolation.
3. Sensor key revocation and active status enforcement on telemetry and heartbeat.
4. Report listing, retrieval, generation, and download tenant ownership.
"""

import asyncio
import os
import time
import pytest
from unittest.mock import AsyncMock, patch
from httpx import AsyncClient, ASGITransport

from backend.main import app
from backend.auth.roles import Role
from backend.auth.jwt_handler import create_access_token
from backend.database.database import DatabaseManager
from backend.database.in_memory_db import InMemoryDatabase
from backend.database.collections import threats_repo, responses_repo, incidents_repo, sensors_repo, reports_repo
from backend.websocket.manager import manager, ConnectionManager
from backend.websocket.broadcaster import broadcaster
from backend.websocket.events import NewIncidentEvent, MonitorStatusEvent, LiveVerdictEvent
from backend.services.analytics_service import analytics_service
from backend.services.report_service import report_service
from backend.services.central_management_service import central_management_service
from backend.schemas.management import SensorRegistrationReq, SensorSoftwareType


@pytest.fixture(autouse=True)
def ensure_in_memory_db():
    DatabaseManager.db = InMemoryDatabase()
    analytics_service.clear_cache()
    yield


@pytest.mark.asyncio
async def test_websocket_tenant_scoped_broadcast_isolation():
    """
    Verify that WebSocket broadcasts are strictly confined to matching tenants.
    Tenant A's incident notifications must NOT bleed into Tenant B's connected sockets.
    """
    ws_mgr = ConnectionManager()

    mock_ws_alpha = AsyncMock()
    mock_ws_beta = AsyncMock()
    mock_ws_global_admin = AsyncMock()

    # Connect 3 clients:
    # 1. Analyst in org_alpha
    await ws_mgr.connect("user_alpha", Role.ANALYST, mock_ws_alpha, tenant_id="org_alpha")
    # 2. Analyst in org_beta
    await ws_mgr.connect("user_beta", Role.ANALYST, mock_ws_beta, tenant_id="org_beta")
    # 3. Super Admin in global scope
    await ws_mgr.connect("admin_global", Role.ADMIN, mock_ws_global_admin, tenant_id="global")

    # A. Emit an incident event specific to org_alpha
    alpha_event = NewIncidentEvent(
        payload={"incident_id": "inc-alpha-99", "tenant_id": "org_alpha"}
    )
    assert alpha_event.tenant_id == "org_alpha"

    for role in alpha_event.target_audience:
        await ws_mgr.broadcast_to_role(role, alpha_event)

    # Assertions:
    # org_alpha analyst must receive the event
    assert mock_ws_alpha.send_json.call_count >= 1
    # org_beta analyst must NOT receive the event
    assert mock_ws_beta.send_json.call_count == 0
    # Global admin should receive the event
    assert mock_ws_global_admin.send_json.call_count >= 1

    # Reset call counts
    mock_ws_alpha.send_json.reset_mock()
    mock_ws_beta.send_json.reset_mock()
    mock_ws_global_admin.send_json.reset_mock()

    # B. Emit a system status event targeted to all tenants ("global")
    global_event = MonitorStatusEvent(
        payload={"status": "online"},
        tenant_id="global"
    )
    for role in global_event.target_audience:
        await ws_mgr.broadcast_to_role(role, global_event)

    # Both tenant analysts and global admin receive global events
    assert mock_ws_alpha.send_json.call_count >= 1
    assert mock_ws_beta.send_json.call_count >= 1
    assert mock_ws_global_admin.send_json.call_count >= 1


@pytest.mark.asyncio
async def test_analytics_tenant_scoped_kpis_and_trends():
    """
    Verify that Analytics KPIs and Trends are isolated per tenant.
    Tenant Alpha metrics must not include Tenant Beta threat data.
    """
    now = time.time()

    # Insert 4 threats for tenant_alpha
    for i in range(4):
        await threats_repo.create({
            "event_id": f"evt-a-{i}",
            "tenant_id": "tenant_alpha",
            "timestamp": now - (i * 100),
            "is_anomaly": True,
            "prediction": "ANOMALY",
            "action": "RECOMMEND_BLOCK"
        })

    # Insert 2 threats for tenant_beta
    for i in range(2):
        await threats_repo.create({
            "event_id": f"evt-b-{i}",
            "tenant_id": "tenant_beta",
            "timestamp": now - (i * 100),
            "is_anomaly": True,
            "prediction": "ANOMALY",
            "action": "RECOMMEND_BLOCK"
        })

    analytics_service.clear_cache()

    # 1. Service layer direct query
    kpis_alpha = await analytics_service.get_kpis(Role.ANALYST, tenant_id="tenant_alpha")
    kpis_beta = await analytics_service.get_kpis(Role.ANALYST, tenant_id="tenant_beta")

    assert kpis_alpha["total_flows"] == 4
    assert kpis_beta["total_flows"] == 2

    # Trends direct query
    trends_alpha = await analytics_service.get_trends(Role.ANALYST, start_time=now - 1000, end_time=now, tenant_id="tenant_alpha")
    trends_beta = await analytics_service.get_trends(Role.ANALYST, start_time=now - 1000, end_time=now, tenant_id="tenant_beta")

    sum_alpha = sum(p["value"] for p in trends_alpha["data"])
    sum_beta = sum(p["value"] for p in trends_beta["data"])
    assert sum_alpha == 4
    assert sum_beta == 2

    # 2. REST API verification with JWT tokens
    token_alpha = create_access_token("analyst_a", "analyst", tenant_id="tenant_alpha")
    token_beta = create_access_token("analyst_b", "analyst", tenant_id="tenant_beta")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Request KPIs as Tenant Alpha
        resp_a = await client.get("/api/v1/analytics/kpis", headers={"Authorization": f"Bearer {token_alpha}"})
        assert resp_a.status_code == 200
        assert resp_a.json()["total_flows"] == 4

        # Request KPIs as Tenant Beta
        resp_b = await client.get("/api/v1/analytics/kpis", headers={"Authorization": f"Bearer {token_beta}"})
        assert resp_b.status_code == 200
        assert resp_b.json()["total_flows"] == 2


@pytest.mark.asyncio
async def test_sensor_revocation_enforcement_telemetry_and_heartbeat():
    """
    Verify that revoking or deactivating a sensor key immediately rejects
    both telemetry ingestion and heartbeat reporting with 401 Unauthorized.
    """
    # 1. Provision a legitimate sensor
    sensor = await central_management_service.register_software_sensor(SensorRegistrationReq(
        tenant_id="tenant_gamma",
        name="edge-probe-gamma",
        software_type=SensorSoftwareType.SURICATA,
        software_version="7.0.2",
        hostname="gamma-box"
    ))
    api_key = sensor.api_key
    sensor_id = sensor.sensor_id

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        hb_body = {
            "sensor_id": sensor_id,
            "cpu_usage_pct": 10.0,
            "memory_usage_mb": 128.0,
            "kernel_drops_count": 0,
            "packets_processed": 1000,
            "uptime_seconds": 60.0
        }

        # 2. Before revocation: Heartbeat succeeds
        resp_valid_hb = await client.post(
            "/api/v1/sensors/heartbeat",
            json=hb_body,
            headers={"X-Sensor-Key": api_key}
        )
        assert resp_valid_hb.status_code == 200

        # Telemetry batch before revocation: succeeds
        batch_body = {
            "sensor_id": sensor_id,
            "batch_id": "batch-init-1",
            "events": [
                {
                    "source_ip": "10.0.0.5",
                    "destination_ip": "10.0.0.1",
                    "protocol": "TCP"
                }
            ]
        }
        resp_valid_batch = await client.post(
            "/api/v1/events/batch",
            json=batch_body,
            headers={"X-Sensor-Key": api_key}
        )
        assert resp_valid_batch.status_code == 200

        # 3. REVOKE the sensor in the database
        await sensors_repo.collection.update_one(
            {"sensor_id": sensor_id},
            {"$set": {"status": "revoked", "is_active": False}}
        )

        # 4. After revocation: Heartbeat MUST be rejected with 401
        resp_revoked_hb = await client.post(
            "/api/v1/sensors/heartbeat",
            json=hb_body,
            headers={"X-Sensor-Key": api_key}
        )
        assert resp_revoked_hb.status_code == 401
        assert "revoked" in resp_revoked_hb.json()["detail"].lower() or "unauthorized" in resp_revoked_hb.json()["detail"].lower()

        # 5. After revocation: Telemetry batch ingestion MUST be rejected with 401
        resp_revoked_batch = await client.post(
            "/api/v1/events/batch",
            json=batch_body,
            headers={"X-Sensor-Key": api_key}
        )
        assert resp_revoked_batch.status_code == 401
        assert "revoked" in resp_revoked_batch.json()["detail"].lower()


@pytest.mark.asyncio
async def test_reports_tenant_ownership_and_isolation():
    """
    Verify report listing, generation, retrieval, and download enforce tenant ownership:
    - Tenant A cannot list Tenant B's reports.
    - Tenant A cannot retrieve or download Tenant B's reports (403 Forbidden).
    - Global Admin can access all reports.
    """
    now = time.time()

    # 1. Generate reports for tenant_alpha and tenant_beta
    rep_a_id = await report_service.generate_report(
        role=Role.ANALYST,
        report_type="incident_summary",
        start_time=now - 3600,
        end_time=now,
        format="pdf",
        tenant_id="tenant_alpha"
    )
    rep_b_id = await report_service.generate_report(
        role=Role.ANALYST,
        report_type="incident_summary",
        start_time=now - 3600,
        end_time=now,
        format="pdf",
        tenant_id="tenant_beta"
    )

    token_alpha = create_access_token("analyst_alpha", "analyst", tenant_id="tenant_alpha")
    token_beta = create_access_token("analyst_beta", "analyst", tenant_id="tenant_beta")
    token_global_admin = create_access_token("admin_root", "admin", tenant_id="global")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers_a = {"Authorization": f"Bearer {token_alpha}"}
        headers_b = {"Authorization": f"Bearer {token_beta}"}
        headers_root = {"Authorization": f"Bearer {token_global_admin}"}

        # 2. List Reports Scoping:
        list_a = await client.get("/api/v1/reports", headers=headers_a)
        assert list_a.status_code == 200
        ids_a = [r["id"] for r in list_a.json()]
        assert rep_a_id in ids_a
        assert rep_b_id not in ids_a

        list_b = await client.get("/api/v1/reports", headers=headers_b)
        assert list_b.status_code == 200
        ids_b = [r["id"] for r in list_b.json()]
        assert rep_b_id in ids_b
        assert rep_a_id not in ids_b

        # Global Admin sees all
        list_root = await client.get("/api/v1/reports", headers=headers_root)
        assert list_root.status_code == 200
        ids_root = [r["id"] for r in list_root.json()]
        assert rep_a_id in ids_root
        assert rep_b_id in ids_root

        # 3. Detail Access & Cross-Tenant Rejection:
        # Tenant Alpha querying rep_b_id -> 403 Forbidden
        cross_get = await client.get(f"/api/v1/reports/{rep_b_id}", headers=headers_a)
        assert cross_get.status_code == 403
        assert "across tenant boundaries" in cross_get.json()["detail"].lower()

        # Tenant Alpha querying rep_a_id -> 200 OK
        valid_get = await client.get(f"/api/v1/reports/{rep_a_id}", headers=headers_a)
        assert valid_get.status_code == 200
        assert valid_get.json()["id"] == rep_a_id

        # 4. Download Access & Cross-Tenant Rejection:
        # Tenant Alpha downloading rep_b_id -> 403 Forbidden
        cross_dl = await client.get(f"/api/v1/reports/{rep_b_id}/download", headers=headers_a)
        assert cross_dl.status_code == 403
        assert "across tenant boundaries" in cross_dl.json()["detail"].lower()

        # Tenant Alpha downloading rep_a_id -> 200 PDF
        valid_dl = await client.get(f"/api/v1/reports/{rep_a_id}/download", headers=headers_a)
        assert valid_dl.status_code == 200
        assert valid_dl.headers["content-type"] == "application/pdf"

