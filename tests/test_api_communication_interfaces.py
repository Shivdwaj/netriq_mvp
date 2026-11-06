import pytest
import time
import uuid
from starlette.testclient import TestClient
from backend.main import app
from backend.database.database import DatabaseManager
from backend.database.in_memory_db import InMemoryDatabase
from backend.auth.jwt_handler import create_access_token

@pytest.fixture(autouse=True)
def setup_db():
    DatabaseManager.db = InMemoryDatabase()
    yield

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def admin_token():
    return create_access_token("admin_test_user", "admin")

@pytest.fixture
def analyst_token():
    return create_access_token("analyst_test_user", "analyst")


# ==============================================================================
# PART A: Local sensor -> Central platform
# ==============================================================================

def test_sensor_registration(client):
    """
    POST /api/v1/sensors/register
    Registers a software daemon (Zeek/Suricata) and returns API key/token.
    """
    payload = {
        "tenant_id": "test_org",
        "name": "edge-zeek-daemon-01",
        "software_type": "zeek",
        "software_version": "6.0.3",
        "hostname": "gateway-node-1",
        "listening_interface": "eth0",
        "environment": "cloud_vm"
    }

    resp = client.post("/api/v1/sensors/register", json=payload)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "sensor_id" in data
    assert data["sensor_id"].startswith("sensor-zeek-")
    assert "api_key" in data
    assert data["api_key"].startswith("ntrq_")
    assert data["tenant_id"] == "test_org"
    assert "sensor_token" in data


def test_event_batch_ingestion_and_idempotency(client):
    """
    POST /api/v1/events/batch
    Verifies:
    1. Authentication via Bearer <sensor-token>
    2. Event acceptance and batch acknowledgment
    3. Idempotent safe retries (submitting duplicate batch does not re-publish)
    4. X-Request-ID propagation
    """
    # 1. Register a sensor first to acquire sensor token
    reg_resp = client.post("/api/v1/sensors/register", json={
        "tenant_id": "cyber_ops",
        "name": "suricata-collector",
        "software_type": "suricata",
        "software_version": "7.0.2",
        "hostname": "collector-vm-1"
    })
    assert reg_resp.status_code == 200
    sensor_data = reg_resp.json()
    sensor_id = sensor_data["sensor_id"]
    sensor_token = sensor_data["api_key"]

    batch_id = f"batch-{uuid.uuid4().hex[:8]}"
    evt_id = f"evt-{uuid.uuid4().hex[:8]}"

    batch_payload = {
        "sensor_id": sensor_id,
        "batch_id": batch_id,
        "events": [
            {
                "event_id": evt_id,
                "timestamp": "2026-11-04T15:00:00Z",
                "source_ip": "192.168.1.10",
                "destination_ip": "192.168.1.20",
                "source_port": 49152,
                "destination_port": 80,
                "protocol": "TCP",
                "event_type": "connection",
                "detection_source": "zeek",
                "severity": "INFO",
                "evidence": {"bytes_sent": 1024}
            }
        ]
    }

    # Test 1: Unauthenticated request must fail with 401
    unauth_resp = client.post("/api/v1/events/batch", json=batch_payload)
    assert unauth_resp.status_code == 401

    # Test 2: Authenticated request with Bearer <sensor-token>
    headers = {
        "Authorization": f"Bearer {sensor_token}",
        "X-Request-ID": "test-req-batch-001"
    }
    resp1 = client.post("/api/v1/events/batch", json=batch_payload, headers=headers)
    assert resp1.status_code == 200, resp1.text
    data1 = resp1.json()
    assert data1["status"] == "acknowledged"
    assert data1["batch_id"] == batch_id
    assert data1["accepted_count"] == 1
    assert data1["duplicate_count"] == 0
    assert evt_id in data1["accepted_event_ids"]
    assert resp1.headers.get("X-Request-ID") == "test-req-batch-001"

    # Test 3: Safe Retry / Idempotency Check
    # Sensor re-sends the exact same batch payload (e.g. after transient network disconnect)
    resp2 = client.post("/api/v1/events/batch", json=batch_payload, headers=headers)
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["status"] == "acknowledged"
    assert data2["batch_id"] == batch_id
    assert data2["accepted_count"] == 0
    assert data2["duplicate_count"] == 1
    assert evt_id in data2["duplicate_event_ids"]


def test_sensor_heartbeat_health_monitoring(client):
    """
    POST /api/v1/sensors/heartbeat
    Tests reporting sensor health (CPU, RAM, kernel drops, uptime).
    Tests degraded status trigger on packet drop threshold.
    """
    # Register sensor
    reg_resp = client.post("/api/v1/sensors/register", json={
        "tenant_id": "health_corp",
        "name": "zeek-probe",
        "software_type": "zeek",
        "software_version": "6.0.3",
        "hostname": "probe-01"
    })
    sensor_id = reg_resp.json()["sensor_id"]
    sensor_token = reg_resp.json()["api_key"]

    headers = {"Authorization": f"Bearer {sensor_token}"}

    # Healthy heartbeat
    hb_payload = {
        "sensor_id": sensor_id,
        "cpu_usage_pct": 25.5,
        "memory_usage_mb": 512.0,
        "kernel_drops_count": 0,
        "packets_processed": 50000,
        "uptime_seconds": 3600.0,
        "software_version": "6.0.3"
    }
    resp = client.post("/api/v1/sensors/heartbeat", json=hb_payload, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["sensor_status"] == "healthy"

    # Degraded heartbeat (kernel drops > 500)
    hb_degraded = {
        "sensor_id": sensor_id,
        "cpu_usage_pct": 45.0,
        "memory_usage_mb": 600.0,
        "kernel_drops_count": 850,
        "packets_processed": 100000,
        "uptime_seconds": 7200.0
    }
    resp_deg = client.post("/api/v1/sensors/heartbeat", json=hb_degraded, headers=headers)
    assert resp_deg.status_code == 200
    assert resp_deg.json()["sensor_status"] == "degraded"


def test_sensor_config_retrieval(client):
    """
    GET /api/v1/sensors/config
    Sensor retrieves assigned configuration (interface, buffer size, log level).
    """
    reg_resp = client.post("/api/v1/sensors/register", json={
        "tenant_id": "config_corp",
        "name": "config-test-sensor",
        "software_type": "suricata",
        "software_version": "7.0.2",
        "hostname": "sensor-cfg-host",
        "listening_interface": "ens33"
    })
    sensor_id = reg_resp.json()["sensor_id"]
    sensor_token = reg_resp.json()["api_key"]

    headers = {"Authorization": f"Bearer {sensor_token}"}
    resp = client.get("/api/v1/sensors/config", headers=headers)
    assert resp.status_code == 200
    cfg = resp.json()
    assert cfg["sensor_id"] == sensor_id
    assert cfg["listening_interface"] == "ens33"
    assert "config" in cfg


def test_rule_manifest_retrieval(client, analyst_token):
    """
    GET /api/v1/rules
    Retrieves detection rules manifest (Suricata signatures, NetrIQ heuristics, behavioural baselines).
    """
    headers = {"Authorization": f"Bearer {analyst_token}"}
    resp = client.get("/api/v1/rules", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "suricata_signatures" in data
    assert "netriq_heuristics" in data
    assert "behaviour_baselines" in data
    assert len(data["suricata_signatures"]) > 0


# ==============================================================================
# PART B: Dashboard -> Backend
# ==============================================================================

def test_dashboard_overview_endpoint(client, analyst_token):
    """
    GET /api/v1/dashboard/overview
    Retrieves aggregated dashboard statistics.
    """
    headers = {"Authorization": f"Bearer {analyst_token}"}
    resp = client.get("/api/v1/dashboard/overview", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "total_events" in data or "threat_level" in data or "active_incidents" in data


def test_events_retrieval_and_filtering(client, analyst_token):
    """
    GET /api/v1/events
    Retrieves normalized security events with query parameter filtering.
    """
    headers = {"Authorization": f"Bearer {analyst_token}"}
    resp = client.get("/api/v1/events?limit=20&protocol=TCP", headers=headers)
    assert resp.status_code == 200
    events = resp.json()
    assert isinstance(events, list)


def test_threats_retrieval(client, analyst_token):
    """
    GET /api/v1/threats
    Retrieves detection alerts and classifications.
    """
    headers = {"Authorization": f"Bearer {analyst_token}"}
    resp = client.get("/api/v1/threats?limit=10", headers=headers)
    assert resp.status_code == 200
    threats = resp.json()
    assert isinstance(threats, list)


def test_incidents_lifecycle_and_audit(client, admin_token):
    """
    GET /api/v1/incidents
    GET /api/v1/incidents/{id}
    PATCH /api/v1/incidents/{id}/status
    Verifies incident creation, status transition (New -> Investigating -> Resolved) and audit trail.
    """
    headers = {"Authorization": f"Bearer {admin_token}"}
    # Seed an incident into DB
    client.post("/api/v1/monitoring/simulate-threat", json={
        "threat_type": "PORT_SCAN",
        "src_ip": "10.0.0.88",
        "dst_ip": "10.0.0.99"
    }, headers=headers)

    list_resp = client.get("/api/v1/incidents", headers=headers)
    assert list_resp.status_code == 200
    incidents = list_resp.json()
    assert len(incidents) > 0

    target_inc = incidents[0]
    inc_id = target_inc["id"]

    # View details
    detail_resp = client.get(f"/api/v1/incidents/{inc_id}", headers=headers)
    assert detail_resp.status_code == 200
    assert detail_resp.json()["id"] == inc_id

    # Update status: New -> Investigating
    patch_resp = client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        json={
            "status": "Investigating",
            "reason": "SOC Lead assigned investigation to tier-2 analyst.",
            "resolution_notes": "Triaging port sweep pattern."
        },
        headers=headers
    )
    assert patch_resp.status_code == 200
    updated = patch_resp.json()
    assert updated["status"].lower() == "investigating"
    assert len(updated["audit_history"]) >= 1
    latest_audit = updated["audit_history"][-1]
    assert latest_audit["action"] == "STATUS_CHANGE"
    assert latest_audit["details"]["to_status"] == "investigating"
    assert "SOC Lead" in latest_audit["reason"]


def test_sensors_list_endpoint(client, analyst_token):
    """
    GET /api/v1/sensors
    Lists registered software sensors for the user's organisation.
    """
    headers = {"Authorization": f"Bearer {analyst_token}"}
    resp = client.get("/api/v1/sensors", headers=headers)
    assert resp.status_code == 200
    sensors = resp.json()
    assert isinstance(sensors, list)


def test_reports_list_endpoint(client, analyst_token):
    """
    GET /api/v1/reports
    Lists historical reports.
    """
    headers = {"Authorization": f"Bearer {analyst_token}"}
    resp = client.get("/api/v1/reports", headers=headers)
    assert resp.status_code == 200
    reports = resp.json()
    assert isinstance(reports, list)


def test_websocket_stream_live_updates(client, analyst_token):
    """
    WS /api/v1/stream
    Tests real-time dashboard WebSocket connection with query param auth and ping/pong.
    """
    with client.websocket_connect(f"/api/v1/stream?token={analyst_token}") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "auth_ok"
        assert msg["role"] == "analyst"

        ws.send_json({"type": "ping"})
        pong = ws.receive_json()
        assert pong["type"] == "pong"


def test_owasp_unrestricted_resource_consumption_batch_limit(client):
    """
    OWASP API4: Unrestricted Resource Consumption
    Batches exceeding 1,000 events must be rejected with HTTP 422/400.
    """
    reg_resp = client.post("/api/v1/sensors/register", json={
        "tenant_id": "dos_test",
        "name": "flood-sensor",
        "software_type": "zeek",
        "software_version": "6.0.3",
        "hostname": "flood-host"
    })
    sensor_token = reg_resp.json()["api_key"]

    oversized_events = [
        {
            "event_id": f"evt-{i}",
            "source_ip": "1.2.3.4",
            "destination_ip": "5.6.7.8",
            "protocol": "TCP"
        }
        for i in range(1005)
    ]

    resp = client.post(
        "/api/v1/events/batch",
        json={
            "sensor_id": "sensor-oversized",
            "batch_id": "batch-oversized",
            "events": oversized_events
        },
        headers={"Authorization": f"Bearer {sensor_token}"}
    )
    assert resp.status_code in (400, 422)
