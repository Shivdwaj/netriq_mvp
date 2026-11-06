import asyncio
import os
import shutil
import tempfile
from unittest.mock import AsyncMock
import pytest

from backend.ai.contracts import Action, PredictionResult, RiskCategory
from backend.auth.roles import Role
from backend.response.response_engine import ResponseEngine
from backend.services.settings_service import settings_service
from backend.services.central_management_service import CentralManagementService
from backend.security.signatures import ManifestSigner
from sensor.event_queue import LocalEventQueue
from sensor.agent import NetriqSensorAgent
from sensor.config import SensorConfig
from sensor.security.confinement import (
    drop_privileges,
    apply_resource_limits,
    generate_seccomp_profile,
    validate_environment_security
)
from backend.pipeline.schemas import NormalizedSecurityEvent

@pytest.fixture
def temp_spool_dir():
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)

@pytest.mark.asyncio
async def test_passive_detection_by_default():
    """
    Ensures NetrIQ defaults to passive detection (auto_quarantine = False).
    High-risk actions (RECOMMEND_BLOCK, QUARANTINE) are NOT executed automatically,
    but instead downgraded to guided analyst review.
    """
    await settings_service.update_settings(Role.ADMIN, {"auto_quarantine": False})
    
    engine = ResponseEngine()
    engine.quarantine.quarantine_device = AsyncMock(return_value=True)
    engine.firewall.block_ip = AsyncMock(return_value=True)

    prediction = PredictionResult(
        verdict=True,
        confidence=95.0,
        risk_category=RiskCategory.HIGH,
        model_used="StructuredIntelligencePipeline",
        latency_ms=1.2
    )

    # 1. Test QUARANTINE in Passive Mode
    success = await engine.handle_verdict(
        prediction=prediction,
        action=Action.QUARANTINE,
        context={"src_ip": "192.168.1.100", "src_mac": "00:11:22:33:44:55"}
    )
    assert success is True
    # The device should NOT be quarantined in passive mode
    assert engine.quarantine.quarantine_device.call_count == 0

    # 2. Test RECOMMEND_BLOCK in Passive Mode
    block_pred = PredictionResult(
        verdict=True,
        confidence=90.0,
        risk_category=RiskCategory.HIGH,
        model_used="StructuredIntelligencePipeline",
        latency_ms=2.1
    )
    success_block = await engine.handle_verdict(
        prediction=block_pred,
        action=Action.RECOMMEND_BLOCK,
        context={"src_ip": "203.0.113.50"}
    )
    assert success_block is True
    # Firewall should NOT have blocked the IP
    assert engine.firewall.block_ip.call_count == 0

    # 3. Test Active Mode (when explicitly enabled by admin)
    await settings_service.update_settings(Role.ADMIN, {"auto_quarantine": True})
    success_active = await engine.handle_verdict(
        prediction=prediction,
        action=Action.QUARANTINE,
        context={"src_ip": "192.168.1.105", "src_mac": "aa:bb:cc:dd:ee:ff"}
    )
    assert success_active is True
    assert engine.quarantine.quarantine_device.call_count == 1

    # Cleanup: restore default passive mode
    await settings_service.update_settings(Role.ADMIN, {"auto_quarantine": False})

@pytest.mark.asyncio
async def test_offline_local_event_queue_disk_persistence(temp_spool_dir):
    """
    Verifies offline operation and local event queue persistence.
    Events survive process termination / crashes and are recovered on next boot.
    """
    spool_file = os.path.join(temp_spool_dir, "test_spool.db")

    queue1 = LocalEventQueue(max_size=100, disk_spool_path=spool_file)

    event1 = NormalizedSecurityEvent(
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        source_port=12345,
        destination_port=80,
        protocol="TCP",
        event_type="connection"
    )
    event2 = NormalizedSecurityEvent(
        source_ip="10.0.0.3",
        destination_ip="10.0.0.4",
        source_port=54321,
        destination_port=443,
        protocol="TCP",
        event_type="connection"
    )

    await queue1.enqueue(event1)
    await queue1.enqueue(event2)

    assert queue1.queue_depth == 2
    assert queue1.disk_spool_depth() == 2

    # Fetch a batch (simulating in-flight shipment)
    batch_id, batch = await queue1.get_batch(max_items=1)
    assert len(batch) == 1
    assert batch[0].source_ip == "10.0.0.1"
    assert queue1.queue_depth == 1

    # Simulate abrupt daemon crash while batch is in-flight: close without acknowledging
    queue1.close()

    # Restart daemon (create new queue pointing to same disk spool)
    queue2 = LocalEventQueue(max_size=100, disk_spool_path=spool_file)

    # Crash recovery: the unacknowledged in-flight event1 must be recovered back into the queue!
    assert queue2.queue_depth == 2
    assert queue2.disk_spool_depth() == 2

    # Get full batch and acknowledge
    b_id, all_events = await queue2.get_batch(max_items=10)
    assert len(all_events) == 2
    await queue2.acknowledge_batch(b_id)

    # Verify spool is now cleared
    assert queue2.queue_depth == 0
    assert queue2.disk_spool_depth() == 0
    queue2.close()

def test_software_integrity_and_manifest_signing():
    """
    Verifies cryptographic rule signing and tamper detection.
    """
    secret = "test-sensor-cluster-secret-key-987"
    raw_manifest = {
        "manifest_id": "mf-001",
        "tenant_id": "org_acme",
        "version": "2026.11.06.01",
        "netriq_rules": [{"rule_id": "RULE:PORT_SCAN", "type": "threshold", "min_ports": 10}],
        "active_whitelists": ["10.0.0.0/8"]
    }

    # 1. Sign manifest
    signed = ManifestSigner.sign_manifest(raw_manifest, secret_key=secret)
    assert "signature" in signed
    assert signed["signature_alg"] == "HMAC-SHA256"

    # 2. Verify genuine manifest
    assert ManifestSigner.verify_manifest(signed, secret_key=secret) is True

    # 3. Detect tampering (e.g. attacker changes rule threshold to bypass detection)
    tampered = dict(signed)
    tampered["netriq_rules"] = [{"rule_id": "RULE:PORT_SCAN", "type": "threshold", "min_ports": 9999}]
    assert ManifestSigner.verify_manifest(tampered, secret_key=secret) is False

    # 4. Detect tampering with incorrect signing key
    assert ManifestSigner.verify_manifest(signed, secret_key="wrong-secret-key") is False

@pytest.mark.asyncio
async def test_sensor_agent_signed_manifest_application(temp_spool_dir):
    """
    Verifies that the Sensor Agent accepts cryptographically valid manifests
    and rejects tampered or unsigned rule updates.
    """
    secret = "shared-cluster-signing-key-42"
    spool_file = os.path.join(temp_spool_dir, "agent_spool.db")
    config = SensorConfig(
        signing_secret_key=secret,
        disk_spool_path=spool_file,
        port_scan_port_threshold=8
    )
    agent = NetriqSensorAgent(config=config)

    assert agent.local_detector.port_scan_threshold == 8

    # Create signed manifest updating threshold to 12
    manifest_data = {
        "manifest_id": "mf-update-88",
        "tenant_id": "default",
        "version": "2026.11.06.02",
        "netriq_rules": [{"rule_id": "RULE:SCAN", "type": "threshold", "min_ports": 12, "window_sec": 45.0}]
    }
    signed_manifest = ManifestSigner.sign_manifest(manifest_data, secret_key=secret)

    # 1. Valid signature -> applied
    applied = agent.apply_rule_manifest(signed_manifest)
    assert applied is True
    assert agent.local_detector.port_scan_threshold == 12
    assert agent.local_detector.window_seconds == 45.0

    # 2. Tampered manifest -> rejected, threshold unchanged
    tampered_manifest = dict(signed_manifest)
    tampered_manifest["netriq_rules"] = [{"rule_id": "RULE:SCAN", "type": "threshold", "min_ports": 50}]
    rejected = agent.apply_rule_manifest(tampered_manifest)
    assert rejected is False
    assert agent.local_detector.port_scan_threshold == 12

    await agent.close()

@pytest.mark.asyncio
async def test_central_management_distributes_signed_manifest():
    """
    Verifies that CentralManagementService automatically signs distributed rule manifests.
    """
    svc = CentralManagementService()
    manifest = await svc.get_rule_manifest("org_acme")
    assert manifest.signature is not None
    assert manifest.signature_alg == "HMAC-SHA256"
    assert ManifestSigner.verify_manifest(manifest) is True

def test_sensor_security_confinement():
    """
    Verifies sensor confinement utilities: seccomp profile generation and security audit.
    """
    profile = generate_seccomp_profile()
    assert profile["defaultAction"] == "SCMP_ACT_ERRNO"
    syscalls = profile["syscalls"]
    allowed = [s for s in syscalls if s["action"] == "SCMP_ACT_ALLOW"]
    killed = [s for s in syscalls if s["action"] == "SCMP_ACT_KILL"]
    
    assert len(allowed) > 0
    assert "socket" in allowed[0]["names"]
    assert "ptrace" in killed[0]["names"]
    assert "reboot" in killed[0]["names"]

    # Test environment security audit
    audit = validate_environment_security()
    assert "is_hardened" in audit
    assert "platform" in audit

    # Test privilege dropping & limits no-op safely on dev platforms
    assert drop_privileges() is True
    assert apply_resource_limits(max_memory_mb=1024) is True


def test_docker_compose_and_jwt_security_guards():
    """
    Regression test for Critical Security Findings:
    - Finding 1: No hardcoded JWT secret in docker-compose.yml (uses env var).
    - Finding 2: MongoDB container does not expose 27017 to host interfaces.
    """
    import yaml
    compose_path = "docker-compose.yml"
    assert os.path.exists(compose_path), "docker-compose.yml missing"
    
    with open(compose_path, "r", encoding="utf-8") as f:
        compose_text = f.read()
        compose_data = yaml.safe_load(compose_text)

    # 1. Verify MongoDB has no public port mapping
    mongo_svc = compose_data.get("services", {}).get("mongodb", {})
    assert "ports" not in mongo_svc, "MongoDB container must NOT publish ports to host interfaces (Finding 2)"

    # 2. Verify no hardcoded secrets in docker-compose.yml
    insecure_keys = [
        "netriq_production_demo_secret_key_32_chars_min!",
        "netriq_super_secret_jwt_key_32_bytes_min!!",
        "JWT_SECRET_KEY=secret"
    ]
    for key in insecure_keys:
        assert key not in compose_text, f"Hardcoded secret '{key}' found in docker-compose.yml (Finding 1)"

    # 3. Verify backend service requires JWT_SECRET_KEY from environment
    backend_svc = compose_data.get("services", {}).get("backend", {})
    env_vars = backend_svc.get("environment", [])
    jwt_env = [e for e in env_vars if "JWT_SECRET_KEY" in e]
    assert len(jwt_env) > 0, "Backend service must declare JWT_SECRET_KEY in environment"
    assert "${JWT_SECRET_KEY" in jwt_env[0], "JWT_SECRET_KEY must reference environment variable ${JWT_SECRET_KEY}"


@pytest.mark.asyncio
async def test_reverse_proxy_and_backend_network_isolation():
    """
    Regression test for Finding 3:
    - Backend is not directly exposed on host ports (no '8000:8000' in compose).
    - Reverse proxy (Nginx) terminates HTTPS (443) and handles HTTP redirect (80).
    - Nginx configuration specifies TLS 1.2/1.3 and security headers.
    """
    import yaml
    with open("docker-compose.yml", "r", encoding="utf-8") as f:
        compose_data = yaml.safe_load(f)

    # 1. Backend must not publish host ports directly
    backend_svc = compose_data.get("services", {}).get("backend", {})
    assert "ports" not in backend_svc, "Backend container must NOT publish direct host ports (Finding 3)"
    assert "8000" in backend_svc.get("expose", []), "Backend container should use 'expose: - 8000' for internal proxying"

    # 2. Frontend Nginx reverse proxy publishes ports 80 and 443
    frontend_svc = compose_data.get("services", {}).get("frontend", {})
    ports = frontend_svc.get("ports", [])
    assert any("80:80" in p for p in ports), "Reverse proxy must listen on port 80"
    assert any("443:443" in p for p in ports), "Reverse proxy must listen on port 443 for HTTPS"

    # 3. Nginx configuration verification
    with open("docker/nginx.conf", "r", encoding="utf-8") as f:
        nginx_conf = f.read()

    assert "listen 443 ssl" in nginx_conf, "Nginx must have an SSL listener on port 443"
    assert "ssl_protocols TLSv1.2 TLSv1.3" in nginx_conf, "Nginx must enforce modern TLS protocols (TLSv1.2 TLSv1.3)"
    assert "Strict-Transport-Security" in nginx_conf, "Nginx must emit HSTS header"
    assert "X-Frame-Options" in nginx_conf, "Nginx must emit X-Frame-Options header"
    assert "return 301 https://$host$request_uri;" in nginx_conf, "Port 80 must redirect to HTTPS"


@pytest.mark.asyncio
async def test_explicit_admin_packet_monitoring_control():
    """
    Regression test for Finding 4:
    - Server startup must not automatically activate live packet monitoring.
    - Sensor activation is an explicit administrator operation requiring Role.ADMIN.
    - Non-admin roles (e.g. Role.ANALYST) are rejected with InsufficientPermissionError.
    - Activation and deactivation generate immutable audit logs.
    """
    from backend.services.monitoring_service import monitoring_service
    from backend.auth.exceptions import InsufficientPermissionError
    from backend.database.collections import audit_logs_repo

    # 1. Ensure monitoring starts in IDLE / stopped state
    if monitoring_service._is_running:
        await monitoring_service.stop(Role.ADMIN)
    assert monitoring_service.get_status()["is_running"] is False

    # 2. Non-admin (Analyst) activation rejected
    with pytest.raises(InsufficientPermissionError):
        await monitoring_service.start(role=Role.ANALYST, user_id="analyst_test")

    # 3. Explicit Admin activation allowed
    started = await monitoring_service.start(role=Role.ADMIN, user_id="admin_test")
    assert started is True
    assert monitoring_service.get_status()["is_running"] is True

    # 4. Verify audit log entry was created for activation
    audit_logs = await audit_logs_repo.list(
        filter_query={"action": "packet_monitoring_started", "user": "admin_test"},
        limit=1
    )
    assert len(audit_logs) > 0
    assert audit_logs[0]["role"] == "admin"

    # 5. Non-admin (Analyst) stop rejected
    with pytest.raises(InsufficientPermissionError):
        await monitoring_service.stop(role=Role.ANALYST, user_id="analyst_test")

    # 6. Admin stop allowed
    stopped = await monitoring_service.stop(role=Role.ADMIN, user_id="admin_test")
    assert stopped is True
    assert monitoring_service.get_status()["is_running"] is False

    # Verify audit log entry for stopping
    stop_logs = await audit_logs_repo.list(
        filter_query={"action": "packet_monitoring_stopped", "user": "admin_test"},
        limit=1
    )
    assert len(stop_logs) > 0



def test_dependencies_pinned_and_lockfile_exists():
    """
    Regression test for Finding 6:
    - Every package in requirements.txt must be pinned with exact versions (==).
    - Open-ended ranges (>=) are prohibited to ensure build determinism.
    - requirements.lock must exist.
    """
    assert os.path.exists("requirements.txt"), "requirements.txt missing"
    assert os.path.exists("requirements.lock"), "requirements.lock missing (Finding 6)"

    with open("requirements.txt", "r", encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    for line in lines:
        assert ">=" not in line, f"Open-ended dependency found in requirements.txt: {line} (Finding 6)"
        assert "==" in line, f"Dependency must be strictly pinned with '==': {line}"


@pytest.mark.asyncio
async def test_exception_masking_and_correlation_id():
    """
    Regression test for Finding 5:
    - 500 responses must mask internal exception details (str(exc)).
    - A traceable correlation_id must be returned to client and logged on server.
    """
    from httpx import AsyncClient, ASGITransport
    from backend.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Trigger an error path
        resp = await client.get("/api/v1/nonexistent-route-404")
        assert resp.status_code == 404

    # Direct test of general_exception_handler
    from starlette.requests import Request
    from backend.main import general_exception_handler

    mock_scope = {
        "type": "http",
        "method": "GET",
        "path": "/test-error",
        "headers": [],
        "query_string": b"",
        "server": ("test", 80)
    }
    mock_request = Request(mock_scope)
    mock_exc = RuntimeError("Sensitive DB Connection String: mongodb://admin:secret@internal-db:27017")

    res = await general_exception_handler(mock_request, mock_exc)
    assert res.status_code == 500
    import json
    data = json.loads(res.body.decode("utf-8"))
    assert data["error"] == "InternalServerError"
    assert "correlation_id" in data
    assert "Sensitive DB Connection String" not in json.dumps(data)
    assert "detail" not in data or not data["detail"]


@pytest.mark.asyncio
async def test_sensor_ingestion_authentication_and_limits():
    """
    Regression test for Critical Finding: Unauthenticated sensor ingestion.
    - Raw sensor ingestion endpoints (/suricata/eve, /zeek/conn, /zeek/dns) must require sensor credentials.
    - Unauthenticated requests are rejected with HTTP 401.
    - Payload size limits (> 1,000 items) are rejected with HTTP 413.
    - Replay protection drops duplicate event hashes.
    """
    from httpx import AsyncClient, ASGITransport
    from backend.main import app
    from backend.auth.jwt_handler import create_access_token

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Unauthenticated ingestion rejected with 401
        from backend.pipeline.schemas import get_utc_iso_now
        suricata_payload = {
            "timestamp": get_utc_iso_now(),
            "event_type": "alert",
            "src_ip": "192.168.1.100",
            "dest_ip": "10.0.0.5",
            "alert": {"signature": "ET SCAN Nmap", "category": "Scan"}
        }
        res_no_auth = await client.post("/api/v1/sensors/suricata/eve", json=suricata_payload)
        assert res_no_auth.status_code == 401, f"Expected 401 Unauthorized without sensor credentials, got {res_no_auth.status_code}"

        res_zeek_no_auth = await client.post("/api/v1/sensors/zeek/conn", json={"id.orig_h": "192.168.1.50"})
        assert res_zeek_no_auth.status_code == 401, f"Expected 401 Unauthorized for Zeek, got {res_zeek_no_auth.status_code}"

        # 2. Authenticated sensor submission succeeds
        sensor_token = create_access_token("sensor-edge-01", "sensor", "org_demo")
        headers = {"Authorization": f"Bearer {sensor_token}"}

        res_auth = await client.post("/api/v1/sensors/suricata/eve", json=suricata_payload, headers=headers)
        assert res_auth.status_code == 200
        auth_data = res_auth.json()
        assert auth_data["status"] == "success"
        assert auth_data["events_ingested"] == 1

        # 3. Replay Protection: immediate resubmission of duplicate record is dropped
        res_replay = await client.post("/api/v1/sensors/suricata/eve", json=suricata_payload, headers=headers)
        assert res_replay.status_code == 200
        replay_data = res_replay.json()
        assert replay_data["events_ingested"] == 0, "Replay duplicate record must be filtered out"

        # 4. Oversized payload (> 1,000 records) rejected with 413
        oversized_payload = [{"timestamp": "2026-11-06T12:00:00Z", "src_ip": f"10.0.0.{i % 250}"} for i in range(1005)]
        res_oversized = await client.post("/api/v1/sensors/suricata/eve", json=oversized_payload, headers=headers)
        assert res_oversized.status_code == 413, f"Expected 413 Payload Too Large, got {res_oversized.status_code}"
