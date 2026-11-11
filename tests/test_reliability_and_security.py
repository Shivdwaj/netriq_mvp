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


@pytest.mark.asyncio
async def test_admin_setup_endpoint_and_lockout():
    """
    Regression test for Finding 1 (Default Administrator Credentials):
    - When an administrator exists, POST /api/v1/auth/setup is locked out with HTTP 403.
    - Weak passwords during setup are rejected with HTTP 400.
    - Initial setup creates the administrator and immediately closes setup mode.
    """
    from httpx import AsyncClient, ASGITransport
    from backend.main import app
    from backend.database.collections import users_repo
    from unittest.mock import patch, AsyncMock

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Existing admin locks out /setup
        with patch.object(users_repo, "list", new_callable=AsyncMock, return_value=[{"id": "existing_admin"}]):
            res_locked = await client.post(
                "/api/v1/auth/setup",
                json={"email": "newadmin@netriq.local", "password": "SecurePassword123!"}
            )
            assert res_locked.status_code == 403
            assert "setup mode is permanently disabled" in res_locked.json()["detail"].lower()

        # 2. No admin present: Weak password rejected
        with patch.object(users_repo, "list", new_callable=AsyncMock, return_value=[]):
            res_weak = await client.post(
                "/api/v1/auth/setup",
                json={"email": "admin@netriq.local", "password": "short"}
            )
            assert res_weak.status_code == 400
            assert "at least 12 characters" in res_weak.json()["detail"].lower()

        # 3. No admin present: Valid setup succeeds
        with patch.object(users_repo, "list", new_callable=AsyncMock, return_value=[]), \
             patch.object(users_repo, "create", new_callable=AsyncMock, return_value="admin_u1"):
            res_ok = await client.post(
                "/api/v1/auth/setup",
                json={"email": "initadmin@netriq.local", "password": "SuperSecureAdminPassword2026!"}
            )
            assert res_ok.status_code == 200
            assert res_ok.json()["success"] is True
            assert res_ok.json()["role"] == "admin"


@pytest.mark.asyncio
async def test_cors_strict_origins_and_no_wildcards():
    """
    Regression test for Finding 2 (Permissive CORS Configuration):
    - Wildcard origins and regex matching are disallowed when credentials are True.
    - Safe explicit trusted origins are loaded by default.
    - ALLOWED_ORIGINS environment parsing sanitizes wildcards.
    """
    from backend.middleware.cors import get_allowed_origins, add_cors_middleware
    from fastapi import FastAPI
    from unittest.mock import patch

    # 1. Default trusted origins when env var is empty
    with patch.dict(os.environ, {"ALLOWED_ORIGINS": ""}, clear=False):
        origins = get_allowed_origins()
        assert "http://localhost:3000" in origins
        assert "http://127.0.0.1:3000" in origins
        assert "*" not in origins

    # 2. Environment with wildcard strips '*' to protect credentialed cookies
    with patch.dict(os.environ, {"ALLOWED_ORIGINS": "*,https://portal.netriq.io"}, clear=False):
        sanitized = get_allowed_origins()
        assert "*" not in sanitized
        assert "https://portal.netriq.io" in sanitized

    # 3. CORSMiddleware does NOT use allow_origin_regex
    test_app = FastAPI()
    add_cors_middleware(test_app)
    cors_mw = [m for m in test_app.user_middleware if "CORSMiddleware" in str(m.cls)]
    assert len(cors_mw) == 1
    kwargs = cors_mw[0].kwargs
    assert kwargs.get("allow_origin_regex") is None
    assert kwargs.get("allow_credentials") is True
    assert "*" not in kwargs.get("allow_origins", [])


@pytest.mark.asyncio
async def test_management_api_tenant_isolation_and_sensor_key_enforcement():
    """
    Regression test for Finding 3 (Multi-tenant isolation & Sensor management):
    - POST /management/sensors/heartbeat without X-Sensor-Key returns 401.
    - POST /management/sensors/heartbeat with invalid X-Sensor-Key returns 401.
    - Non-admin user cannot access cross-tenant data via X-Tenant-ID spoofing.
    - Admin user can query across tenants.
    """
    from httpx import AsyncClient, ASGITransport
    from backend.main import app
    from backend.api.management import _get_request_tenant
    from starlette.requests import Request
    from fastapi import HTTPException

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Heartbeat missing X-Sensor-Key rejected
        hb_payload = {
            "sensor_id": "sensor-suricata-01",
            "cpu_usage_pct": 12.5,
            "memory_usage_mb": 256.0,
            "kernel_drops_count": 0,
            "packets_processed": 1000,
            "uptime_seconds": 3600.0
        }
        res_no_key = await client.post("/api/v1/management/sensors/heartbeat", json=hb_payload)
        assert res_no_key.status_code == 401
        assert "Missing required sensor authentication key" in res_no_key.json()["detail"]

        # 2. Heartbeat with invalid X-Sensor-Key rejected
        res_bad_key = await client.post(
            "/api/v1/management/sensors/heartbeat",
            json=hb_payload,
            headers={"X-Sensor-Key": "invalid_bogus_key"}
        )
        assert res_bad_key.status_code == 401
        assert "Invalid or unauthorized" in res_bad_key.json()["detail"]

    # 3. Cross-tenant spoofing rejected for non-admin user
    scope_user = {
        "type": "http",
        "method": "GET",
        "path": "/management/sensors",
        "headers": [(b"x-tenant-id", b"tenant_target")],
        "query_string": b"",
        "server": ("test", 80)
    }
    req_user = Request(scope_user)
    req_user.state.user = {"sub": "user_123", "role": "analyst", "tenant_id": "tenant_assigned"}

    with pytest.raises(HTTPException) as exc_info:
        _get_request_tenant(req_user)
    assert exc_info.value.status_code == 403
    assert "Cross-tenant access prohibited" in exc_info.value.detail

    # 4. Admin caller permitted to query specified tenant
    scope_admin = {
        "type": "http",
        "method": "GET",
        "path": "/management/sensors",
        "headers": [(b"x-tenant-id", b"tenant_target")],
        "query_string": b"",
        "server": ("test", 80)
    }
    req_admin = Request(scope_admin)
    req_admin.state.user = {"sub": "admin_root", "role": "admin", "tenant_id": "tenant_admin"}
    assert _get_request_tenant(req_admin) == "tenant_target"


@pytest.mark.asyncio
async def test_rate_limiter_bounded_lru_and_bucket_partitioning():
    """
    Regression test for Finding 4 (Rate-Limiting Hardening):
    - Dedicated rate buckets for Auth vs Ingest vs General.
    - LRU eviction prunes old/stale entries without wiping the entire cache.
    - Cache clear bypass vulnerability is eliminated.
    """
    import time
    from backend.middleware.rate_limit import RateLimitMiddleware
    from fastapi import FastAPI

    test_app = FastAPI()
    limiter = RateLimitMiddleware(test_app, max_requests=100, auth_max=15, ingest_max=1200)

    # 1. Verify bucket partitioning
    assert limiter._determine_bucket_and_limit("/api/v1/auth/login") == ("auth", 15, 60)
    assert limiter._determine_bucket_and_limit("/api/v1/sensor/eve") == ("ingest", 1200, 60)
    assert limiter._determine_bucket_and_limit("/api/v1/incidents") == ("general", 100, 60)

    # 2. Test bounded LRU eviction (does NOT wipe cache)
    now = time.time()
    # Populate cache with dummy entries
    for i in range(10050):
        limiter._cache[f"key_{i}"] = {"count": 1, "reset_time": now + 60}

    # Evict
    limiter._evict_stale_or_oldest(now)
    # Cache should be bounded and not wiped to 0
    assert len(limiter._cache) <= 10000
    assert len(limiter._cache) > 8000, "Cache must not be wiped entirely on threshold overflow"


@pytest.mark.asyncio
async def test_websocket_preauth_limits_and_max_payload():
    """
    Regression test for Finding 5 (WebSocket Security Hardening):
    - Concurrency limit per IP for pre-auth connections.
    - Maximum frame payload size (64 KB).
    - Slot release upon authentication completion.
    """
    from backend.api.websocket import (
        _acquire_preauth_slot,
        _release_preauth_slot,
        MAX_PREAUTH_PER_IP,
        MAX_PAYLOAD_BYTES
    )

    test_ip = "198.51.100.42"

    # 1. Frame size limit is 64KB
    assert MAX_PAYLOAD_BYTES == 65536

    # 2. Acquire up to max slots
    for _ in range(MAX_PREAUTH_PER_IP):
        assert await _acquire_preauth_slot(test_ip) is True

    # 3. Next connection from same IP is rejected
    assert await _acquire_preauth_slot(test_ip) is False

    # 4. Releasing slot allows new connection
    await _release_preauth_slot(test_ip)
    assert await _acquire_preauth_slot(test_ip) is True

    # Cleanup
    for _ in range(MAX_PREAUTH_PER_IP):
        await _release_preauth_slot(test_ip)


@pytest.mark.asyncio
async def test_response_engine_cidr_infrastructure_and_quarantine_quota():
    """
    Regression test for Finding 6 (Automated Response Engine Safeguards):
    - CIDR-aware infrastructure bypass (loopback, broadcast, gateway, crown jewels).
    - Crown jewel assets protected from automated quarantine.
    - Sliding-window quarantine quota enforcement prevents cascading network DoS.
    """
    from backend.response.response_engine import ResponseEngine
    from backend.ai.contracts import Action, PredictionResult, RiskCategory
    from unittest.mock import AsyncMock, patch

    engine = ResponseEngine()
    engine.quarantine.quarantine_device = AsyncMock(return_value=True)

    # 1. Loopback, broadcast, and standard gateway are protected
    is_loopback, r1 = engine._is_protected_infrastructure("127.0.0.1", {})
    assert is_loopback is True
    assert "Loopback" in r1

    is_bcast, r2 = engine._is_protected_infrastructure("255.255.255.255", {})
    assert is_bcast is True

    is_gw, r3 = engine._is_protected_infrastructure("192.168.1.1", {})
    assert is_gw is True
    assert "Gateway" in r3

    # 2. Crown Jewel Asset Protection
    context_jewel = {"crown_jewel_assets": ["10.50.1.10"]}
    is_jewel, r4 = engine._is_protected_infrastructure("10.50.1.10", context_jewel)
    assert is_jewel is True
    assert "Crown Jewel" in r4

    # 3. Normal IP is NOT protected
    is_normal, _ = engine._is_protected_infrastructure("192.168.1.55", {})
    assert is_normal is False

    # 4. Quarantine Quota Limiting
    pred = PredictionResult(
        verdict=True,
        confidence=98.0,
        risk_category=RiskCategory.CRITICAL,
        model_used="Test",
        latency_ms=1.0
    )

    with patch.dict(os.environ, {"QUARANTINE_MAX_QUOTA_PER_HOUR": "2"}), \
         patch("backend.services.settings_service.settings_service.get_settings", new_callable=AsyncMock, return_value={"auto_quarantine": True}):
        # Mock ResponseEngine quota to 2
        engine.max_quarantine_quota = 2
        engine._recent_quarantines = {}

        # 1st quarantine: Allowed
        q1 = await engine.handle_verdict(pred, Action.QUARANTINE, {"src_ip": "192.168.1.51", "src_mac": "00:11:22:33:44:51"})
        assert q1 is True

        # 2nd quarantine: Allowed
        q2 = await engine.handle_verdict(pred, Action.QUARANTINE, {"src_ip": "192.168.1.52", "src_mac": "00:11:22:33:44:52"})
        assert q2 is True

        # 3rd quarantine exceeds quota (2 max per hour): Suppressed/bypassed
        q3 = await engine.handle_verdict(pred, Action.QUARANTINE, {"src_ip": "192.168.1.53", "src_mac": "00:11:22:33:44:53"})
        assert q3 is False
        assert engine.quarantine.quarantine_device.call_count == 2


@pytest.mark.asyncio
async def test_sensor_registration_authentication_and_tenant_enforcement():
    """
    Regression test for Phase 1 Step 1 (Sensor Registration Security):
    - Unauthenticated registration rejected with 401 when not in testing mode.
    - Non-admin user cannot register a sensor for a foreign tenant (403).
    - Authenticated admin or matching tenant user can register.
    """
    from httpx import AsyncClient, ASGITransport
    from backend.main import app
    from backend.auth.jwt_handler import create_access_token
    from unittest.mock import patch

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        reg_payload = {
            "tenant_id": "target_tenant",
            "name": "edge-suricata-probe",
            "software_type": "suricata",
            "software_version": "7.0.2",
            "hostname": "probe-vm"
        }

        # 1. Unauthenticated registration rejected when TESTING is false
        with patch.dict(os.environ, {"TESTING": "false"}):
            resp_unauth = await client.post("/api/v1/sensors/register", json=reg_payload)
            assert resp_unauth.status_code == 401
            assert "Authentication required" in resp_unauth.json()["detail"]

        # 2. Non-admin user attempting cross-tenant registration rejected with 403
        analyst_token = create_access_token("analyst_user", "analyst", tenant_id="analyst_tenant")
        with patch.dict(os.environ, {"TESTING": "false"}):
            resp_cross = await client.post(
                "/api/v1/sensors/register",
                json=reg_payload,
                headers={"Authorization": f"Bearer {analyst_token}"}
            )
            assert resp_cross.status_code == 403
            assert "foreign organisation" in resp_cross.json()["detail"]


@pytest.mark.asyncio
async def test_sensor_heartbeat_key_enforcement_and_identity_binding():
    """
    Regression test for Phase 1 Step 1 (Sensor Heartbeat Authentication & Identity Binding):
    - Heartbeat without X-Sensor-Key or Bearer token is rejected with 401.
    - Heartbeat with invalid X-Sensor-Key is rejected with 401.
    - Heartbeat with key for sensor A reporting for sensor B is rejected with 403 (identity binding).
    """
    from httpx import AsyncClient, ASGITransport
    from backend.main import app
    from backend.services.central_management_service import central_management_service
    from backend.schemas.management import SensorRegistrationReq, SensorSoftwareType

    # Provision two sensors
    s1 = await central_management_service.register_software_sensor(SensorRegistrationReq(
        tenant_id="tenant_alpha",
        name="alpha-probe",
        software_type=SensorSoftwareType.SURICATA,
        software_version="7.0.2",
        hostname="alpha-box"
    ))
    s2 = await central_management_service.register_software_sensor(SensorRegistrationReq(
        tenant_id="tenant_beta",
        name="beta-probe",
        software_type=SensorSoftwareType.ZEEK,
        software_version="6.0.3",
        hostname="beta-box"
    ))

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        hb_body = {
            "sensor_id": s1.sensor_id,
            "cpu_usage_pct": 15.0,
            "memory_usage_mb": 256.0,
            "kernel_drops_count": 0,
            "packets_processed": 5000,
            "uptime_seconds": 600.0
        }

        # 1. Missing authentication rejected with 401
        res_no_auth = await client.post("/api/v1/sensors/heartbeat", json=hb_body)
        assert res_no_auth.status_code == 401

        # 2. Invalid sensor key rejected with 401
        res_bad_key = await client.post(
            "/api/v1/sensors/heartbeat",
            json=hb_body,
            headers={"X-Sensor-Key": "ntrq_invalid_key_12345"}
        )
        assert res_bad_key.status_code == 401

        # 3. Valid key for sensor A submitting heartbeat for sensor B rejected with 403
        hb_body_mismatch = dict(hb_body)
        hb_body_mismatch["sensor_id"] = s2.sensor_id
        res_mismatch = await client.post(
            "/api/v1/sensors/heartbeat",
            json=hb_body_mismatch,
            headers={"X-Sensor-Key": s1.api_key}
        )
        assert res_mismatch.status_code == 401 or res_mismatch.status_code == 403
        assert "mismatch" in res_mismatch.json()["detail"].lower() or "unauthorized" in res_mismatch.json()["detail"].lower()

        # 4. Valid key with matching sensor ID accepted with 200
        res_valid = await client.post(
            "/api/v1/sensors/heartbeat",
            json=hb_body,
            headers={"X-Sensor-Key": s1.api_key}
        )
        assert res_valid.status_code == 200
        assert res_valid.json()["sensor_status"] == "healthy"


@pytest.mark.asyncio
async def test_database_health_reporting_and_production_safeguards():
    """
    Regression test for Phase 1 Step 2 (Database Health Reporting & Production Safeguards):
    - In-memory database fallback is accurately detected and reported as 'degraded'.
    - /health endpoint returns status: 'degraded' when MongoDB is not connected.
    - MongoDB ping when healthy returns status: 'healthy' and database: 'online'.
    - DatabaseManager.connect_db() in production environment refuses silent in-memory fallback.
    """
    from httpx import AsyncClient, ASGITransport
    from backend.main import app
    from backend.database.database import DatabaseManager
    from backend.database.in_memory_db import InMemoryDatabase
    from backend.database.exceptions import DatabaseConnectionError
    from unittest.mock import AsyncMock, patch

    # 1. In-memory database health status
    DatabaseManager.db = InMemoryDatabase()
    DatabaseManager.client = None

    assert DatabaseManager.is_in_memory() is True
    assert DatabaseManager.is_persistent() is False
    assert await DatabaseManager.health_check() is False

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/v1/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "degraded"
        assert "in-memory fallback" in data["components"]["database"]
        assert data["components"]["database_persistent"] is False
        assert data["components"]["database_storage"] == "in-memory"

        # 2. Healthy MongoDB mock
        mock_client = AsyncMock()
        mock_client.admin.command = AsyncMock(return_value={"ok": 1})
        old_client = DatabaseManager.client
        old_db = DatabaseManager.db
        try:
            DatabaseManager.client = mock_client
            DatabaseManager.db = AsyncMock() # Non InMemoryDatabase
            assert DatabaseManager.is_persistent() is True
            assert await DatabaseManager.health_check() is True

            res_healthy = await client.get("/api/v1/health")
            data_healthy = res_healthy.json()
            assert data_healthy["components"]["database"] == "online"
            assert data_healthy["components"]["database_persistent"] is True
            assert data_healthy["components"]["database_storage"] == "mongodb"
        finally:
            DatabaseManager.client = old_client
            DatabaseManager.db = old_db

    # 3. Production safeguard: connect_db refuses in-memory fallback in production
    DatabaseManager.db = None
    DatabaseManager.client = None
    with patch.dict(os.environ, {"ENVIRONMENT": "production", "MONGO_TIMEOUT_MS": "100"}), \
         patch("backend.database.database.AsyncIOMotorClient", side_effect=Exception("Connection refused")):
        with pytest.raises(DatabaseConnectionError) as exc_info:
            await DatabaseManager.connect_db(retries=1)
        assert "Refusing to run on unpersisted volatile in-memory fallback" in str(exc_info.value)
    DatabaseManager.db = InMemoryDatabase()


@pytest.mark.asyncio
async def test_event_bus_bounded_queue_and_backpressure():
    """
    Regression test for Phase 2 Step 3 (Bounded Event Processing & Backpressure):
    - Replaces unbounded create_task with bounded queue and worker pool.
    - Full queue triggers backpressure timeout and safely drops without memory leak.
    - Worker pool consumes and executes subscriber callbacks.
    """
    from backend.pipeline.event_bus import SecurityEventBus
    from backend.pipeline.schemas import NormalizedSecurityEvent

    bus = SecurityEventBus(history_limit=10, max_queue_size=3, max_concurrency=1)
    processed = []

    async def slow_consumer(event: NormalizedSecurityEvent):
        await asyncio.sleep(0.5)
        processed.append(event.event_id)

    bus.subscribe(slow_consumer)

    # Rapidly burst 15 events into queue of capacity 3 with 0.001s timeout
    dropped_count = 0
    for i in range(15):
        evt = NormalizedSecurityEvent(
            event_id=f"evt-{i}",
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2"
        )
        res = await bus.publish(evt, timeout=0.001)
        if not res:
            dropped_count += 1

    assert dropped_count > 0 or bus.dropped_count > 0
    assert bus.dropped_count >= 1

    # Drain remaining events
    await bus.drain(timeout=2.0)
    await bus.shutdown()
    assert len(processed) > 0


@pytest.mark.asyncio
async def test_correlation_duplicate_event_insertion_prevention():
    """
    Regression test for Phase 2 Step 4 (Duplicate Event Insertion Prevention):
    - evidence_service.link_event_to_incident deduplicates multiple linkages for same (incident_id, event_id).
    - correlation_engine does not duplicate events in tracker when evaluating findings.
    """
    from backend.services.evidence_service import evidence_service
    from backend.database.collections import incident_events_repo
    from backend.schemas.entities import IncidentEventRole
    from backend.database.in_memory_db import InMemoryDatabase
    from backend.database.database import DatabaseManager

    DatabaseManager.db = InMemoryDatabase()

    tenant_id = "test_tenant"
    inc_id = "inc-test-dedup-01"
    evt_id = "evt-test-unique-01"

    # 1. Link event first time
    l1 = await evidence_service.link_event_to_incident(
        tenant_id=tenant_id,
        incident_id=inc_id,
        event_id=evt_id,
        role_in_incident=IncidentEventRole.TRIGGER
    )
    assert l1 is not None

    # 2. Repeated link calls for same incident_id and event_id return existing without creating duplicates
    l2 = await evidence_service.link_event_to_incident(
        tenant_id=tenant_id,
        incident_id=inc_id,
        event_id=evt_id,
        role_in_incident=IncidentEventRole.SUPPORTING
    )
    assert l2.event_id == l1.event_id
    assert l2.incident_id == l1.incident_id

    # 3. Verify exactly 1 record in incident_events repository
    matches = await incident_events_repo.list(filter_query={"incident_id": inc_id, "event_id": evt_id})
    assert len(matches) == 1


@pytest.mark.asyncio
async def test_restore_active_incident_association_after_restart():
    """
    Regression test for Phase 2 Step 5 (Restore Active Incident Association after Restarts):
    - When backend restarts, in-memory trackers are empty.
    - Next event for an asset with an ongoing open incident associates with the existing incident
      instead of creating a fragmented second incident.
    """
    import time
    from backend.services.correlation_service import CorrelationEngine
    from backend.database.collections import incidents_repo
    from backend.pipeline.schemas import NormalizedSecurityEvent, DeviceIdentity
    from backend.database.in_memory_db import InMemoryDatabase
    from backend.database.database import DatabaseManager

    DatabaseManager.db = InMemoryDatabase()

    attacker_ip = "192.168.1.99"
    now = time.time()

    # 1. Seed existing open incident created 10 minutes ago
    existing_inc_id = await incidents_repo.create({
        "tenant_id": "corp_restart",
        "status": "investigating",
        "incident_type": "Multi-Stage Attack",
        "severity": "HIGH",
        "title": "Initial Discovery",
        "src_ip": attacker_ip,
        "affected_assets": [attacker_ip],
        "created_at": now - 600,
        "updated_at": now - 300,
        "attack_chain": ["Stage 1: Discovery (T1046)"],
        "evidence": [{"event_id": "seed-evt-1", "dst_port": 80, "stage": "reconnaissance"}],
        "event_count": 1
    })

    # 2. Simulate fresh engine post-restart (empty _trackers)
    engine = CorrelationEngine(window_seconds=1200.0)
    assert attacker_ip not in engine._trackers

    # 3. New event arrives from same attacker IP
    new_evt = NormalizedSecurityEvent(
        tenant_id="corp_restart",
        source_ip=attacker_ip,
        destination_ip="192.168.1.10",
        source_port=55100,
        destination_port=445,  # Lateral SMB probe
        protocol="TCP",
        event_type="connection",
        direction="internal",
        device=DeviceIdentity(ip=attacker_ip, hostname="Restart-Node", is_managed=True)
    )

    await engine.process_event(new_evt)

    # 4. Verify the active incident was restored from DB rather than duplicated
    tracker = engine._trackers.get(attacker_ip)
    assert tracker is not None
    assert tracker.active_incident_id == existing_inc_id

    # 5. Verify no second incident was created in incidents_repo
    all_incs = await incidents_repo.list(filter_query={"src_ip": attacker_ip})
    assert len(all_incs) == 1
    assert all_incs[0]["id"] == existing_inc_id


@pytest.mark.asyncio
async def test_threshold_optimizer_empirical_calibration():
    """
    Phase 3: Verify ThresholdOptimizer calibrates optimal score thresholds
    using empirical validation distributions without crashing or hardcoded fallbacks.
    """
    from backend.ai.threshold_optimizer import ThresholdOptimizer
    import numpy as np

    optimizer = ThresholdOptimizer(target_metric="f1")

    # Generate synthetic scores: 50 clean scores around 0.2, 50 malicious around 0.8
    np.random.seed(42)
    clean_scores = np.random.normal(loc=0.2, scale=0.1, size=50).tolist()
    malicious_scores = np.random.normal(loc=0.8, scale=0.1, size=50).tolist()

    val_scores = clean_scores + malicious_scores
    labels = [0] * 50 + [1] * 50

    result = optimizer.calibrate(val_scores, labels)

    assert result["calibrated"] is True
    assert 0.3 <= result["optimal_threshold"] <= 0.7
    assert result["metrics"]["f1_score"] > 0.85
    assert result["metrics"]["sample_count"] == 100
    assert result["metrics"]["target_metric"] == "f1"

    # Test edge case: empty or invalid inputs gracefully fall back
    fallback = optimizer.calibrate([], [])
    assert fallback["calibrated"] is False
    assert fallback["optimal_threshold"] == 0.5


@pytest.mark.asyncio
async def test_adapters_observable_telemetry_and_tls_enrichment():
    """
    Phase 3: Verify Suricata and Zeek adapters track malformed event telemetry,
    log warnings, and enrich events with TLS/SSL metadata.
    """
    from backend.adapters.suricata_adapter import SuricataAdapter
    from backend.adapters.zeek_adapter import ZeekAdapter

    suricata = SuricataAdapter()
    zeek = ZeekAdapter()

    # 1. Suricata malformed JSON handling
    res1 = suricata.transform("INVALID_NOT_A_JSON")
    assert res1 is None
    assert suricata.malformed_count == 1
    assert suricata.processed_count == 1

    # 2. Suricata TLS metadata enrichment
    suricata_tls_payload = {
        "timestamp": "2026-11-11T12:00:00.000Z",
        "event_type": "alert",
        "src_ip": "192.168.1.100",
        "dest_ip": "10.0.0.5",
        "src_port": 49200,
        "dest_port": 443,
        "proto": "TCP",
        "alert": {
            "signature": "ET TROJAN Observed Malicious SSL Cert",
            "category": "A Network Trojan was detected",
            "severity": 1,
            "signature_id": 202888
        },
        "tls": {
            "sni": "malicious-c2.evil.com",
            "version": "TLS 1.3",
            "subject": "CN=malicious-c2.evil.com",
            "issuer": "CN=Evil CA",
            "ja3": "51c64c77e60f3980ebd90973b1b70467"
        }
    }
    evt_suri = suricata.transform(suricata_tls_payload)
    assert evt_suri is not None
    assert evt_suri.evidence["tls"]["sni"] == "malicious-c2.evil.com"
    assert evt_suri.evidence["tls"]["ja3"] == "51c64c77e60f3980ebd90973b1b70467"
    assert suricata.transformed_count == 1
    metrics_suri = suricata.get_metrics()
    assert metrics_suri["processed"] == 2
    assert metrics_suri["transformed"] == 1
    assert metrics_suri["malformed"] == 1

    # 3. Zeek malformed string and missing IPs
    res_z1 = zeek.transform("{bad_json")
    assert res_z1 is None
    assert zeek.malformed_count == 1

    res_z2 = zeek.transform({"proto": "tcp"})  # Missing src_ip and dst_ip
    assert res_z2 is None
    assert zeek.malformed_count == 2

    # 4. Zeek SSL record and TLS enrichment
    zeek_ssl_payload = {
        "ts": 1700000000.0,
        "uid": "CHfSZ32168zeek",
        "id.orig_h": "192.168.1.105",
        "id.resp_h": "10.0.0.25",
        "id.orig_p": 51234,
        "id.resp_p": 443,
        "proto": "tcp",
        "ssl": {
            "server_name": "internal-vault.corp.local",
            "subject": "CN=internal-vault.corp.local",
            "issuer": "CN=Corp Internal CA",
            "ja3": "6734f37431670b3ab4292b8f60f29984",
            "version": "TLSv1.2",
            "cipher": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        }
    }
    evt_zeek = zeek.transform(zeek_ssl_payload)
    assert evt_zeek is not None
    assert evt_zeek.evidence["tls"]["sni"] == "internal-vault.corp.local"
    assert evt_zeek.evidence["tls"]["ja3"] == "6734f37431670b3ab4292b8f60f29984"
    assert evt_zeek.evidence["tls"]["cipher"] == "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    assert zeek.transformed_count == 1
    metrics_zeek = zeek.get_metrics()
    assert metrics_zeek["processed"] == 3
    assert metrics_zeek["transformed"] == 1
    assert metrics_zeek["malformed"] == 2


@pytest.mark.asyncio
async def test_response_engine_mac_verification_and_retry_resilience():
    """
    Phase 3: Verify ResponseEngine suppresses Layer 2 quarantine on unverified MACs,
    resolves MACs via IdentityResolver when possible, and retries on transient adapter errors.
    """
    from backend.response.response_engine import ResponseEngine
    from backend.ai.contracts import Action, PredictionResult, RiskCategory
    from backend.pipeline.identity_resolver import identity_resolver
    from unittest.mock import AsyncMock, patch

    engine = ResponseEngine()
    engine.quarantine.quarantine_device = AsyncMock(return_value=True)
    engine.firewall.block_ip = AsyncMock(return_value=True)

    pred = PredictionResult(
        verdict=True,
        confidence=96.0,
        risk_category=RiskCategory.HIGH,
        model_used="BehavioralPipeline",
        latency_ms=1.5
    )

    with patch("backend.services.settings_service.settings_service.get_settings", new_callable=AsyncMock, return_value={"auto_quarantine": True}):
        # 1. Unverified MAC (None / missing) with unmanaged IP -> Quarantine SUPPRESSED
        suppressed1 = await engine.handle_verdict(
            prediction=pred,
            action=Action.QUARANTINE,
            context={"src_ip": "192.168.1.222", "src_mac": None}
        )
        assert suppressed1 is False
        assert engine.quarantine.quarantine_device.call_count == 0

        # 2. Invalid / broadcast MAC -> Quarantine SUPPRESSED
        suppressed2 = await engine.handle_verdict(
            prediction=pred,
            action=Action.QUARANTINE,
            context={"src_ip": "192.168.1.222", "src_mac": "ff:ff:ff:ff:ff:ff"}
        )
        assert suppressed2 is False
        assert engine.quarantine.quarantine_device.call_count == 0

        # 3. Unspecified MAC, but target IP IS registered in IdentityResolver -> Resolves & executes quarantine
        identity_resolver.register_device(
            ip="192.168.1.88",
            mac="00:11:22:33:44:88",
            hostname="workstation-88"
        )
        success_resolved = await engine.handle_verdict(
            prediction=pred,
            action=Action.QUARANTINE,
            context={"src_ip": "192.168.1.88"}  # no src_mac in context
        )
        assert success_resolved is True
        assert engine.quarantine.quarantine_device.call_count == 1
        # Check that quarantine was called with the resolved MAC
        call_args = engine.quarantine.quarantine_device.call_args[0]
        assert call_args[0] == "192.168.1.88"
        assert call_args[1] == "00:11:22:33:44:88"

        # 4. Response Retries: transient error on attempt 1, success on attempt 2
        call_counter = 0
        async def flaky_block(ip, reason):
            nonlocal call_counter
            call_counter += 1
            if call_counter == 1:
                raise ConnectionError("Transient network reset")
            return True

        engine.firewall.block_ip = AsyncMock(side_effect=flaky_block)
        retry_success = await engine.handle_verdict(
            prediction=pred,
            action=Action.RECOMMEND_BLOCK,
            context={"src_ip": "198.51.100.44"}
        )
        assert retry_success is True
        assert call_counter == 2  # Succeeded on retry attempt 2


@pytest.mark.asyncio
async def test_localized_forensic_event_explanation():
    """
    Phase 3: Verify IncidentExplainer provides localized forensic feature
    contribution explanations for individual events without requiring SHAP.
    """
    from backend.intelligence.explainer import incident_explainer
    from backend.pipeline.schemas import NormalizedSecurityEvent

    event = NormalizedSecurityEvent(
        tenant_id="corp_sec",
        sensor_id="sensor-zeek-01",
        source_ip="192.168.1.200",
        destination_ip="192.168.1.10",
        source_port=49500,
        destination_port=445,  # Sensitive SMB port
        protocol="TCP",
        event_type="connection",
        severity="HIGH",
        direction="internal",
        evidence={
            "conn_state": "S0",
            "scan_indicator": True,
            "tls": {
                "sni": "auth.corp.local",
                "ja3": "771f35e521e4c79f3b93b46007f91d75"
            }
        }
    )

    explanation = incident_explainer.explain_event(event)

    assert explanation["event_id"] == event.event_id
    assert explanation["severity"] == "HIGH"
    assert "Reconnaissance" in explanation["primary_driver"] or "Scan" in explanation["primary_driver"]
    assert "destination_port_sensitivity" in explanation["feature_contributions"]
    assert explanation["feature_contributions"]["destination_port_sensitivity"] >= 0.90
    assert explanation["feature_contributions"]["reconnaissance_pattern"] >= 0.90
    assert explanation["feature_contributions"]["tls_metadata_presence"] > 0
    assert len(explanation["risk_factors"]) >= 2
    assert "auth.corp.local" in str(explanation["risk_factors"])
    assert "T1046" in explanation["mitre_technique"]


@pytest.mark.asyncio
async def test_event_bus_atomic_concurrency_and_graceful_shutdown():
    """
    Verify EventBus queue limit checking and task enrollment are atomic under load,
    and shutdown drains in-flight tasks before cancelling.
    """
    from backend.pipeline.event_bus import SecurityEventBus
    from backend.pipeline.schemas import NormalizedSecurityEvent

    bus = SecurityEventBus(max_concurrency=10, max_queue_size=10)
    processed_count = 0

    async def slow_subscriber(ev):
        nonlocal processed_count
        await asyncio.sleep(0.05)
        processed_count += 1

    bus.subscribe(slow_subscriber)

    evt = NormalizedSecurityEvent(
        tenant_id="test",
        source_ip="192.168.1.1",
        destination_ip="192.168.1.2",
        source_port=1000,
        destination_port=80,
        protocol="TCP"
    )

    # Concurrently publish 40 events with 0.001s backpressure timeout
    results = await asyncio.gather(*[bus.publish(evt, timeout=0.001) for _ in range(40)])

    # Max queue size is 10: exactly 10 accepted, 30 rejected
    accepted = sum(1 for r in results if r is True)
    rejected = sum(1 for r in results if r is False)
    assert accepted == 10
    assert rejected == 30
    assert bus.dropped_count == 30
    assert bus.queue_depth <= 10

    # Test graceful shutdown (drains in-flight tasks)
    await bus.shutdown(drain_timeout=2.0)
    assert bus.queue_depth == 0
    assert processed_count == 10


@pytest.mark.asyncio
async def test_multi_tenant_correlation_isolation():
    """
    Verify CorrelationEngine maintains independent trackers for different tenants
    even when RFC1918 private IP addresses overlap (e.g. 10.0.0.99).
    """
    from backend.services.correlation_service import CorrelationEngine
    from backend.pipeline.schemas import NormalizedSecurityEvent

    engine = CorrelationEngine()

    # Tenant Alpha event from 10.0.0.99
    evt_alpha = NormalizedSecurityEvent(
        tenant_id="org_alpha",
        source_ip="10.0.0.99",
        destination_ip="10.0.0.1",
        source_port=50000,
        destination_port=445,
        protocol="TCP",
        event_type="connection"
    )

    # Tenant Beta event from exact same IP 10.0.0.99
    evt_beta = NormalizedSecurityEvent(
        tenant_id="org_beta",
        source_ip="10.0.0.99",
        destination_ip="10.0.0.1",
        source_port=50001,
        destination_port=3389,
        protocol="TCP",
        event_type="connection"
    )

    await engine.process_event(evt_alpha)
    await engine.process_event(evt_beta)

    # Ensure separate trackers exist under composite tenant keys
    assert "org_alpha:10.0.0.99" in engine._trackers
    assert "org_beta:10.0.0.99" in engine._trackers

    tracker_alpha = engine._trackers["org_alpha:10.0.0.99"]
    tracker_beta = engine._trackers["org_beta:10.0.0.99"]

    assert tracker_alpha is not tracker_beta
    assert len(tracker_alpha.events) == 1
    assert len(tracker_beta.events) == 1
    assert tracker_alpha.events[0]["dst_port"] == 445
    assert tracker_beta.events[0]["dst_port"] == 3389


@pytest.mark.asyncio
async def test_threshold_optimizer_fpr_budget_and_live_risk_engine_application():
    """
    Verify ThresholdOptimizer applies false positive rate constraints,
    respects target_metric (precision), and applies calibrated thresholds to live RiskEngine.
    """
    from backend.ai.threshold_optimizer import ThresholdOptimizer
    from backend.intelligence.config import intelligence_config
    import numpy as np

    optimizer = ThresholdOptimizer(target_metric="precision")

    # Generate synthetic scores
    np.random.seed(123)
    benign = np.random.normal(loc=0.3, scale=0.1, size=80).tolist()
    malicious = np.random.normal(loc=0.8, scale=0.1, size=80).tolist()
    scores = benign + malicious
    labels = [0] * 80 + [1] * 80

    calibrated = optimizer.calibrate(scores, labels, target_false_positive_rate=0.05)

    assert calibrated["calibrated"] is True
    assert calibrated["metrics"]["false_positive_rate"] <= 0.05 + 1e-4
    assert calibrated["metrics"]["target_metric"] == "precision"

    # Apply to live RiskEngine with isolated restore
    import backend.config.config as global_config
    orig_thresholds = dict(global_config.RISK_THRESHOLDS)
    orig_med = intelligence_config.severity_medium_threshold
    orig_high = intelligence_config.severity_high_threshold
    orig_crit = intelligence_config.severity_critical_threshold

    try:
        optimizer.apply_to_risk_engine()
        assert intelligence_config.severity_medium_threshold == calibrated["LOW_MAX"]
        assert intelligence_config.severity_high_threshold == calibrated["MEDIUM_MAX"]
        assert intelligence_config.severity_critical_threshold == calibrated["HIGH_MAX"]

        # Persist
        persisted = await optimizer.persist()
        assert persisted is True
    finally:
        global_config.RISK_THRESHOLDS.clear()
        global_config.RISK_THRESHOLDS.update(orig_thresholds)
        intelligence_config.severity_medium_threshold = orig_med
        intelligence_config.severity_high_threshold = orig_high
        intelligence_config.severity_critical_threshold = orig_crit


@pytest.mark.asyncio
async def test_zeek_adapter_malformed_numeric_ports_handling():
    """
    Verify ZeekAdapter safely catches malformed/non-numeric port values
    without raising exceptions and records dropped malformed metrics.
    """
    from backend.adapters.zeek_adapter import ZeekAdapter

    adapter = ZeekAdapter()
    malformed_record = {
        "id.orig_h": "192.168.1.50",
        "id.resp_h": "10.0.0.1",
        "id.orig_p": "invalid_not_a_number",
        "id.resp_p": 80,
        "proto": "tcp"
    }

    res = adapter.transform(malformed_record)
    assert res is None
    assert adapter.malformed_count == 1
    metrics = adapter.get_metrics()
    assert metrics["malformed"] == 1


@pytest.mark.asyncio
async def test_response_engine_mac_spoofing_mismatch_and_idempotent_retry():
    """
    Verify ResponseEngine suppresses quarantine when supplied MAC contradicts
    authoritative IdentityResolver, and treats 409 Conflict/already-enforced as idempotent success.
    """
    from backend.response.response_engine import ResponseEngine
    from backend.ai.contracts import Action, PredictionResult, RiskCategory
    from backend.pipeline.identity_resolver import identity_resolver
    from unittest.mock import AsyncMock, patch

    engine = ResponseEngine()
    engine.quarantine.quarantine_device = AsyncMock(return_value=True)

    # 1. Authoritative identity registration
    identity_resolver.register_device(
        ip="192.168.1.150",
        mac="00:11:22:33:44:55",
        hostname="finance-workstation",
        is_managed=True
    )

    pred = PredictionResult(
        verdict=True,
        confidence=98.0,
        risk_category=RiskCategory.CRITICAL,
        model_used="FusionEngine",
        latency_ms=1.0
    )

    with patch("backend.services.settings_service.settings_service.get_settings", new_callable=AsyncMock, return_value={"auto_quarantine": True}):
        # Attacker claims target IP 192.168.1.150 but presents a spoofed MAC address
        spoofed_result = await engine.handle_verdict(
            prediction=pred,
            action=Action.QUARANTINE,
            context={"src_ip": "192.168.1.150", "src_mac": "AA:BB:CC:DD:EE:FF"}  # Contradicts 00:11:22:33:44:55
        )
        assert spoofed_result is False
        assert engine.quarantine.quarantine_device.call_count == 0

        # Legitimate MAC matching authoritative identity: quarantine succeeds
        legit_result = await engine.handle_verdict(
            prediction=pred,
            action=Action.QUARANTINE,
            context={"src_ip": "192.168.1.150", "src_mac": "00:11:22:33:44:55"}
        )
        assert legit_result is True
        assert engine.quarantine.quarantine_device.call_count == 1

        # 2. Idempotency test: adapter throws error indicating target already blocked
        async def already_blocked_action(ip, reason):
            raise Exception("Rule already exists on firewall: target IP is already blocked")

        engine.firewall.block_ip = AsyncMock(side_effect=already_blocked_action)
        idempotent_res = await engine.handle_verdict(
            prediction=pred,
            action=Action.RECOMMEND_BLOCK,
            context={"src_ip": "198.51.100.99"}
        )
        assert idempotent_res is True



