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
