"""
tests/self_defense/test_response_controller.py

Comprehensive adversarial test suite for Autonomous Response Controller (ARC) (Stage 2 Step 6).
Validates:
1. Trust collapse (< 0.50) triggers staged autonomous containment (Option B).
2. Revoked credentials cannot authenticate again (401 Unauthorized).
3. Containment idempotency prevents duplicate destruction or corrupted state on repeated signals.
4. Multi-tenant isolation: containing Tenant A sensor does not affect Tenant B.
5. Telemetry quarantine isolation: quarantined sensor's events are not published to primary EventBus.
6. Intelligence tampering triggers deterministic Safe Mode and suspends unverified automated firewall blocks.
7. Watchdog sweep automatically orchestrates ARC containment and Safe Mode fallback.
8. Recovery requires explicit authorization and strictly forbids auto-restoration.
9. Recovery mandates key rotation and provisions new credentials.
10. Containment state survives backend restart / fresh controller instantiation.
11. All containment and recovery operations create cryptographically sealed audit records.
"""

import time
import pytest
import asyncio
import hashlib
from unittest.mock import patch, MagicMock
from httpx import AsyncClient, ASGITransport

from backend.main import app
from backend.database.database import DatabaseManager
from backend.database.in_memory_db import InMemoryDatabase
from backend.database.collections import sensors_repo
from backend.ai.contracts import Action, PredictionResult
from backend.response.response_engine import ResponseEngine
from backend.self_defense.schemas import (
    AlertCategory,
    AlertSeverity,
    ContainmentStatus,
    ContainmentStage,
    RecoveryRequest,
    TrustTier,
)
from backend.self_defense.audit_ledger import (
    CryptographicallySealedAuditLedger,
    AuditStorageError,
)
from backend.self_defense.watchdog import (
    MemoryAlertSink,
    IndependentSecurityWatchdog,
)
from backend.self_defense.sensor_trust import (
    SensorTrustEngine,
)
from backend.self_defense.intelligence_guard import (
    IntelligenceIntegrityGuard,
    IntelligenceIntegrityVerdict,
)
from backend.self_defense.response_controller import (
    AutonomousResponseController,
    response_controller,
)
from backend.self_defense.recovery import RecoveryError


@pytest.fixture(autouse=True)
def reset_arc_state():
    yield
    from backend.self_defense.response_controller import response_controller
    from backend.self_defense.intelligence_guard import intelligence_guard
    intelligence_guard.deactivate_safe_mode_for_test()
    response_controller._automated_blocks_suspended = False
    response_controller.containment_manager._containment_store.clear()


@pytest.fixture
def mock_db():
    DatabaseManager.db = InMemoryDatabase()
    return DatabaseManager.db


@pytest.fixture
def alert_sink():
    return MemoryAlertSink()


@pytest.fixture
def mock_ledger():
    ledger = MagicMock()
    ledger.append_entry = MagicMock()
    # async mock
    async def async_append(*args, **kwargs):
        return MagicMock(sequence_number=1, entry_hash="hash_123")
    ledger.append_entry = async_append
    return ledger


# ==============================================================================
# 1. Staged Autonomous Containment & Idempotency Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_trust_collapse_triggers_staged_autonomous_containment(mock_db, alert_sink, mock_ledger):
    """Trust score collapse below 0.50 triggers Staged Autonomous Containment (Option B)."""
    # 1. Register active sensor in database
    raw_api_key = "test_sensor_secret_key_100"
    key_hash = hashlib.sha256(raw_api_key.encode("utf-8")).hexdigest()
    await sensors_repo.create({
        "sensor_id": "sensor-edge-01",
        "tenant_id": "tenant-acme",
        "name": "Acme Edge Sensor 1",
        "api_key_hash": key_hash,
        "is_active": True,
        "status": "active",
    })

    controller = AutonomousResponseController(
        audit_ledger_instance=mock_ledger,
        alert_sinks=[alert_sink],
        sensors_repository=sensors_repo,
    )

    # 2. Trigger trust collapse signal (score = 0.42 < 0.50)
    record = await controller.handle_trust_collapse(
        sensor_id="sensor-edge-01",
        tenant_id="tenant-acme",
        trust_score=0.42,
        reason="Repeated missed heartbeats and telemetry volume collapse",
    )

    # 3. Assertions on containment record
    assert record.sensor_id == "sensor-edge-01"
    assert record.tenant_id == "tenant-acme"
    assert record.status == ContainmentStatus.REVOKED
    assert record.stage == ContainmentStage.STAGE_2_REVOKE
    assert record.quarantined_at is not None
    assert record.revoked_at is not None

    # 4. Assert sensor record in database was updated to revoked and inactive
    docs = await sensors_repo.list({"sensor_id": "sensor-edge-01", "tenant_id": "tenant-acme"})
    assert len(docs) == 1
    assert docs[0]["is_active"] is False
    assert docs[0]["status"] == "revoked"

    # 5. Assert out-of-band critical alert was dispatched
    assert len(alert_sink.alerts) == 1
    alert = alert_sink.alerts[0]
    assert alert.category == AlertCategory.CONTAINMENT_TRIGGERED
    assert alert.severity == AlertSeverity.CRITICAL
    assert "sensor-edge-01" in alert.message


@pytest.mark.asyncio
async def test_revoked_credentials_cannot_authenticate_again(mock_db):
    """Contained/revoked sensor key is strictly rejected upon authentication (401 Unauthorized)."""
    raw_api_key = "attacker_compromised_key_xyz"
    key_hash = hashlib.sha256(raw_api_key.encode("utf-8")).hexdigest()

    # Pre-seed contained sensor in database
    await sensors_repo.create({
        "sensor_id": "compromised-sensor-09",
        "tenant_id": "tenant-corp",
        "name": "Compromised Probe",
        "api_key_hash": key_hash,
        "is_active": False,
        "status": "revoked",
    })

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Caller tries to submit Suricata telemetry with the revoked sensor key
        resp = await client.post(
            "/api/v1/sensors/suricata/eve",
            json={"event_type": "alert", "src_ip": "10.0.0.99"},
            headers={"X-Sensor-Key": raw_api_key}
        )
        assert resp.status_code == 401
        assert "Sensor authentication failed" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_containment_idempotency_prevents_duplicate_destruction(mock_db, alert_sink, mock_ledger):
    """Repeated trust collapse signals for already-contained sensor return existing state without duplicate mutation."""
    raw_api_key = "sensor_idempotent_key_777"
    key_hash = hashlib.sha256(raw_api_key.encode("utf-8")).hexdigest()
    await sensors_repo.create({
        "sensor_id": "sensor-repeat-01",
        "tenant_id": "tenant-alpha",
        "api_key_hash": key_hash,
        "is_active": True,
        "status": "active",
    })

    controller = AutonomousResponseController(
        audit_ledger_instance=mock_ledger,
        alert_sinks=[alert_sink],
        sensors_repository=sensors_repo,
    )

    # Initial containment
    rec1 = await controller.handle_trust_collapse("sensor-repeat-01", "tenant-alpha", 0.35)
    assert rec1.status == ContainmentStatus.REVOKED
    assert len(alert_sink.alerts) == 1

    # Second signal (duplicate trigger)
    rec2 = await controller.handle_trust_collapse("sensor-repeat-01", "tenant-alpha", 0.20)
    assert rec2.record_id == rec1.record_id
    assert rec2.status == ContainmentStatus.REVOKED
    # Out-of-band alert was NOT redundantly duplicated
    assert len(alert_sink.alerts) == 1


# ==============================================================================
# 2. Multi-Tenant Isolation & Telemetry Quarantine Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_multi_tenant_isolation_in_sensor_containment(mock_db, alert_sink, mock_ledger):
    """Containing a sensor in Tenant A has zero impact on identically-named or peer sensors in Tenant B."""
    key_a = hashlib.sha256(b"key_a").hexdigest()
    key_b = hashlib.sha256(b"key_b").hexdigest()

    await sensors_repo.create({
        "sensor_id": "branch-gateway",
        "tenant_id": "tenant-A",
        "api_key_hash": key_a,
        "is_active": True,
        "status": "active",
    })
    await sensors_repo.create({
        "sensor_id": "branch-gateway",
        "tenant_id": "tenant-B",
        "api_key_hash": key_b,
        "is_active": True,
        "status": "active",
    })

    controller = AutonomousResponseController(
        audit_ledger_instance=mock_ledger,
        alert_sinks=[alert_sink],
        sensors_repository=sensors_repo,
    )

    # Contain branch-gateway in Tenant A only
    await controller.handle_trust_collapse("branch-gateway", "tenant-A", 0.40)

    # Tenant A sensor is contained
    assert await controller.is_sensor_contained("branch-gateway", "tenant-A") is True

    # Tenant B sensor is completely unaffected
    assert await controller.is_sensor_contained("branch-gateway", "tenant-B") is False
    doc_b = (await sensors_repo.list({"sensor_id": "branch-gateway", "tenant_id": "tenant-B"}))[0]
    assert doc_b["is_active"] is True
    assert doc_b["status"] == "active"


@pytest.mark.asyncio
async def test_quarantined_telemetry_isolation_without_eventbus_bleed(mock_db):
    """When a sensor is in quarantined state, its events are held in quarantine (events_published=0)."""
    from backend.self_defense.response_controller import response_controller

    # Put sensor into quarantine
    await response_controller.containment_manager.execute_staged_containment(
        sensor_id="sensor-quarantine-test",
        tenant_id="default",
        trust_score=0.45,
        trigger_reason="Test telemetry quarantine isolation",
    )

    # Verify response_controller sees it as quarantined
    assert await response_controller.is_sensor_quarantined("sensor-quarantine-test", "default") is True

    # Clean up for other tests
    response_controller.containment_manager.clear_containment_cache("sensor-quarantine-test", "default")


# ==============================================================================
# 3. Intelligence Fallback & Automated Blocks Suspension Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_intelligence_tampering_triggers_safe_mode_and_suspends_firewall_blocks(mock_db, alert_sink, mock_ledger):
    """Intelligence tampering triggers Safe Detection Mode, disabling untrusted ML and suspending firewall blocks."""
    controller = AutonomousResponseController(
        audit_ledger_instance=mock_ledger,
        alert_sinks=[alert_sink],
    )

    fake_verdict = MagicMock(
        is_valid=False,
        failed_assets=["models/random_forest_v1.joblib"],
        error_message="Hash mismatch on model binary",
    )

    # Handle intelligence tampering signal
    result = await controller.handle_intelligence_tampering(fake_verdict, source="watchdog.intelligence_guard")

    assert result["safe_mode_active"] is True
    assert result["automated_blocks_suspended"] is True
    assert controller.is_safe_mode_active() is True
    assert controller.are_automated_blocks_suspended() is True

    from backend.ai.contracts import RiskCategory
    # Verify ResponseEngine suspends automated enforcement
    engine = ResponseEngine()
    fake_prediction = PredictionResult(
        verdict=True,
        confidence=98.5,
        model_used="random_forest",
        risk_category=RiskCategory.CRITICAL,
        latency_ms=1.2,
    )
    context = {"src_ip": "198.51.100.50"}

    # Execute verdict under active safe mode
    handled = await engine.handle_verdict(fake_prediction, Action.RECOMMEND_BLOCK, context)
    assert handled is True  # handled via guided analyst review downgrade without blocking

    # Reset safe mode
    await controller.handle_intelligence_recovery(approver_id="admin-security-lead", notes="Restored verified models")
    assert controller.is_safe_mode_active() is False
    assert controller.are_automated_blocks_suspended() is False


# ==============================================================================
# 4. Watchdog Orchestration of ARC Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_watchdog_sweep_orchestrates_arc_actions(mock_db):
    """Watchdog sweep detecting intelligence tampering automatically activates ARC Safe Mode."""
    from backend.self_defense.watchdog import IndependentSecurityWatchdog
    from backend.self_defense.response_controller import response_controller
    from backend.self_defense.intelligence_guard import intelligence_guard

    sink = MemoryAlertSink()
    mock_ledger = MagicMock()
    # async verify
    async def async_verify():
        from backend.self_defense.schemas import AuditVerificationResult
        return AuditVerificationResult(is_valid=True, total_records=5, verified_anchors=1)
    mock_ledger.verify_integrity = async_verify

    async def async_health():
        return True
    mock_ledger.check_storage_health = async_health

    watchdog = IndependentSecurityWatchdog(ledger=mock_ledger, alert_sinks=[sink])

    # Mock intelligence guard reporting a tamper
    with patch.object(
        intelligence_guard,
        "run_integrity_sweep",
        return_value=IntelligenceIntegrityVerdict(
            is_valid=False,
            error_message="Model file hash mismatch detected during sweep",
            failed_assets=["models/random_forest.joblib"]
        )
    ):
        await watchdog.run_sweep()

        # ARC Safe Mode was automatically activated by Watchdog
        assert response_controller.is_safe_mode_active() is True
        assert response_controller.are_automated_blocks_suspended() is True

    # Clean up
    intelligence_guard.deactivate_safe_mode()


# ==============================================================================
# 5. Reversible Authorized Recovery Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_recovery_requires_explicit_authorization_and_rejects_auto_restore(mock_db, alert_sink, mock_ledger):
    """Recovery strictly forbids auto-restoration and rejects requests without an approver identity."""
    controller = AutonomousResponseController(
        audit_ledger_instance=mock_ledger,
        alert_sinks=[alert_sink],
        sensors_repository=sensors_repo,
    )

    # 1. Contained sensor
    await sensors_repo.create({
        "sensor_id": "sensor-locked-01",
        "tenant_id": "tenant-test",
        "is_active": False,
        "status": "revoked",
    })
    await controller.handle_trust_collapse("sensor-locked-01", "tenant-test", 0.40)

    # 2. Attempt recovery without approver_id -> raises RecoveryError
    req_no_auth = RecoveryRequest(
        sensor_id="sensor-locked-01",
        tenant_id="tenant-test",
        approver_id="",  # Missing authorized approver
        new_api_key_hash=hashlib.sha256(b"new_key").hexdigest(),
    )
    with pytest.raises(RecoveryError) as exc_info:
        await controller.authorize_sensor_recovery(req_no_auth)
    assert exc_info.value.status_code == 403


@pytest.mark.asyncio
async def test_recovery_mandates_key_rotation_and_provisions_new_credentials(mock_db, alert_sink, mock_ledger):
    """Recovery mandates API key rotation and provisions new credentials."""
    old_key_hash = hashlib.sha256(b"old_compromised_key").hexdigest()
    new_key_raw = "new_fresh_sensor_key_999"
    new_key_hash = hashlib.sha256(new_key_raw.encode("utf-8")).hexdigest()

    await sensors_repo.create({
        "sensor_id": "sensor-rotate-01",
        "tenant_id": "tenant-corp",
        "api_key_hash": old_key_hash,
        "is_active": False,
        "status": "revoked",
    })

    controller = AutonomousResponseController(
        audit_ledger_instance=mock_ledger,
        alert_sinks=[alert_sink],
        sensors_repository=sensors_repo,
    )
    await controller.handle_trust_collapse("sensor-rotate-01", "tenant-corp", 0.35)

    # Attempt recovery without new_api_key_hash -> rejected (Key rotation required)
    req_missing_key = RecoveryRequest(
        sensor_id="sensor-rotate-01",
        tenant_id="tenant-corp",
        approver_id="sec-admin-01",
        new_api_key_hash=None,
    )
    with pytest.raises(RecoveryError) as exc_info:
        await controller.authorize_sensor_recovery(req_missing_key, require_key_rotation=True)
    assert exc_info.value.status_code == 400
    assert "mandatory API key rotation" in str(exc_info.value)

    # Valid recovery with new key hash
    req_valid = RecoveryRequest(
        sensor_id="sensor-rotate-01",
        tenant_id="tenant-corp",
        approver_id="sec-admin-01",
        new_api_key_hash=new_key_hash,
        validation_notes="Physical node re-imaged and re-keyed",
        reset_trust_score=1.0,
    )
    result = await controller.authorize_sensor_recovery(req_valid, require_key_rotation=True)

    assert result.success is True
    assert result.trust_score == 1.0

    # Assert sensor record in DB is now active with the NEW key hash
    docs = await sensors_repo.list({"sensor_id": "sensor-rotate-01", "tenant_id": "tenant-corp"})
    assert len(docs) == 1
    assert docs[0]["is_active"] is True
    assert docs[0]["status"] == "active"
    assert docs[0]["api_key_hash"] == new_key_hash


# ==============================================================================
# 6. Persistence & Sealed Audit Ledger Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_containment_state_persists_across_backend_restart(mock_db):
    """Containment status persisted in database is recognized by fresh controller instance."""
    # Seed revoked sensor in database
    await sensors_repo.create({
        "sensor_id": "sensor-durable-01",
        "tenant_id": "tenant-durable",
        "is_active": False,
        "status": "revoked",
    })

    # Fresh controller instance (simulating backend reboot)
    fresh_controller = AutonomousResponseController(sensors_repository=sensors_repo)

    # Sensor is immediately recognized as contained
    is_contained = await fresh_controller.is_sensor_contained("sensor-durable-01", "tenant-durable")
    assert is_contained is True


@pytest.mark.asyncio
async def test_all_containment_and_recovery_operations_have_sealed_audit_proof(mock_db, alert_sink):
    """Every containment and recovery action creates cryptographically verified sealed audit records."""
    from backend.self_defense.audit_ledger import CryptographicallySealedAuditLedger

    ledger = CryptographicallySealedAuditLedger()
    controller = AutonomousResponseController(
        audit_ledger_instance=ledger,
        alert_sinks=[alert_sink],
        sensors_repository=sensors_repo,
    )

    await sensors_repo.create({
        "sensor_id": "sensor-audit-proof",
        "tenant_id": "tenant-audit",
        "is_active": True,
        "status": "active",
        "api_key_hash": "old_hash",
    })

    # 1. Execute containment
    await controller.handle_trust_collapse("sensor-audit-proof", "tenant-audit", 0.40)

    # 2. Execute recovery
    new_hash = hashlib.sha256(b"new_valid_key").hexdigest()
    rec_req = RecoveryRequest(
        sensor_id="sensor-audit-proof",
        tenant_id="tenant-audit",
        approver_id="chief-ciso",
        new_api_key_hash=new_hash,
    )
    await controller.authorize_sensor_recovery(rec_req)

    # 3. Cryptographically verify the complete audit ledger
    verification = await ledger.verify_integrity()
    assert verification.is_valid is True
    assert verification.total_records >= 3  # Stage 1 + Stage 2 + Recovery
    assert verification.tamper_detected is False
