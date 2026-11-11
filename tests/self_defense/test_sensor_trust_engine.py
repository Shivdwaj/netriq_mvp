"""
tests/self_defense/test_sensor_trust_engine.py

Comprehensive test suite for Sensor Trust Engine (STE) (Stage 2 Step 2).
Validates:
1. New sensor starts with trust score 1.0.
2. Regular heartbeats preserve trust.
3. Missed and irregular heartbeats reduce trust.
4. Clock drift beyond 5 seconds applies bounded penalty.
5. Sudden telemetry volume changes are detected (volume spike & drop).
6. Repeated invalid reports reduce trust.
7. Trust recovers gradually after healthy behavior.
8. Tenant A sensor data cannot affect Tenant B's trust score.
9. Concurrent heartbeat updates do not corrupt the score.
10. Restarting backend does not reset established trust history.
11. Suspicious status does not disable legitimate sensor telemetry.
"""

import time
import pytest
import asyncio
from unittest.mock import AsyncMock

from backend.database.in_memory_db import InMemoryDatabase
from backend.self_defense.schemas import (
    TrustTier,
    SensorAnomalyType,
)
from backend.self_defense.sensor_trust import (
    SensorTrustEngine,
)


@pytest.fixture
def mock_db():
    return InMemoryDatabase()


@pytest.fixture
def mock_sensors_repo(mock_db):
    class MockSensorRepo:
        def __init__(self, db):
            self.collection = db["sensors"]

        async def create(self, data: dict) -> str:
            clean = dict(data)
            res = await self.collection.insert_one(clean)
            return str(res.inserted_id)

        async def list(self, filter_query=None, limit=100, **kwargs):
            cursor = self.collection.find(filter_query or {})
            docs = await cursor.to_list(length=limit)
            return [dict(d) for d in docs]

        async def update(self, doc_id: str, data: dict):
            await self.collection.update_one({"_id": doc_id}, {"$set": data})

    return MockSensorRepo(mock_db)


@pytest.fixture
def mock_audit():
    mock = AsyncMock()
    mock.append_entry = AsyncMock()
    return mock


@pytest.fixture
def ste(mock_sensors_repo, mock_audit):
    return SensorTrustEngine(
        sensors_repository=mock_sensors_repo,
        audit_ledger_instance=mock_audit,
    )


# ==============================================================================
# Test Cases
# ==============================================================================

@pytest.mark.asyncio
async def test_new_sensor_starts_with_trust_score_1(ste):
    """Requirement 1: Newly registered sensor initializes with trust score 1.0 and TRUSTED tier."""
    score = await ste.get_or_create_trust_score("sensor-alpha-01", "org_acme")
    assert score.sensor_id == "sensor-alpha-01"
    assert score.tenant_id == "org_acme"
    assert score.trust_score == 1.0
    assert score.trust_tier == TrustTier.TRUSTED
    assert score.observation_count == 0


@pytest.mark.asyncio
async def test_regular_heartbeats_preserve_trust(ste):
    """Requirement 2: Consecutive regular, healthy heartbeats preserve full trust."""
    for i in range(10):
        # Heartbeats with synchronized timestamp
        now = time.time()
        score = await ste.evaluate_heartbeat(
            sensor_id="sensor-alpha-01",
            tenant_id="org_acme",
            heartbeat_data={"cpu_usage_pct": 25.0, "memory_usage_mb": 128.0, "kernel_drops_count": 0, "packets_processed": 500},
            reported_timestamp=now,
        )
        assert score.trust_score == 1.0
        assert score.trust_tier == TrustTier.TRUSTED

    assert score.consecutive_healthy == 10
    assert len(score.recent_anomalies) == 0


@pytest.mark.asyncio
async def test_missed_heartbeats_reduce_trust(ste):
    """Requirement 3: Missed heartbeat gap (> 75s) applies bounded penalty."""
    # First baseline heartbeat
    now = time.time()
    await ste.evaluate_heartbeat(
        sensor_id="sensor-beta-01",
        tenant_id="org_beta",
        heartbeat_data={"cpu_usage_pct": 20.0, "memory_usage_mb": 100.0},
    )

    # Simulate sensor disappearing and submitting heartbeat 120 seconds later
    ste._trust_cache[("org_beta", "sensor-beta-01")].last_heartbeat_timestamp = now - 120.0

    score = await ste.evaluate_heartbeat(
        sensor_id="sensor-beta-01",
        tenant_id="org_beta",
        heartbeat_data={"cpu_usage_pct": 20.0, "memory_usage_mb": 100.0},
    )

    assert score.trust_score < 1.0
    assert any(a.anomaly_type == SensorAnomalyType.MISSED_HEARTBEAT for a in score.recent_anomalies)


@pytest.mark.asyncio
async def test_irregular_jittery_heartbeats_reduce_trust(ste):
    """Requirement 3b: Wildly irregular heartbeat intervals trigger JITTER anomaly."""
    now = time.time()
    # Pre-populate highly erratic intervals: 2s, 80s, 3s, 95s
    score_state = await ste.get_or_create_trust_score("sensor-jitter-01", "org_jitter")
    score_state.last_heartbeat_timestamp = now - 5.0
    score_state.heartbeat_intervals = [2.0, 85.0, 3.0, 95.0, 4.0]

    score = await ste.evaluate_heartbeat(
        sensor_id="sensor-jitter-01",
        tenant_id="org_jitter",
        heartbeat_data={"cpu_usage_pct": 15.0, "memory_usage_mb": 80.0},
    )

    assert any(a.anomaly_type == SensorAnomalyType.HEARTBEAT_JITTER for a in score.recent_anomalies)


@pytest.mark.asyncio
async def test_clock_drift_beyond_five_seconds_raises_anomaly(ste):
    """Requirement 4: Clock drift > 5.0 seconds deducts bounded penalty."""
    now = time.time()
    # Sensor claims timestamp is 15 seconds in the past
    drifted_ts = now - 15.0

    score = await ste.evaluate_heartbeat(
        sensor_id="sensor-drift-01",
        tenant_id="org_drift",
        heartbeat_data={"cpu_usage_pct": 10.0, "memory_usage_mb": 50.0},
        reported_timestamp=drifted_ts,
    )

    assert score.trust_score == 0.90  # 1.0 - 0.10
    assert any(a.anomaly_type == SensorAnomalyType.CLOCK_DRIFT for a in score.recent_anomalies)


@pytest.mark.asyncio
async def test_sudden_telemetry_volume_changes_detected(ste):
    """Requirement 5: Sudden volume spikes (>4.5x rolling mean) or drops are detected."""
    # Build baseline of 6 batches around 50 events each
    for _ in range(6):
        await ste.record_telemetry_batch("sensor-vol-01", "org_vol", 50)

    # 1. Sudden surge to 500 events
    surge_score = await ste.record_telemetry_batch("sensor-vol-01", "org_vol", 500)
    assert surge_score.trust_score < 1.0
    assert any(a.anomaly_type == SensorAnomalyType.VOLUME_SPIKE for a in surge_score.recent_anomalies)

    # 2. Sudden drop to 0 events while baseline was active
    drop_score = await ste.record_telemetry_batch("sensor-vol-01", "org_vol", 0)
    assert any(a.anomaly_type == SensorAnomalyType.VOLUME_DROP for a in drop_score.recent_anomalies)


@pytest.mark.asyncio
async def test_repeated_invalid_reports_reduce_trust(ste):
    """Requirement 6: Repeated invalid reports (impossible metrics or bad schemas) decay trust."""
    for i in range(4):
        # Impossible CPU metric > 100% or negative drops
        score = await ste.evaluate_heartbeat(
            sensor_id="sensor-bad-01",
            tenant_id="org_bad",
            heartbeat_data={"cpu_usage_pct": 150.0, "memory_usage_mb": -10.0, "kernel_drops_count": -5},
        )

    # After 4 invalid submissions (-0.05 each), score is 0.80
    assert score.trust_score <= 0.85
    assert len(score.recent_anomalies) == 4


@pytest.mark.asyncio
async def test_trust_recovers_gradually_after_healthy_behavior(ste):
    """Requirement 7: Trust recovers gradually (+0.02 per clean heartbeat) up to 1.0."""
    # Degrade score artificially
    state = await ste.get_or_create_trust_score("sensor-recov-01", "org_recov")
    state.trust_score = 0.80
    state.trust_tier = TrustTier.TRUSTED

    # Submit 3 clean heartbeats
    for _ in range(3):
        score = await ste.evaluate_heartbeat(
            sensor_id="sensor-recov-01",
            tenant_id="org_recov",
            heartbeat_data={"cpu_usage_pct": 20.0, "memory_usage_mb": 100.0, "kernel_drops_count": 0, "packets_processed": 100},
        )

    # 0.80 + (3 * 0.02) = 0.86
    assert round(score.trust_score, 2) == 0.86
    assert score.consecutive_healthy == 3


@pytest.mark.asyncio
async def test_tenant_isolation_sensor_trust(ste):
    """Requirement 8: Sensor in Tenant Alpha cannot affect trust of sensor in Tenant Beta."""
    # Degrade Tenant Alpha's sensor
    for _ in range(5):
        await ste.record_invalid_report("sensor-shared-id", "tenant_alpha", "Simulated attack")

    score_alpha = await ste.get_or_create_trust_score("sensor-shared-id", "tenant_alpha")
    score_beta = await ste.get_or_create_trust_score("sensor-shared-id", "tenant_beta")

    assert score_alpha.trust_score <= 0.75
    assert score_beta.trust_score == 1.0  # Tenant Beta is untouched!
    assert score_beta.trust_tier == TrustTier.TRUSTED


@pytest.mark.asyncio
async def test_concurrent_heartbeats_do_not_corrupt_score(ste):
    """Requirement 9: Concurrent heartbeats for the same sensor execute without race conditions."""
    async def _send_hb(idx):
        return await ste.evaluate_heartbeat(
            sensor_id="sensor-concurrent",
            tenant_id="org_concur",
            heartbeat_data={"cpu_usage_pct": 10.0 + idx, "memory_usage_mb": 50.0, "packets_processed": idx},
        )

    # Fire 15 concurrent heartbeats
    results = await asyncio.gather(*[_send_hb(i) for i in range(15)])
    final_score = results[-1]

    # Observations should be exactly 15
    assert final_score.observation_count == 15
    assert 0.0 <= final_score.trust_score <= 1.0


@pytest.mark.asyncio
async def test_restarting_backend_preserves_established_trust_history(mock_sensors_repo, mock_audit):
    """Requirement 10: State survives backend restarts by reloading persisted state from DB."""
    ste1 = SensorTrustEngine(sensors_repository=mock_sensors_repo, audit_ledger_instance=mock_audit)
    
    # Degrade sensor in instance 1
    await ste1.record_invalid_report("sensor-persist-01", "org_persist", "First anomaly")
    await ste1.record_invalid_report("sensor-persist-01", "org_persist", "Second anomaly")
    score1 = await ste1.get_or_create_trust_score("sensor-persist-01", "org_persist")
    assert score1.trust_score == 0.90

    # Simulate backend reboot: create new engine instance with empty in-memory cache
    ste2 = SensorTrustEngine(sensors_repository=mock_sensors_repo, audit_ledger_instance=mock_audit)
    assert ("org_persist", "sensor-persist-01") not in ste2._trust_cache

    # Reload from DB
    score2 = await ste2.get_or_create_trust_score("sensor-persist-01", "org_persist")
    assert score2.trust_score == 0.90
    assert len(score2.recent_anomalies) == 2


@pytest.mark.asyncio
async def test_suspicious_status_does_not_disable_legitimate_sensor(ste):
    """Requirement 11: Suspicious status (0.50 - 0.79) flags sensor but does not revoke access."""
    state = await ste.get_or_create_trust_score("sensor-suspicious", "org_ops")
    # Set to suspicious range
    state.trust_score = 0.65
    state.trust_tier = TrustTier.SUSPICIOUS

    # Heartbeat can still be evaluated and telemetry accepted
    new_state = await ste.evaluate_heartbeat(
        sensor_id="sensor-suspicious",
        tenant_id="org_ops",
        heartbeat_data={"cpu_usage_pct": 30.0, "memory_usage_mb": 120.0},
    )

    assert new_state.trust_tier == TrustTier.SUSPICIOUS
    # Score recovers slightly
    assert new_state.trust_score == 0.67
