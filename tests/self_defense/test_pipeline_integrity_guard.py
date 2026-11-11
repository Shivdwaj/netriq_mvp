"""
tests/self_defense/test_pipeline_integrity_guard.py

Comprehensive adversarial test suite for Pipeline Integrity Guard (PIG) (Stage 2 Step 3).
Validates:
1. HKDF-SHA256 key isolation (master secret separation, per-sensor uniqueness).
2. Valid HMAC-SHA256 payload verification and monotonic sequence advance.
3. Single-byte payload tampering rejection (InvalidSignatureError).
4. Forged and invalid signature rejection (InvalidSignatureError).
5. Replay attack rejection for duplicate sequences (ReplaySequenceError).
6. Out-of-order sequence rejection (ReplaySequenceError).
7. Sequence gap detection (> 10 batches lost).
8. Expired timestamp rejection (> 15s in the past).
9. Future timestamp rejection (> 15s in the future).
10. Multi-worker concurrent atomic compare-and-swap race defense.
11. Key rotation versioning (v1 -> v2).
12. Sensor identity spoofing rejection (Sensor A cannot sign for Sensor B).
13. Multi-tenant sequence isolation (Tenant A does not block Tenant B).
14. Migration compatibility vs Strict mode enforcement.
15. Integration with /api/v1/sensors/suricata/eve endpoint.
16. Integration with /api/v1/events/batch endpoint.
"""

import time
import json
import pytest
import asyncio
from unittest.mock import patch
from httpx import AsyncClient, ASGITransport

from backend.database.in_memory_db import InMemoryDatabase
from backend.self_defense.schemas import PipelineAnomalyType, PipelineIntegrityVerdict
from backend.self_defense.pipeline_guard import (
    PipelineIntegrityGuard,
    PipelineIntegrityError,
    MissingIntegrityHeadersError,
    InvalidSignatureError,
    ExpiredTimestampError,
    FutureTimestampError,
    ReplaySequenceError,
    derive_sensor_signing_key,
)
from backend.services.central_management_service import central_management_service
from backend.schemas.management import SensorRegistrationReq, SensorSoftwareType
from backend.main import app


class MockRepo:
    def __init__(self, collection):
        self.collection = collection


@pytest.fixture
def mock_db():
    return InMemoryDatabase()


@pytest.fixture
def sequences_repo(mock_db):
    return MockRepo(mock_db["pipeline_sequences"])


@pytest.fixture
def pig(sequences_repo):
    return PipelineIntegrityGuard(
        master_secret="test_master_secret_stage2_step3_pig_key",
        sequences_repo=sequences_repo,
        freshness_window_seconds=15.0,
        max_allowed_gap=10,
        strict_mode=True,
    )


# ==============================================================================
# Unit & Adversarial Tests
# ==============================================================================

def test_hkdf_key_derivation_isolation():
    """HKDF-SHA256 derives unique, deterministic keys per tenant, sensor, and key version."""
    master = "super_secure_master_secret_12345"
    key_t1_s1_v1 = derive_sensor_signing_key(master, "tenant-1", "sensor-1", "v1")
    key_t1_s1_v2 = derive_sensor_signing_key(master, "tenant-1", "sensor-1", "v2")
    key_t1_s2_v1 = derive_sensor_signing_key(master, "tenant-1", "sensor-2", "v1")
    key_t2_s1_v1 = derive_sensor_signing_key(master, "tenant-2", "sensor-1", "v1")

    # 256-bit key length
    assert len(key_t1_s1_v1) == 32
    assert len(key_t1_s1_v2) == 32

    # Deterministic
    assert key_t1_s1_v1 == derive_sensor_signing_key(master, "tenant-1", "sensor-1", "v1")

    # Isolated across versions, sensors, and tenants
    assert key_t1_s1_v1 != key_t1_s1_v2
    assert key_t1_s1_v1 != key_t1_s2_v1
    assert key_t1_s1_v1 != key_t2_s1_v1


@pytest.mark.asyncio
async def test_valid_signature_and_monotonic_advance(pig):
    """Valid payload, signature, and timestamp advance sequence cleanly."""
    tenant_id = "tenant-alpha"
    sensor_id = "sensor-001"
    raw_body = json.dumps({"event": "network_flow", "bytes": 1024}).encode("utf-8")
    now_ts = str(time.time())

    sig_1 = pig.sign_payload(raw_body, sequence=1, timestamp_str=now_ts, tenant_id=tenant_id, sensor_id=sensor_id)
    headers_1 = {
        "X-Sensor-Signature": sig_1,
        "X-Sensor-Sequence": "1",
        "X-Sensor-Timestamp": now_ts,
    }

    verdict_1 = await pig.verify_request(
        raw_body=raw_body,
        headers=headers_1,
        authenticated_sensor_id=sensor_id,
        authenticated_tenant_id=tenant_id,
    )

    assert verdict_1.is_valid is True
    assert verdict_1.sequence_number == 1
    assert verdict_1.gap_detected is False

    # Second valid request with sequence 2
    raw_body_2 = json.dumps({"event": "network_flow", "bytes": 2048}).encode("utf-8")
    now_ts_2 = str(time.time())
    sig_2 = pig.sign_payload(raw_body_2, sequence=2, timestamp_str=now_ts_2, tenant_id=tenant_id, sensor_id=sensor_id)
    headers_2 = {
        "X-Sensor-Signature": sig_2,
        "X-Sensor-Sequence": "2",
        "X-Sensor-Timestamp": now_ts_2,
    }

    verdict_2 = await pig.verify_request(
        raw_body=raw_body_2,
        headers=headers_2,
        authenticated_sensor_id=sensor_id,
        authenticated_tenant_id=tenant_id,
    )

    assert verdict_2.is_valid is True
    assert verdict_2.sequence_number == 2


@pytest.mark.asyncio
async def test_payload_tampering_rejected(pig):
    """Flipping a single byte in the raw payload invalidates HMAC signature."""
    tenant_id = "tenant-alpha"
    sensor_id = "sensor-001"
    raw_body = b'{"event": "alert", "severity": "LOW"}'
    now_ts = str(time.time())

    sig = pig.sign_payload(raw_body, sequence=1, timestamp_str=now_ts, tenant_id=tenant_id, sensor_id=sensor_id)
    headers = {
        "X-Sensor-Signature": sig,
        "X-Sensor-Sequence": "1",
        "X-Sensor-Timestamp": now_ts,
    }

    # Attacker alters "LOW" to "CRITICAL"
    tampered_body = b'{"event": "alert", "severity": "CRITICAL"}'

    with pytest.raises(InvalidSignatureError) as exc_info:
        await pig.verify_request(
            raw_body=tampered_body,
            headers=headers,
            authenticated_sensor_id=sensor_id,
            authenticated_tenant_id=tenant_id,
        )

    assert exc_info.value.status_code == 401
    assert exc_info.value.anomaly_type == PipelineAnomalyType.INVALID_SIGNATURE


@pytest.mark.asyncio
async def test_forged_signature_rejected(pig):
    """Signatures computed with invalid keys or corrupted values are rejected."""
    tenant_id = "tenant-alpha"
    sensor_id = "sensor-001"
    raw_body = b'{"event": "dns_query"}'
    now_ts = str(time.time())

    headers = {
        "X-Sensor-Signature": "deadbeef" * 8,  # Corrupted signature
        "X-Sensor-Sequence": "1",
        "X-Sensor-Timestamp": now_ts,
    }

    with pytest.raises(InvalidSignatureError):
        await pig.verify_request(
            raw_body=raw_body,
            headers=headers,
            authenticated_sensor_id=sensor_id,
            authenticated_tenant_id=tenant_id,
        )


@pytest.mark.asyncio
async def test_replay_sequence_rejected(pig):
    """Replaying an already processed sequence number triggers ReplaySequenceError (409)."""
    tenant_id = "tenant-alpha"
    sensor_id = "sensor-001"
    raw_body = b'{"event": "conn"}'
    now_ts = str(time.time())

    sig = pig.sign_payload(raw_body, sequence=1, timestamp_str=now_ts, tenant_id=tenant_id, sensor_id=sensor_id)
    headers = {
        "X-Sensor-Signature": sig,
        "X-Sensor-Sequence": "1",
        "X-Sensor-Timestamp": now_ts,
    }

    # First attempt: succeeds
    v1 = await pig.verify_request(
        raw_body=raw_body,
        headers=headers,
        authenticated_sensor_id=sensor_id,
        authenticated_tenant_id=tenant_id,
    )
    assert v1.is_valid is True

    # Replay attack: submitting exact same sequence 1
    with pytest.raises(ReplaySequenceError) as exc_info:
        await pig.verify_request(
            raw_body=raw_body,
            headers=headers,
            authenticated_sensor_id=sensor_id,
            authenticated_tenant_id=tenant_id,
        )

    assert exc_info.value.status_code == 409
    assert exc_info.value.anomaly_type == PipelineAnomalyType.REPLAY_SEQUENCE


@pytest.mark.asyncio
async def test_out_of_order_sequence_rejected(pig):
    """Submitting a sequence number lower than current committed state is rejected."""
    tenant_id = "tenant-alpha"
    sensor_id = "sensor-001"
    raw_body = b'{"event": "conn"}'

    # Establish sequence at 5
    now_ts = str(time.time())
    sig_5 = pig.sign_payload(raw_body, sequence=5, timestamp_str=now_ts, tenant_id=tenant_id, sensor_id=sensor_id)
    await pig.verify_request(
        raw_body=raw_body,
        headers={"X-Sensor-Signature": sig_5, "X-Sensor-Sequence": "5", "X-Sensor-Timestamp": now_ts},
        authenticated_sensor_id=sensor_id,
        authenticated_tenant_id=tenant_id,
    )

    # Submitting older sequence 3
    now_ts_3 = str(time.time())
    sig_3 = pig.sign_payload(raw_body, sequence=3, timestamp_str=now_ts_3, tenant_id=tenant_id, sensor_id=sensor_id)
    with pytest.raises(ReplaySequenceError) as exc_info:
        await pig.verify_request(
            raw_body=raw_body,
            headers={"X-Sensor-Signature": sig_3, "X-Sensor-Sequence": "3", "X-Sensor-Timestamp": now_ts_3},
            authenticated_sensor_id=sensor_id,
            authenticated_tenant_id=tenant_id,
        )

    assert exc_info.value.status_code == 409


@pytest.mark.asyncio
async def test_sequence_gap_detection(pig):
    """Sequence jumping more than 10 batches flags gap_detected=True without dropping valid batch."""
    tenant_id = "tenant-alpha"
    sensor_id = "sensor-001"
    raw_body = b'{"event": "conn"}'

    # Sequence 1
    now_ts = str(time.time())
    sig_1 = pig.sign_payload(raw_body, sequence=1, timestamp_str=now_ts, tenant_id=tenant_id, sensor_id=sensor_id)
    await pig.verify_request(
        raw_body=raw_body,
        headers={"X-Sensor-Signature": sig_1, "X-Sensor-Sequence": "1", "X-Sensor-Timestamp": now_ts},
        authenticated_sensor_id=sensor_id,
        authenticated_tenant_id=tenant_id,
    )

    # Sensor jumps to sequence 20 (gap of 18 missing batches, threshold is 10)
    now_ts_20 = str(time.time())
    sig_20 = pig.sign_payload(raw_body, sequence=20, timestamp_str=now_ts_20, tenant_id=tenant_id, sensor_id=sensor_id)
    verdict = await pig.verify_request(
        raw_body=raw_body,
        headers={"X-Sensor-Signature": sig_20, "X-Sensor-Sequence": "20", "X-Sensor-Timestamp": now_ts_20},
        authenticated_sensor_id=sensor_id,
        authenticated_tenant_id=tenant_id,
    )

    assert verdict.is_valid is True
    assert verdict.gap_detected is True
    assert verdict.gap_size == 18


@pytest.mark.asyncio
async def test_expired_timestamp_rejected(pig):
    """Timestamps older than freshness window (> 15 seconds) are rejected with 400."""
    tenant_id = "tenant-alpha"
    sensor_id = "sensor-001"
    raw_body = b'{"event": "conn"}'

    stale_ts = str(time.time() - 30.0)  # 30s ago
    sig = pig.sign_payload(raw_body, sequence=1, timestamp_str=stale_ts, tenant_id=tenant_id, sensor_id=sensor_id)

    with pytest.raises(ExpiredTimestampError) as exc_info:
        await pig.verify_request(
            raw_body=raw_body,
            headers={"X-Sensor-Signature": sig, "X-Sensor-Sequence": "1", "X-Sensor-Timestamp": stale_ts},
            authenticated_sensor_id=sensor_id,
            authenticated_tenant_id=tenant_id,
        )

    assert exc_info.value.status_code == 400
    assert exc_info.value.anomaly_type == PipelineAnomalyType.EXPIRED_TIMESTAMP


@pytest.mark.asyncio
async def test_future_timestamp_rejected(pig):
    """Timestamps ahead of clock by more than 15 seconds are rejected with 400."""
    tenant_id = "tenant-alpha"
    sensor_id = "sensor-001"
    raw_body = b'{"event": "conn"}'

    future_ts = str(time.time() + 30.0)  # 30s in future
    sig = pig.sign_payload(raw_body, sequence=1, timestamp_str=future_ts, tenant_id=tenant_id, sensor_id=sensor_id)

    with pytest.raises(FutureTimestampError) as exc_info:
        await pig.verify_request(
            raw_body=raw_body,
            headers={"X-Sensor-Signature": sig, "X-Sensor-Sequence": "1", "X-Sensor-Timestamp": future_ts},
            authenticated_sensor_id=sensor_id,
            authenticated_tenant_id=tenant_id,
        )

    assert exc_info.value.status_code == 400
    assert exc_info.value.anomaly_type == PipelineAnomalyType.FUTURE_TIMESTAMP


@pytest.mark.asyncio
async def test_concurrent_sequence_cas_race(pig):
    """Concurrent workers racing to commit the same sequence number: exactly one succeeds."""
    tenant_id = "tenant-alpha"
    sensor_id = "sensor-concurrent"
    raw_body = b'{"event": "race"}'
    now_ts = str(time.time())

    # Establish sequence at 1
    sig_1 = pig.sign_payload(raw_body, sequence=1, timestamp_str=now_ts, tenant_id=tenant_id, sensor_id=sensor_id)
    await pig.verify_request(
        raw_body=raw_body,
        headers={"X-Sensor-Signature": sig_1, "X-Sensor-Sequence": "1", "X-Sensor-Timestamp": now_ts},
        authenticated_sensor_id=sensor_id,
        authenticated_tenant_id=tenant_id,
    )

    # 10 concurrent requests all attempting to advance to sequence 2
    sig_2 = pig.sign_payload(raw_body, sequence=2, timestamp_str=now_ts, tenant_id=tenant_id, sensor_id=sensor_id)
    headers_2 = {"X-Sensor-Signature": sig_2, "X-Sensor-Sequence": "2", "X-Sensor-Timestamp": now_ts}

    success_count = 0
    failure_count = 0

    async def attempt():
        nonlocal success_count, failure_count
        try:
            await pig.verify_request(
                raw_body=raw_body,
                headers=headers_2,
                authenticated_sensor_id=sensor_id,
                authenticated_tenant_id=tenant_id,
            )
            success_count += 1
        except ReplaySequenceError:
            failure_count += 1

    tasks = [asyncio.create_task(attempt()) for _ in range(10)]
    await asyncio.gather(*tasks)

    # Atomic compare-and-swap guarantees only 1 winner
    assert success_count == 1
    assert failure_count == 9


@pytest.mark.asyncio
async def test_key_rotation_versioning(pig):
    """Sensor can rotate keys (v1 -> v2) smoothly via X-Sensor-Key-Version header."""
    tenant_id = "tenant-rot"
    sensor_id = "sensor-rot"
    raw_body = b'{"event": "rotation"}'
    now_ts = str(time.time())

    # Signed with v2
    sig_v2 = pig.sign_payload(
        raw_body, sequence=1, timestamp_str=now_ts, tenant_id=tenant_id, sensor_id=sensor_id, key_version="v2"
    )

    # Verified specifying v2 header
    verdict = await pig.verify_request(
        raw_body=raw_body,
        headers={
            "X-Sensor-Signature": sig_v2,
            "X-Sensor-Sequence": "1",
            "X-Sensor-Timestamp": now_ts,
            "X-Sensor-Key-Version": "v2",
        },
        authenticated_sensor_id=sensor_id,
        authenticated_tenant_id=tenant_id,
    )

    assert verdict.is_valid is True
    assert verdict.key_version == "v2"

    # Mismatch: signed with v2, but verified with v1 (default) -> fails
    with pytest.raises(InvalidSignatureError):
        await pig.verify_request(
            raw_body=raw_body,
            headers={
                "X-Sensor-Signature": sig_v2,
                "X-Sensor-Sequence": "2",
                "X-Sensor-Timestamp": now_ts,
                # omitted key version defaults to v1
            },
            authenticated_sensor_id=sensor_id,
            authenticated_tenant_id=tenant_id,
        )


@pytest.mark.asyncio
async def test_sensor_identity_spoofing(pig):
    """Sensor A signing a payload cannot pass verification when sensor B is the claimed identity."""
    tenant_id = "tenant-sec"
    sensor_a = "sensor-attacker"
    sensor_b = "sensor-victim"
    raw_body = b'{"event": "spoofed"}'
    now_ts = str(time.time())

    # Attacker uses Sensor A's signing key
    forged_sig = pig.sign_payload(raw_body, sequence=1, timestamp_str=now_ts, tenant_id=tenant_id, sensor_id=sensor_a)

    # Attempting to verify as Sensor B
    with pytest.raises(InvalidSignatureError):
        await pig.verify_request(
            raw_body=raw_body,
            headers={"X-Sensor-Signature": forged_sig, "X-Sensor-Sequence": "1", "X-Sensor-Timestamp": now_ts},
            authenticated_sensor_id=sensor_b,
            authenticated_tenant_id=tenant_id,
        )


@pytest.mark.asyncio
async def test_cross_tenant_sequence_isolation(pig):
    """Tenant A and Tenant B maintaining identical sequence numbers have strictly isolated state."""
    sensor_id = "shared-sensor-name"
    raw_body = b'{"event": "flow"}'
    now_ts = str(time.time())

    # Tenant A advances sequence to 10
    sig_a = pig.sign_payload(raw_body, sequence=10, timestamp_str=now_ts, tenant_id="tenant-A", sensor_id=sensor_id)
    va = await pig.verify_request(
        raw_body=raw_body,
        headers={"X-Sensor-Signature": sig_a, "X-Sensor-Sequence": "10", "X-Sensor-Timestamp": now_ts},
        authenticated_sensor_id=sensor_id,
        authenticated_tenant_id="tenant-A",
    )
    assert va.is_valid is True

    # Tenant B can independently advance sequence to 1 and then 5 without conflict
    sig_b_1 = pig.sign_payload(raw_body, sequence=1, timestamp_str=now_ts, tenant_id="tenant-B", sensor_id=sensor_id)
    vb1 = await pig.verify_request(
        raw_body=raw_body,
        headers={"X-Sensor-Signature": sig_b_1, "X-Sensor-Sequence": "1", "X-Sensor-Timestamp": now_ts},
        authenticated_sensor_id=sensor_id,
        authenticated_tenant_id="tenant-B",
    )
    assert vb1.is_valid is True

    sig_b_5 = pig.sign_payload(raw_body, sequence=5, timestamp_str=now_ts, tenant_id="tenant-B", sensor_id=sensor_id)
    vb5 = await pig.verify_request(
        raw_body=raw_body,
        headers={"X-Sensor-Signature": sig_b_5, "X-Sensor-Sequence": "5", "X-Sensor-Timestamp": now_ts},
        authenticated_sensor_id=sensor_id,
        authenticated_tenant_id="tenant-B",
    )
    assert vb5.is_valid is True


@pytest.mark.asyncio
async def test_strict_vs_legacy_mode(sequences_repo):
    """Without headers, migration mode permits requests while strict mode rejects them."""
    guard_legacy = PipelineIntegrityGuard(
        sequences_repo=sequences_repo,
        strict_mode=False,
    )
    guard_strict = PipelineIntegrityGuard(
        sequences_repo=sequences_repo,
        strict_mode=True,
    )

    raw_body = b'{"event": "legacy"}'
    headers = {}

    # Migration mode returns valid legacy verdict
    verdict = await guard_legacy.verify_request(
        raw_body=raw_body,
        headers=headers,
        authenticated_sensor_id="sensor-old",
        authenticated_tenant_id="tenant-old",
    )
    assert verdict.is_valid is True
    assert verdict.key_version == "legacy"

    # Strict mode raises MissingIntegrityHeadersError
    with pytest.raises(MissingIntegrityHeadersError):
        await guard_strict.verify_request(
            raw_body=raw_body,
            headers=headers,
            authenticated_sensor_id="sensor-old",
            authenticated_tenant_id="tenant-old",
        )


# ==============================================================================
# HTTP Endpoint Integration Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_api_sensor_ingest_suricata_adversarial():
    """Verify HTTP endpoint /api/v1/sensors/suricata/eve rejects tampered bodies and replayed sequences."""
    sensor = await central_management_service.register_software_sensor(SensorRegistrationReq(
        tenant_id="tenant_pig_test",
        name="pig-probe",
        software_type=SensorSoftwareType.SURICATA,
        software_version="7.0.2",
        hostname="pig-box"
    ))
    api_key = sensor.api_key
    sensor_id = sensor.sensor_id
    tenant_id = "tenant_pig_test"

    payload = {
        "event_type": "alert",
        "src_ip": "192.168.1.100",
        "dest_ip": "10.0.0.5",
        "alert": {"signature": "ET TROJAN Test Alert"},
    }
    raw_body = json.dumps(payload).encode("utf-8")
    now_ts = str(time.time())

    from backend.self_defense.pipeline_guard import pipeline_guard
    sig = pipeline_guard.sign_payload(
        raw_body=raw_body,
        sequence=1,
        timestamp_str=now_ts,
        tenant_id=tenant_id,
        sensor_id=sensor_id,
    )

    headers = {
        "X-Sensor-Key": api_key,
        "X-Sensor-Signature": sig,
        "X-Sensor-Sequence": "1",
        "X-Sensor-Timestamp": now_ts,
        "Content-Type": "application/json",
    }

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Valid signed request -> 200 OK
        resp = await client.post("/api/v1/sensors/suricata/eve", content=raw_body, headers=headers)
        assert resp.status_code == 200
        assert resp.json()["status"] == "success"

        # 2. Tampered body with original signature -> 401 Unauthorized
        tampered_body = json.dumps({
            "event_type": "alert",
            "src_ip": "192.168.1.100",
            "dest_ip": "10.0.0.99",  # altered IP
            "alert": {"signature": "ET TROJAN Test Alert"},
        }).encode("utf-8")

        resp_tampered = await client.post("/api/v1/sensors/suricata/eve", content=tampered_body, headers=headers)
        assert resp_tampered.status_code == 401

        # 3. Replay attack: re-submitting sequence 1 -> 409 Conflict
        resp_replay = await client.post("/api/v1/sensors/suricata/eve", content=raw_body, headers=headers)
        assert resp_replay.status_code == 409


@pytest.mark.asyncio
async def test_api_events_batch_adversarial():
    """Verify HTTP endpoint /api/v1/events/batch rejects tampered bodies and replayed sequences."""
    sensor = await central_management_service.register_software_sensor(SensorRegistrationReq(
        tenant_id="tenant_pig_batch",
        name="pig-batch-probe",
        software_type=SensorSoftwareType.ZEEK,
        software_version="6.0.0",
        hostname="pig-batch-box"
    ))
    api_key = sensor.api_key
    sensor_id = sensor.sensor_id
    tenant_id = "tenant_pig_batch"

    batch_payload = {
        "sensor_id": sensor_id,
        "batch_id": "pig-batch-001",
        "events": [
            {
                "source_ip": "10.0.1.10",
                "destination_ip": "10.0.2.20",
                "protocol": "TCP"
            }
        ]
    }
    raw_body = json.dumps(batch_payload).encode("utf-8")
    now_ts = str(time.time())

    from backend.self_defense.pipeline_guard import pipeline_guard
    sig = pipeline_guard.sign_payload(
        raw_body=raw_body,
        sequence=1,
        timestamp_str=now_ts,
        tenant_id=tenant_id,
        sensor_id=sensor_id,
    )

    headers = {
        "X-Sensor-Key": api_key,
        "X-Sensor-Signature": sig,
        "X-Sensor-Sequence": "1",
        "X-Sensor-Timestamp": now_ts,
        "Content-Type": "application/json",
    }

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Valid signed request -> 200 OK
        resp = await client.post("/api/v1/events/batch", content=raw_body, headers=headers)
        assert resp.status_code == 200
        assert resp.json()["status"] in ("success", "acknowledged")

        # 2. Tampered body -> 401 Unauthorized
        tampered_body = json.dumps({
            "sensor_id": sensor_id,
            "batch_id": "pig-batch-001",
            "events": [
                {
                    "source_ip": "10.0.1.99",
                    "destination_ip": "10.0.2.20",
                    "protocol": "TCP"
                }
            ]
        }).encode("utf-8")
        resp_tampered = await client.post("/api/v1/events/batch", content=tampered_body, headers=headers)
        assert resp_tampered.status_code == 401

        # 3. Replay attack: re-submitting sequence 1 -> 409 Conflict
        resp_replay = await client.post("/api/v1/events/batch", content=raw_body, headers=headers)
        assert resp_replay.status_code == 409
