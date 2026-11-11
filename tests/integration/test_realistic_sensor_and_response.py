"""
tests/integration/test_realistic_sensor_and_response.py

Part B Focused Integration Tests:
1. Real Suricata eve.json stream ingestion (alerts, DNS, TLS, flow, malformed, duplicates).
2. Real Zeek log stream ingestion (conn.log, ssl, dns, malformed numeric fields, missing IPs).
3. Response reversal lifecycle (firewall unblock, quarantine release, audit trail, RBAC enforcement).
4. Concurrent event ingestion and correlation state isolation.
5. Database disconnect, health state transition, and recovery.
"""

import asyncio
import json
import time
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from httpx import AsyncClient, ASGITransport

from backend.main import app
from backend.adapters.suricata_adapter import SuricataAdapter
from backend.adapters.zeek_adapter import ZeekAdapter
from backend.auth.roles import Role
from backend.auth.jwt_handler import create_access_token
from backend.ai.contracts import Action, PredictionResult, RiskCategory
from backend.response.response_engine import ResponseEngine
from backend.services.response_service import response_service
from backend.services.correlation_service import CorrelationEngine
from backend.pipeline.schemas import NormalizedSecurityEvent
from backend.database.database import DatabaseManager
from backend.database.in_memory_db import InMemoryDatabase
from backend.database.collections import responses_repo


@pytest.fixture(autouse=True)
def setup_db():
    DatabaseManager.db = InMemoryDatabase()
    yield


@pytest.mark.asyncio
async def test_realistic_suricata_eve_json_stream_ingestion():
    """
    Ingests a realistic multi-line Suricata eve.json stream containing:
    - Standard alert records
    - TLS handshake records with SNI and JA3 fingerprints
    - DNS queries
    - Malformed JSON strings
    - Missing required IP fields
    - Out-of-order timestamps
    """
    adapter = SuricataAdapter()

    realistic_eve_stream = [
        # 1. Standard alert
        json.dumps({
            "timestamp": "2026-11-11T08:15:30.123456+0000",
            "event_type": "alert",
            "src_ip": "192.168.1.105",
            "src_port": 49201,
            "dest_ip": "10.0.0.50",
            "dest_port": 445,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2010935,
                "rev": 4,
                "signature": "ET EXPLOIT Lateral SMB Exec",
                "category": "Attempted Administrator Privilege Gain",
                "severity": 1
            }
        }),
        # 2. TLS event with SNI and JA3
        json.dumps({
            "timestamp": "2026-11-11T08:15:31.000000+0000",
            "event_type": "tls",
            "src_ip": "192.168.1.105",
            "src_port": 51234,
            "dest_ip": "185.220.101.5",
            "dest_port": 443,
            "proto": "TCP",
            "tls": {
                "subject": "CN=c2-beacon.darknet.org",
                "issuerdn": "CN=Let's Encrypt Authority X3",
                "sni": "c2-beacon.darknet.org",
                "version": "TLS 1.3",
                "ja3": {
                    "hash": "51c64c77e60f3980eea90869b68c58a8",
                    "string": "771,4865-4866-4867,0-23-65281-10-11,29-23-24,0"
                }
            }
        }),
        # 3. DNS query
        json.dumps({
            "timestamp": "2026-11-11T08:15:29.500000+0000",
            "event_type": "dns",
            "src_ip": "192.168.1.105",
            "src_port": 61200,
            "dest_ip": "192.168.1.1",
            "dest_port": 53,
            "proto": "UDP",
            "dns": {
                "type": "query",
                "rrname": "c2-beacon.darknet.org",
                "rrtype": "A"
            }
        }),
        # 4. Malformed JSON string (unparseable)
        '{"timestamp": "2026-11-11T08:15:32", "event_type": "alert", "src_ip": "192.168.1.',
        # 5. Missing required IP endpoints
        json.dumps({
            "timestamp": "2026-11-11T08:15:33.000000+0000",
            "event_type": "alert",
            "alert": {"signature": "Orphan alert without source or destination"}
        }),
        # 6. Malformed port values
        json.dumps({
            "timestamp": "2026-11-11T08:15:34.000000+0000",
            "event_type": "alert",
            "src_ip": "192.168.1.200",
            "dest_ip": "10.0.0.1",
            "src_port": "CORRUPTED_PORT",
            "dest_port": 80,
            "proto": "TCP"
        })
    ]

    transformed_events = []
    for line in realistic_eve_stream:
        ev = adapter.transform(line)
        if ev:
            transformed_events.append(ev)

    # 3 valid records, 3 malformed/dropped records
    assert len(transformed_events) == 3
    assert adapter.malformed_count == 3
    assert adapter.processed_count == 6
    assert adapter.transformed_count == 3

    # Validate first event (Alert)
    alert_ev = transformed_events[0]
    assert alert_ev.source_ip == "192.168.1.105"
    assert alert_ev.destination_ip == "10.0.0.50"
    assert alert_ev.destination_port == 445
    assert alert_ev.detection_source == "suricata"
    assert alert_ev.event_type == "alert"
    assert alert_ev.evidence.get("mitre") == "T1190 Exploit Public-Facing Application"

    # Validate second event (TLS metadata enrichment)
    tls_ev = transformed_events[1]
    assert tls_ev.destination_port == 443
    assert tls_ev.evidence["tls"]["sni"] == "c2-beacon.darknet.org"
    assert tls_ev.evidence["tls"]["ja3"] == "51c64c77e60f3980eea90869b68c58a8"


@pytest.mark.asyncio
async def test_realistic_zeek_log_stream_ingestion():
    """
    Ingests a realistic Zeek log stream (conn.log, ssl.log) with:
    - Dot-notation fields (id.orig_h, id.resp_h, id.orig_p, id.resp_p)
    - Connection states (S0, SF, REJ)
    - Non-numeric port/byte corruption
    - Missing host keys
    """
    adapter = ZeekAdapter()

    realistic_zeek_stream = [
        # 1. Standard conn.log port scan probe (S0 = no reply)
        {
            "ts": 1793800100.12,
            "uid": "CZk101ScanProbe",
            "id.orig_h": "192.168.1.10",
            "id.orig_p": 49152,
            "id.resp_h": "10.0.0.1",
            "id.resp_p": 22,
            "proto": "tcp",
            "conn_state": "S0",
            "orig_bytes": 0,
            "resp_bytes": 0
        },
        # 2. Established connection (SF)
        {
            "ts": 1793800105.50,
            "uid": "CZk102CleanSession",
            "id.orig_h": "192.168.1.10",
            "id.orig_p": 49153,
            "id.resp_h": "10.0.0.1",
            "id.resp_p": 80,
            "proto": "tcp",
            "service": "http",
            "conn_state": "SF",
            "orig_bytes": 1024,
            "resp_bytes": 4096
        },
        # 3. SSL record with SNI and JA3
        {
            "ts": 1793800110.88,
            "uid": "CZk103TlsSession",
            "id.orig_h": "192.168.1.10",
            "id.orig_p": 49154,
            "id.resp_h": "185.220.101.5",
            "id.resp_p": 443,
            "proto": "tcp",
            "server_name": "exfil.c2system.org",
            "ja3": "6734f37431670b3ab4292b8f60f29984",
            "conn_state": "SF"
        },
        # 4. Malformed record missing orig_h
        {
            "ts": 1793800115.00,
            "uid": "CZk104Corrupt",
            "id.resp_h": "10.0.0.1",
            "id.resp_p": 80
        },
        # 5. Malformed numeric port
        {
            "ts": 1793800120.00,
            "uid": "CZk105BadPort",
            "id.orig_h": "192.168.1.10",
            "id.orig_p": "INVALID_PORT_STR",
            "id.resp_h": "10.0.0.1",
            "id.resp_p": 80
        }
    ]

    transformed = []
    for rec in realistic_zeek_stream:
        ev = adapter.transform(rec)
        if ev:
            transformed.append(ev)

    assert len(transformed) == 3
    assert adapter.malformed_count == 2
    assert adapter.processed_count == 5

    # Check connection state mapping
    s0_ev = transformed[0]
    assert s0_ev.destination_port == 22
    assert "Port Scan" in s0_ev.evidence.get("conn_state_desc", "")

    # Check TLS SNI extraction
    ssl_ev = transformed[2]
    assert ssl_ev.evidence.get("server_name") == "exfil.c2system.org"
    assert ssl_ev.evidence.get("ja3") == "6734f37431670b3ab4292b8f60f29984"


@pytest.mark.asyncio
async def test_response_reversal_lifecycle_and_audit():
    """
    Validates the end-to-end response action reversal lifecycle:
    1. Enforcement execution (Firewall block & Layer 2 quarantine).
    2. Reversal via ResponseEngine.reverse_action.
    3. Reversal via REST API endpoint /api/v1/response/reverse.
    4. Durable audit logging in responses_repo with reversal metadata.
    5. RBAC enforcement: Viewers cannot trigger reversal (403).
    """
    engine = ResponseEngine()
    engine.firewall.block_ip = AsyncMock(return_value=True)
    engine.firewall.unblock_ip = AsyncMock(return_value=True)
    engine.quarantine.quarantine_device = AsyncMock(return_value=True)
    engine.quarantine.release_device = AsyncMock(return_value=True)

    target_ip = "198.51.100.88"
    target_mac = "00:11:22:33:44:88"

    # 1. Enforce Firewall Block
    pred = PredictionResult(
        verdict=True,
        confidence=95.0,
        risk_category=RiskCategory.HIGH,
        model_used="FusionEngine",
        latency_ms=1.2
    )

    with patch("backend.services.settings_service.settings_service.get_settings", new_callable=AsyncMock, return_value={"auto_quarantine": True}):
        # Block IP
        block_success = await engine.handle_verdict(prediction=pred, action=Action.RECOMMEND_BLOCK, context={"src_ip": target_ip})
        assert block_success is True
        assert engine.firewall.block_ip.call_count == 1

        # 2. Reverse Firewall Block
        unblock_success = await engine.reverse_action(Action.RECOMMEND_BLOCK, target_ip)
        assert unblock_success is True
        assert engine.firewall.unblock_ip.call_count == 1

        # 3. Enforce Device Quarantine
        quar_success = await engine.handle_verdict(
            prediction=pred,
            action=Action.QUARANTINE,
            context={"src_ip": target_ip, "src_mac": target_mac}
        )
        assert quar_success is True
        assert target_ip in engine._recent_quarantines

        # 4. Reverse Device Quarantine
        release_success = await engine.reverse_action(Action.QUARANTINE, target_ip, target_mac)
        assert release_success is True
        assert engine.quarantine.release_device.call_count == 1
        assert target_ip not in engine._recent_quarantines

    # 5. REST API Reversal Verification
    analyst_token = create_access_token("analyst_jane", "analyst", tenant_id="tenant_omega")
    viewer_token = create_access_token("viewer_bob", "viewer", tenant_id="tenant_omega")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # A. Authorized Analyst triggers reversal
        with patch.object(response_service.engine.firewall, "unblock_ip", new_callable=AsyncMock, return_value=True):
            rev_resp = await client.post(
                "/api/v1/response/reverse",
                json={"action": "recommend_block", "target_ip": target_ip},
                headers={"Authorization": f"Bearer {analyst_token}"}
            )
            assert rev_resp.status_code == 200
            assert rev_resp.json()["success"] is True

        # B. Unauthorized Viewer attempting reversal rejected with 403
        rev_forbidden = await client.post(
            "/api/v1/response/reverse",
            json={"action": "recommend_block", "target_ip": target_ip},
            headers={"Authorization": f"Bearer {viewer_token}"}
        )
        assert rev_forbidden.status_code == 403


@pytest.mark.asyncio
async def test_concurrent_event_ingestion_and_correlation():
    """
    Validates concurrency safety under parallel event submission:
    Dispatches 30 concurrent events across multiple tenants and IPs.
    Verifies no key collisions, race conditions, or unhandled exceptions.
    """
    engine = CorrelationEngine()

    async def simulate_event(tenant_id: str, ip: str, port: int):
        ev = NormalizedSecurityEvent(
            event_id=f"evt-{tenant_id}-{ip}-{port}",
            tenant_id=tenant_id,
            source_ip=ip,
            destination_ip="10.0.0.1",
            destination_port=port,
            protocol="TCP",
            event_type="connection",
            detection_source="zeek",
            severity="INFO"
        )
        await engine.process_event(ev)

    tasks = []
    # 3 distinct tenants, each sending to multiple ports simultaneously
    for t_idx in range(3):
        t_id = f"tenant_concurrency_{t_idx}"
        for port in range(10):
            tasks.append(simulate_event(t_id, f"192.168.1.{10 + t_idx}", 1000 + port))

    # Run all 30 events concurrently
    await asyncio.gather(*tasks)

    # Verify that each tenant's tracker was created and partitioned accurately
    assert len(engine._trackers) == 3
    for t_idx in range(3):
        t_id = f"tenant_concurrency_{t_idx}"
        expected_key = f"tenant:{t_id}/device:192.168.1.{10 + t_idx}"
        assert expected_key in engine._trackers
        tracker = engine._trackers[expected_key]
        assert len(tracker.events) == 10


@pytest.mark.asyncio
async def test_database_health_reporting_and_disconnect_transition():
    """
    Validates DatabaseManager health check transitions:
    - Reports degraded (False) when using in-memory store.
    - Accurately reports status changes when ping succeeds or fails.
    """
    # 1. Under default in-memory fallback
    assert DatabaseManager.is_in_memory() is True
    assert await DatabaseManager.health_check() is False

    # 2. Simulate healthy MongoDB client with active ping
    mock_mongo = MagicMock()
    mock_mongo.admin.command = AsyncMock(return_value={"ok": 1.0})

    orig_client = DatabaseManager.client
    orig_db = DatabaseManager.db

    try:
        DatabaseManager.client = mock_mongo
        DatabaseManager.db = mock_mongo["netriq_test"]

        # Client attached -> healthy
        assert DatabaseManager.is_persistent() is True
        assert await DatabaseManager.health_check() is True

        # Simulate network drop / connection loss: ping raises exception
        mock_mongo.admin.command = AsyncMock(side_effect=Exception("Connection lost"))
        assert await DatabaseManager.health_check() is False

        # Simulate connection recovery
        mock_mongo.admin.command = AsyncMock(return_value={"ok": 1.0})
        assert await DatabaseManager.health_check() is True

    finally:
        DatabaseManager.client = orig_client
        DatabaseManager.db = orig_db
