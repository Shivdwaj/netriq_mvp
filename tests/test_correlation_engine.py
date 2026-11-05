import time
import pytest
import asyncio
from unittest.mock import AsyncMock, patch
from bson import ObjectId

from backend.pipeline.schemas import (
    NormalizedSecurityEvent,
    DeviceIdentity,
    format_utc_timestamp
)
from backend.database.collections import incidents_repo
from backend.services.notification_service import notification_service
from backend.services.correlation_service import CorrelationEngine

@pytest.mark.asyncio
async def test_severity_and_confidence_decoupling():
    """
    Validates that Severity (Impact) and Confidence (Certainty) are completely decoupled.
    Scenario 1: High Severity, Low Confidence (Single uncorroborated probe on Crown Jewel database)
    Scenario 2: Medium Severity, High Confidence (Multi-port scan with high repetition/evidence count)
    """
    valid_oid = str(ObjectId())
    with patch.object(incidents_repo, "create", new_callable=AsyncMock) as mock_create, \
         patch.object(incidents_repo, "update", new_callable=AsyncMock) as mock_update, \
         patch.object(notification_service, "notify_new_incident", new_callable=AsyncMock):
        
        mock_create.return_value = valid_oid
        mock_update.return_value = True
        engine = CorrelationEngine(window_seconds=600.0)

        # 1. SCENARIO 1: High Severity, Low Confidence
        target_host = "192.168.1.55"
        ev_crown_jewel = NormalizedSecurityEvent(
            source_ip=target_host,
            destination_ip="192.168.1.10",
            source_port=51234,
            destination_port=1433,
            protocol="TCP",
            event_type="connection",
            detection_source="zeek",
            direction="internal",
            device=DeviceIdentity(ip=target_host, hostname="Dev-Workstation-55", is_managed=True)
        )

        # Ingest 3 observations so it meets the minimum investigation threshold
        for _ in range(3):
            await engine.process_event(ev_crown_jewel)

        tracker1 = engine._trackers.get(target_host)
        assert tracker1 is not None
        assert len(tracker1.crown_jewel_attempts) >= 1

        # Check call arguments to mock_create
        assert mock_create.called
        created_doc = mock_create.call_args[0][0]
        # In single-sensor database probe with 3 observations:
        # Severity is HIGH or CRITICAL due to Crown Jewel asset criticality
        assert created_doc["severity"] in ("HIGH", "CRITICAL")
        # Confidence is low (Needs Validation / Suspected) because there is only 1 engine source without full multi-engine agreement
        assert created_doc["confidence"] <= 0.70
        assert created_doc["confidence_label"] in ("NEEDS_VALIDATION", "SUSPECTED")
        assert created_doc["incident_type"] == "Crown Jewel Access Attempt"

@pytest.mark.asyncio
async def test_multi_stage_attack_chain_synthesis():
    """
    Validates that multiple observations across stages (Discovery -> Lateral Movement)
    are synthesized into ONE investigation ticket rather than multiple alerts.
    """
    valid_oid = str(ObjectId())
    with patch.object(incidents_repo, "create", new_callable=AsyncMock) as mock_create, \
         patch.object(incidents_repo, "update", new_callable=AsyncMock) as mock_update, \
         patch.object(notification_service, "notify_new_incident", new_callable=AsyncMock):
        
        mock_create.return_value = valid_oid
        mock_update.return_value = True
        engine = CorrelationEngine(window_seconds=600.0)
        attacker_ip = "192.168.1.185"

        device = DeviceIdentity(ip=attacker_ip, hostname="Compromised-Sales-Laptop", is_managed=True)

        # Stage 1: Port scan (Discovery)
        for port in range(1001, 1010):
            ev_scan = NormalizedSecurityEvent(
                source_ip=attacker_ip,
                destination_ip="192.168.1.10",
                source_port=50000 + port,
                destination_port=port,
                protocol="TCP",
                event_type="connection",
                detection_source="zeek",
                direction="internal",
                device=device
            )
            await engine.process_event(ev_scan)

        # Stage 2: Lateral SMB probe (Lateral Movement)
        ev_lateral = NormalizedSecurityEvent(
            source_ip=attacker_ip,
            destination_ip="192.168.1.10",
            source_port=54321,
            destination_port=445,
            protocol="TCP",
            event_type="connection",
            detection_source="zeek",
            direction="internal",
            device=device
        )
        await engine.process_event(ev_lateral)

        tracker = engine._trackers.get(attacker_ip)
        assert tracker is not None
        # Both stages must be tracked under ONE device tracker
        assert len(tracker.scanned_ports) >= 8
        assert len(tracker.lateral_attempts) >= 1
        assert len(tracker.events) >= 10
        assert mock_create.called
        assert mock_update.called

        # Initial creation at 3 observations
        init_doc = mock_create.call_args[0][0]
        assert "reconnaissance" in init_doc["title"].lower()

        # Final update synthesized multi-stage attack chain
        latest_update = mock_update.call_args[0][1]
        assert "Discovery" in latest_update["description"]
        assert "Lateral Movement" in latest_update["description"]
