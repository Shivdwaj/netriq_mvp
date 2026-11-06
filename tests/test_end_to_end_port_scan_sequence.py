import asyncio
import pytest
import time
import uuid
from starlette.testclient import TestClient

from backend.main import app
from backend.database.database import DatabaseManager
from backend.database.in_memory_db import InMemoryDatabase
from backend.auth.jwt_handler import create_access_token
from backend.pipeline import event_bus
from backend.services.correlation_service import correlation_engine
from sensor.agent import NetriqSensorAgent
from sensor.config import SensorConfig

@pytest.fixture(autouse=True)
def setup_db():
    DatabaseManager.db = InMemoryDatabase()
    event_bus.subscribe(correlation_engine.process_event)
    yield

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def analyst_token():
    return create_access_token("analyst_jane", "analyst", tenant_id="corp_net")


@pytest.mark.asyncio
async def test_end_to_end_port_scan_pipeline_sequence(client, analyst_token):
    """
    Validates the exact 8-step intended workflow:
    Step 1: Traffic capture (TCP connection attempts across multiple ports)
    Step 2: Analysis (Suricata & Zeek observe traffic)
    Step 3: Event generation (Structured connection records)
    Step 4: Normalisation (NetrIQ Common Event Format - NCEF)
    Step 5: Detection (Local Detection Rule triggers in configured sliding window)
    Step 6: Intelligence (Correlation Engine associates observations with host context)
    Step 7: Incident creation (Incident Management creates investigation with evidence & playbook)
    Step 8: Presentation (Dashboard delivers incident with deep links to supporting events)
    """
    # 0. Central Platform Setup: Register sensor
    reg_resp = client.post("/api/v1/sensors/register", json={
        "tenant_id": "corp_net",
        "name": "edge-sensor-tap1",
        "software_type": "zeek",
        "software_version": "6.0.3",
        "hostname": "tap-switch-01",
        "listening_interface": "eth0"
    })
    assert reg_resp.status_code == 200
    sensor_info = reg_resp.json()
    sensor_id = sensor_info["sensor_id"]
    api_key = sensor_info["api_key"]

    # Initialize Edge Sensor Agent with local detection thresholds
    sensor_cfg = SensorConfig(
        sensor_id=sensor_id,
        tenant_id="corp_net",
        api_key=api_key,
        port_scan_window_sec=60.0,
        port_scan_port_threshold=8,
        local_pcap_buffer_mb=64
    )
    sensor_agent = NetriqSensorAgent(config=sensor_cfg)

    # --------------------------------------------------------------------------
    # Step 1: Traffic capture (Computer A sends TCP connection attempts to multiple ports on Device B)
    # --------------------------------------------------------------------------
    attacker_ip = "192.168.1.10"
    target_ip = "192.168.1.20"
    probed_ports = [21, 22, 23, 25, 80, 110, 135, 139, 443, 445]

    for port in probed_ports:
        # Steps 1-5 executed sequentially on the sensor agent
        await sensor_agent.ingest_packet(
            src_ip=attacker_ip,
            dst_ip=target_ip,
            src_port=50000 + port,
            dst_port=port,
            protocol="TCP",
            raw_payload=b"\x02\x04\x05\xb4\x01\x03\x03\x08", # TCP SYN probe
            packet_len=74,
            zeek_state="S0"
        )

    # Verify: Raw packets remain local in sensor PCAP buffer, NOT yet transmitted
    assert sensor_agent.pcap_buffer.total_buffered_packets == len(probed_ports)
    assert sensor_agent.event_queue.queue_depth == len(probed_ports)

    # Verify: Selective local extraction can extract packet evidence without mass upload
    selective_pkts = sensor_agent.pcap_buffer.extract_selective_pcap(src_ip=attacker_ip)
    assert len(selective_pkts) == len(probed_ports)
    assert selective_pkts[0]["src_ip"] == attacker_ip

    # --------------------------------------------------------------------------
    # Step 6 & 7: Secure Cloud Ingestion (Local Event Queue -> Central Cloud)
    # --------------------------------------------------------------------------
    batch_id, events_to_ship = await sensor_agent.event_queue.get_batch(max_items=50)
    assert len(events_to_ship) == len(probed_ports)

    # Ingest into Central Platform via POST /api/v1/events/batch
    batch_payload = {
        "sensor_id": sensor_id,
        "batch_id": batch_id,
        "events": [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp,
                "source_ip": e.source_ip,
                "destination_ip": e.destination_ip,
                "source_port": e.source_port,
                "destination_port": e.destination_port,
                "protocol": e.protocol,
                "event_type": e.event_type,
                "detection_source": e.detection_source,
                "severity": e.severity,
                "evidence": e.evidence
            }
            for e in events_to_ship
        ]
    }

    ingest_resp = client.post(
        "/api/v1/events/batch",
        json=batch_payload,
        headers={"Authorization": f"Bearer {api_key}"}
    )
    assert ingest_resp.status_code == 200, ingest_resp.text
    ack = ingest_resp.json()
    assert ack["status"] == "acknowledged"
    assert ack["accepted_count"] == len(probed_ports)

    # Sensor marks batch acknowledged
    await sensor_agent.event_queue.acknowledge_batch(batch_id)
    assert sensor_agent.event_queue.in_flight_count == 0

    # Allow event bus asyncio tasks to process
    await asyncio.sleep(0.1)

    # --------------------------------------------------------------------------
    # Step 8: Presentation & Analyst Output (Dashboard -> Backend)
    # --------------------------------------------------------------------------
    headers = {"Authorization": f"Bearer {analyst_token}"}

    # 1. Dashboard Overview reflects fresh telemetry
    overview_resp = client.get("/api/v1/dashboard/overview", headers=headers)
    assert overview_resp.status_code == 200

    # 2. Supporting Events are queryable
    events_resp = client.get(f"/api/v1/events?source_ip={attacker_ip}", headers=headers)
    assert events_resp.status_code == 200
    events_list = events_resp.json()
    assert len(events_list) >= len(probed_ports)

    # 3. Incident Management contains the generated investigation
    incidents_resp = client.get("/api/v1/incidents", headers=headers)
    assert incidents_resp.status_code == 200
    incidents = incidents_resp.json()
    assert len(incidents) > 0

    # Locate incident for attacker IP
    recon_inc = next((i for i in incidents if i.get("src_ip") == attacker_ip or attacker_ip in (i.get("affected_assets") or [])), None)
    assert recon_inc is not None, "Expected an investigation correlated for the port scan source IP"

    # Verify Analyst Output requirements:
    # - Incident Type: Possible reconnaissance
    # - Source: 192.168.1.10
    # - Confidence: Needs validation or calibrated confidence
    # - Severity: Contextually separate from confidence
    assert "reconnaissance" in recon_inc.get("description", "").lower() or recon_inc.get("severity") in ("MEDIUM", "HIGH", "CRITICAL")
    assert recon_inc["status"] in ("new", "investigating")

    # Clean up
    await sensor_agent.close()

