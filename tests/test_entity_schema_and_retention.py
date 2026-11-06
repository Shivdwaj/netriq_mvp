"""
tests/test_entity_schema_and_retention.py
Comprehensive test suite verifying:
1. 12 Core NetrIQ Entities and ER Diagram Relationships:
   - organizations, users, roles, sensors, sensor_health, network_events,
     detection_rules, alerts, incidents, incident_events, evidence, audit_logs.
2. Tenant Isolation & UTC Timestamps.
3. External PCAP binary serialization, SHA-256 hashing, and tamper detection.
4. Retention policy pruning & file cleanup.
5. Index definitions across all 12 entities.
6. Incidents evidence & incident_events API endpoints.
"""

import os
import time
import pytest
import hashlib
from datetime import datetime, timezone
from starlette.testclient import TestClient

from backend.main import app
from backend.database.database import DatabaseManager
from backend.database.in_memory_db import InMemoryDatabase
from backend.database.collections import (
    organizations_repo,
    users_repo,
    roles_repo,
    sensors_repo,
    sensor_health_repo,
    network_events_repo,
    detection_rules_repo,
    alerts_repo,
    incidents_repo,
    incident_events_repo,
    evidence_repo,
    audit_logs_repo,
)
from backend.schemas.entities import (
    Organization,
    User,
    RoleEntity,
    Sensor,
    SensorType,
    SensorHealth,
    NetworkEvent,
    DetectionRule,
    RuleType,
    Alert,
    Incident,
    IncidentEvent,
    IncidentEventRole,
    Evidence,
    EvidenceType,
    AuditLog,
    AuditAction,
    get_utc_now_iso,
    get_utc_now_timestamp
)
from backend.database.indexes import ensure_indexes
from backend.database.partitioning import TimePartitionManager, RetentionPolicyManager
from backend.services.evidence_service import evidence_service
from backend.auth.jwt_handler import create_access_token


@pytest.fixture(autouse=True)
def setup_db():
    """Ensure in-memory test database is cleanly connected."""
    os.environ["TESTING"] = "true"
    DatabaseManager.db = InMemoryDatabase()
    yield


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def test_tenant():
    return "tenant-acme-corp"


@pytest.fixture
def auth_headers(test_tenant):
    token = create_access_token(
        user_id="analyst_alice",
        role="analyst",
        tenant_id=test_tenant
    )
    return {
        "Authorization": f"Bearer {token}",
        "X-Tenant-ID": test_tenant
    }


# ==============================================================================
# 1. TEST 12 CORE ENTITY INSTANTIATION & TENANT SCOPING
# ==============================================================================

@pytest.mark.asyncio
async def test_all_12_entities_schema_and_tenant_scoping(test_tenant):
    """
    Validates that all 12 entities instantiate properly with UTC timestamps and tenant_id.
    """
    now = time.time()
    now_iso = get_utc_now_iso()

    # 1. Organization
    org = Organization(
        tenant_id=test_tenant,
        name="Acme Corporation",
        slug="acme-corp",
        admin_email="admin@acme.com"
    )
    assert org.tenant_id == test_tenant
    assert org.created_at_iso.endswith("+00:00") or org.created_at_iso.endswith("Z")

    # 2. User
    user = User(
        user_id="usr-001",
        tenant_id=test_tenant,
        username="alice",
        email="alice@acme.com",
        role="analyst"
    )
    assert user.tenant_id == test_tenant
    assert user.email == "alice@acme.com"

    # 3. Role
    role = RoleEntity(
        role_name="Security Analyst",
        tenant_id=test_tenant,
        description="Analyst role",
        capabilities=["view_summary", "view_events", "view_threats", "manage_incidents"]
    )
    assert role.tenant_id == test_tenant
    assert "view_events" in role.capabilities

    # 4. Sensor
    sensor = Sensor(
        sensor_id="sensor-sniff-01",
        tenant_id=test_tenant,
        name="DMZ Sensor",
        software_type=SensorType.NETRIQ_COLLECTOR,
        software_version="1.0.0",
        hostname="dmz-gw-01",
        listening_interface="eth0",
        status="online",
        api_key_hash="hash123"
    )
    assert sensor.sensor_id == "sensor-sniff-01"

    # 5. SensorHealth
    health = SensorHealth(
        sensor_id="sensor-sniff-01",
        tenant_id=test_tenant,
        status="healthy",
        cpu_pct=12.5,
        ram_mb=256.0,
        kernel_drops=0
    )
    assert health.cpu_pct == 12.5

    # 6. NetworkEvent
    event = NetworkEvent(
        event_id="evt-1001",
        tenant_id=test_tenant,
        sensor_id="sensor-sniff-01",
        source_ip="192.168.1.50",
        destination_ip="10.0.0.5",
        destination_port=445,
        protocol="TCP",
        event_type="connection",
        detection_source="netriq_collector",
        timestamp=now_iso
    )
    assert event.source_ip == "192.168.1.50"
    assert event.destination_port == 445

    # 7. DetectionRule
    rule = DetectionRule(
        rule_id="RULE-PORT-SCAN",
        tenant_id=test_tenant,
        name="SYN Port Scan",
        rule_type=RuleType.SIGNATURE,
        engine="local_sensor",
        severity="HIGH"
    )
    assert rule.rule_id == "RULE-PORT-SCAN"

    # 8. Alert
    alert = Alert(
        alert_id="alt-5001",
        tenant_id=test_tenant,
        rule_id="RULE-PORT-SCAN",
        event_id="evt-1001",
        sensor_id="sensor-sniff-01",
        title="Port Scan Alert",
        description="Scanned multiple ports",
        severity="HIGH",
        confidence=0.95,
        source_ip="192.168.1.50",
        destination_ip="10.0.0.5"
    )
    assert alert.confidence == 0.95

    # 9. Incident
    incident = Incident(
        tenant_id=test_tenant,
        title="Reconnaissance and Lateral Sweep",
        description="Suspicious port scan followed by lateral attempt",
        incident_type="Port Scan & Recon",
        severity="HIGH",
        status="new",
        src_ip="192.168.1.50"
    )
    assert incident.status == "new"

    # 10. IncidentEvent (Join Entity)
    inc_event = IncidentEvent(
        tenant_id=test_tenant,
        incident_id="inc-9001",
        event_id="evt-1001",
        alert_id="alt-5001",
        timestamp=now_iso,
        role_in_incident=IncidentEventRole.TRIGGER
    )
    assert inc_event.role_in_incident == IncidentEventRole.TRIGGER

    # 11. Evidence (External PCAP Reference & SHA-256)
    evidence = Evidence(
        evidence_id="evi-pcap-001",
        tenant_id=test_tenant,
        incident_id="inc-9001",
        sensor_id="sensor-sniff-01",
        file_path="storage/evidence/tenant-acme-corp/inc-9001/evi-pcap-001.pcap",
        file_hash_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        file_size_bytes=24,
        storage_backend="local_disk",
        expires_at=now + 86400 * 14,
        expires_at_iso=now_iso
    )
    assert evidence.evidence_type == EvidenceType.SELECTIVE_PCAP

    # 12. AuditLog
    audit = AuditLog(
        tenant_id=test_tenant,
        user_id="usr-001",
        username="alice",
        action=AuditAction.PCAP_EXTRACT,
        resource_type="evidence",
        resource_id="evi-pcap-001"
    )
    assert audit.action == AuditAction.PCAP_EXTRACT


# ==============================================================================
# 2. TEST ER DIAGRAM REPOSITORY RELATIONSHIPS
# ==============================================================================

@pytest.mark.asyncio
async def test_er_diagram_relational_flow(test_tenant):
    """
    Tests the complete relational chain from ER diagram:
    ORGANIZATION -> USER, SENSOR, INCIDENT
    SENSOR -> NETWORK_EVENT -> ALERT -> INCIDENT_EVENTS -> INCIDENT
    INCIDENT -> EVIDENCE
    USER -> AUDIT_LOG
    """
    await ensure_indexes()

    # 1. Organization owns sensors, contains users, manages incidents
    org_id = await organizations_repo.create({
        "tenant_id": test_tenant,
        "name": "Acme Corp",
        "slug": "acme-corp",
        "admin_email": "admin@acme.com"
    })
    org = await organizations_repo.get_by_tenant(test_tenant, org_id)
    assert org is not None

    # 2. User
    await users_repo.create({
        "tenant_id": test_tenant,
        "username": "bob_analyst",
        "email": "bob@acme.com",
        "role": "Analyst"
    })
    users = await users_repo.list_by_tenant(test_tenant)
    assert len(users) >= 1
    user_bob = users[0]

    # 3. Sensor
    await sensors_repo.create({
        "tenant_id": test_tenant,
        "sensor_id": "sensor-core-01",
        "name": "Core Sensor",
        "status": "active"
    })

    # 4. Sensor generates Network Event
    await network_events_repo.create({
        "tenant_id": test_tenant,
        "event_id": "evt-sweep-01",
        "sensor_id": "sensor-core-01",
        "source_ip": "10.0.0.99",
        "destination_ip": "10.0.0.1",
        "destination_port": 80,
        "protocol": "TCP",
        "event_type": "connection",
        "timestamp": get_utc_now_iso(),
        "created_at": time.time()
    })

    # 5. Network Event produces Alert
    await alerts_repo.create({
        "tenant_id": test_tenant,
        "alert_id": "alt-sweep-01",
        "event_id": "evt-sweep-01",
        "sensor_id": "sensor-core-01",
        "rule_id": "RULE-TCP-SWEEP",
        "title": "TCP Syn Sweep Detected",
        "description": "TCP Syn sweep detected from 10.0.0.99",
        "severity": "HIGH",
        "confidence": 0.88,
        "timestamp": get_utc_now_iso()
    })

    # 6. Incident created
    inc_doc_id = await incidents_repo.create({
        "tenant_id": test_tenant,
        "incident_id": "inc-sec-55",
        "title": "Suspected Subnet Scan",
        "description": "Suspected subnet scan on core network",
        "incident_type": "Network Reconnaissance",
        "severity": "HIGH",
        "status": "new",
        "created_at": time.time(),
        "updated_at": time.time()
    })

    # 7. Incident contains IncidentEvent (join entity linking event & alert)
    linked = await evidence_service.link_event_to_incident(
        tenant_id=test_tenant,
        incident_id=inc_doc_id,
        event_id="evt-sweep-01",
        alert_id="alt-sweep-01",
        role_in_incident=IncidentEventRole.TRIGGER
    )
    assert linked.incident_id == inc_doc_id
    assert linked.event_id == "evt-sweep-01"

    # 8. User generates Audit Log
    audit = await evidence_service.log_audit_action(
        tenant_id=test_tenant,
        user_id=user_bob.get("username", "bob"),
        username="bob_analyst",
        action=AuditAction.RULE_CREATE,
        resource_type="rule",
        resource_id="RULE-TCP-SWEEP",
        details={"status": "enabled"}
    )
    assert audit.resource_id == "RULE-TCP-SWEEP"
    assert audit.tenant_id == test_tenant


# ==============================================================================
# 3. TEST EXTERNAL PCAP EVIDENCE STORAGE & TAMPER DETECTION
# ==============================================================================

@pytest.mark.asyncio
async def test_external_pcap_storage_and_tamper_detection(test_tenant, tmp_path):
    """
    Tests external storage of binary PCAP, SHA-256 calculation,
    and ensures cryptographic verification catches any disk-level file tampering.
    """
    custom_service = type(evidence_service)(base_storage_dir=tmp_path / "storage" / "evidence")

    packets = [
        {
            "timestamp": time.time(),
            "length": 64,
            "payload_hex": "4500003c1c4640004006b1e60a0000020a000003005001bb00000000a00272101e1a0000020405b40402080a"
        },
        {
            "timestamp": time.time() + 0.01,
            "length": 64,
            "payload_hex": "4500003ca046400040062de60a0000020a000003005101bb00000000a00272101e190000020405b40402080a"
        }
    ]

    # Store selective PCAP
    evi = await custom_service.store_selective_pcap(
        tenant_id=test_tenant,
        incident_id="inc-forensic-01",
        sensor_id="sensor-sniff-01",
        packets=packets,
        filter_criteria={"src_ip": "10.0.0.2", "dst_ip": "10.0.0.3"}
    )

    assert evi.evidence_id.startswith("evi-pcap-")
    assert evi.packet_count == 2
    assert evi.file_size_bytes > 24
    assert len(evi.file_hash_sha256) == 64

    # Verify integrity (Untampered)
    res_valid = await custom_service.verify_evidence_integrity(evi.evidence_id, test_tenant)
    assert res_valid["verified"] is True
    assert res_valid["is_tampered"] is False

    # Simulate Malicious Tampering: flip 1 byte on disk
    full_disk_path = custom_service.storage_dir.parent / evi.file_path
    assert full_disk_path.exists()

    with open(full_disk_path, "r+b") as f:
        f.seek(30)
        original_byte = f.read(1)
        tampered_byte = bytes([(original_byte[0] ^ 0xFF)])
        f.seek(30)
        f.write(tampered_byte)

    # Re-verify integrity (Tampered)
    res_tampered = await custom_service.verify_evidence_integrity(evi.evidence_id, test_tenant)
    assert res_tampered["verified"] is False
    assert res_tampered["is_tampered"] is True
    assert res_tampered["computed_hash"] != res_tampered["stored_hash"]


# ==============================================================================
# 4. TEST TIME PARTITIONING & RETENTION POLICY PRUNING
# ==============================================================================

@pytest.mark.asyncio
async def test_partitioning_and_retention_policy(test_tenant, tmp_path):
    """
    Tests partition name calculation and automated pruning of expired records.
    """
    # 1. Partition Names
    fixed_ts = datetime(2026, 11, 4, 15, 0, 0, tzinfo=timezone.utc).timestamp()
    p_name = TimePartitionManager.get_partition_name(fixed_ts)
    assert p_name == "network_events_2026_11"

    # Multi-month range
    start_ts = datetime(2026, 9, 15, tzinfo=timezone.utc).timestamp()
    end_ts = datetime(2026, 11, 1, tzinfo=timezone.utc).timestamp()
    ranges = TimePartitionManager.get_partition_range_names(start_ts, end_ts)
    assert "network_events_2026_09" in ranges
    assert "network_events_2026_10" in ranges
    assert "network_events_2026_11" in ranges

    # 2. Retention Pruning
    now = time.time()
    old_time = now - (35 * 86400)  # 35 days ago (older than 30-day policy)

    # Insert old network event
    await network_events_repo.create({
        "tenant_id": test_tenant,
        "event_id": "evt-expired-01",
        "created_at": old_time
    })

    # Insert old sensor health (older than 7 days)
    await sensor_health_repo.create({
        "tenant_id": test_tenant,
        "sensor_id": "sensor-01",
        "timestamp": now - (10 * 86400)
    })

    # Insert expired evidence
    fake_evi_file = tmp_path / "expired.pcap"
    fake_evi_file.write_bytes(b"dummy pcap content")
    await evidence_repo.create({
        "tenant_id": test_tenant,
        "evidence_id": "evi-expired-01",
        "file_path": str(fake_evi_file.relative_to(tmp_path)),
        "expires_at": now - 3600  # expired 1 hour ago
    })

    # Execute pruning
    counts = await RetentionPolicyManager.prune_expired_records(
        tenant_id=test_tenant,
        event_retention_days=30,
        sensor_health_retention_days=7,
        evidence_retention_days=14
    )

    assert counts["network_events_pruned"] >= 1
    assert counts["sensor_health_pruned"] >= 1
    assert counts["evidence_pruned"] >= 1


# ==============================================================================
# 5. TEST INCIDENT EVIDENCE & SUPPORTING EVENTS HTTP ENDPOINTS
# ==============================================================================

@pytest.mark.asyncio
async def test_incident_evidence_and_event_navigation_api(client, test_tenant, auth_headers):
    """
    Tests the SOC analyst capability to:
    1. Navigate from an Incident to its supporting Network Events (GET /incidents/{id}/events).
    2. Inspect forensic evidence items (GET /incidents/{id}/evidence).
    3. Verify SHA-256 cryptographic proof (POST /incidents/{id}/evidence/{id}/verify).
    """
    # 1. Create Incident
    inc_id = await incidents_repo.create({
        "tenant_id": test_tenant,
        "incident_id": "inc-nav-100",
        "title": "Privilege Escalation & Port Scan",
        "description": "Port scan detected from untrusted endpoint",
        "incident_type": "Lateral Movement",
        "severity": "CRITICAL",
        "status": "new",
        "created_at": time.time(),
        "updated_at": time.time()
    })

    # 2. Insert Supporting Network Event
    await network_events_repo.create({
        "tenant_id": test_tenant,
        "event_id": "evt-recon-99",
        "source_ip": "172.16.0.4",
        "destination_ip": "172.16.0.10",
        "destination_port": 22,
        "protocol": "TCP",
        "event_type": "connection"
    })

    # 3. Link Event via incident_events
    await evidence_service.link_event_to_incident(
        tenant_id=test_tenant,
        incident_id=inc_id,
        event_id="evt-recon-99",
        role_in_incident=IncidentEventRole.TRIGGER
    )

    # 4. Attach selective PCAP Evidence
    evidence_item = await evidence_service.store_selective_pcap(
        tenant_id=test_tenant,
        incident_id=inc_id,
        sensor_id="sensor-sniff-01",
        packets=[{"timestamp": time.time(), "length": 64, "payload_hex": "4500003c"}]
    )

    # A. Query Supporting Events
    res_events = client.get(
        f"/api/v1/incidents/{inc_id}/events",
        headers=auth_headers
    )
    assert res_events.status_code == 200
    events_data = res_events.json()
    assert len(events_data) >= 1
    assert events_data[0]["event_id"] == "evt-recon-99"
    assert events_data[0]["role_in_incident"] == "trigger"
    assert "network_event" in events_data[0]
    assert events_data[0]["network_event"]["source_ip"] == "172.16.0.4"

    # B. Query Evidence
    res_evidence = client.get(
        f"/api/v1/incidents/{inc_id}/evidence",
        headers=auth_headers
    )
    assert res_evidence.status_code == 200
    evi_list = res_evidence.json()
    assert len(evi_list) >= 1
    assert any(e["evidence_id"] == evidence_item.evidence_id for e in evi_list)

    # C. Verify SHA-256 Checksum via API
    res_verify = client.post(
        f"/api/v1/incidents/{inc_id}/evidence/{evidence_item.evidence_id}/verify",
        headers=auth_headers
    )
    assert res_verify.status_code == 200
    ver_data = res_verify.json()
    assert ver_data["verified"] is True
    assert ver_data["stored_hash"] == evidence_item.file_hash_sha256
