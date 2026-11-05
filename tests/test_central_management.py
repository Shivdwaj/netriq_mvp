import pytest
import time
from unittest.mock import AsyncMock, MagicMock, patch
from bson import ObjectId

from backend.schemas.management import (
    OrganisationCreateReq,
    SensorRegistrationReq,
    SensorSoftwareType,
    SensorHeartbeatReq,
    SensorConfigUpdateReq,
    SensorHealthStatus
)
from backend.services.central_management_service import (
    central_management_service,
    BENCHMARK_SOFTWARE_VERSIONS
)
from backend.database.collections import organisations_repo, sensors_repo
from backend.database.database import DatabaseManager

@pytest.fixture(autouse=True)
def setup_mock_db():
    mock_db = MagicMock()
    mock_col = MagicMock()
    mock_db.__getitem__.return_value = mock_col
    DatabaseManager.db = mock_db
    return mock_col

@pytest.mark.asyncio
async def test_organisation_registration_and_tenant_isolation(setup_mock_db):
    """Validates multi-tenant organisation registration with isolated tenant_id."""
    orgs_db = []

    async def mock_list(filter_query=None, limit=100, **kwargs):
        if not filter_query:
            return list(orgs_db)
        matched = []
        for o in orgs_db:
            match = True
            for k, v in filter_query.items():
                if o.get(k) != v:
                    match = False
                    break
            if match:
                matched.append(o)
        return matched

    async def mock_create(doc):
        doc["_id"] = ObjectId()
        doc["id"] = str(doc["_id"])
        orgs_db.append(doc)
        return doc["id"]

    with patch.object(organisations_repo, "list", side_effect=mock_list), \
         patch.object(organisations_repo, "create", side_effect=mock_create):

        req = OrganisationCreateReq(
            name="Acme Corporation",
            slug="acme-corp",
            admin_email="security@acme.com",
            plan_tier="enterprise",
            internal_subnets=["10.100.0.0/16", "172.20.0.0/16"]
        )

        org = await central_management_service.create_organisation(req)
        assert org["tenant_id"] == "org_acme_corp"
        assert org["name"] == "Acme Corporation"
        assert "10.100.0.0/16" in org["internal_subnets"]

        # Duplicate registration with same slug should raise ValueError
        with pytest.raises(ValueError) as exc:
            await central_management_service.create_organisation(req)
        assert "already exists" in str(exc.value)

@pytest.mark.asyncio
async def test_software_sensor_registration_and_auth(setup_mock_db):
    """
    Validates provisioning of a software sensor daemon (Suricata/Zeek process on a VM or container).
    Verifies SHA-256 hashed API key storage and constant-time authentication.
    """
    sensors_db = []

    async def mock_sensor_create(doc):
        doc["_id"] = ObjectId()
        doc["id"] = str(doc["_id"])
        sensors_db.append(doc)
        return doc["id"]

    async def mock_sensor_list(filter_query=None, **kwargs):
        if not filter_query:
            return list(sensors_db)
        matched = []
        for s in sensors_db:
            match = True
            for k, v in filter_query.items():
                if s.get(k) != v:
                    match = False
                    break
            if match:
                matched.append(s)
        return matched

    async def mock_org_update(*args, **kwargs):
        return True

    setup_mock_db.update_one = AsyncMock(side_effect=mock_org_update)

    with patch.object(sensors_repo, "create", side_effect=mock_sensor_create), \
         patch.object(sensors_repo, "list", side_effect=mock_sensor_list):

        # 1. Register Suricata daemon
        reg_req = SensorRegistrationReq(
            tenant_id="org_acme_corp",
            name="suricata-gw-us-east",
            software_type=SensorSoftwareType.SURICATA,
            software_version="7.0.2",
            hostname="gw-prod-vm01",
            listening_interface="eth0",
            environment="cloud_vm"
        )

        reg_resp = await central_management_service.register_software_sensor(reg_req)
        assert reg_resp.sensor_id.startswith("sensor-suricata-")
        assert reg_resp.api_key.startswith("ntrq_")
        assert reg_resp.tenant_id == "org_acme_corp"

        # Verify plaintext key is NOT stored raw in sensors_db (only SHA-256 hash is stored)
        stored_sensor = sensors_db[0]
        assert stored_sensor["api_key_hash"] != reg_resp.api_key
        assert len(stored_sensor["api_key_hash"]) == 64 # SHA-256 hex string

        # 2. Authenticate sensor with valid API key
        auth_success = await central_management_service.authenticate_sensor(reg_resp.sensor_id, reg_resp.api_key)
        assert auth_success is not None
        assert auth_success["sensor_id"] == reg_resp.sensor_id

        # 3. Authenticate with invalid key should fail
        auth_fail = await central_management_service.authenticate_sensor(reg_resp.sensor_id, "ntrq_invalid_key_attempt")
        assert auth_fail is None

@pytest.mark.asyncio
async def test_sensor_health_monitoring_and_kernel_packet_drops(setup_mock_db):
    """
    Validates software daemon health monitoring.
    High software kernel packet drops (> 500) trigger DEGRADED health status.
    """
    sensor_id = "sensor-zeek-abcd1234"
    sensor_store = {
        "_id": ObjectId(),
        "sensor_id": sensor_id,
        "tenant_id": "org_acme_corp",
        "software_type": "zeek",
        "software_version": "6.0.3",
        "status": SensorHealthStatus.HEALTHY.value,
        "last_heartbeat": time.time(),
        "cpu_usage_pct": 15.0,
        "memory_usage_mb": 512.0,
        "kernel_drops_count": 0
    }

    async def mock_list(filter_query=None, **kwargs):
        if filter_query and filter_query.get("sensor_id") == sensor_id:
            return [sensor_store]
        return []

    async def mock_update_one(filter_dict, update_dict):
        if "$set" in update_dict:
            sensor_store.update(update_dict["$set"])
        return True

    setup_mock_db.update_one = AsyncMock(side_effect=mock_update_one)

    with patch.object(sensors_repo, "list", side_effect=mock_list):
        # Normal heartbeat: healthy
        hb1 = SensorHeartbeatReq(
            sensor_id=sensor_id,
            cpu_usage_pct=25.0,
            memory_usage_mb=550.0,
            kernel_drops_count=10,
            packets_processed=100000,
            uptime_seconds=3600.0
        )
        res1 = await central_management_service.record_sensor_heartbeat(hb1)
        assert res1["sensor_status"] == SensorHealthStatus.HEALTHY.value
        assert sensor_store["status"] == SensorHealthStatus.HEALTHY.value

        # High kernel packet drops (> 500) indicating software packet queue saturation
        hb2 = SensorHeartbeatReq(
            sensor_id=sensor_id,
            cpu_usage_pct=40.0,
            memory_usage_mb=620.0,
            kernel_drops_count=850,
            packets_processed=250000,
            uptime_seconds=7200.0
        )
        res2 = await central_management_service.record_sensor_heartbeat(hb2)
        assert res2["sensor_status"] == SensorHealthStatus.DEGRADED.value
        assert sensor_store["status"] == SensorHealthStatus.DEGRADED.value

@pytest.mark.asyncio
async def test_rule_distribution_and_version_tracking(setup_mock_db):
    """Validates rule distribution manifests and fleet software version audits."""
    org_doc = {
        "tenant_id": "org_beta",
        "name": "Beta Industries",
        "internal_subnets": ["10.0.0.0/8"]
    }

    sensors_list = [
        {
            "sensor_id": "sensor-suricata-1",
            "name": "edge-suricata",
            "hostname": "vm-east-1",
            "software_type": "suricata",
            "software_version": "7.0.2", # Matches benchmark
            "status": "healthy"
        },
        {
            "sensor_id": "sensor-suricata-2",
            "name": "legacy-suricata",
            "hostname": "vm-west-1",
            "software_type": "suricata",
            "software_version": "6.0.4", # Outdated (< 7.0.2)
            "status": "healthy"
        }
    ]

    async def mock_org_list(filter_query=None, **kwargs):
        return [org_doc]

    async def mock_sensors_list(filter_query=None, **kwargs):
        return list(sensors_list)

    with patch.object(organisations_repo, "list", side_effect=mock_org_list), \
         patch.object(sensors_repo, "list", side_effect=mock_sensors_list):

        # 1. Test Rule Distribution
        manifest = await central_management_service.get_rule_manifest("org_beta")
        assert manifest.tenant_id == "org_beta"
        assert len(manifest.suricata_rules) >= 3
        assert any(r["sid"] == 2010935 for r in manifest.suricata_rules)
        assert any(r["rule_id"] == "NETRIQ:RULE:PORT_SCAN_RECON" for r in manifest.netriq_rules)
        assert "10.0.0.0/8" in manifest.active_whitelists

        # 2. Test Software Version Matrix
        matrix = await central_management_service.get_software_version_matrix("org_beta")
        assert matrix["total_software_sensors"] == 2
        assert matrix["outdated_sensors_count"] == 1
        fleet = matrix["fleet"]
        assert fleet[0]["is_outdated"] is False
        assert fleet[1]["is_outdated"] is True # 6.0.4 < 7.0.2
