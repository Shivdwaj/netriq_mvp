import time
import secrets
import hashlib
import hmac
import uuid
from typing import Dict, Any, List, Optional

from backend.utils.logger import get_logger
from backend.database.collections import organisations_repo, sensors_repo, rules_repo
from backend.pipeline.schemas import get_utc_iso_now
from backend.schemas.management import (
    OrganisationCreateReq,
    OrganisationItem,
    SensorRegistrationReq,
    SensorRegistrationResponse,
    SensorHeartbeatReq,
    SensorConfigUpdateReq,
    DetectionRuleManifest,
    SensorHealthStatus
)

logger = get_logger(__name__)

# Standard target versions for software sensor components
BENCHMARK_SOFTWARE_VERSIONS = {
    "suricata": "7.0.2",
    "zeek": "6.0.3",
    "netriq_collector": "1.2.0",
    "endpoint_agent": "1.2.0"
}

class CentralManagementService:
    """
    Central Management Service
    Manages multi-tenant customer deployments and distributed software sensors:
    1. Organisation registration & strict data isolation
    2. Software Sensor registration & provisioning
    3. Sensor authentication (SHA-256 hashed API keys)
    4. Sensor health monitoring (software kernel_drops, CPU%, RAM, daemon uptime)
    5. Detection rule distribution (Suricata & NetrIQ rule manifests)
    6. Configuration management (remote daemon tuning, interfaces, CIDRs)
    7. User & role management scoped per tenant
    8. Software version tracking (flagging outdated daemons/containers)
    """

    # --- 1. Organisation Management ---
    async def create_organisation(self, req: OrganisationCreateReq) -> Dict[str, Any]:
        """Registers a new customer organisation with tenant isolation."""
        tenant_id = f"org_{req.slug.lower().replace('-', '_')}"
        now = time.time()

        # Check existing
        existing = await organisations_repo.list(filter_query={"tenant_id": tenant_id}, limit=1)
        if existing:
            raise ValueError(f"Organisation with tenant_id '{tenant_id}' already exists.")

        org_doc = {
            "tenant_id": tenant_id,
            "name": req.name,
            "slug": req.slug,
            "admin_email": req.admin_email,
            "plan_tier": req.plan_tier,
            "internal_subnets": req.internal_subnets,
            "crown_jewel_assets": req.crown_jewel_assets,
            "sensor_count": 0,
            "active_incidents_count": 0,
            "created_at": now,
            "updated_at": now
        }

        org_id = await organisations_repo.create(org_doc)
        org_doc["id"] = org_id
        logger.info(f"[CentralManagement] Registered new organisation '{req.name}' (tenant_id={tenant_id})")
        return org_doc

    async def get_organisation(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves organisation profile by tenant_id."""
        results = await organisations_repo.list(filter_query={"tenant_id": tenant_id}, limit=1)
        return results[0] if results else None

    async def list_organisations(self) -> List[Dict[str, Any]]:
        """Lists all registered customer organisations (Super-Admin)."""
        return await organisations_repo.list(limit=100)

    # --- 2 & 3. Software Sensor Registration & Authentication ---
    async def register_software_sensor(self, req: SensorRegistrationReq) -> SensorRegistrationResponse:
        """
        Provisions a new software sensor daemon running on a customer VM, container, or cloud node.
        Generates a secure API key, stores its SHA-256 hash, and returns the key once.
        """
        sensor_type = req.software_type.value
        sensor_id = f"sensor-{sensor_type}-{uuid.uuid4().hex[:8]}"
        plaintext_key = f"ntrq_{secrets.token_urlsafe(32)}"
        key_hash = hashlib.sha256(plaintext_key.encode("utf-8")).hexdigest()
        now = time.time()

        # Check benchmark version status
        benchmark_v = BENCHMARK_SOFTWARE_VERSIONS.get(sensor_type, "1.0.0")
        is_outdated = req.software_version < benchmark_v

        sensor_doc = {
            "sensor_id": sensor_id,
            "tenant_id": req.tenant_id,
            "name": req.name,
            "software_type": sensor_type,
            "software_version": req.software_version,
            "benchmark_version": benchmark_v,
            "is_version_outdated": is_outdated,
            "hostname": req.hostname,
            "listening_interface": req.listening_interface or "eth0",
            "environment": req.environment,
            "api_key_hash": key_hash,
            "status": SensorHealthStatus.HEALTHY.value,
            "last_heartbeat": now,
            "last_heartbeat_iso": get_utc_iso_now(),
            "cpu_usage_pct": 0.0,
            "memory_usage_mb": 0.0,
            "kernel_drops_count": 0,
            "packets_processed": 0,
            "uptime_seconds": 0.0,
            "config": {
                "capture_interface": req.listening_interface or "eth0",
                "buffer_size_mb": 256,
                "log_level": "INFO"
            },
            "created_at": now,
            "updated_at": now
        }

        await sensors_repo.create(sensor_doc)

        # Increment sensor count on organisation doc
        await organisations_repo.collection.update_one(
            {"tenant_id": req.tenant_id},
            {"$inc": {"sensor_count": 1}}
        )

        logger.info(f"[CentralManagement] Registered software sensor {sensor_id} ({sensor_type}) for tenant {req.tenant_id}")

        return SensorRegistrationResponse(
            sensor_id=sensor_id,
            tenant_id=req.tenant_id,
            name=req.name,
            api_key=plaintext_key
        )

    async def authenticate_sensor(self, sensor_id: str, api_key: str) -> Optional[Dict[str, Any]]:
        """Authenticates a software sensor using constant-time hash comparison."""
        sensors = await sensors_repo.list(filter_query={"sensor_id": sensor_id}, limit=1)
        if not sensors:
            return None

        sensor = sensors[0]
        expected_hash = sensor.get("api_key_hash", "")
        provided_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest()

        if hmac.compare_digest(expected_hash, provided_hash):
            return sensor
        return None

    # --- 4. Sensor Health & Metric Telemetry ---
    async def record_sensor_heartbeat(self, req: SensorHeartbeatReq) -> Dict[str, Any]:
        """
        Records health telemetry from a running software sensor daemon.
        Evaluates software packet drop counts (kernel_drops) to detect queue saturation.
        """
        sensors = await sensors_repo.list(filter_query={"sensor_id": req.sensor_id}, limit=1)
        if not sensors:
            raise ValueError(f"Sensor {req.sensor_id} not registered")

        sensor = sensors[0]
        now = time.time()
        now_iso = get_utc_iso_now()

        # Health state evaluation: if kernel packet drops exceed 500, flag as DEGRADED
        if req.kernel_drops_count > 500:
            status = SensorHealthStatus.DEGRADED.value
        elif req.cpu_usage_pct > 95.0:
            status = SensorHealthStatus.DEGRADED.value
        else:
            status = SensorHealthStatus.HEALTHY.value

        updates: Dict[str, Any] = {
            "last_heartbeat": now,
            "last_heartbeat_iso": now_iso,
            "status": status,
            "cpu_usage_pct": req.cpu_usage_pct,
            "memory_usage_mb": req.memory_usage_mb,
            "kernel_drops_count": req.kernel_drops_count,
            "packets_processed": req.packets_processed,
            "uptime_seconds": req.uptime_seconds,
            "updated_at": now
        }

        if req.software_version:
            updates["software_version"] = req.software_version
            b_v = BENCHMARK_SOFTWARE_VERSIONS.get(sensor.get("software_type"), "1.0.0")
            updates["is_version_outdated"] = req.software_version < b_v

        await sensors_repo.collection.update_one(
            {"sensor_id": req.sensor_id},
            {"$set": updates}
        )

        return {"status": "success", "sensor_status": status, "timestamp": now_iso}

    async def list_software_sensors(self, tenant_id: str) -> List[Dict[str, Any]]:
        """Lists all software sensors scoped strictly to a tenant's organisation."""
        now = time.time()
        filter_q = {} if tenant_id == "global" else {"tenant_id": tenant_id}
        sensors = await sensors_repo.list(filter_query=filter_q, limit=100)

        # Update offline status dynamically if heartbeat missed for > 60 seconds
        results = []
        for s in sensors:
            last_hb = s.get("last_heartbeat", 0)
            if (now - last_hb) > 60.0:
                s["status"] = SensorHealthStatus.OFFLINE.value
            results.append(s)
        return results

    # --- 5. Detection Rule Distribution ---
    async def get_rule_manifest(self, tenant_id: str) -> DetectionRuleManifest:
        """
        Compiles and distributes detection rules for software sensors in an organisation.
        Combines Suricata ET signatures, NetrIQ threshold rules, and tenant whitelists.
        """
        org = await self.get_organisation(tenant_id)
        internal_subnets = org.get("internal_subnets", []) if org else ["10.0.0.0/8"]

        manifest = DetectionRuleManifest(
            tenant_id=tenant_id,
            version=time.strftime("%Y.%m.%d.01", time.gmtime()),
            suricata_rules=[
                {"sid": 2010935, "action": "alert", "msg": "ET EXPLOIT Lateral SMB Exec", "classtype": "attempted-admin"},
                {"sid": 2028911, "action": "alert", "msg": "ET TROJAN Cobalt Strike Beaconing", "classtype": "trojan-activity"},
                {"sid": 2001219, "action": "alert", "msg": "ET SCAN Potential Nmap Service Sweep", "classtype": "network-scan"}
            ],
            netriq_rules=[
                {"rule_id": "NETRIQ:RULE:PORT_SCAN_RECON", "type": "threshold", "window_sec": 60, "min_ports": 8},
                {"rule_id": "NETRIQ:RULE:FAILED_CONNECTION_CHURN", "type": "zeek_state", "states": ["S0", "REJ"], "min_failed": 5},
                {"rule_id": "NETRIQ:RULE:UNUSUAL_DNS_ACTIVITY", "type": "entropy", "min_entropy": 3.8, "min_len": 35}
            ],
            active_whitelists=internal_subnets
        )
        return manifest

    # --- 6. Remote Configuration Management ---
    async def update_sensor_config(self, tenant_id: str, sensor_id: str, config: SensorConfigUpdateReq) -> Dict[str, Any]:
        """Pushes remote configuration changes to a customer's software sensor daemon."""
        sensors = await sensors_repo.list(filter_query={"sensor_id": sensor_id, "tenant_id": tenant_id}, limit=1)
        if not sensors:
            raise ValueError(f"Sensor {sensor_id} not found under tenant {tenant_id}")

        clean_cfg = {k: v for k, v in config.model_dump().items() if v is not None}
        now = time.time()

        await sensors_repo.collection.update_one(
            {"sensor_id": sensor_id},
            {
                "$set": {
                    "config": clean_cfg,
                    "listening_interface": config.listening_interface or sensors[0].get("listening_interface"),
                    "updated_at": now
                }
            }
        )

        logger.info(f"[CentralManagement] Remote config updated for sensor {sensor_id} (tenant={tenant_id})")
        sensors_updated = await sensors_repo.list(filter_query={"sensor_id": sensor_id}, limit=1)
        return sensors_updated[0] if sensors_updated else {}

    # --- 8. Software Version Tracking ---
    async def get_software_version_matrix(self, tenant_id: str) -> Dict[str, Any]:
        """Returns a fleet audit matrix showing daemon software versions vs current benchmark releases."""
        filter_q = {} if tenant_id == "global" else {"tenant_id": tenant_id}
        sensors = await sensors_repo.list(filter_query=filter_q, limit=100)

        fleet_matrix = []
        outdated_count = 0

        for s in sensors:
            stype = s.get("software_type", "suricata")
            installed_v = s.get("software_version", "unknown")
            benchmark_v = BENCHMARK_SOFTWARE_VERSIONS.get(stype, "1.0.0")
            is_outdated = installed_v < benchmark_v
            if is_outdated:
                outdated_count += 1

            fleet_matrix.append({
                "sensor_id": s.get("sensor_id"),
                "name": s.get("name"),
                "hostname": s.get("hostname"),
                "software_type": stype,
                "installed_version": installed_v,
                "benchmark_version": benchmark_v,
                "is_outdated": is_outdated,
                "status": s.get("status")
            })

        return {
            "tenant_id": tenant_id,
            "total_software_sensors": len(sensors),
            "outdated_sensors_count": outdated_count,
            "benchmarks": BENCHMARK_SOFTWARE_VERSIONS,
            "fleet": fleet_matrix
        }

central_management_service = CentralManagementService()

