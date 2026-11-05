import uuid
from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from backend.pipeline.schemas import get_utc_iso_now

class SensorSoftwareType(str, Enum):
    SURICATA = "suricata"
    ZEEK = "zeek"
    NETRIQ_COLLECTOR = "netriq_collector"
    ENDPOINT_AGENT = "endpoint_agent"

class SensorHealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    OFFLINE = "offline"

# --- Organisation Schemas ---
class OrganisationCreateReq(BaseModel):
    name: str
    slug: str
    admin_email: str
    plan_tier: str = "enterprise"
    internal_subnets: List[str] = Field(default_factory=lambda: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
    crown_jewel_assets: List[Dict[str, Any]] = Field(default_factory=list)

class OrganisationItem(BaseModel):
    id: str
    tenant_id: str
    name: str
    slug: str
    admin_email: str
    plan_tier: str
    internal_subnets: List[str] = Field(default_factory=list)
    crown_jewel_assets: List[Dict[str, Any]] = Field(default_factory=list)
    sensor_count: int = 0
    active_incidents_count: int = 0
    created_at: float
    updated_at: Optional[float] = None

# --- Software Sensor Schemas ---
class SensorRegistrationReq(BaseModel):
    tenant_id: str
    name: str
    software_type: SensorSoftwareType
    software_version: str # e.g. "suricata-7.0.2", "zeek-6.0.3", "v1.2.0"
    hostname: str
    listening_interface: Optional[str] = "eth0" # e.g. eth0, ens33, mirror0
    environment: str = "cloud_vm" # cloud_vm, container, on_prem_vm, bare_metal

class SensorItem(BaseModel):
    id: str
    sensor_id: str
    tenant_id: str
    name: str
    software_type: str
    software_version: str
    hostname: str
    listening_interface: str
    environment: str
    status: str = SensorHealthStatus.HEALTHY.value
    last_heartbeat: float
    last_heartbeat_iso: str
    cpu_usage_pct: float = 0.0
    memory_usage_mb: float = 0.0
    kernel_drops_count: int = 0 # Packet loss in software kernel
    packets_processed: int = 0
    uptime_seconds: float = 0.0
    is_version_outdated: bool = False
    config: Dict[str, Any] = Field(default_factory=dict)

class SensorRegistrationResponse(BaseModel):
    sensor_id: str
    tenant_id: str
    name: str
    api_key: str # Plaintext API key returned only once upon registration
    auth_header_instruction: str = "Pass 'X-Sensor-Key: <api_key>' on all ingestion requests."

class SensorHeartbeatReq(BaseModel):
    sensor_id: str
    cpu_usage_pct: float
    memory_usage_mb: float
    kernel_drops_count: int = 0
    packets_processed: int = 0
    uptime_seconds: float
    software_version: Optional[str] = None

# --- Remote Configuration & Rule Distribution Schemas ---
class SensorConfigUpdateReq(BaseModel):
    listening_interface: Optional[str] = None
    capture_buffer_size_mb: Optional[int] = None
    internal_subnets: Optional[List[str]] = None
    log_level: Optional[str] = None
    custom_settings: Optional[Dict[str, Any]] = None

class DetectionRuleManifest(BaseModel):
    manifest_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str
    version: str # e.g. "2026.11.05.01"
    published_at: str = Field(default_factory=get_utc_iso_now)
    suricata_rules: List[Dict[str, Any]] = Field(default_factory=list) # SID, content, action
    netriq_rules: List[Dict[str, Any]] = Field(default_factory=list)    # Thresholds, patterns
    active_whitelists: List[str] = Field(default_factory=list)
