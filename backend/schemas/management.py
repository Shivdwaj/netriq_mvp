import uuid
import os
from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from backend.pipeline.schemas import get_utc_iso_now

class SensorHealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    OFFLINE = "offline"

class SensorSoftwareType(str, Enum):
    ALL_IN_ONE = "all_in_one"      # Full NetrIQ stack (Suricata + Zeek + Collector + Detector)
    SURICATA_ONLY = "suricata"     # Signature IDS engine only
    SURICATA = "suricata"
    ZEEK_ONLY = "zeek"             # Protocol & metadata telemetry engine only
    ZEEK = "zeek"
    EDGE_COLLECTOR = "collector"   # Lightweight collector / forwarder
    COLLECTOR = "collector"

# --- Customer Organisation Schemas ---
class OrganisationCreateReq(BaseModel):
    name: str # e.g. "Acme Corporation"
    slug: str # e.g. "acme-corp"
    admin_email: str
    plan_tier: str = "enterprise" # starter, professional, enterprise
    internal_subnets: List[str] = Field(default_factory=lambda: ["10.0.0.0/8", "192.168.0.0/16"])
    crown_jewel_assets: List[str] = Field(default_factory=list) # Critical IP addresses

class OrganisationItem(BaseModel):
    id: str
    tenant_id: str
    name: str
    slug: str
    admin_email: str
    plan_tier: str
    internal_subnets: List[str]
    crown_jewel_assets: List[str]
    sensor_count: int = 0
    active_incidents_count: int = 0
    created_at: float
    updated_at: float

# --- Software Sensor Management Schemas ---
class SensorRegistrationReq(BaseModel):
    tenant_id: str
    name: str # Descriptive name e.g. "HQ Data Center Sensor 01"
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
    sensor_token: str = "" # Bearer token equivalent
    auth_header_instruction: str = "Pass 'Authorization: Bearer <sensor-token>' or 'X-Sensor-Key: <api_key>' on all ingestion requests."

class SensorHeartbeatReq(BaseModel):
    sensor_id: str
    cpu_usage_pct: float
    memory_usage_mb: float
    kernel_drops_count: int = 0
    packets_processed: int = 0
    uptime_seconds: float
    software_version: Optional[str] = None
    timestamp: Optional[float] = None

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
    signature: Optional[str] = None
    signature_alg: Optional[str] = "HMAC-SHA256"
