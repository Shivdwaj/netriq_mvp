"""
entities.py
Canonical domain models and Pydantic schemas for the 12 core NetrIQ entities:
1. organizations   - Customer organisations
2. users           - User accounts
3. roles           - Access permissions
4. sensors         - Registered network sensors
5. sensor_health   - Sensor operational status
6. network_events  - Normalised events
7. detection_rules - Detection configurations
8. alerts          - Individual detection results
9. incidents       - Correlated investigations
10. incident_events - Events linked to incidents
11. evidence       - Supporting evidence references (external PCAP / files & SHA-256 hashes)
12. audit_logs     - User and administrative actions

Implementation Decisions:
- Every customer-owned record is tenant-scoped via tenant_id.
- All timestamps are stored in UTC (both ISO-8601 string and epoch seconds).
- Strict separation between severity (impact) and confidence (certainty).
"""

import time
import uuid
from enum import Enum
from typing import Dict, Any, List, Optional, Union
from datetime import datetime, timezone
from pydantic import BaseModel, Field, ConfigDict


def get_utc_now_iso() -> str:
    """Returns current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def get_utc_now_timestamp() -> float:
    """Returns current UTC timestamp in epoch seconds."""
    return time.time()


# ==============================================================================
# 1. ORGANIZATIONS (Customer organisations)
# ==============================================================================

class PlanTier(str, Enum):
    COMMUNITY = "community"
    STARTER = "starter"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"


class Organization(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    tenant_id: str = Field(description="Unique customer tenant identifier")
    name: str = Field(description="Display organisation name")
    slug: str = Field(description="URL-safe slug")
    admin_email: str
    plan_tier: PlanTier = PlanTier.COMMUNITY
    internal_subnets: List[str] = Field(default_factory=lambda: ["192.168.0.0/16", "10.0.0.0/8"])
    crown_jewel_assets: List[str] = Field(default_factory=list)
    event_retention_days: int = 30
    pcap_retention_days: int = 7
    sensor_health_retention_days: int = 7
    created_at: float = Field(default_factory=get_utc_now_timestamp)
    updated_at: float = Field(default_factory=get_utc_now_timestamp)
    created_at_iso: str = Field(default_factory=get_utc_now_iso)


# ==============================================================================
# 2. USERS (User accounts)
# ==============================================================================

class UserStatus(str, Enum):
    ACTIVE = "active"
    DISABLED = "disabled"
    LOCKED = "locked"


class User(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    id: Optional[str] = None
    tenant_id: str = Field(description="Tenant isolation key")
    username: str
    email: str
    role: str = "analyst"  # admin, analyst, readonly, sensor
    status: UserStatus = UserStatus.ACTIVE
    hashed_password: Optional[str] = None
    failed_login_attempts: int = 0
    locked_until: float = 0.0
    created_at: float = Field(default_factory=get_utc_now_timestamp)
    updated_at: float = Field(default_factory=get_utc_now_timestamp)
    last_login_at: Optional[float] = None


# ==============================================================================
# 3. ROLES (Access permissions)
# ==============================================================================

class RoleEntity(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    role_name: str
    tenant_id: str = "global"  # "global" for system roles, or tenant-specific
    description: str
    capabilities: List[str] = Field(default_factory=list)
    is_system: bool = False
    created_at: float = Field(default_factory=get_utc_now_timestamp)


# ==============================================================================
# 4. SENSORS (Registered network sensors)
# ==============================================================================

class SensorType(str, Enum):
    SURICATA = "suricata"
    ZEEK = "zeek"
    NETRIQ_COLLECTOR = "netriq_collector"
    ENDPOINT_AGENT = "endpoint_agent"


class Sensor(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    sensor_id: str
    tenant_id: str
    name: str
    software_type: SensorType
    software_version: str
    hostname: str
    listening_interface: str = "eth0"
    environment: str = "bare_metal"  # cloud_vm, k8s_pod, container, bare_metal
    status: str = "online"  # online, offline, degraded
    api_key_hash: str
    local_pcap_buffer_mb: int = 256
    port_scan_window_sec: float = 60.0
    created_at: float = Field(default_factory=get_utc_now_timestamp)
    updated_at: float = Field(default_factory=get_utc_now_timestamp)
    last_heartbeat: Optional[float] = None
    last_heartbeat_iso: Optional[str] = None


# ==============================================================================
# 5. SENSOR_HEALTH (Sensor operational status)
# ==============================================================================

class SensorHealth(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    id: Optional[str] = None
    tenant_id: str
    sensor_id: str
    timestamp: float = Field(default_factory=get_utc_now_timestamp)
    timestamp_iso: str = Field(default_factory=get_utc_now_iso)
    cpu_pct: float = 0.0
    ram_mb: float = 0.0
    kernel_drops: int = 0
    packets_processed: int = 0
    uptime_seconds: float = 0.0
    status: str = "healthy"  # healthy, warning, critical


# ==============================================================================
# 6. NETWORK_EVENTS (Normalised events)
# ==============================================================================

class NetworkEvent(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    event_id: str
    tenant_id: str
    sensor_id: str
    timestamp: str = Field(description="UTC ISO-8601 formatted timestamp")
    timestamp_epoch: float = Field(default_factory=get_utc_now_timestamp)
    source_ip: str
    destination_ip: str
    source_port: int = 0
    destination_port: int = 0
    protocol: str = "TCP"
    event_type: str = "connection"  # connection, dns, http, alert, anomaly
    detection_source: str = "sensor"  # zeek, suricata, netriq_local
    severity: str = "INFO"  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    evidence: Dict[str, Any] = Field(default_factory=dict)
    ingestion_time: str = Field(default_factory=get_utc_now_iso)


# ==============================================================================
# 7. DETECTION_RULES (Detection configurations)
# ==============================================================================

class RuleType(str, Enum):
    THRESHOLD = "threshold"
    SIGNATURE = "signature"
    BEHAVIORAL = "behavioral"
    CORRELATION = "correlation"


class DetectionRule(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    rule_id: str
    tenant_id: str = "global"  # "global" or specific tenant
    name: str
    rule_type: RuleType = RuleType.THRESHOLD
    engine: str = "local_sensor"  # suricata, zeek, local_sensor, central_intelligence
    pattern: Dict[str, Any] = Field(default_factory=dict)
    severity: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL
    enabled: bool = True
    created_at: float = Field(default_factory=get_utc_now_timestamp)
    updated_at: float = Field(default_factory=get_utc_now_timestamp)


# ==============================================================================
# 8. ALERTS (Individual detection results)
# ==============================================================================

class Alert(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    alert_id: str = Field(default_factory=lambda: f"alt-{uuid.uuid4().hex[:12]}")
    tenant_id: str
    sensor_id: str
    event_id: Optional[str] = None
    rule_id: Optional[str] = None
    timestamp: float = Field(default_factory=get_utc_now_timestamp)
    timestamp_iso: str = Field(default_factory=get_utc_now_iso)
    source_ip: str
    destination_ip: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = "TCP"
    severity: str = "MEDIUM"
    confidence: float = 0.85
    title: str
    description: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    status: str = "open"  # open, acknowledged, suppressed, escalated


# ==============================================================================
# 9. INCIDENTS (Correlated investigations)
# ==============================================================================

class Incident(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    id: Optional[str] = None
    tenant_id: str
    incident_code: Optional[str] = None
    title: str
    description: str
    incident_type: str = "Possible reconnaissance"
    severity: str = "MEDIUM"  # Contextual impact (LOW, MEDIUM, HIGH, CRITICAL)
    confidence: float = 0.75  # Evidentiary proof (0.0 to 1.0)
    confidence_label: str = "PROBABLE"  # CONFIRMED, PROBABLE, SUSPECTED, NEEDS_VALIDATION
    status: str = "new"  # new, investigating, confirmed, false_positive, resolved
    attack_chain: List[str] = Field(default_factory=list)
    affected_assets: List[str] = Field(default_factory=list)
    src_ip: Optional[str] = None
    hostname: Optional[str] = None
    mac: Optional[str] = None
    user: Optional[str] = None
    assigned_to: Optional[str] = None
    event_count: int = 1
    created_at: float = Field(default_factory=get_utc_now_timestamp)
    updated_at: float = Field(default_factory=get_utc_now_timestamp)
    closed_at: Optional[float] = None
    closed_by: Optional[str] = None
    resolution_notes: Optional[str] = None
    recommended_investigation_steps: List[str] = Field(default_factory=list)


# ==============================================================================
# 10. INCIDENT_EVENTS (Events linked to incidents)
# ==============================================================================

class IncidentEventRole(str, Enum):
    TRIGGER = "trigger"
    RECON = "reconnaissance"
    LATERAL = "lateral_movement"
    EXPLOIT = "exploit"
    SUPPORTING = "supporting_evidence"


class IncidentEvent(BaseModel):
    """
    Join relation linking Incidents to contributing Network Events and Alerts.
    Enables SOC analysts to trace directly from an incident to every supporting packet event.
    """
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    id: Optional[str] = None
    tenant_id: str
    incident_id: str
    event_id: str
    alert_id: Optional[str] = None
    timestamp: str
    timestamp_epoch: float = Field(default_factory=get_utc_now_timestamp)
    role_in_incident: IncidentEventRole = IncidentEventRole.SUPPORTING
    added_at: float = Field(default_factory=get_utc_now_timestamp)
    added_at_iso: str = Field(default_factory=get_utc_now_iso)


# ==============================================================================
# 11. EVIDENCE (Supporting evidence references - External PCAP & files)
# ==============================================================================

class EvidenceType(str, Enum):
    SELECTIVE_PCAP = "selective_pcap"
    LOG_EXTRACT = "log_extract"
    FLOW_DUMP = "flow_dump"
    FORENSIC_SNAPSHOT = "forensic_snapshot"


class Evidence(BaseModel):
    """
    Supporting evidence references.
    
    Architectural Mandate:
    Large PCAP files are stored outside the relational/document database (on filesystem or object store).
    The database retains file references, paths, and cryptographic SHA-256 hashes for integrity verification.
    """
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    evidence_id: str = Field(default_factory=lambda: f"evi-{uuid.uuid4().hex[:12]}")
    tenant_id: str
    incident_id: str
    sensor_id: str
    evidence_type: EvidenceType = EvidenceType.SELECTIVE_PCAP
    file_path: str = Field(description="Storage URI or relative file path on external storage")
    file_hash_sha256: str = Field(description="SHA-256 digest of the PCAP file for tamper-evident proof")
    file_size_bytes: int = 0
    storage_backend: str = "local_disk"  # local_disk, s3, azure_blob, edge_buffer
    packet_count: int = 0
    filter_criteria: Dict[str, Any] = Field(default_factory=dict)
    captured_at: float = Field(default_factory=get_utc_now_timestamp)
    captured_at_iso: str = Field(default_factory=get_utc_now_iso)
    expires_at: float = Field(description="Retention deadline when the external PCAP file can be purged")
    expires_at_iso: str
    is_immutable: bool = True


# ==============================================================================
# 12. AUDIT_LOGS (User and administrative actions)
# ==============================================================================

class AuditAction(str, Enum):
    LOGIN = "LOGIN"
    LOGOUT = "LOGOUT"
    STATUS_CHANGE = "STATUS_CHANGE"
    ASSIGNMENT = "ASSIGNMENT"
    NOTE_ADDED = "NOTE_ADDED"
    SEVERITY_OVERRIDE = "SEVERITY_OVERRIDE"
    PCAP_EXTRACT = "PCAP_EXTRACT"
    CONFIG_UPDATE = "CONFIG_UPDATE"
    RULE_CREATE = "RULE_CREATE"
    RULE_TOGGLE = "RULE_TOGGLE"
    SENSOR_REGISTER = "SENSOR_REGISTER"
    EXPORT = "EXPORT"


class AuditLog(BaseModel):
    """
    Immutable audit record tracking every security analyst and administrative action.
    """
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    audit_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str
    user_id: str
    username: str
    action: Union[AuditAction, str]
    resource_type: str  # incident, sensor, rule, user, evidence, organization
    resource_id: str
    timestamp: float = Field(default_factory=get_utc_now_timestamp)
    timestamp_iso: str = Field(default_factory=get_utc_now_iso)
    details: Dict[str, Any] = Field(default_factory=dict)
    ip_address: Optional[str] = None
    status: str = "SUCCESS"  # SUCCESS, FAILED, DENIED

