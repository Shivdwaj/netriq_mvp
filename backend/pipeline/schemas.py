from enum import Enum
from typing import Optional, Dict, Any, List, Union
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid
import time

def get_utc_iso_now() -> str:
    """Returns current UTC timestamp formatted as ISO 8601."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

def format_utc_timestamp(ts: Optional[Union[str, float, int]]) -> str:
    """Normalizes any timestamp (float, int, or string) into consistent ISO 8601 UTC."""
    if ts is None:
        return get_utc_iso_now()
    if isinstance(ts, (int, float)):
        try:
            return datetime.fromtimestamp(float(ts), timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        except Exception:
            return get_utc_iso_now()
    if isinstance(ts, str):
        # Already an ISO string or similar
        try:
            clean = ts.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        except Exception:
            return ts
    return get_utc_iso_now()

class EventType(str, Enum):
    CONNECTION = "connection"
    ALERT = "alert"
    ANOMALY = "anomaly"
    PROCESS_EXECUTION = "process_execution"
    USER_AUTHENTICATION = "user_authentication"
    NETWORK_CONNECTION = "network_connection"
    NETWORK_FLOW = "connection"

class DetectionSource(str, Enum):
    SURICATA = "suricata"
    ZEEK = "zeek"
    NETRIQ = "netriq"
    ENDPOINT_AGENT = "endpoint_agent"
    NETWORK_SENSOR = "netriq"

EventSource = DetectionSource

class SeverityLevel(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class DeviceIdentity(BaseModel):
    hostname: Optional[str] = "unknown"
    mac: Optional[str] = None
    ip: Optional[str] = None
    os_name: Optional[str] = None
    logged_in_user: Optional[str] = None
    is_managed: bool = False

class NetworkDetails(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = 0
    dst_port: Optional[int] = 0
    protocol: str = "TCP"
    packet_count: Optional[int] = 1
    byte_count: Optional[int] = 0
    tcp_flags: Optional[List[str]] = Field(default_factory=list)
    dns_query: Optional[str] = None
    direction: Optional[str] = "unknown"

class EndpointDetails(BaseModel):
    pid: Optional[int] = None
    ppid: Optional[int] = None
    process_name: Optional[str] = None
    executable_path: Optional[str] = None
    command_line: Optional[str] = None
    user: Optional[str] = None
    auth_status: Optional[str] = None
    connection_state: Optional[str] = None
    remote_ip: Optional[str] = None
    remote_port: Optional[int] = None
    local_port: Optional[int] = None
    is_suspicious: bool = False
    suspicious_reason: Optional[str] = None

class NormalizedSecurityEvent(BaseModel):
    """
    NetrIQ Common Event Format (NCEF)
    Standard internal event schema across Suricata, Zeek, NetrIQ Sensors, and Endpoint Agents.
    """
    # Primary Standard Fields
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = Field(default="default")
    sensor_id: str = Field(default="sensor-netriq-01")
    timestamp: str = Field(default_factory=get_utc_iso_now)
    source_ip: str
    destination_ip: str
    source_port: int = 0
    destination_port: int = 0
    protocol: str = "TCP"
    event_type: str = "connection"
    detection_source: str = "netriq"
    severity: str = "INFO"
    evidence: Dict[str, Any] = Field(default_factory=dict)

    # Additional Standard Metadata Fields
    network_interface: Optional[str] = "eth0"
    direction: Optional[str] = "internal"  # internal, inbound, outbound
    flow_id: Optional[str] = None
    rule_id: Optional[str] = None
    event_version: str = "1.0.0"
    ingestion_time: str = Field(default_factory=get_utc_iso_now)

    # Context Objects
    device: Optional[DeviceIdentity] = None
    endpoint: Optional[EndpointDetails] = None

    # Backward compatibility properties for existing modules
    @property
    def source(self) -> str:
        return self.detection_source

    @property
    def raw_metadata(self) -> Dict[str, Any]:
        return self.evidence

    @property
    def network(self) -> NetworkDetails:
        """Returns a NetworkDetails view of the top-level network fields."""
        return NetworkDetails(
            src_ip=self.source_ip,
            dst_ip=self.destination_ip,
            src_port=self.source_port,
            dst_port=self.destination_port,
            protocol=self.protocol,
            direction=self.direction,
            dns_query=self.evidence.get("dns_query")
        )
