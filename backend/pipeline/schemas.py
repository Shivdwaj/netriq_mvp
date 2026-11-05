from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
import time
import uuid

class EventType(str, Enum):
    NETWORK_FLOW = "network_flow"
    PROCESS_EXECUTION = "process_execution"
    USER_AUTHENTICATION = "user_authentication"
    NETWORK_CONNECTION = "network_connection"
    SYSTEM_SECURITY = "system_security"

class EventSource(str, Enum):
    NETWORK_SENSOR = "network_sensor"
    ENDPOINT_AGENT = "endpoint_agent"
    EXTERNAL_TAP = "external_tap"

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
    protocol: str = "IP"
    packet_count: Optional[int] = 1
    byte_count: Optional[int] = 0
    tcp_flags: Optional[List[str]] = Field(default_factory=list)
    dns_query: Optional[str] = None
    direction: Optional[str] = "unknown"  # inbound, outbound, internal

class EndpointDetails(BaseModel):
    pid: Optional[int] = None
    ppid: Optional[int] = None
    process_name: Optional[str] = None
    executable_path: Optional[str] = None
    command_line: Optional[str] = None
    user: Optional[str] = None
    auth_status: Optional[str] = None     # success, failure, lock, logoff
    connection_state: Optional[str] = None # LISTENING, ESTABLISHED, SYN_SENT, etc.
    remote_ip: Optional[str] = None
    remote_port: Optional[int] = None
    local_port: Optional[int] = None
    is_suspicious: bool = False
    suspicious_reason: Optional[str] = None

class NormalizedSecurityEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = Field(default_factory=time.time)
    event_type: EventType
    source: EventSource
    device: DeviceIdentity
    network: Optional[NetworkDetails] = None
    endpoint: Optional[EndpointDetails] = None
    raw_metadata: Dict[str, Any] = Field(default_factory=dict)

