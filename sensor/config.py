import os
from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class SensorConfig:
    """
    Configuration for NetrIQ Software Sensor Daemon running on customer VM/container.
    All settings are fully configurable via environment variables (zero hardcoded values).
    """
    sensor_id: str = os.getenv("NETRIQ_SENSOR_ID", "sensor-edge-01")
    tenant_id: str = os.getenv("NETRIQ_TENANT_ID", "default")
    api_key: str = os.getenv("NETRIQ_SENSOR_KEY", "")
    central_api_url: str = os.getenv("NETRIQ_CENTRAL_URL", "http://127.0.0.1:8000")
    
    # Network Capture Config
    capture_interface: str = os.getenv("NETRIQ_INTERFACE", "eth0")
    promiscuous_mode: bool = True
    
    # Local PCAP Ring Buffer (Privacy & Bandwidth optimization)
    # Packets are kept locally on the sensor host, NOT sent to the cloud.
    local_pcap_buffer_mb: int = int(os.getenv("NETRIQ_PCAP_BUFFER_MB", "256"))
    pcap_retention_minutes: int = int(os.getenv("NETRIQ_PCAP_RETENTION_MIN", "60"))
    
    # Local Detection Rule Thresholds
    port_scan_window_sec: float = float(os.getenv("NETRIQ_PORT_SCAN_WINDOW_SEC", "60.0"))
    port_scan_port_threshold: int = int(os.getenv("NETRIQ_PORT_SCAN_PORT_THRESHOLD", "8"))
    multi_host_ip_threshold: int = int(os.getenv("NETRIQ_MULTI_HOST_IP_THRESHOLD", "5"))
    
    # Cloud Batching & Ingestion
    batch_size: int = int(os.getenv("NETRIQ_BATCH_SIZE", "50"))
    flush_interval_sec: float = float(os.getenv("NETRIQ_FLUSH_INTERVAL_SEC", "2.0"))
    max_queue_size: int = int(os.getenv("NETRIQ_MAX_QUEUE_SIZE", "10000"))
    heartbeat_interval_sec: float = float(os.getenv("NETRIQ_HEARTBEAT_INTERVAL_SEC", "30.0"))

    # Offline Operation & Local Event Spooling
    disk_spool_path: Optional[str] = os.getenv("NETRIQ_SENSOR_SPOOL_PATH", None)
    max_disk_spool_events: int = int(os.getenv("NETRIQ_MAX_SPOOL_EVENTS", "50000"))

    # Security: Cryptographic Verification Key
    signing_secret_key: Optional[str] = os.getenv("NETRIQ_SIGNING_KEY", None)
