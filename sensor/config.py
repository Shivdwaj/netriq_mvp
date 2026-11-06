import os
from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class SensorConfig:
    """
    Configuration for NetrIQ Software Sensor Daemon running on customer VM/container.
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
    port_scan_window_sec: float = 60.0
    port_scan_port_threshold: int = 8
    multi_host_ip_threshold: int = 5
    
    # Cloud Batching & Ingestion
    batch_size: int = 50
    flush_interval_sec: float = 2.0
    max_queue_size: int = 10000
    heartbeat_interval_sec: float = 30.0

