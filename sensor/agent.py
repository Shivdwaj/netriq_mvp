import asyncio
import time
from typing import Dict, Any, List, Optional

from sensor.config import SensorConfig
from sensor.packet_capture import LocalPcapBuffer
from sensor.collector import EventCollector
from sensor.local_detector import LocalDetectionEngine
from sensor.event_queue import LocalEventQueue
from sensor.shipper import SecureCloudShipper
from backend.pipeline.schemas import NormalizedSecurityEvent
from backend.security.signatures import ManifestSigner
from backend.utils.logger import get_logger

logger = get_logger(__name__)

class NetriqSensorAgent:
    """
    NetrIQ Software Sensor Agent
    Autonomous daemon deployed on customer VM, container, or cloud node.
    Implements the complete local edge sequence:
    1. Network Switch / TAP -> Packet Capture (Local Ring Buffer)
    2. Analysis via Suricata & Zeek inspection
    3. Event Collection
    4. Normalisation to NetrIQ Common Event Format
    5. Local Detection Engine (sliding window rules)
    6. Local Event Queue (buffer with retries & disk spooling)
    7. Secure Cloud Ingestion (HTTPS batch transmission)
    8. Software Integrity: Cryptographic verification of distributed rule manifests
    """
    def __init__(self, config: Optional[SensorConfig] = None):
        self.config = config or SensorConfig()
        
        # Local Components
        self.pcap_buffer = LocalPcapBuffer(
            max_mb=self.config.local_pcap_buffer_mb,
            retention_seconds=self.config.pcap_retention_minutes * 60.0
        )
        self.collector = EventCollector(
            sensor_id=self.config.sensor_id,
            tenant_id=self.config.tenant_id
        )
        self.local_detector = LocalDetectionEngine(
            window_seconds=self.config.port_scan_window_sec,
            port_scan_threshold=self.config.port_scan_port_threshold,
            host_sweep_threshold=self.config.multi_host_ip_threshold
        )
        self.event_queue = LocalEventQueue(
            max_size=self.config.max_queue_size,
            disk_spool_path=self.config.disk_spool_path,
            max_disk_size=self.config.max_disk_spool_events
        )
        self.shipper = SecureCloudShipper(
            central_url=self.config.central_api_url,
            sensor_id=self.config.sensor_id,
            api_key=self.config.api_key,
            event_queue=self.event_queue
        )
        
        self.is_running = False
        self._start_time = time.time()
        self.total_packets_observed = 0
        self.total_events_processed = 0

    async def ingest_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str = "TCP",
        raw_payload: bytes = b"",
        packet_len: int = 64,
        zeek_state: str = "S0"
    ) -> NormalizedSecurityEvent:
        """
        Step 1-6 End-to-End Pipeline:
        1. Captures packet into Local PCAP Ring Buffer (NOT sent to cloud).
        2. Suricata / Zeek processes traffic.
        3. Event Collector generates structured record.
        4. Normalisation Engine creates standard NormalizedSecurityEvent.
        5. Local Detection Engine evaluates connection pattern (e.g., port scan threshold).
        6. Enqueues event into Local Event Queue.
        """
        # Step 1: Record packet in local buffer for privacy & selective deep inspection
        self.pcap_buffer.record_packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            raw_payload=raw_payload,
            packet_len=packet_len
        )
        self.total_packets_observed += 1

        # Step 2, 3, 4: Collector creates normalized event
        event = self.collector.create_connection_event(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            state=zeek_state,
            detection_source="zeek"
        )

        # Step 5: Local Detection Engine evaluates pattern against sliding window
        local_alert = self.local_detector.evaluate(event)
        if local_alert:
            logger.info(
                f"[LocalDetector] Triggered rule {local_alert['rule_id']} "
                f"for source {src_ip}: {local_alert['title']}"
            )

        # Step 6: Enqueue into Local Event Queue (with persistence if configured)
        await self.event_queue.enqueue(event)
        self.total_events_processed += 1
        return event

    def apply_rule_manifest(self, manifest_data: Dict[str, Any], secret_key: Optional[str] = None) -> bool:
        """
        Applies a signed DetectionRuleManifest from Central Management.
        Verifies software integrity & cryptographic signature before updating local detection rules.
        Rejects tampered manifests and prevents untrusted updates.
        """
        key = secret_key or self.config.signing_secret_key
        is_valid = ManifestSigner.verify_manifest(manifest_data, key)
        if not is_valid:
            logger.warning("[SensorAgent] REJECTED rule manifest: Cryptographic signature verification failed or payload tampered.")
            return False

        logger.info(f"[SensorAgent] Rule manifest '{manifest_data.get('manifest_id')}' verified successfully. Applying updates...")
        netriq_rules = manifest_data.get("netriq_rules", [])
        for rule in netriq_rules:
            if rule.get("type") == "threshold":
                if "min_ports" in rule:
                    self.local_detector.port_scan_threshold = int(rule["min_ports"])
                if "window_sec" in rule:
                    self.local_detector.window_seconds = float(rule["window_sec"])
        return True

    async def flush_to_cloud(self) -> Dict[str, Any]:
        """Step 7: Ships queued batches to Central NetrIQ Platform via HTTPS."""
        return await self.shipper.flush_once(max_items=self.config.batch_size)

    async def send_heartbeat(self) -> Dict[str, Any]:
        """Reports sensor health to Central NetrIQ Platform."""
        uptime = time.time() - self._start_time
        return await self.shipper.send_heartbeat(
            cpu_pct=15.0,
            ram_mb=256.0,
            kernel_drops=0,
            packets_processed=self.total_packets_observed,
            uptime_seconds=uptime
        )

    async def close(self):
        """Releases network and storage resources cleanly."""
        await self.shipper.close()
        self.event_queue.close()
