import time
import uuid
from typing import Dict, Any, List, Optional
from backend.adapters import suricata_adapter, zeek_adapter
from backend.pipeline.schemas import NormalizedSecurityEvent, get_utc_iso_now

class EventCollector:
    """
    Step 3 & 4: Event Collector & Normalisation Engine
    Gathers structured outputs from Suricata and Zeek daemons running on the edge sensor,
    and normalizes them into standard NetrIQ Common Event Format (NCEF).
    """
    def __init__(self, sensor_id: str = "sensor-edge-01", tenant_id: str = "default"):
        self.sensor_id = sensor_id
        self.tenant_id = tenant_id

    def collect_suricata_eve(self, eve_record: Dict[str, Any]) -> Optional[NormalizedSecurityEvent]:
        """Collects and transforms a raw Suricata EVE JSON alert or protocol record."""
        event = suricata_adapter.transform(eve_record)
        if event:
            event.sensor_id = self.sensor_id
            event.tenant_id = self.tenant_id
        return event

    def collect_zeek_conn(self, conn_record: Dict[str, Any]) -> Optional[NormalizedSecurityEvent]:
        """Collects and transforms a Zeek conn.log record describing connection states (S0, SF, REJ)."""
        event = zeek_adapter.transform(conn_record)
        if event:
            event.sensor_id = self.sensor_id
            event.tenant_id = self.tenant_id
        return event

    def collect_zeek_dns(self, dns_record: Dict[str, Any]) -> Optional[NormalizedSecurityEvent]:
        """Collects and transforms a Zeek dns.log record describing domain queries."""
        event = zeek_adapter.transform(dns_record)
        if event:
            event.sensor_id = self.sensor_id
            event.tenant_id = self.tenant_id
        return event

    def create_connection_event(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str = "TCP",
        state: str = "S0",
        detection_source: str = "zeek"
    ) -> NormalizedSecurityEvent:
        """Constructs a normalized connection event directly from sensor network analysis."""
        return NormalizedSecurityEvent(
            event_id=f"evt-{uuid.uuid4().hex[:10]}",
            tenant_id=self.tenant_id,
            sensor_id=self.sensor_id,
            timestamp=get_utc_iso_now(),
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=src_port,
            destination_port=dst_port,
            protocol=protocol,
            event_type="connection",
            detection_source=detection_source,
            severity="INFO",
            evidence={"conn_state": state}
        )
