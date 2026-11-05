import json
import time
from typing import Dict, Any, Optional, Union
from datetime import datetime

from backend.adapters.base import BaseEventAdapter
from backend.pipeline.schemas import (
    NormalizedSecurityEvent,
    EventType,
    EventSource,
    NetworkDetails
)
from backend.pipeline.identity_resolver import identity_resolver
from backend.pipeline.deduplicator import deduplicator
from backend.pipeline.normalizer import _determine_direction
from backend.utils.logger import get_logger

logger = get_logger(__name__)

class SuricataAdapter(BaseEventAdapter):
    """
    Component B: Suricata Adapter.
    Translates Suricata EVE JSON alerts, anomalies, and protocol records
    into NetrIQ's common event format.
    """

    @property
    def engine_name(self) -> str:
        return "suricata"

    @staticmethod
    def _parse_timestamp(ts_raw: Optional[Union[str, float, int]]) -> float:
        if ts_raw is None:
            return time.time()
        if isinstance(ts_raw, (int, float)):
            return float(ts_raw)
        try:
            clean_ts = str(ts_raw).split(".")[0].replace("Z", "")
            return datetime.fromisoformat(clean_ts).timestamp()
        except Exception:
            return time.time()

    @staticmethod
    def _extract_mitre(category: str, signature: str) -> Optional[str]:
        sig_lower = (signature or "").lower()
        if "scan" in sig_lower or "nmap" in sig_lower:
            return "T1046 Network Service Discovery"
        if "exploit" in sig_lower or "cve-" in sig_lower or "rce" in sig_lower:
            return "T1190 Exploit Public-Facing Application"
        if "credential" in sig_lower or "mimikatz" in sig_lower:
            return "T1003 OS Credential Dumping"
        if "smb" in sig_lower or "rdp" in sig_lower or "lateral" in sig_lower:
            return "T1021 Remote Services"
        if "c2" in sig_lower or "beacon" in sig_lower or "trojan" in sig_lower:
            return "T1071 Application Layer Protocol"
        return None

    def transform(self, raw_data: Union[str, Dict[str, Any]]) -> Optional[NormalizedSecurityEvent]:
        """Transforms a raw Suricata EVE dictionary or JSON line."""
        if isinstance(raw_data, str):
            try:
                record = json.loads(raw_data.strip())
            except Exception:
                return None
        else:
            record = raw_data

        # Normalize IP field variants (dest_ip vs dst_ip)
        src_ip = record.get("src_ip")
        dst_ip = record.get("dest_ip") or record.get("dst_ip")
        if not src_ip or not dst_ip:
            return None

        proto = str(record.get("proto", "TCP")).upper()
        src_port = int(record.get("src_port") or 0)
        dst_port = int(record.get("dest_port") or record.get("dst_port") or 0)
        ts = self._parse_timestamp(record.get("timestamp"))

        # Resolve authoritative device identity
        device = identity_resolver.resolve(ip=src_ip)
        direction = _determine_direction(src_ip, dst_ip)

        network_details = NetworkDetails(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto,
            direction=direction,
            packet_count=1,
            byte_count=int(record.get("length") or 0)
        )

        event_type_str = record.get("event_type", "alert")
        raw_metadata = dict(record)

        if event_type_str == "alert":
            alert_obj = record.get("alert", {})
            signature = alert_obj.get("signature", "Suricata Alert")
            category = alert_obj.get("category", "Potentially Bad Traffic")
            severity_num = alert_obj.get("severity", 2)
            mitre_tag = self._extract_mitre(category, signature)

            raw_metadata["signature"] = signature
            raw_metadata["severity_level"] = severity_num
            raw_metadata["mitre"] = mitre_tag

        elif event_type_str == "anomaly":
            anomaly_obj = record.get("anomaly", {})
            raw_metadata["anomaly_event"] = anomaly_obj.get("event", "Protocol anomaly")

        event = NormalizedSecurityEvent(
            timestamp=ts,
            event_type=EventType.NETWORK_FLOW,
            source=EventSource.SURICATA,
            device=device,
            network=network_details,
            raw_metadata=raw_metadata
        )

        if deduplicator.is_duplicate(event):
            return None

        return event

suricata_adapter = SuricataAdapter()
