import json
import time
from typing import Optional, Dict, Any, List
from datetime import datetime

from backend.utils.logger import get_logger
from backend.pipeline.schemas import (
    NormalizedSecurityEvent,
    EventType,
    EventSource,
    NetworkDetails
)
from backend.pipeline.identity_resolver import identity_resolver
from backend.pipeline.deduplicator import deduplicator
from backend.pipeline.normalizer import _determine_direction

logger = get_logger(__name__)

class SuricataEveIngestor:
    """
    Parses Suricata EVE JSON (Extensible Event Format).
    Translates signature matches, protocol anomalies, and alerts into
    NetrIQ NormalizedSecurityEvents.
    """

    @staticmethod
    def _parse_timestamp(ts_str: Optional[str]) -> float:
        """Parses ISO 8601 timestamp (e.g., 2026-11-05T13:45:00.123456+0000)."""
        if not ts_str:
            return time.time()
        try:
            # Strip microseconds / timezone if complex
            clean_ts = ts_str.split(".")[0].replace("Z", "")
            dt = datetime.fromisoformat(clean_ts)
            return dt.timestamp()
        except Exception:
            return time.time()

    @staticmethod
    def _extract_mitre_technique(category: str, signature: str) -> Optional[str]:
        """Maps Emerging Threats (ET) and Suricata rules to MITRE ATT&CK techniques."""
        sig_lower = signature.lower()
        cat_lower = (category or "").lower()

        if "scan" in sig_lower or "nmap" in sig_lower or "portscan" in sig_lower:
            return "T1046 Network Service Discovery"
        if "exploit" in sig_lower or "cve-" in sig_lower or "rce" in sig_lower:
            return "T1190 Exploit Public-Facing Application"
        if "credential" in sig_lower or "mimikatz" in sig_lower or "dump" in sig_lower:
            return "T1003 OS Credential Dumping"
        if "smb" in sig_lower or "rdp" in sig_lower or "lateral" in sig_lower or "psexec" in sig_lower:
            return "T1021 Remote Services"
        if "c2" in sig_lower or "beacon" in sig_lower or "trojan" in sig_lower or "cobalt" in sig_lower:
            return "T1071 Application Layer Protocol"
        if "exfiltration" in sig_lower or "upload" in sig_lower:
            return "T1048 Exfiltration Over Alternative Protocol"
        return None

    def parse_eve_record(self, record: Dict[str, Any]) -> Optional[NormalizedSecurityEvent]:
        """Converts a single decoded Suricata EVE record into a NormalizedSecurityEvent."""
        src_ip = record.get("src_ip")
        dst_ip = record.get("dest_ip") or record.get("dst_ip")
        if not src_ip or not dst_ip:
            return None

        event_type_str = record.get("event_type", "alert")
        ts = self._parse_timestamp(record.get("timestamp"))
        device = identity_resolver.resolve(ip=src_ip)

        direction = _determine_direction(src_ip, dst_ip)
        network_details = NetworkDetails(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=record.get("src_port", 0),
            dst_port=record.get("dest_port", 0),
            protocol=record.get("proto", "TCP").upper(),
            direction=direction
        )

        raw_meta = dict(record)

        # Handle Alerts
        if event_type_str == "alert":
            alert_obj = record.get("alert", {})
            signature = alert_obj.get("signature", "Suricata Alert")
            category = alert_obj.get("category", "Potentially Bad Traffic")
            severity_num = alert_obj.get("severity", 3)
            mitre_tag = self._extract_mitre_technique(category, signature)

            raw_meta["signature"] = signature
            raw_meta["signature_id"] = alert_obj.get("signature_id")
            raw_meta["category"] = category
            raw_meta["severity_level"] = severity_num
            raw_meta["mitre"] = mitre_tag

            event = NormalizedSecurityEvent(
                timestamp=ts,
                event_type=EventType.NETWORK_FLOW,
                source=EventSource.SURICATA,
                device=device,
                network=network_details,
                raw_metadata=raw_meta
            )
            if deduplicator.is_duplicate(event):
                return None
            return event

        # Handle Protocol Anomalies
        elif event_type_str == "anomaly":
            anomaly_obj = record.get("anomaly", {})
            raw_meta["anomaly_event"] = anomaly_obj.get("event", "Malformed packet anomaly")
            raw_meta["layer"] = anomaly_obj.get("layer", "PROTO")

            event = NormalizedSecurityEvent(
                timestamp=ts,
                event_type=EventType.NETWORK_FLOW,
                source=EventSource.SURICATA,
                device=device,
                network=network_details,
                raw_metadata=raw_meta
            )
            if deduplicator.is_duplicate(event):
                return None
            return event

        # Standard flow / protocol records (dns, http, tls)
        elif event_type_str in ("flow", "dns", "http", "tls"):
            if "dns" in record:
                network_details.dns_query = record["dns"].get("rrname")
            event = NormalizedSecurityEvent(
                timestamp=ts,
                event_type=EventType.NETWORK_FLOW,
                source=EventSource.SURICATA,
                device=device,
                network=network_details,
                raw_metadata=raw_meta
            )
            if deduplicator.is_duplicate(event):
                return None
            return event

        return None

    def parse_eve_line(self, line: str) -> Optional[NormalizedSecurityEvent]:
        """Parses a single JSON line string from eve.json."""
        line = line.strip()
        if not line or line.startswith("#"):
            return None
        try:
            record = json.loads(line)
            return self.parse_eve_record(record)
        except Exception as e:
            logger.debug(f"[SuricataEveIngestor] Failed to parse EVE line: {e}")
            return None

suricata_ingestor = SuricataEveIngestor()
