import json
import time
from typing import Dict, Any, Optional, Union
from datetime import datetime

from backend.adapters.base import BaseEventAdapter
from backend.pipeline.schemas import (
    NormalizedSecurityEvent,
    format_utc_timestamp,
    get_utc_iso_now
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
    into the standard NetrIQ Common Event Format (NCEF).
    Includes observable malformed-event telemetry and TLS metadata enrichment.
    """

    def __init__(self):
        self.processed_count = 0
        self.malformed_count = 0
        self.transformed_count = 0

    @property
    def engine_name(self) -> str:
        return "suricata"

    def get_metrics(self) -> Dict[str, int]:
        return {
            "processed": self.processed_count,
            "transformed": self.transformed_count,
            "malformed": self.malformed_count
        }

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
        self.processed_count += 1
        if isinstance(raw_data, str):
            try:
                record = json.loads(raw_data.strip())
            except Exception as parse_err:
                self.malformed_count += 1
                logger.warning(f"[SuricataAdapter] Malformed JSON dropped: {parse_err}")
                return None
        elif isinstance(raw_data, dict):
            record = raw_data
        else:
            self.malformed_count += 1
            logger.warning(f"[SuricataAdapter] Unsupported payload type: {type(raw_data)}")
            return None

        # Normalize IP field variants (dest_ip vs dst_ip)
        src_ip = record.get("src_ip")
        dst_ip = record.get("dest_ip") or record.get("dst_ip")
        if not src_ip or not dst_ip:
            self.malformed_count += 1
            logger.warning(f"[SuricataAdapter] Malformed event missing IP endpoints: {record}")
            return None

        try:
            proto = str(record.get("proto", "TCP")).upper()
            src_port = int(record.get("src_port") or 0)
            dst_port = int(record.get("dest_port") or record.get("dst_port") or 0)
        except (ValueError, TypeError) as num_err:
            self.malformed_count += 1
            logger.warning(f"[SuricataAdapter] Malformed numeric ports in event: {num_err}")
            return None

        # Resolve authoritative device identity
        device = identity_resolver.resolve(ip=src_ip)
        direction = _determine_direction(src_ip, dst_ip)

        event_type_str = record.get("event_type", "alert")
        raw_evidence = dict(record)

        # TLS metadata enrichment
        tls_data = record.get("tls")
        if tls_data and isinstance(tls_data, dict):
            raw_evidence["tls"] = {
                "sni": tls_data.get("sni") or tls_data.get("server_name"),
                "version": tls_data.get("version"),
                "subject": tls_data.get("subject"),
                "issuer": tls_data.get("issuerdn") or tls_data.get("issuer"),
                "ja3": tls_data.get("ja3", {}).get("hash") if isinstance(tls_data.get("ja3"), dict) else tls_data.get("ja3"),
                "ja3s": tls_data.get("ja3s", {}).get("hash") if isinstance(tls_data.get("ja3s"), dict) else tls_data.get("ja3s"),
                "fingerprint": tls_data.get("fingerprint")
            }

        rule_id = None
        severity = "INFO"
        standard_event_type = "connection"

        if event_type_str == "alert":
            standard_event_type = "alert"
            alert_obj = record.get("alert", {})
            signature = alert_obj.get("signature", "Suricata Alert")
            category = alert_obj.get("category", "Potentially Bad Traffic")
            severity_num = alert_obj.get("severity", 2)
            mitre_tag = self._extract_mitre(category, signature)

            raw_evidence["signature"] = signature
            raw_evidence["category"] = category
            raw_evidence["severity_level"] = severity_num
            raw_evidence["mitre"] = mitre_tag

            severity_map = {1: "HIGH", 2: "MEDIUM", 3: "LOW", 4: "INFO"}
            severity = severity_map.get(severity_num, "MEDIUM")
            rule_id = f"SID:{alert_obj.get('signature_id')}" if alert_obj.get("signature_id") else None

        elif event_type_str == "anomaly":
            standard_event_type = "anomaly"
            anomaly_obj = record.get("anomaly", {})
            raw_evidence["anomaly_event"] = anomaly_obj.get("event", "Protocol anomaly")
            severity = "MEDIUM"

        elif event_type_str == "tls":
            standard_event_type = "connection"
            severity = "INFO"

        # Build standard NetrIQ Common Event Format (NCEF) instance
        event = NormalizedSecurityEvent(
            tenant_id=record.get("tenant_id", "default"),
            sensor_id=record.get("sensor_id", "sensor-suricata-01"),
            timestamp=format_utc_timestamp(record.get("timestamp")),
            ingestion_time=get_utc_iso_now(),
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=src_port,
            destination_port=dst_port,
            protocol=proto,
            event_type=standard_event_type,
            detection_source="suricata",
            severity=severity,
            evidence=raw_evidence,
            network_interface=record.get("in_iface") or record.get("network_interface", "eth0"),
            direction=direction,
            flow_id=str(record.get("flow_id") or record.get("flow", {}).get("id") or ""),
            rule_id=rule_id,
            event_version="1.0.0",
            device=device
        )

        if deduplicator.is_duplicate(event):
            return None

        self.transformed_count += 1
        return event

suricata_adapter = SuricataAdapter()
