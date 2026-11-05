import json
import time
from typing import Dict, Any, Optional, Union

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

ZEEK_STATE_DESCRIPTIONS = {
    "S0": "Connection attempt seen, no reply (Port Scan / Unresponsive Host)",
    "S1": "Connection established, not terminated",
    "SF": "Normal connection establishment and clean termination",
    "REJ": "Connection attempt rejected by target host (RST received)",
    "RSTO": "Connection established, then aborted by originator (RST sent)",
    "RSTR": "Connection established, then aborted by responder",
    "SH": "Originator sent a SYN followed by FIN (Half-open scan)",
    "SHR": "Responder sent a SYN-ACK followed by FIN (Half-open)",
    "OTH": "Midstream traffic recorded without SYN"
}

class ZeekAdapter(BaseEventAdapter):
    """
    Component B: Zeek Adapter.
    Translates Zeek connection logs (conn.log), DNS logs, and SSL records
    into the standard NetrIQ Common Event Format (NCEF).
    """

    @property
    def engine_name(self) -> str:
        return "zeek"

    def transform(self, raw_data: Union[str, Dict[str, Any]]) -> Optional[NormalizedSecurityEvent]:
        """Transforms a raw Zeek record (JSON line or dict)."""
        if isinstance(raw_data, str):
            try:
                record = json.loads(raw_data.strip())
            except Exception:
                return None
        else:
            record = raw_data

        # Support both dot-notation keys (id.orig_h) and nested dicts ({id: {orig_h: ...}})
        src_ip = record.get("id.orig_h") or record.get("id", {}).get("orig_h") or record.get("src_ip")
        dst_ip = record.get("id.resp_h") or record.get("id", {}).get("resp_h") or record.get("dst_ip") or record.get("dest_ip")
        if not src_ip or not dst_ip:
            return None

        src_port = int(record.get("id.orig_p") or record.get("id", {}).get("orig_p") or record.get("src_port") or 0)
        dst_port = int(record.get("id.resp_p") or record.get("id", {}).get("resp_p") or record.get("dst_port") or 0)
        proto = str(record.get("proto", "tcp")).upper()
        ts_raw = record.get("ts", time.time())

        conn_state = record.get("conn_state")
        state_desc = ZEEK_STATE_DESCRIPTIONS.get(conn_state, conn_state) if conn_state else None

        device = identity_resolver.resolve(ip=src_ip)
        direction = _determine_direction(src_ip, dst_ip)

        orig_bytes = int(record.get("orig_bytes") or record.get("orig_ip_bytes") or 0)
        resp_bytes = int(record.get("resp_bytes") or record.get("resp_ip_bytes") or 0)

        raw_evidence = {
            "zeek_uid": record.get("uid"),
            "service": record.get("service"),
            "duration": float(record.get("duration") or 0.0),
            "orig_bytes": orig_bytes,
            "resp_bytes": resp_bytes,
            "history": record.get("history")
        }
        if conn_state:
            raw_evidence["conn_state"] = conn_state
            raw_evidence["conn_state_desc"] = state_desc

        # DNS specific fields
        if "query" in record:
            raw_evidence["dns_query"] = record.get("query")
            raw_evidence["qtype_name"] = record.get("qtype_name")
            raw_evidence["rcode_name"] = record.get("rcode_name")
            raw_evidence["answers"] = record.get("answers", [])

        # SSL / TLS specific fields
        if "server_name" in record or "subject" in record:
            raw_evidence["server_name"] = record.get("server_name")
            raw_evidence["subject"] = record.get("subject")
            raw_evidence["issuer"] = record.get("issuer")
            raw_evidence["ja3"] = record.get("ja3")

        # Tag reconnaissance pattern if Zeek recorded unresponded SYN sweeps (S0 / SH / REJ)
        is_scan = conn_state in ("S0", "SH", "REJ")
        if is_scan:
            raw_evidence["scan_indicator"] = True
            raw_evidence["mitre"] = "T1046 Network Service Discovery"

        severity = "HIGH" if is_scan and dst_port in (445, 3389, 22, 1433) else ("MEDIUM" if is_scan else "INFO")

        rule_id = f"CONN:{conn_state}" if conn_state else (
            f"DNS:{record.get('qtype_name', 'QUERY')}" if "query" in record else (
                f"SSL:{record.get('server_name')}" if "server_name" in record else None
            )
        )

        # Build standard NetrIQ Common Event Format (NCEF) instance
        event = NormalizedSecurityEvent(
            tenant_id=record.get("tenant_id", "default"),
            sensor_id=record.get("sensor_id", "sensor-zeek-01"),
            timestamp=format_utc_timestamp(ts_raw),
            ingestion_time=get_utc_iso_now(),
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=src_port,
            destination_port=dst_port,
            protocol=proto,
            event_type="connection",
            detection_source="zeek",
            severity=severity,
            evidence=raw_evidence,
            network_interface=record.get("network_interface", "eth0"),
            direction=direction,
            flow_id=record.get("uid"),
            rule_id=rule_id,
            event_version="1.0.0",
            device=device
        )

        if deduplicator.is_duplicate(event):
            return None

        return event

zeek_adapter = ZeekAdapter()
