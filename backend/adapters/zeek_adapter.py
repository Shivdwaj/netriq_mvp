import json
import time
from typing import Dict, Any, Optional, Union

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
    into NetrIQ's common event format.
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
        try:
            ts = float(ts_raw)
        except (ValueError, TypeError):
            ts = time.time()

        conn_state = record.get("conn_state", "SF")
        state_desc = ZEEK_STATE_DESCRIPTIONS.get(conn_state, conn_state)

        device = identity_resolver.resolve(ip=src_ip)
        direction = _determine_direction(src_ip, dst_ip)

        orig_bytes = int(record.get("orig_bytes") or record.get("orig_ip_bytes") or 0)
        resp_bytes = int(record.get("resp_bytes") or record.get("resp_ip_bytes") or 0)

        network_details = NetworkDetails(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto,
            byte_count=orig_bytes + resp_bytes,
            packet_count=int(record.get("orig_pkts", 1)) + int(record.get("resp_pkts", 0)),
            direction=direction,
            dns_query=record.get("query")
        )

        raw_metadata = {
            "zeek_uid": record.get("uid"),
            "service": record.get("service"),
            "conn_state": conn_state,
            "conn_state_desc": state_desc,
            "duration": float(record.get("duration") or 0.0),
            "history": record.get("history")
        }

        # Tag reconnaissance pattern if Zeek recorded unresponded SYN sweeps (S0 / SH)
        if conn_state in ("S0", "SH", "REJ"):
            raw_metadata["scan_indicator"] = True
            raw_metadata["mitre"] = "T1046 Network Service Discovery"

        event = NormalizedSecurityEvent(
            timestamp=ts,
            event_type=EventType.NETWORK_FLOW,
            source=EventSource.ZEEK,
            device=device,
            network=network_details,
            raw_metadata=raw_metadata
        )

        if deduplicator.is_duplicate(event):
            return None

        return event

zeek_adapter = ZeekAdapter()
