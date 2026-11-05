import json
import time
from typing import Optional, Dict, Any, List

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

# Zeek conn_state meanings for threat intelligence
ZEEK_STATE_DESCRIPTIONS = {
    "S0": "Connection attempt seen, no reply (Port Scan / Unresponsive Host)",
    "S1": "Connection established, not terminated",
    "SF": "Normal connection establishment and clean termination",
    "REJ": "Connection attempt rejected by target host (RST received)",
    "RSTO": "Connection established, then aborted by originator (RST sent)",
    "RSTR": "Connection established, then aborted by responder",
    "SH": "Originator sent a SYN followed by FIN, never saw SYN-ACK (Half-open scan)",
    "SHR": "Responder sent a SYN-ACK followed by FIN (Half-open)",
    "OTH": "No SYN seen, midstream traffic traffic recorded"
}

class ZeekLogIngestor:
    """
    Parses Zeek connection and protocol logs (conn.log, dns.log, ssl.log).
    Maps Zeek session state (S0, REJ, SF), durations, and protocol metadata
    into NetrIQ NormalizedSecurityEvents.
    """

    def parse_conn_record(self, record: Dict[str, Any]) -> Optional[NormalizedSecurityEvent]:
        """Parses a single Zeek conn.log record."""
        # Support both nested JSON format ('id.orig_h' or id: {orig_h: ...})
        src_ip = record.get("id.orig_h") or record.get("id", {}).get("orig_h")
        dst_ip = record.get("id.resp_h") or record.get("id", {}).get("resp_h")
        if not src_ip or not dst_ip:
            return None

        src_port = record.get("id.orig_p") or record.get("id", {}).get("orig_p", 0)
        dst_port = record.get("id.resp_p") or record.get("id", {}).get("resp_p", 0)

        ts = float(record.get("ts", time.time()))
        proto = str(record.get("proto", "tcp")).upper()
        conn_state = record.get("conn_state", "SF")
        state_desc = ZEEK_STATE_DESCRIPTIONS.get(conn_state, conn_state)

        device = identity_resolver.resolve(ip=src_ip)
        direction = _determine_direction(src_ip, dst_ip)

        orig_bytes = int(record.get("orig_bytes") or record.get("orig_ip_bytes") or 0)
        resp_bytes = int(record.get("resp_bytes") or record.get("resp_ip_bytes") or 0)

        network_details = NetworkDetails(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=int(src_port),
            dst_port=int(dst_port),
            protocol=proto,
            byte_count=orig_bytes + resp_bytes,
            packet_count=int(record.get("orig_pkts", 1)) + int(record.get("resp_pkts", 0)),
            direction=direction
        )

        raw_meta = {
            "zeek_uid": record.get("uid"),
            "conn_state": conn_state,
            "conn_state_desc": state_desc,
            "duration": float(record.get("duration") or 0.0),
            "service": record.get("service"),
            "history": record.get("history")
        }

        # Tag reconnaissance pattern if Zeek recorded unresponded SYN sweeps (S0 / SH)
        if conn_state in ("S0", "SH", "REJ"):
            raw_meta["scan_indicator"] = True
            raw_meta["mitre"] = "T1046 Network Service Discovery"

        event = NormalizedSecurityEvent(
            timestamp=ts,
            event_type=EventType.NETWORK_FLOW,
            source=EventSource.ZEEK,
            device=device,
            network=network_details,
            raw_metadata=raw_meta
        )

        if deduplicator.is_duplicate(event):
            return None

        return event

    def parse_dns_record(self, record: Dict[str, Any]) -> Optional[NormalizedSecurityEvent]:
        """Parses a single Zeek dns.log record."""
        src_ip = record.get("id.orig_h") or record.get("id", {}).get("orig_h")
        dst_ip = record.get("id.resp_h") or record.get("id", {}).get("resp_h")
        if not src_ip or not dst_ip:
            return None

        query = record.get("query")
        answers = record.get("answers", [])
        ts = float(record.get("ts", time.time()))
        device = identity_resolver.resolve(ip=src_ip)

        network_details = NetworkDetails(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=int(record.get("id.orig_p") or record.get("id", {}).get("orig_p", 0)),
            dst_port=53,
            protocol="UDP",
            dns_query=query,
            direction=_determine_direction(src_ip, dst_ip)
        )

        raw_meta = {
            "dns_query": query,
            "qtype_name": record.get("qtype_name"),
            "answers": answers,
            "rcode_name": record.get("rcode_name")
        }

        event = NormalizedSecurityEvent(
            timestamp=ts,
            event_type=EventType.NETWORK_FLOW,
            source=EventSource.ZEEK,
            device=device,
            network=network_details,
            raw_metadata=raw_meta
        )

        if deduplicator.is_duplicate(event):
            return None

        return event

    def parse_json_line(self, line: str, log_type: str = "conn") -> Optional[NormalizedSecurityEvent]:
        """Parses a single JSON line from Zeek."""
        line = line.strip()
        if not line or line.startswith("#"):
            return None
        try:
            record = json.loads(line)
            if log_type == "conn":
                return self.parse_conn_record(record)
            elif log_type == "dns":
                return self.parse_dns_record(record)
            return self.parse_conn_record(record)
        except Exception as e:
            logger.debug(f"[ZeekLogIngestor] Failed to parse Zeek record: {e}")
            return None

zeek_ingestor = ZeekLogIngestor()
