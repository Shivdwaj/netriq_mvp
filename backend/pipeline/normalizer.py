import time
import ipaddress
from typing import List, Dict, Any, Optional

from backend.pipeline.schemas import (
    NormalizedSecurityEvent,
    EventType,
    EventSource,
    DeviceIdentity,
    NetworkDetails,
    EndpointDetails
)
from backend.pipeline.identity_resolver import identity_resolver
from backend.pipeline.deduplicator import deduplicator

def _determine_direction(src_ip: str, dst_ip: str) -> str:
    """Categorizes traffic as internal, outbound, or inbound."""
    try:
        src_private = ipaddress.ip_address(src_ip).is_private
        dst_private = ipaddress.ip_address(dst_ip).is_private
        if src_private and dst_private:
            return "internal"
        if src_private and not dst_private:
            return "outbound"
        return "inbound"
    except Exception:
        return "unknown"

class EventNormalizer:
    """
    Transforms raw heterogeneous sensor inputs into structured, normalized security events.
    Enriches with device identity and applies deduplication filters.
    """

    @staticmethod
    def normalize_network_packet(pkt: Dict[str, Any], source: EventSource = EventSource.NETWORK_SENSOR) -> Optional[NormalizedSecurityEvent]:
        """Normalizes a single captured IP packet from a SPAN port, TAP, or Npcap interface."""
        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")
        if not src_ip or not dst_ip:
            return None

        # Resolve device identity for source host
        device = identity_resolver.resolve(ip=src_ip)

        protocol_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        proto_raw = pkt.get("protocol", "IP")
        if isinstance(proto_raw, int):
            proto_name = protocol_map.get(proto_raw, f"IP-{proto_raw}")
        else:
            proto_name = str(proto_raw).upper()

        network_details = NetworkDetails(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=pkt.get("src_port", 0),
            dst_port=pkt.get("dst_port", 0),
            protocol=proto_name,
            packet_count=1,
            byte_count=pkt.get("length", 0),
            tcp_flags=pkt.get("flags", []),
            dns_query=pkt.get("dns_query"),
            direction=_determine_direction(src_ip, dst_ip)
        )

        event = NormalizedSecurityEvent(
            timestamp=pkt.get("timestamp", time.time()),
            event_type=EventType.NETWORK_FLOW,
            source=source,
            device=device,
            network=network_details,
            raw_metadata=pkt
        )

        if deduplicator.is_duplicate(event):
            return None

        return event

    @staticmethod
    def normalize_network_flow(flow: Any, source: EventSource = EventSource.NETWORK_SENSOR) -> Optional[NormalizedSecurityEvent]:
        """Normalizes a bi-directional network flow record produced by FlowBuilder."""
        src_ip = getattr(flow, "src_ip", "")
        dst_ip = getattr(flow, "dst_ip", "")
        if not src_ip or not dst_ip:
            return None

        device = identity_resolver.resolve(ip=src_ip)
        network_details = NetworkDetails(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=getattr(flow, "src_port", 0),
            dst_port=getattr(flow, "dst_port", 0),
            protocol=str(getattr(flow, "protocol", "TCP")),
            packet_count=getattr(flow, "packet_count", 1),
            byte_count=getattr(flow, "byte_count", 0),
            tcp_flags=getattr(flow, "tcp_flags", []),
            direction=_determine_direction(src_ip, dst_ip)
        )

        event = NormalizedSecurityEvent(
            timestamp=getattr(flow, "start_time", time.time()),
            event_type=EventType.NETWORK_FLOW,
            source=source,
            device=device,
            network=network_details,
            raw_metadata={"duration": getattr(flow, "duration", 0.0)}
        )

        if deduplicator.is_duplicate(event):
            return None

        return event

    @staticmethod
    def normalize_endpoint_telemetry(payload: Dict[str, Any]) -> List[NormalizedSecurityEvent]:
        """
        Decomposes complex agent telemetry into standardized atomic events:
        - Device registration / identity update
        - Process execution metadata events
        - Network socket / connection events
        - User authentication events
        """
        now = payload.get("timestamp") or time.time()
        mac = payload.get("mac")
        ip = payload.get("ip")
        hostname = payload.get("hostname", "unknown")
        user = payload.get("logged_in_user")
        os_name = payload.get("os")

        # 1. Update identity resolver
        device = identity_resolver.register_device(
            ip=ip,
            mac=mac,
            hostname=hostname,
            os_name=os_name,
            logged_in_user=user,
            is_managed=True
        )

        normalized_events: List[NormalizedSecurityEvent] = []

        # 2. Authentication Events
        auth_events = payload.get("auth_events", [])
        if not auth_events and user:
            # Synthetic session event for current user
            auth_events = [{"user": user, "status": "active_session", "time": now}]

        for auth in auth_events:
            ev = NormalizedSecurityEvent(
                timestamp=auth.get("time", now),
                event_type=EventType.USER_AUTHENTICATION,
                source=EventSource.ENDPOINT_AGENT,
                device=device,
                endpoint=EndpointDetails(
                    user=auth.get("user", user),
                    auth_status=auth.get("status", "success"),
                    event_action="session_heartbeat"
                ),
                raw_metadata=auth
            )
            if not deduplicator.is_duplicate(ev):
                normalized_events.append(ev)

        # 3. Process Execution Events
        processes = payload.get("processes", [])
        # If agent sent simple process names list
        if not processes and payload.get("sample_processes"):
            processes = [{"name": p} for p in payload.get("sample_processes", [])]

        suspicious_set = set(payload.get("suspicious_processes", []))

        for proc in processes:
            proc_name = proc.get("name", "")
            is_susp = proc_name.lower() in suspicious_set or proc.get("is_suspicious", False)
            ev = NormalizedSecurityEvent(
                timestamp=proc.get("timestamp", now),
                event_type=EventType.PROCESS_EXECUTION,
                source=EventSource.ENDPOINT_AGENT,
                device=device,
                endpoint=EndpointDetails(
                    pid=proc.get("pid"),
                    ppid=proc.get("ppid"),
                    process_name=proc_name,
                    command_line=proc.get("command_line"),
                    executable_path=proc.get("path"),
                    user=proc.get("user", user),
                    is_suspicious=is_susp,
                    suspicious_reason="Blacklisted tool pattern" if is_susp else None
                ),
                raw_metadata=proc
            )
            if not deduplicator.is_duplicate(ev):
                normalized_events.append(ev)

        # 4. Network Connections Reported by Endpoint
        connections = payload.get("connections", [])
        for conn in connections:
            remote_ip = conn.get("remote_ip")
            remote_port = conn.get("remote_port", 0)
            local_port = conn.get("local_port", 0)
            state = conn.get("state", "ESTABLISHED")

            ev = NormalizedSecurityEvent(
                timestamp=conn.get("timestamp", now),
                event_type=EventType.NETWORK_CONNECTION,
                source=EventSource.ENDPOINT_AGENT,
                device=device,
                endpoint=EndpointDetails(
                    pid=conn.get("pid"),
                    process_name=conn.get("process_name"),
                    connection_state=state,
                    local_port=local_port,
                    remote_ip=remote_ip,
                    remote_port=remote_port
                ),
                network=NetworkDetails(
                    src_ip=ip or "127.0.0.1",
                    dst_ip=remote_ip or "0.0.0.0",
                    src_port=local_port,
                    dst_port=remote_port,
                    protocol=conn.get("protocol", "TCP"),
                    direction=_determine_direction(ip or "127.0.0.1", remote_ip or "0.0.0.0")
                ) if remote_ip else None,
                raw_metadata=conn
            )
            if not deduplicator.is_duplicate(ev):
                normalized_events.append(ev)

        return normalized_events

normalizer = EventNormalizer()

