import time
import ipaddress
from typing import List, Dict, Any, Optional

from backend.pipeline.schemas import (
    NormalizedSecurityEvent,
    EventType,
    DetectionSource,
    format_utc_timestamp,
    get_utc_iso_now,
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
    Transforms raw heterogeneous sensor inputs into structured, normalized security events
    adhering strictly to the NetrIQ Common Event Format (NCEF).
    """

    @staticmethod
    def normalize_network_packet(pkt: Dict[str, Any], source: str = "netriq") -> Optional[NormalizedSecurityEvent]:
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

        direction = _determine_direction(src_ip, dst_ip)
        src_port = int(pkt.get("src_port") or 0)
        dst_port = int(pkt.get("dst_port") or 0)

        event = NormalizedSecurityEvent(
            tenant_id=pkt.get("tenant_id", "default"),
            sensor_id=pkt.get("sensor_id", "sensor-netriq-01"),
            timestamp=format_utc_timestamp(pkt.get("timestamp")),
            ingestion_time=get_utc_iso_now(),
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=src_port,
            destination_port=dst_port,
            protocol=proto_name,
            event_type="connection",
            detection_source=str(source).lower(),
            severity="INFO",
            evidence=pkt,
            network_interface=pkt.get("network_interface", "eth0"),
            direction=direction,
            flow_id=pkt.get("flow_id"),
            rule_id=pkt.get("rule_id"),
            event_version="1.0.0",
            device=device
        )

        if deduplicator.is_duplicate(event):
            return None

        return event

    @staticmethod
    def normalize_network_flow(flow: Any, source: str = "netriq") -> Optional[NormalizedSecurityEvent]:
        """Normalizes a bi-directional network flow record produced by FlowBuilder."""
        src_ip = getattr(flow, "src_ip", "")
        dst_ip = getattr(flow, "dst_ip", "")
        if not src_ip or not dst_ip:
            return None

        device = identity_resolver.resolve(ip=src_ip)
        direction = _determine_direction(src_ip, dst_ip)

        start_time = getattr(flow, "start_time", time.time())
        duration = getattr(flow, "duration", 0.0)

        evidence = {
            "duration": duration,
            "packet_count": getattr(flow, "packet_count", 1),
            "byte_count": getattr(flow, "byte_count", 0),
            "tcp_flags": getattr(flow, "tcp_flags", [])
        }

        event = NormalizedSecurityEvent(
            tenant_id="default",
            sensor_id="sensor-netriq-01",
            timestamp=format_utc_timestamp(start_time),
            ingestion_time=get_utc_iso_now(),
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=getattr(flow, "src_port", 0),
            destination_port=getattr(flow, "dst_port", 0),
            protocol=str(getattr(flow, "protocol", "TCP")).upper(),
            event_type="connection",
            detection_source=str(source).lower(),
            severity="INFO",
            evidence=evidence,
            network_interface="eth0",
            direction=direction,
            flow_id=getattr(flow, "flow_id", None),
            rule_id=None,
            event_version="1.0.0",
            device=device
        )

        if deduplicator.is_duplicate(event):
            return None

        return event

    @staticmethod
    def normalize_endpoint_telemetry(payload: Dict[str, Any]) -> List[NormalizedSecurityEvent]:
        """
        Decomposes complex agent telemetry into standardized atomic events:
        - User authentication events
        - Process execution metadata events
        - Network socket / connection events
        """
        now = payload.get("timestamp") or time.time()
        mac = payload.get("mac")
        ip = payload.get("ip") or "127.0.0.1"
        hostname = payload.get("hostname", "unknown")
        user = payload.get("logged_in_user")
        os_name = payload.get("os")
        tenant_id = payload.get("tenant_id", "default")
        sensor_id = f"agent-{mac}" if mac else "agent-endpoint-01"

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
            auth_events = [{"user": user, "status": "active_session", "time": now}]

        for auth in auth_events:
            ev = NormalizedSecurityEvent(
                tenant_id=tenant_id,
                sensor_id=sensor_id,
                timestamp=format_utc_timestamp(auth.get("time", now)),
                ingestion_time=get_utc_iso_now(),
                source_ip=ip,
                destination_ip=ip,
                protocol="LOCAL",
                event_type="user_authentication",
                detection_source="endpoint_agent",
                severity="INFO",
                evidence=auth,
                direction="internal",
                device=device,
                endpoint=EndpointDetails(
                    user=auth.get("user", user),
                    auth_status=auth.get("status", "success")
                )
            )
            if not deduplicator.is_duplicate(ev):
                normalized_events.append(ev)

        # 3. Process Execution Events
        processes = payload.get("processes", [])
        if not processes and payload.get("sample_processes"):
            processes = [{"name": p} for p in payload.get("sample_processes", [])]

        suspicious_set = set(payload.get("suspicious_processes", []))

        for proc in processes:
            proc_name = proc.get("name", "")
            is_susp = proc_name.lower() in suspicious_set or proc.get("is_suspicious", False)
            ev = NormalizedSecurityEvent(
                tenant_id=tenant_id,
                sensor_id=sensor_id,
                timestamp=format_utc_timestamp(proc.get("timestamp", now)),
                ingestion_time=get_utc_iso_now(),
                source_ip=ip,
                destination_ip=ip,
                protocol="LOCAL",
                event_type="process_execution",
                detection_source="endpoint_agent",
                severity="HIGH" if is_susp else "INFO",
                rule_id="BLACK_LIST_PROC" if is_susp else None,
                evidence=proc,
                direction="internal",
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
                )
            )
            if not deduplicator.is_duplicate(ev):
                normalized_events.append(ev)

        # 4. Network Connections Reported by Endpoint
        connections = payload.get("connections", [])
        for conn in connections:
            remote_ip = conn.get("remote_ip") or "0.0.0.0"
            remote_port = int(conn.get("remote_port") or 0)
            local_port = int(conn.get("local_port") or 0)
            state = conn.get("state", "ESTABLISHED")

            ev = NormalizedSecurityEvent(
                tenant_id=tenant_id,
                sensor_id=sensor_id,
                timestamp=format_utc_timestamp(conn.get("timestamp", now)),
                ingestion_time=get_utc_iso_now(),
                source_ip=ip,
                destination_ip=remote_ip,
                source_port=local_port,
                destination_port=remote_port,
                protocol=conn.get("protocol", "TCP").upper(),
                event_type="network_connection",
                detection_source="endpoint_agent",
                severity="INFO",
                evidence=conn,
                direction=_determine_direction(ip, remote_ip),
                device=device,
                endpoint=EndpointDetails(
                    pid=conn.get("pid"),
                    connection_state=state,
                    local_port=local_port,
                    remote_ip=remote_ip,
                    remote_port=remote_port
                )
            )
            if not deduplicator.is_duplicate(ev):
                normalized_events.append(ev)

        return normalized_events

normalizer = EventNormalizer()
