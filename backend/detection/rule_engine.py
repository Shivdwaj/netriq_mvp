import time
import math
import collections
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field

from backend.detection.models import DetectionFinding, DetectionEngineType
from backend.pipeline.schemas import NormalizedSecurityEvent
from backend.utils.logger import get_logger

logger = get_logger(__name__)

def shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    data_lower = data.lower()
    for x in set(data_lower):
        p_x = float(data_lower.count(x)) / len(data_lower)
        entropy -= p_x * math.log2(p_x)
    return entropy

@dataclass
class HostRuleState:
    """Stateful sliding window tracking for a single host."""
    source_ip: str
    window_seconds: float = 60.0
    connection_timestamps: collections.deque = field(default_factory=collections.deque)
    dst_ports_seen: Dict[int, float] = field(default_factory=dict) # port -> latest timestamp
    dst_ips_seen: Dict[str, float] = field(default_factory=dict)   # ip -> latest timestamp
    failed_connections: collections.deque = field(default_factory=collections.deque) # (ts, dst_ip, dst_port, state)
    dns_queries: collections.deque = field(default_factory=collections.deque)        # (ts, query, qtype)
    recent_event_ids: collections.deque = field(default_factory=lambda: collections.deque(maxlen=100))
    last_alerted: Dict[str, float] = field(default_factory=dict) # rule_id -> timestamp to prevent alert storms

    def prune(self, now: float):
        cutoff = now - self.window_seconds
        while self.connection_timestamps and self.connection_timestamps[0] < cutoff:
            self.connection_timestamps.popleft()

        # Prune dst ports
        self.dst_ports_seen = {p: ts for p, ts in self.dst_ports_seen.items() if ts >= cutoff}
        self.dst_ips_seen = {ip: ts for ip, ts in self.dst_ips_seen.items() if ts >= cutoff}

        while self.failed_connections and self.failed_connections[0][0] < cutoff:
            self.failed_connections.popleft()

        while self.dns_queries and self.dns_queries[0][0] < cutoff:
            self.dns_queries.popleft()

class RuleEngine:
    """
    Engine 2: Rule Engine
    Implements NetrIQ-specific, stateful detection rules over sliding time windows:
    1. Connection Burst / Flood detection
    2. Multi-port / multi-host reconnaissance scans
    3. Unusual outbound DNS activity (tunneling, DGA, high query rate)
    4. Repeated failed connection patterns (Zeek S0/REJ churn, brute force)
    """

    def __init__(
        self,
        window_seconds: float = 60.0,
        conn_burst_threshold: int = 50,
        port_scan_threshold: int = 8,
        dns_burst_threshold: int = 25,
        failed_conn_threshold: int = 5,
        cooldown_seconds: float = 45.0
    ):
        self.window_seconds = window_seconds
        self.conn_burst_threshold = conn_burst_threshold
        self.port_scan_threshold = port_scan_threshold
        self.dns_burst_threshold = dns_burst_threshold
        self.failed_conn_threshold = failed_conn_threshold
        self.cooldown_seconds = cooldown_seconds
        self._states: Dict[str, HostRuleState] = {}

    def get_configuration_state(self) -> Dict[str, Any]:
        """Returns active rule engine threshold configuration for cryptographic integrity verification."""
        return {
            "window_seconds": self.window_seconds,
            "conn_burst_threshold": self.conn_burst_threshold,
            "port_scan_threshold": self.port_scan_threshold,
            "dns_burst_threshold": self.dns_burst_threshold,
            "failed_conn_threshold": self.failed_conn_threshold,
            "cooldown_seconds": self.cooldown_seconds,
        }

    def _get_state(self, source_ip: str, now: float) -> HostRuleState:
        if source_ip not in self._states:
            self._states[source_ip] = HostRuleState(source_ip=source_ip, window_seconds=self.window_seconds)
        state = self._states[source_ip]
        state.prune(now)
        return state

    def analyze(self, event: NormalizedSecurityEvent) -> List[DetectionFinding]:
        findings: List[DetectionFinding] = []
        src_ip = event.source_ip
        if not src_ip or src_ip in ("127.0.0.1", "0.0.0.0", "unknown"):
            return findings

        now = time.time()
        state = self._get_state(src_ip, now)
        state.recent_event_ids.append(event.event_id)

        # Record connection attempt
        state.connection_timestamps.append(now)
        dst_port = event.destination_port or 0
        dst_ip = event.destination_ip or ""
        if dst_port > 0:
            state.dst_ports_seen[dst_port] = now
        if dst_ip:
            state.dst_ips_seen[dst_ip] = now

        # --- Rule 1: Connection Burst / Flood ---
        rule1_id = "NETRIQ:RULE:CONN_BURST_FLOOD"
        if len(state.connection_timestamps) >= self.conn_burst_threshold:
            if now - state.last_alerted.get(rule1_id, 0) > self.cooldown_seconds:
                state.last_alerted[rule1_id] = now
                findings.append(DetectionFinding(
                    engine_type=DetectionEngineType.RULE,
                    rule_id=rule1_id,
                    title="High-Volume Connection Burst Detected",
                    description=f"Host {src_ip} initiated {len(state.connection_timestamps)} connections within {self.window_seconds:.0f}s (Threshold: {self.conn_burst_threshold}).",
                    severity="MEDIUM",
                    confidence=0.85,
                    mitre_technique="T1498 Network Denial of Service",
                    mitre_stage="impact",
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=event.source_port,
                    destination_port=dst_port,
                    protocol=event.protocol,
                    timestamp=event.timestamp,
                    evidence={
                        "burst_count": len(state.connection_timestamps),
                        "window_seconds": self.window_seconds,
                        "unique_dst_ports": len(state.dst_ports_seen),
                        "unique_dst_ips": len(state.dst_ips_seen)
                    },
                    matched_event_ids=list(state.recent_event_ids)[-10:]
                ))

        # --- Rule 2: Multi-port Reconnaissance / Port Scan ---
        rule2_id = "NETRIQ:RULE:PORT_SCAN_RECON"
        unique_ports = len(state.dst_ports_seen)
        unique_ips = len(state.dst_ips_seen)
        if unique_ports >= self.port_scan_threshold or (unique_ips >= 5 and unique_ports >= 3):
            if now - state.last_alerted.get(rule2_id, 0) > self.cooldown_seconds:
                state.last_alerted[rule2_id] = now
                findings.append(DetectionFinding(
                    engine_type=DetectionEngineType.RULE,
                    rule_id=rule2_id,
                    title="Network Reconnaissance / Port Sweep Detected",
                    description=f"Host {src_ip} probed {unique_ports} distinct ports across {unique_ips} destinations within {self.window_seconds:.0f}s.",
                    severity="HIGH",
                    confidence=0.92,
                    mitre_technique="T1046 Network Service Discovery",
                    mitre_stage="discovery",
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=event.source_port,
                    destination_port=dst_port,
                    protocol=event.protocol,
                    timestamp=event.timestamp,
                    evidence={
                        "unique_ports_count": unique_ports,
                        "probed_ports": sorted(list(state.dst_ports_seen.keys()))[:25],
                        "unique_destinations": unique_ips,
                        "window_seconds": self.window_seconds
                    },
                    matched_event_ids=list(state.recent_event_ids)[-15:]
                ))

        # --- Rule 3: Unusual Outbound DNS Activity (High Query Rate, Tunneling, High Entropy) ---
        dns_query = event.evidence.get("dns_query") or (
            event.evidence.get("query") if event.protocol == "DNS" or dst_port == 53 else None
        )
        if dns_query:
            state.dns_queries.append((now, dns_query, event.evidence.get("qtype_name", "A")))
            entropy = shannon_entropy(dns_query)
            query_len = len(dns_query)

            rule3_id = "NETRIQ:RULE:UNUSUAL_DNS_ACTIVITY"
            is_dns_tunnel = entropy > 3.8 and query_len > 35
            is_dns_burst = len(state.dns_queries) >= self.dns_burst_threshold

            if (is_dns_tunnel or is_dns_burst) and (now - state.last_alerted.get(rule3_id, 0) > self.cooldown_seconds):
                state.last_alerted[rule3_id] = now
                sub_reason = "High entropy domain payload (potential DNS Tunneling/DGA)" if is_dns_tunnel else f"High DNS query burst ({len(state.dns_queries)} in window)"
                findings.append(DetectionFinding(
                    engine_type=DetectionEngineType.RULE,
                    rule_id=rule3_id,
                    title="Anomalous Outbound DNS Activity",
                    description=f"Host {src_ip} generated suspicious DNS traffic: {sub_reason}.",
                    severity="HIGH" if is_dns_tunnel else "MEDIUM",
                    confidence=0.88 if is_dns_tunnel else 0.82,
                    mitre_technique="T1071.004 DNS Application Layer Protocol",
                    mitre_stage="c2_exfil",
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=event.source_port,
                    destination_port=dst_port,
                    protocol="DNS",
                    timestamp=event.timestamp,
                    evidence={
                        "query": dns_query,
                        "query_length": query_len,
                        "entropy": round(entropy, 2),
                        "dns_burst_count": len(state.dns_queries),
                        "is_tunnel_indicator": is_dns_tunnel
                    },
                    matched_event_ids=[event.event_id]
                ))

        # --- Rule 4: Repeated Failed Connection Patterns (Zeek S0 / REJ / Reset) ---
        conn_state = event.evidence.get("conn_state") or (
            event.rule_id.split(":")[-1] if event.rule_id and event.rule_id.startswith("CONN:") else None
        )
        # S0 = connection attempt seen, no reply; REJ = rejected (RST); SH = half-open
        if conn_state in ("S0", "REJ", "SH", "RSTO"):
            state.failed_connections.append((now, dst_ip, dst_port, conn_state))

        rule4_id = "NETRIQ:RULE:FAILED_CONNECTION_CHURN"
        if len(state.failed_connections) >= self.failed_conn_threshold:
            if now - state.last_alerted.get(rule4_id, 0) > self.cooldown_seconds:
                state.last_alerted[rule4_id] = now
                failed_ports = [fc[2] for fc in state.failed_connections]
                has_admin_probe = any(p in (445, 3389, 22, 1433, 135) for p in failed_ports)

                findings.append(DetectionFinding(
                    engine_type=DetectionEngineType.RULE,
                    rule_id=rule4_id,
                    title="Repeated Failed Connection Pattern (Recon/Brute Force)",
                    description=f"Host {src_ip} recorded {len(state.failed_connections)} unresponded/rejected connections (States: S0/REJ) within {self.window_seconds:.0f}s.",
                    severity="HIGH" if has_admin_probe else "MEDIUM",
                    confidence=0.87,
                    mitre_technique="T1110 Brute Force" if has_admin_probe else "T1046 Network Service Discovery",
                    mitre_stage="lateral_movement" if has_admin_probe else "discovery",
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=event.source_port,
                    destination_port=dst_port,
                    protocol=event.protocol,
                    timestamp=event.timestamp,
                    evidence={
                        "failed_count": len(state.failed_connections),
                        "sample_states": [fc[3] for fc in list(state.failed_connections)[-5:]],
                        "sample_target_ports": list(set(failed_ports))[:10],
                        "has_admin_ports": has_admin_probe
                    },
                    matched_event_ids=list(state.recent_event_ids)[-10:]
                ))

        return findings

rule_engine = RuleEngine()
